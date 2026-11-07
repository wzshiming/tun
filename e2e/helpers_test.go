package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/elevate"
	"go4.org/netipx"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/stack"
)

// ttDNSQuery is a DNS query for the A record of example.com.
const ttDNSQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

// ttCaptureLab is a capture list covering only the benchmarking and documentation ranges.
var ttCaptureLab = []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("2001:db8::/32")}

// ttGate skips the test, which changes the host's interfaces, routes or sockets, unless TUN_E2E=1.
func ttGate(t *testing.T) {
	t.Helper()
	if os.Getenv("TUN_E2E") != "1" {
		t.Skip("changes the host's interfaces and routes; set TUN_E2E=1 to run")
	}
	// CreateTUN would write the interface name to the file this names.
	os.Unsetenv("WG_TUN_NAME_FILE")
}

// ttExecProc is an elevate.Proc for a helper started with exec, mapping a non-zero exit to *elevate.ExitError.
type ttExecProc struct{ cmd *exec.Cmd }

func (p ttExecProc) Wait() error {
	err := p.cmd.Wait()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return &elevate.ExitError{Code: ee.ExitCode()}
	}
	return err
}

// ttConfig is the TUN every e2e test opens, with bypass as its Bypass.
func ttConfig(bypass []netip.Prefix) tun.Config {
	return tun.Config{Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64"), MTU: 1500, Bypass: bypass}
}

func ttPrefixes(s ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(s))
	for i, p := range s {
		prefixes[i] = netip.MustParsePrefix(p)
	}
	return prefixes
}

func ttSet(t *testing.T, add, remove []netip.Prefix) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	for _, p := range add {
		b.AddPrefix(p)
	}
	for _, p := range remove {
		b.RemovePrefix(p)
	}
	set, err := b.IPSet()
	if err != nil {
		t.Fatalf("IP set of %v minus %v: %v", add, remove, err)
	}
	return set
}

// ttWaitFor polls cond every 200ms and fails t unless it holds within timeout.
func ttWaitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", timeout, msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ttOpen opens cfg's TUN and fails t on an error; the TUN closes when t ends or after 3 minutes.
func ttOpen(t *testing.T, ctx context.Context, cfg tun.Config) *tun.Device {
	t.Helper()
	dev, err := tun.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Should the test hang, closing the TUN still removes its interface and routes.
	watchdog := time.AfterFunc(3*time.Minute, func() { dev.Close() })
	t.Cleanup(func() {
		watchdog.Stop()
		dev.Close()
	})
	t.Logf("opened %s, warnings %q", dev.Interface, dev.Warnings)
	return dev
}

// ttServeDev runs stack.Serve on dev until ctx ends; the channel receives its result.
func ttServeDev(ctx context.Context, dev *tun.Device, cfg tun.Config, dialer *ttDialRecorder) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- stack.Serve(ctx, dev, dialer, stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	}()
	return errCh
}

// ttIfaceHas reports whether the interface name holds the address ip.
func ttIfaceHas(name, ip string) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	want := netip.MustParseAddr(ip)
	return slices.ContainsFunc(addrs, func(a net.Addr) bool {
		n, ok := a.(*net.IPNet)
		if !ok {
			return false
		}
		got, ok := netip.AddrFromSlice(n.IP)
		return ok && got.Unmap() == want
	})
}

// ttDial is one dial Serve made through a ttDialRecorder.
type ttDial struct{ network, address, client string }

// ttDialRecorder records Serve's dials; with redirect set it connects them to local fakes instead of base.
type ttDialRecorder struct {
	base stack.Dialer
	// redirect maps destinations to the loopback addresses standing in for them; any other port 53 goes to dns.
	redirect map[string]string
	dns      string

	mu       sync.Mutex
	dials    []ttDial
	dialErrs []string
}

func (r *ttDialRecorder) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	dial := ttDial{network: network, address: address}
	if client := stack.ClientAddr(ctx); client != nil {
		dial.client = client.String()
	}
	r.mu.Lock()
	r.dials = append(r.dials, dial)
	r.mu.Unlock()
	defer func() {
		if err != nil {
			r.mu.Lock()
			r.dialErrs = append(r.dialErrs, fmt.Sprintf("%+v: %v", dial, err))
			r.mu.Unlock()
		}
	}()
	if len(r.redirect) == 0 {
		return r.base.DialContext(ctx, network, address)
	}
	target, ok := r.redirect[address]
	if _, port, _ := net.SplitHostPort(address); !ok && port == "53" {
		target, ok = r.dns, true
	}
	if !ok {
		return nil, fmt.Errorf("tt: nothing stands in for %s", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, target)
}

// dialsTo returns the recorded dials to address.
func (r *ttDialRecorder) dialsTo(address string) []ttDial {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.DeleteFunc(slices.Clone(r.dials), func(d ttDial) bool { return d.address != address })
}

// logDialErrorsOnFailure logs the failed dials from t's cleanup once t has failed, as Serve's goroutines may outlive t.
func (r *ttDialRecorder) logDialErrorsOnFailure(t *testing.T) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		r.mu.Lock()
		errs := slices.Clone(r.dialErrs)
		r.mu.Unlock()
		t.Logf("%d failed dials:\n%s", len(errs), strings.Join(errs, "\n"))
	})
}

// wantDial fails t unless Serve dialed network address for a client on clientHost, or for any client when clientHost is empty.
func (r *ttDialRecorder) wantDial(t *testing.T, network, address, clientHost string) {
	t.Helper()
	dials := r.dialsTo(address)
	for _, d := range dials {
		host, _, _ := net.SplitHostPort(d.client)
		if d.network == network && (clientHost == "" || host == clientHost) {
			return
		}
	}
	t.Errorf("dials to %s = %+v, want a %s dial from client host %q", address, dials, network, clientHost)
}

// ttServeLocal serves each connection to a new 127.0.0.1 listener with handle and returns the listener's address.
func ttServeLocal(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return ln.Addr().String()
}

func ttEchoServer(conn net.Conn) { io.Copy(conn, conn) }

// ttDNSServer answers each length-framed DNS message with the same message marked as a response.
func ttDNSServer(conn net.Conn) {
	var size [2]byte
	for {
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		if len(msg) > 2 {
			msg[2] |= 0x80
		}
		if _, err := conn.Write(append(size[:], msg...)); err != nil {
			return
		}
	}
}

// ttEchoVia dials address through the TUN, echoes 64 KiB and checks Serve dialed it for clientHost.
func ttEchoVia(t *testing.T, rec *ttDialRecorder, address, clientHost string) {
	t.Helper()
	var conn net.Conn
	// A fresh IPv6 address may stay tentative for a moment, which fails a dial at once.
	ttWaitFor(t, 10*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			t.Logf("dial %s: %v", address, err)
			return false
		}
		conn = c
		return true
	}, "a connection to "+address)
	defer conn.Close()
	ttEcho(t, conn, 64<<10)
	rec.wantDial(t, "tcp", address, clientHost)
}

// ttEcho fails t unless size random bytes written to conn come back unchanged within 5s.
func ttEcho(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	want := make([]byte, size)
	rand.Read(want)
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write(want)
		written <- err
	}()
	got := make([]byte, size)
	_, err := io.ReadFull(conn, got)
	if werr := <-written; err == nil {
		err = werr
	}
	if err != nil {
		t.Fatalf("echo %d bytes via %v: %v", size, conn.RemoteAddr(), err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo %d bytes via %v: the bytes came back changed", size, conn.RemoteAddr())
	}
}

// ttDNSVia sends ttDNSQuery to address over UDP and fails t unless the fake's response comes back within 5s.
func ttDNSVia(t *testing.T, address string) {
	t.Helper()
	conn, err := net.Dial("udp", address)
	if err != nil {
		t.Fatalf("dial udp %s: %v", address, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(ttDNSQuery)); err != nil {
		t.Fatalf("send the DNS query to %s: %v", address, err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil {
		t.Fatalf("read the DNS reply from %s: %v", address, err)
	}
	want := []byte(ttDNSQuery)
	want[2] |= 0x80
	if !bytes.Equal(reply[:n], want) {
		t.Fatalf("DNS reply from %s = %x, want %x", address, reply[:n], want)
	}
}

// ttGet fetches url on a new connection without following redirects and logs the status.
func ttGet(t *testing.T, url string, timeout time.Duration) error {
	t.Helper()
	client := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       timeout,
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	t.Logf("GET %s: %s", url, resp.Status)
	return nil
}

// ttTool returns the first of paths that exists, as the library itself picks it, or else name found in PATH.
func ttTool(name string, paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	path, _ := exec.LookPath(name)
	return path
}

// ttRouteTool and ttIPTool are the route (macOS) and ip (Linux) commands the library configures the TUN with.
func ttRouteTool() string { return ttTool("route", "/sbin/route") }
func ttIPTool() string    { return ttTool("ip", "/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip") }

// ttRouteDev returns the interface a macOS or Linux host routes ip through, or "" when it has no route.
func ttRouteDev(t *testing.T, ip string) string {
	t.Helper()
	route, ipTool := ttRouteTool(), ttIPTool()
	argv, key := []string{route, "-n", "get", ip}, "interface:"
	v6 := netip.MustParseAddr(ip).Is6()
	switch {
	case runtime.GOOS == "linux" && v6:
		argv, key = []string{ipTool, "-6", "route", "get", ip}, "dev"
	case runtime.GOOS == "linux":
		argv, key = []string{ipTool, "route", "get", ip}, "dev"
	case v6:
		argv = []string{route, "-n", "get", "-inet6", ip}
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	fields := strings.Fields(string(out))
	if i := slices.Index(fields, key); err == nil && i >= 0 && i+1 < len(fields) {
		return fields[i+1]
	}
	t.Logf("%q: %v\n%s", argv, err, out)
	return ""
}

// ttLogRoutes logs the host's route to 1.1.1.1 and, on macOS, the one scoped to phys and the IPv4 defaults; it returns the scoped lookup.
func ttLogRoutes(t *testing.T, when, phys string) (scoped string) {
	t.Helper()
	logOutput := func(what, out string, err error) {
		t.Helper()
		var lines []string
		for line := range strings.Lines(out) {
			if line = strings.TrimSpace(line); line != "" {
				lines = append(lines, line)
			}
		}
		msg := strings.Join(lines, "; ")
		if err != nil {
			msg += fmt.Sprintf(" (error: %v)", err)
		}
		t.Logf("%s, %s: %s", when, what, msg)
	}
	run := func(argv ...string) string {
		t.Helper()
		out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
		logOutput(strings.Join(argv, " "), string(out), err)
		return string(out)
	}
	if runtime.GOOS == "linux" {
		run(ttIPTool(), "route", "get", "1.1.1.1")
		return ""
	}
	route := ttRouteTool()
	run(route, "-n", "get", "-inet", "1.1.1.1")
	scoped = run(route, "-n", "get", "-inet", "-ifscope", phys, "1.1.1.1")
	netstat, err := exec.LookPath("netstat")
	if err != nil {
		t.Logf("%s, look up netstat: %v", when, err)
		return scoped
	}
	out, err := exec.Command(netstat, "-rn", "-f", "inet").CombinedOutput()
	var defaults []string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "default") {
			defaults = append(defaults, line)
		}
	}
	logOutput(netstat+" -rn -f inet, its default lines", strings.Join(defaults, "\n"), err)
	return scoped
}

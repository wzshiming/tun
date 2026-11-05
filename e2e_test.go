//go:build e2e && (darwin || linux)

package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
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
	"syscall"
	"testing"
	"time"

	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/stack"
)

// ttDNSQuery is a DNS query for the A record of example.com.
const ttDNSQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

// ttE2EConfig is the TUN every e2e test opens; each sets its own Bypass.
func ttE2EConfig() Config {
	return Config{Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64"), MTU: 1500}
}

// ttGate skips the e2e tests, which change the host's interfaces and routes, unless TUN_E2E=1 and -test.run names them.
func ttGate(t *testing.T) {
	t.Helper()
	if os.Getenv("TUN_E2E") != "1" {
		t.Skip("changes the host's interfaces and routes; set TUN_E2E=1 to run")
	}
	if run := flag.Lookup("test.run"); run == nil || !strings.Contains(run.Value.String(), "TestE2E") {
		t.Skip("runs only when -test.run names the TestE2E tests")
	}
	// CreateTUN would write the interface name to the file this names.
	os.Unsetenv("WG_TUN_NAME_FILE")
}

// TestE2EHelperChild is the helper TestE2EHelper launches through sudo; without a socket it does nothing.
func TestE2EHelperChild(t *testing.T) {
	if sock := os.Getenv("TUN_E2E_SOCKET"); sock != "" {
		os.Exit(Helper([]string{sock}))
	}
}

func TestE2EHelper(t *testing.T) {
	ttGate(t)
	if os.Geteuid() == 0 {
		t.Skip("runs unprivileged")
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		t.Fatalf("look up sudo: %v", err)
	}
	prev := elevate
	t.Cleanup(func() { elevate = prev })
	elevate = func(ctx context.Context, _, socket string) *exec.Cmd {
		return exec.CommandContext(ctx, sudo, "-n", "env", "TUN_E2E_SOCKET="+socket, os.Args[0], "-test.run=^TestE2EHelperChild$")
	}

	cfg := ttE2EConfig()
	// Bypassing everything else keeps the runner's own traffic off the TUN.
	cfg.Bypass = ttSet(t, ttPrefixes("0.0.0.0/0", "::/0"), ttPrefixes("1.1.1.1/32", "2606:4700:4700::1111/128")).Prefixes()
	want := ttPrefixes("1.1.1.1/32", "2606:4700:4700::1111/128")
	if got := CaptureRoutes(cfg); len(got) != len(want) || slices.ContainsFunc(want, func(p netip.Prefix) bool { return !slices.Contains(got, p) }) {
		t.Fatalf("CaptureRoutes = %v, want exactly %v", got, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dev := ttOpen(t, ctx, cfg)
	echo := ttServeLocal(t, ttEchoServer)
	rec := &ttDialRecorder{
		redirect: map[string]string{"1.1.1.1:8080": echo, "[2606:4700:4700::1111]:8080": echo},
		dns:      ttServeLocal(t, ttDNSServer),
	}
	rec.logDialErrorsOnFailure(t)
	errCh := ttServeDev(ctx, dev, cfg, rec)

	ttWaitFor(t, 10*time.Second, func() bool {
		return ttIfaceHas(dev.Interface, "198.18.0.1") && ttIfaceHas(dev.Interface, "fd00:6a77:7761::1")
	}, dev.Interface+" to hold 198.18.0.1 and fd00:6a77:7761::1")
	for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if got := ttRouteDev(t, ip); got != dev.Interface {
			t.Fatalf("route to %s leaves through %q, want %s", ip, got, dev.Interface)
		}
	}
	if got := ttRouteDev(t, "8.8.8.8"); got == dev.Interface {
		t.Errorf("route to 8.8.8.8 leaves through %s, want it left off the TUN", got)
	}

	t.Run("tcp4 echo", func(t *testing.T) { ttEchoVia(t, rec, "1.1.1.1:8080", "198.18.0.1") })
	t.Run("tcp6 echo", func(t *testing.T) { ttEchoVia(t, rec, "[2606:4700:4700::1111]:8080", "fd00:6a77:7761::1") })
	t.Run("dns over udp", func(t *testing.T) {
		ttDNSVia(t, "1.1.1.1:53")
		rec.wantDial(t, "tcp", "1.1.1.1:53", "")
	})
	t.Run("udp port unreachable", func(t *testing.T) {
		conn, err := net.Dial("udp", "1.1.1.1:9999")
		if err != nil {
			t.Fatalf("dial udp 1.1.1.1:9999: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write(make([]byte, 8)); err != nil {
			t.Fatalf("send to udp 1.1.1.1:9999: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("read from udp 1.1.1.1:9999 = %v, want ECONNREFUSED from an ICMP port unreachable", err)
		}
		if dials := rec.dialsTo("1.1.1.1:9999"); len(dials) != 0 {
			t.Errorf("Serve dialed %+v, want UDP to port 9999 never dialed", dials)
		}
	})
	t.Run("ping", func(t *testing.T) {
		for _, ip := range []string{"198.18.0.1", "fd00:6a77:7761::1"} {
			if !ttPingOK(t, ip) {
				t.Errorf("ping %s got no reply", ip)
			}
		}
	})

	ttTeardown(t, cancel, errCh, dev)
	conn, err := net.DialTimeout("tcp", echo, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the echo server at %s after teardown: %v", echo, err)
	}
	defer conn.Close()
	ttEcho(t, conn, 1<<10)
}

func TestE2ERoot(t *testing.T) {
	ttGate(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	phys, err := bypass.DefaultInterface(false)
	if err != nil {
		t.Skipf("no IPv4 default route for the bypass dialer: %v", err)
	}
	cfg := ttE2EConfig()
	// The embedded default no_proxy entries.
	cfg.Bypass = ttPrefixes("127.0.0.1/32", "::1/128", "192.168.0.0/16", "10.0.0.0/8", "fe80::/64", "fd00::/8")
	capture := CaptureRoutes(cfg)
	if len(capture) <= 50 {
		t.Fatalf("CaptureRoutes = %v, want more than 50 routes", capture)
	}
	for _, kept := range ttPrefixes("10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4") {
		if i := slices.IndexFunc(capture, kept.Overlaps); i >= 0 {
			t.Fatalf("capture route %v overlaps %v, which must stay off the TUN", capture[i], kept)
		}
	}
	rec := &ttDialRecorder{base: bypass.NewDialer(capture)}
	rec.logDialErrorsOnFailure(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ttLogRoutes(t, "before Open", phys.Name)
	dev := ttOpen(t, ctx, cfg)
	// Sockets bound to phys need a default route scoped to it; the "\n" keeps en1 from matching en10.
	if scoped := ttLogRoutes(t, "after Open", phys.Name); runtime.GOOS == "darwin" && !strings.Contains(scoped, "interface: "+phys.Name+"\n") {
		t.Errorf("route -n get -inet -ifscope %s 1.1.1.1 found no route through %s, want the default route Open scopes to it", phys.Name, phys.Name)
	}
	errCh := ttServeDev(ctx, dev, cfg, rec)

	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "140.82.112.3"} {
		if got := ttRouteDev(t, ip); got != dev.Interface {
			t.Fatalf("route to %s leaves through %q, want %s", ip, got, dev.Interface)
		}
	}
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "169.254.169.254"} {
		if got := ttRouteDev(t, ip); got == dev.Interface {
			t.Errorf("route to %s leaves through %s, want it left off the TUN", ip, got)
		}
	}

	if err := ttGet(t, "https://1.1.1.1/", 20*time.Second); err != nil {
		t.Errorf("GET https://1.1.1.1/ through %s: %v", dev.Interface, err)
	}
	rec.wantDial(t, "tcp", "1.1.1.1:443", "198.18.0.1")
	// Its name resolves through whatever resolver the runner has, so a failure is only logged.
	if err := ttGet(t, "https://api.github.com/", 15*time.Second); err != nil {
		t.Logf("GET https://api.github.com/ through %s: %v", dev.Interface, err)
	}
	if !ttPingOK(t, "198.18.0.1") {
		t.Error("ping 198.18.0.1 got no reply")
	}

	ttTeardown(t, cancel, errCh, dev)
	if err := ttGet(t, "https://1.1.1.1/", 20*time.Second); err != nil {
		t.Errorf("GET https://1.1.1.1/ after teardown: %v", err)
	}
}

// ttOpen opens cfg's TUN and fails t on an error or a warning; the TUN closes when t ends or after 3 minutes.
func ttOpen(t *testing.T, ctx context.Context, cfg Config) *Device {
	t.Helper()
	dev, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Should the test hang, closing the TUN still removes its interface and routes.
	watchdog := time.AfterFunc(3*time.Minute, func() { dev.Close() })
	t.Cleanup(func() {
		watchdog.Stop()
		dev.Close()
	})
	if len(dev.Warnings) != 0 {
		t.Fatalf("Open warned: %q", dev.Warnings)
	}
	t.Logf("opened %s", dev.Interface)
	return dev
}

// ttServeDev runs stack.Serve on dev until ctx ends; the channel receives its result.
func ttServeDev(ctx context.Context, dev *Device, cfg Config, dialer *ttDialRecorder) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- stack.Serve(ctx, dev, dialer, stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	}()
	return errCh
}

// ttTeardown stops Serve and closes dev, then waits for its interface and its route to 1.1.1.1 to go.
func ttTeardown(t *testing.T, cancel context.CancelFunc, errCh <-chan error, dev *Device) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Serve = %v, want %v", err, context.Canceled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve still running 10s after cancel")
	}
	dev.Close()
	ttWaitFor(t, 10*time.Second, func() bool {
		_, err := net.InterfaceByName(dev.Interface)
		return err != nil && ttRouteDev(t, "1.1.1.1") != dev.Interface
	}, dev.Interface+" and its route to 1.1.1.1 to go away")
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

// ttRouteDev returns the interface the host routes ip through, or "" when it has no route.
func ttRouteDev(t *testing.T, ip string) string {
	t.Helper()
	bin := defaultTools(runtime.GOOS)
	argv, key := []string{bin.route, "-n", "get", ip}, "interface:"
	v6 := netip.MustParseAddr(ip).Is6()
	switch {
	case runtime.GOOS == "linux" && v6:
		argv, key = []string{bin.ip, "-6", "route", "get", ip}, "dev"
	case runtime.GOOS == "linux":
		argv, key = []string{bin.ip, "route", "get", ip}, "dev"
	case v6:
		argv = []string{bin.route, "-n", "get", "-inet6", ip}
	}
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	fields := strings.Fields(string(out))
	if i := slices.Index(fields, key); err == nil && i >= 0 && i+1 < len(fields) {
		return fields[i+1]
	}
	t.Logf("%q: %v\n%s", argv, err, out)
	return ""
}

// ttLogRoutes logs the host's route to 1.1.1.1 and, on darwin, the one scoped to phys and the IPv4 defaults; it returns the scoped lookup.
func ttLogRoutes(t *testing.T, when, phys string) (scoped string) {
	t.Helper()
	bin := defaultTools(runtime.GOOS)
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
		run(bin.ip, "route", "get", "1.1.1.1")
		return ""
	}
	run(bin.route, "-n", "get", "-inet", "1.1.1.1")
	scoped = run(bin.route, "-n", "get", "-inet", "-ifscope", phys, "1.1.1.1")
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

// ttPingOK reports whether ip answers one ICMP echo within a few seconds.
func ttPingOK(t *testing.T, ip string) bool {
	t.Helper()
	name, args := "ping", []string{"-c", "1", "-W", "3", ip}
	switch v6 := netip.MustParseAddr(ip).Is6(); {
	case runtime.GOOS == "darwin" && v6:
		// ping6 has no timeout flag; the context bounds it.
		name, args = "ping6", []string{"-c", "1", ip}
	case runtime.GOOS == "darwin":
		args = []string{"-c", "1", "-t", "3", ip}
	case v6:
		args = []string{"-6", "-c", "1", "-W", "3", ip}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		t.Logf("look up %s: %v", name, err)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		t.Logf("%s %q: %v\n%s", path, args, err, out)
	}
	return err == nil
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

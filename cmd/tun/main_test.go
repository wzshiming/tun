package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	nethttp "net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/flow/flowlog"
	"github.com/wzshiming/tun/internal/stacktest"
)

// testRunMainEnv set to 1 makes the test binary run main instead of the tests.
const testRunMainEnv = "TUN_CMD_TEST_RUN_MAIN"

// testStopFlag ends every argument list testRunMain passes, so a child main that parses up to it exits there, never opening a device.
const (
	testStopFlag     = "-tun-cmd-test-stop"
	testStopExitCode = 3
)

func TestMain(m *testing.M) {
	if os.Getenv(testRunMainEnv) == "1" {
		flag.BoolFunc(testStopFlag[1:], "exits the test child before main gets past flag parsing", func(string) error {
			fmt.Fprintf(os.Stderr, "main parsed up to %s; every argument before it was accepted\n", testStopFlag)
			os.Exit(testStopExitCode)
			return nil
		})
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type failingListener struct{ err error }

func (l failingListener) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, l.err
}

func (l failingListener) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, l.err
}

// testCaptureLog returns what the log package writes until the test ends, without its date and time.
func testCaptureLog(t *testing.T) *syncBuffer {
	logged := &syncBuffer{}
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(logged)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	return logged
}

// testClient is the source of every flow testServeUDP serves.
var testClient = netip.MustParseAddrPort("198.18.0.1:4000")

// testServeUDP serves newHandler with dnsTarget a UDP flow to target carrying one datagram, as testServeLogged does.
func testServeUDP(t *testing.T, dnsTarget, target, until string) string {
	to := netip.MustParseAddrPort(target)
	session := stacktest.NewSession(testClient, to)
	// A DNS query for the A record of example.com: the mirror at port 53 answers nothing else.
	session.Send([]byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"), to)
	return testServeLogged(t, dnsTarget, stacktest.NewFlow("udp", testClient, to, session), until)
}

// testServeLogged serves f with newHandler and the space-separated DNS targets of dnsTarget through a flowlog.Dialer whose dials and listens all fail, until it logged until, and returns what it logged once ServeFlow returned.
func testServeLogged(t *testing.T, dnsTarget string, f *stacktest.Flow, until string) string {
	logged := testCaptureLog(t)
	refused := errors.New("dial refused")
	d := &flowlog.Dialer{
		Dialer:       &net.Dialer{Control: func(string, string, syscall.RawConn) error { return refused }},
		ListenConfig: failingListener{errors.New("listen refused")},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h := newHandler(d, nil, settings{dnsTargets: strings.Fields(dnsTarget), readyPort: 80})
		h.ServeFlow(ctx, f)
	}()
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(logged.String(), until); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("logged %q 5s after serving a %s flow to %v, want it to hold %q", logged.String(), f.Network(), f.Target(), until)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("ServeFlow of a %s flow to %v did not return 5s after its ctx ended", f.Network(), f.Target())
	}
	return logged.String()
}

// The dials and listens of these tests all fail, so each shows as the line the flowlog.Dialer logs for a failure.
const (
	testFlowLine53   = "198.18.0.1:4000 -> udp 192.0.2.53:53\n"
	testDialServer   = "198.18.0.1:4000 -> tcp 192.0.2.53:53: dial tcp 192.0.2.53:53: dial refused\n"
	testDialTarget   = "198.18.0.1:4000 -> tcp 203.0.113.5:5353: dial tcp 203.0.113.5:5353: dial refused\n"
	testDialTarget2  = "198.18.0.1:4000 -> tcp 203.0.113.6:53: dial tcp 203.0.113.6:53: dial refused\n"
	testListenPacket = "198.18.0.1:4000 -> udp4 :0: listen refused\n"
)

func TestHandlerAsksServerOfUDPPort53OverTCP(t *testing.T) {
	logged := testServeUDP(t, "", "192.0.2.53:53", testDialServer)
	if !strings.HasPrefix(logged, testFlowLine53+testDialServer) {
		t.Errorf("logged %q, want first the flow's line and then the failed tcp dial %q", logged, testDialServer)
	}
}

func TestHandlerAsksTheDNSTargetForUDPPort53OverTCP(t *testing.T) {
	logged := testServeUDP(t, "203.0.113.5:5353", "192.0.2.53:53", testDialTarget)
	if !strings.HasPrefix(logged, testFlowLine53+testDialTarget) {
		t.Errorf("logged %q, want first the flow's line and then the failed tcp dial %q to the -dns target", logged, testDialTarget)
	}
}

func TestHandlerAsksTheNextDNSTargetWhenOneFails(t *testing.T) {
	logged := testServeUDP(t, "203.0.113.5:5353 203.0.113.6:53", "192.0.2.53:53", testDialTarget2)
	if !strings.HasPrefix(logged, testFlowLine53+testDialTarget+testDialTarget2) {
		t.Errorf("logged %q, want the failed tcp dial to the first -dns target and then the one to the second", logged)
	}
}

func TestHandlerDoesNotDialTCPForOtherUDPPorts(t *testing.T) {
	for _, dnsTarget := range []string{"", "203.0.113.5:5353"} {
		if logged := testServeUDP(t, dnsTarget, "192.0.2.53:5353", " closed: "); strings.Contains(logged, " -> tcp ") {
			t.Errorf("logged %q for UDP to port 5353 with -dns %q, want no tcp dial", logged, dnsTarget)
		}
	}
}

func TestHandlerListensPacketsForOtherUDPPorts(t *testing.T) {
	want := "198.18.0.1:4000 -> udp 192.0.2.53:5353\n" + testListenPacket
	if logged := testServeUDP(t, "", "192.0.2.53:5353", testListenPacket); !strings.HasPrefix(logged, want) {
		t.Errorf("logged %q for UDP to port 5353, want first the flow's line and then the failed full cone ListenPacket %q", logged, testListenPacket)
	}
}

func TestHandlerDialsTCPToTheFlowsTarget(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	to := netip.MustParseAddrPort("192.0.2.9:443")
	logged := testServeLogged(t, "", stacktest.NewFlow("tcp", testClient, to, conn), " rejected\n")
	want := "198.18.0.1:4000 -> tcp 192.0.2.9:443\n198.18.0.1:4000 -> tcp 192.0.2.9:443: dial tcp 192.0.2.9:443: dial refused\n198.18.0.1:4000 -> tcp 192.0.2.9:443 rejected\n"
	if logged != want {
		t.Errorf("logged %q, want the flow's line, its failed dial and its rejection:\n%s", logged, want)
	}
}

func TestHandlerRejectsAnICMPSessionWithoutASocket(t *testing.T) {
	testCaptureLog(t)
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	served := stacktest.NewFlow("icmp", netip.MustParseAddrPort("198.18.0.1:7"), netip.MustParseAddrPort("192.0.2.9:0"), conn)
	icmpListen := &net.ListenConfig{Control: func(string, string, syscall.RawConn) error { return errors.New("socket refused") }}
	newHandler(&flowlog.Dialer{}, icmpListen, settings{readyPort: 80}).ServeFlow(t.Context(), served)
	if !served.Rejected() {
		t.Error("icmp flow not rejected though no ICMP socket can be opened")
	}
}

func TestHandlerAsksTheDNSTargetForTCPPort53(t *testing.T) {
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	go peer.Write([]byte("\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"))
	target := netip.MustParseAddrPort("192.0.2.53:53")
	logged := testServeLogged(t, "203.0.113.5:5353", stacktest.NewFlow("tcp", testClient, target, flowConn{conn, target}), testDialTarget)
	if !strings.HasPrefix(logged, "198.18.0.1:4000 -> tcp 192.0.2.53:53\n"+testDialTarget) {
		t.Errorf("logged %q, want first the flow's line and then the failed tcp dial %q to the -dns target", logged, testDialTarget)
	}
}

// flowConn is a conn with the addresses of a tcp flow's: its RemoteAddr testClient and its LocalAddr the target.
type flowConn struct {
	net.Conn
	target netip.AddrPort
}

func (c flowConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(testClient) }
func (c flowConn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.target) }

// testRunMainTimeout bounds a child of testRunMain, which exits within flag parsing.
const testRunMainTimeout = 30 * time.Second

// testRunMain runs main in a child process of the test binary with args, each one flag in -name or -name=value form, then testStopFlag, and returns its exit code and stderr.
func testRunMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") || arg == "-" || arg == "--" {
			t.Fatalf("run main %q: %q is not one flag, so parsing could stop before %s", args, arg, testStopFlag)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), testRunMainTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append(args, testStopFlag)...)
	cmd.Env = append(os.Environ(), testRunMainEnv+"=1")
	cmd.WaitDelay = time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("run main %q: still running after %s, killed; stderr %q", args, testRunMainTimeout, stderr.String())
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode(), stderr.String()
	}
	if err != nil {
		t.Fatalf("run main %q: %v", args, err)
	}
	return 0, stderr.String()
}

func TestMainRejectsAnInvalidDNSTargetLikeOtherFlags(t *testing.T) {
	wantCode, _ := testRunMain(t, "-mtu=x")
	if wantCode == testStopExitCode {
		t.Fatalf("main -mtu=x parsed up to %s, want -mtu x rejected", testStopFlag)
	}
	for _, value := range []string{"1.1.1.1", "1.1.1.1:", ":53", "1.1.1.1:domain", "1.1.1.1:70000"} {
		code, stderr := testRunMain(t, "-dns="+value)
		if want := `invalid value "` + value + `" for flag -dns`; code != wantCode || !strings.Contains(stderr, want) {
			t.Errorf("main -dns %q exited %d with stderr %q, want exit %d, as for -mtu x, with %q", value, code, stderr, wantCode, want)
		}
	}
}

func TestMainHelpListsTheDNSFlag(t *testing.T) {
	code, stderr := testRunMain(t, "-h")
	if code != 0 {
		t.Errorf("main -h exited %d, want 0", code)
	}
	for _, name := range []string{"-addr", "-mtu", "-bypass", "-name", "-dns"} {
		if !strings.Contains(stderr, "\n  "+name+" ") {
			t.Errorf("main -h printed %q, want it to list %s", stderr, name)
		}
	}
}

// syncBuffer is a bytes.Buffer safe to read while the log writes it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHandlerAnswersICMPEchoToTheDeviceAddressesItself(t *testing.T) {
	testCaptureLog(t)
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	served := stacktest.NewFlow("icmp", netip.MustParseAddrPort("198.18.0.2:7"), netip.MustParseAddrPort("198.18.0.1:0"), conn)
	icmpListen := &net.ListenConfig{Control: func(string, string, syscall.RawConn) error { return errors.New("socket refused") }}
	go newHandler(&flowlog.Dialer{}, icmpListen, settings{tun: tun.Config{Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}}, readyPort: 80}).ServeFlow(t.Context(), served)
	peer.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := peer.Write([]byte{8, 0, 0, 0, 0, 7, 0, 1, 'x'}); err != nil {
		t.Fatalf("echo request to the device address: %v", err)
	}
	reply := make([]byte, 64)
	n, err := peer.Read(reply)
	if want := []byte{0, 0, 0, 0, 0, 7, 0, 1, 'x'}; err != nil || !bytes.Equal(reply[:n], want) {
		t.Fatalf("echo request to the device address got % x, %v, want the echo reply % x without any socket", reply[:n], err, want)
	}
}

func TestHandlerServesTheReadyPageNextToTheDeviceAddresses(t *testing.T) {
	testCaptureLog(t)
	d := &flowlog.Dialer{Dialer: &net.Dialer{Control: func(string, string, syscall.RawConn) error { return errors.New("dial refused") }}}
	addresses := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")}
	h := newHandler(d, nil, settings{tun: tun.Config{Addresses: addresses}, readyPort: 80})
	// The page moves with -ready-port.
	moved := newHandler(d, nil, settings{tun: tun.Config{Addresses: addresses}, readyPort: 8080})
	for _, target := range []string{"198.18.0.2:80", "[fd00:6a77:7761::2]:80", "198.18.0.2:8080"} {
		h := h
		if strings.HasSuffix(target, ":8080") {
			h = moved
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		peer, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		conn, err := listener.Accept()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		go h.ServeFlow(t.Context(), stacktest.NewFlow("tcp", testClient, netip.MustParseAddrPort(target), conn))
		peer.SetDeadline(time.Now().Add(10 * time.Second))
		fmt.Fprintf(peer, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		resp, err := nethttp.ReadResponse(bufio.NewReader(peer), nil)
		if err != nil {
			t.Fatalf("GET http://%s/: %v", target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != nethttp.StatusOK || string(body) != "ready\n" {
			t.Fatalf("GET http://%s/ = %s %q, want 200 OK and the ready page without any dial", target, resp.Status, body)
		}
	}
}

func TestReadyAddrsAreNextToTheDeviceAddresses(t *testing.T) {
	for address, want := range map[string]string{
		"198.18.0.1/30":        "198.18.0.2",
		"198.18.0.2/30":        "198.18.0.1",
		"198.18.0.0/31":        "198.18.0.1",
		"198.18.0.1/31":        "198.18.0.0",
		"198.18.0.1/32":        "",
		"10.0.0.254/24":        "10.0.0.253",
		"fd00:6a77:7761::1/64": "fd00:6a77:7761::2",
		"fd00::1/127":          "fd00::",
		"fd00::1/128":          "",
	} {
		got := ""
		if addrs := readyAddrs([]netip.Prefix{netip.MustParsePrefix(address)}); len(addrs) > 0 {
			got = addrs[0].String()
		}
		if got != want {
			t.Errorf("readyAddrs(%s) = %q, want %q", address, got, want)
		}
	}
}

// The default bypass leaves the reserved blocks off the TUN, but of ::/8 not the NAT64 prefixes.
func TestDefaultBypassLeavesReservedBlocksOffAndNAT64On(t *testing.T) {
	cfg := tun.Config{Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")}, Bypass: defaultBypass()}
	routes := tun.CaptureRoutes(cfg)
	contains := func(s string) bool {
		addr := netip.MustParseAddr(s)
		for _, p := range routes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, off := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.251", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:192.0.2.1", "64:ff9a::1", "64:ff9b:2::1", "fe80::1", "ff02::1"} {
		if contains(off) {
			t.Errorf("a route contains %s, want it left off the TUN", off)
		}
	}
	for _, on := range []string{"1.1.1.1", "10.0.0.1", "64:ff9b::192.0.2.1", "64:ff9b:1::1", "100::1", "2001:db8::1"} {
		if !contains(on) {
			t.Errorf("no route contains %s, want it captured", on)
		}
	}
}

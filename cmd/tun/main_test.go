package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// logDialer must listen too, so stack.DefaultMux relays UDP full cone.
var (
	_ stack.ListenConfig = (*logDialer)(nil)
	_ stack.Dialer       = (*logDialer)(nil)
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

func TestLogDialerListenPacketLogsEachNewTargetOnce(t *testing.T) {
	var logged bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&logged)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	var targets []net.PacketConn
	for range 2 {
		target, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for a target: %v", err)
		}
		defer target.Close()
		targets = append(targets, target)
	}
	d := &logDialer{listen: &net.ListenConfig{}}
	ctx := stack.WithClientAddr(context.Background(), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 4000})
	pc, err := d.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	for _, target := range []net.PacketConn{targets[0], targets[1], targets[0], targets[1]} {
		if _, err := pc.WriteTo([]byte("datagram"), target.LocalAddr()); err != nil {
			t.Fatalf("WriteTo %v: %v", target.LocalAddr(), err)
		}
	}
	want := "198.18.0.1:4000 -> udp " + targets[0].LocalAddr().String() + "\n198.18.0.1:4000 -> udp " + targets[1].LocalAddr().String() + "\n"
	if got := logged.String(); got != want {
		t.Errorf("logged %q, want one line per new target:\n%s", got, strings.TrimSpace(want))
	}
}

type failingListener struct{ err error }

func (l failingListener) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, l.err
}

func (l failingListener) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, l.err
}

func TestLogDialerListenUsesItsListenConfig(t *testing.T) {
	listenErr := errors.New("listen refused")
	d := &logDialer{listen: failingListener{listenErr}}
	if l, err := d.Listen(context.Background(), "tcp4", ":0"); !errors.Is(err, listenErr) {
		t.Fatalf("Listen = %v, %v; want the listen config's error", l, err)
	}
}

func TestLogDialerListenPacketLogsItsFailure(t *testing.T) {
	var logged bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&logged)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	listenErr := errors.New("listen refused")
	d := &logDialer{listen: failingListener{listenErr}}
	ctx := stack.WithClientAddr(context.Background(), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 4000})
	if pc, err := d.ListenPacket(ctx, "udp4", ":0"); !errors.Is(err, listenErr) {
		t.Fatalf("ListenPacket = %v, %v; want the listener's error", pc, err)
	}
	if got, want := logged.String(), "198.18.0.1:4000 -> udp4 :0: listen refused\n"; got != want {
		t.Errorf("logged %q, want the one line %q", got, want)
	}
}

type closeWriteConn struct {
	net.Conn
	closedWrite bool
}

func (c *closeWriteConn) CloseWrite() error {
	c.closedWrite = true
	return nil
}

func TestLogConnPassesCloseWriteToTheInnerConn(t *testing.T) {
	inner := &closeWriteConn{}
	cw, ok := any(&logConn{Conn: inner}).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("*logConn does not expose CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil || !inner.closedWrite {
		t.Errorf("CloseWrite = %v, inner closed write %t; want nil, true", err, inner.closedWrite)
	}
}

func TestLogConnCloseWriteIsUnsupportedWithoutTheInnerOne(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cw, ok := any(&logConn{Conn: a}).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("*logConn does not expose CloseWrite")
	}
	if err := cw.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("CloseWrite = %v, want errors.ErrUnsupported", err)
	}
}

// testClient is the source of every flow testServeUDP serves.
var testClient = netip.MustParseAddrPort("198.18.0.1:4000")

// testServeUDP serves newHandler with dnsTarget a UDP flow to target carrying one datagram, through a logDialer whose dials and listens all fail, and returns what it logged.
func testServeUDP(t *testing.T, dnsTarget, target string) string {
	logged := &syncBuffer{}
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(logged)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	refused := errors.New("dial refused")
	d := &logDialer{
		dialer: &net.Dialer{Control: func(string, string, syscall.RawConn) error { return refused }},
		listen: failingListener{errors.New("listen refused")},
	}
	to := netip.MustParseAddrPort(target)
	session := stacktest.NewSession(testClient, to)
	session.Send([]byte("query"), to)
	f := stacktest.NewFlow("udp", testClient, to, session)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h := newHandler(d, dnsTarget)
		h.ServeFlow(ctx, f)
	}()
	for deadline := time.Now().Add(5 * time.Second); logged.String() == ""; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("nothing logged 5s after serving a UDP flow to %s", target)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("ServeFlow of a UDP flow to %s did not return 5s after its ctx ended", target)
	}
	return logged.String()
}

func TestHandlerDialsUDPPort53OverTCPToItsTarget(t *testing.T) {
	logged := testServeUDP(t, "", "192.0.2.53:53")
	if first, _, _ := strings.Cut(logged, "\n"); first != "198.18.0.1:4000 -> tcp 192.0.2.53:53" {
		t.Errorf("logged %q, want first the tcp dial line %q", logged, "198.18.0.1:4000 -> tcp 192.0.2.53:53")
	}
}

func TestHandlerDialsUDPPort53OverTCPToTheDNSTarget(t *testing.T) {
	logged := testServeUDP(t, "203.0.113.5:5353", "192.0.2.53:53")
	if first, _, _ := strings.Cut(logged, "\n"); first != "198.18.0.1:4000 -> tcp 203.0.113.5:5353" {
		t.Errorf("logged %q, want first the tcp dial line %q to the -dns target", logged, "198.18.0.1:4000 -> tcp 203.0.113.5:5353")
	}
}

func TestHandlerDoesNotDialTCPForOtherUDPPorts(t *testing.T) {
	for _, dnsTarget := range []string{"", "203.0.113.5:5353"} {
		if logged := testServeUDP(t, dnsTarget, "192.0.2.53:5353"); strings.Contains(logged, " -> tcp ") {
			t.Errorf("logged %q for UDP to port 5353 with -dns %q, want no tcp dial", logged, dnsTarget)
		}
	}
}

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

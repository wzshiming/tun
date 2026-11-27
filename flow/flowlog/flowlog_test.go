package flowlog

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"regexp"
	"sync"
	"syscall"
	"testing"

	"github.com/wzshiming/tun/flow"
	"github.com/wzshiming/tun/internal/stacktest"
)

// testClient is the source of the flows served.
var testClient = netip.MustParseAddrPort("198.18.0.1:4000")

// testLogger returns a logger without date and time, and what it writes.
func testLogger() (*syncBuffer, Logger) {
	captured := &syncBuffer{}
	return captured, log.New(captured, "", 0)
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

type failingListener struct{ err error }

func (l failingListener) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, l.err
}

func (l failingListener) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, l.err
}

func TestDialerListenUsesItsListenConfig(t *testing.T) {
	listenErr := errors.New("listen refused")
	d := &Dialer{ListenConfig: failingListener{listenErr}}
	if l, err := d.Listen(context.Background(), "tcp4", ":0"); !errors.Is(err, listenErr) {
		t.Fatalf("Listen = %v, %v; want the listen config's error", l, err)
	}
}

func TestDialerListenPacketLogsItsFailure(t *testing.T) {
	captured, logger := testLogger()
	listenErr := errors.New("listen refused")
	d := &Dialer{ListenConfig: failingListener{listenErr}, Logger: logger}
	ctx := flow.WithClientAddr(context.Background(), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 4000})
	if pc, err := d.ListenPacket(ctx, "udp4", ":0"); !errors.Is(err, listenErr) {
		t.Fatalf("ListenPacket = %v, %v; want the listener's error", pc, err)
	}
	if got, want := captured.String(), "198.18.0.1:4000 -> udp4 :0: listen refused\n"; got != want {
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

// durations stands for the time a flow lasted, which no test fixes.
var durations = regexp.MustCompile(` in \S+\n`)

func TestHandlerLogsATCPFlowAndTheBytesItCarried(t *testing.T) {
	captured, logger := testLogger()
	conn, peer := net.Pipe()
	t.Cleanup(func() {
		conn.Close()
		peer.Close()
	})
	go func() {
		peer.Write([]byte("hello"))
		io.Copy(io.Discard, peer)
	}()
	served := stacktest.NewFlow("tcp", testClient, netip.MustParseAddrPort("192.0.2.9:443"), conn)
	Handler(flow.HandlerFunc(func(_ context.Context, f flow.Flow) {
		c, err := f.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		if _, err := io.ReadFull(c, make([]byte, 5)); err != nil {
			t.Errorf("read the client's bytes: %v", err)
		}
		if _, err := c.Write([]byte("reply to it")); err != nil {
			t.Errorf("write to the client: %v", err)
		}
	}), logger).ServeFlow(t.Context(), served)
	want := "198.18.0.1:4000 -> tcp 192.0.2.9:443\n198.18.0.1:4000 -> tcp 192.0.2.9:443 closed: read 11, written 5 bytes in T\n"
	if got := durations.ReplaceAllString(captured.String(), " in T\n"); got != want {
		t.Errorf("logged %q, want %q", got, want)
	}
}

func TestHandlerLogsAFlowLeftUnacceptedAsRejected(t *testing.T) {
	for name, serve := range map[string]func(flow.Flow){
		"rejected":   func(f flow.Flow) { f.Reject() },
		"unanswered": func(flow.Flow) {},
	} {
		t.Run(name, func(t *testing.T) {
			captured, logger := testLogger()
			served := stacktest.NewFlow("icmp", netip.MustParseAddrPort("198.18.0.2:7"), netip.MustParseAddrPort("192.0.2.9:0"), nil)
			Handler(flow.HandlerFunc(func(_ context.Context, f flow.Flow) { serve(f) }), logger).ServeFlow(t.Context(), served)
			want := "198.18.0.2 -> icmp 192.0.2.9\n198.18.0.2 -> icmp 192.0.2.9 rejected\n"
			if got := captured.String(); got != want {
				t.Errorf("logged %q, want %q", got, want)
			}
		})
	}
}

func TestHandlerLogsEachFurtherTargetOfAUDPSessionOnce(t *testing.T) {
	captured, logger := testLogger()
	first, second := netip.MustParseAddrPort("192.0.2.9:5000"), netip.MustParseAddrPort("192.0.2.10:6000")
	session := stacktest.NewSession(testClient, first)
	for _, target := range []netip.AddrPort{first, second, first, second} {
		session.Send([]byte("datagram"), target)
	}
	served := stacktest.NewFlow("udp", testClient, first, session)
	Handler(flow.HandlerFunc(func(_ context.Context, f flow.Flow) {
		c, err := f.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		pc, ok := c.(net.PacketConn)
		if !ok {
			t.Errorf("the accepted conn of a udp flow is a %T, want a net.PacketConn", c)
			return
		}
		buf := make([]byte, 64)
		for range 4 {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				t.Errorf("ReadFrom: %v", err)
			}
		}
		if _, err := pc.WriteTo([]byte("reply"), net.UDPAddrFromAddrPort(second)); err != nil {
			t.Errorf("WriteTo: %v", err)
		}
	}), logger).ServeFlow(t.Context(), served)
	want := "198.18.0.1:4000 -> udp 192.0.2.9:5000\n198.18.0.1:4000 -> udp 192.0.2.10:6000\n198.18.0.1:4000 -> udp 192.0.2.9:5000 closed: read 5, written 32 bytes in T\n"
	if got := durations.ReplaceAllString(captured.String(), " in T\n"); got != want {
		t.Errorf("logged %q, want one line per new target and the session's bytes:\n%s", got, want)
	}
}

func TestDialerLogsAFailedDial(t *testing.T) {
	captured, logger := testLogger()
	refused := errors.New("dial refused")
	d := &Dialer{Dialer: &net.Dialer{Control: func(string, string, syscall.RawConn) error { return refused }}, Logger: logger}
	ctx := flow.WithClientAddr(context.Background(), &net.TCPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 4000})
	if conn, err := d.DialContext(ctx, "tcp", "192.0.2.9:443"); !errors.Is(err, refused) {
		t.Fatalf("DialContext = %v, %v; want the dialer's error", conn, err)
	}
	if got, want := captured.String(), "198.18.0.1:4000 -> tcp 192.0.2.9:443: dial tcp 192.0.2.9:443: dial refused\n"; got != want {
		t.Errorf("logged %q, want the one line %q", got, want)
	}
}

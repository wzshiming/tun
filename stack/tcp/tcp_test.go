package tcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// testWait bounds every wait.
const testWait = 10 * time.Second

var (
	testClient  = netip.MustParseAddrPort("10.0.0.2:40000")
	testTarget  = netip.MustParseAddrPort("10.0.0.9:443")
	testClient6 = netip.MustParseAddrPort("[fd00::2]:40000")
	testTarget6 = netip.MustParseAddrPort("[fd00::9]:443")
)

// dialRecord is one DialContext call; client is ClientAddr of its ctx, accepted whether the flow was accepted by then.
type dialRecord struct {
	network, address string
	client           net.Addr
	accepted         bool
}

// fakeDialer records its dials and answers each with conn, or with err when set.
type fakeDialer struct {
	flow *stacktest.Flow
	conn net.Conn
	err  error
	// reject has flow rejected before the dial answers, as the stack may while a dial is slow.
	reject bool

	mu    sync.Mutex
	dials []dialRecord
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dials = append(d.dials, dialRecord{network, address, stack.ClientAddr(ctx), d.flow.Accepted()})
	if d.reject {
		d.flow.Reject()
	}
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func (d *fakeDialer) recorded() []dialRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialRecord(nil), d.dials...)
}

// expectOnly expects exactly one dial, of "tcp" to address before the flow was accepted, its ctx carrying client as a *net.TCPAddr.
func (d *fakeDialer) expectOnly(t *testing.T, address string, client netip.AddrPort) {
	t.Helper()
	dials := d.recorded()
	if len(dials) != 1 {
		t.Fatalf("Dialer.DialContext called %d times %+v, want once", len(dials), dials)
	}
	got := dials[0]
	if got.network != "tcp" || got.address != address {
		t.Fatalf(`Dialer.DialContext(%q, %q), want ("tcp", %q)`, got.network, got.address, address)
	}
	if want := net.TCPAddrFromAddrPort(client); got.client == nil || fmt.Sprintf("%T %v", got.client, got.client) != fmt.Sprintf("%T %v", want, want) {
		t.Fatalf("ClientAddr(dial ctx) = %T %v, want the client's %T %v", got.client, got.client, want, want)
	}
	if got.accepted {
		t.Fatal("the flow was accepted before its target was dialled, want the dial first")
	}
}

// stalledConn is a dialled conn that never answers: Read and Write block until Close.
type stalledConn struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stalledConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stalledConn) Write([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stalledConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *stalledConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stalledConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stalledConn) SetDeadline(time.Time) error      { return nil }
func (c *stalledConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stalledConn) SetWriteDeadline(time.Time) error { return nil }

// loopbackPair returns both ends of a real loopback TCP connection, closed when t ends, with deadlines testWait away.
func loopbackPair(t *testing.T) (conn, peer *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := listener.Accept()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); p.Close() })
	for _, end := range []net.Conn{c, p} {
		end.SetDeadline(time.Now().Add(testWait))
	}
	return c.(*net.TCPConn), p.(*net.TCPConn)
}

// testEnv is a Handler serving one flow whose conn is a loopback TCP conn.
type testEnv struct {
	flow   *stacktest.Flow
	dialer *fakeDialer
	// accepted is the flow's conn, as Accept returns it; client is the client's end of it.
	accepted, client *net.TCPConn
	cancel           context.CancelFunc
	done             chan struct{}
}

// testServe runs a Handler over d on a flow of network from client to target until the test ends.
func testServe(t *testing.T, network string, client, target netip.AddrPort, d *fakeDialer) *testEnv {
	t.Helper()
	return testServeHandler(t, &Handler{}, network, client, target, d)
}

// testServeHandler runs h over d on a flow of network from client to target until the test ends.
func testServeHandler(t *testing.T, h *Handler, network string, client, target netip.AddrPort, d *fakeDialer) *testEnv {
	t.Helper()
	accepted, peer := loopbackPair(t)
	env := &testEnv{flow: stacktest.NewFlow(network, client, target, accepted), dialer: d, accepted: accepted, client: peer, done: make(chan struct{})}
	d.flow = env.flow
	h.Dialer = d
	ctx, cancel := context.WithCancel(context.Background())
	env.cancel = cancel
	go func() {
		defer close(env.done)
		h.ServeFlow(ctx, env.flow)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-env.done:
		case <-time.After(testWait):
			t.Errorf("ServeFlow did not return within %v of its ctx ending", testWait)
		}
	})
	return env
}

// testRelayEnv serves a TCP flow from testClient to testTarget whose dial answers with dialled.
func testRelayEnv(t *testing.T, dialled net.Conn) *testEnv {
	t.Helper()
	return testServe(t, "tcp", testClient, testTarget, &fakeDialer{conn: dialled})
}

// testRelayPair serves a TCP flow whose dial answers with one end of a loopback TCP conn, and returns that end and the target's.
func testRelayPair(t *testing.T) (env *testEnv, dialled, target *net.TCPConn) {
	t.Helper()
	dialled, target = loopbackPair(t)
	return testRelayEnv(t, dialled), dialled, target
}

func (e *testEnv) wait(t *testing.T, after string) {
	t.Helper()
	select {
	case <-e.done:
	case <-time.After(testWait):
		t.Fatalf("ServeFlow did not return within %v after %s", testWait, after)
	}
}

// testRelay writes payload on from and expects it to arrive on to.
func testRelay(t *testing.T, from, to net.Conn, payload string) {
	t.Helper()
	if _, err := io.WriteString(from, payload); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatalf("read %q on the other side of the relay: %v", payload, err)
	}
	if string(got) != payload {
		t.Fatalf("relayed %q, want %q", got, payload)
	}
}

func testReadEOF(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	n, err := conn.Read(make([]byte, 1))
	if n != 0 || err != io.EOF {
		t.Fatalf("%s: Read() = %d, %v, want 0, EOF", what, n, err)
	}
}

func testClosed(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	if _, err := conn.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("%s.Write after ServeFlow returned: %v, want net.ErrClosed", what, err)
	}
}

func TestDialsDestinationWithClientAddr(t *testing.T) {
	env, _, _ := testRelayPair(t)
	waitAccepted(t, env)
	env.dialer.expectOnly(t, "10.0.0.9:443", testClient)
}

func TestIPv6DialsBracketedDestination(t *testing.T) {
	dialled, _ := loopbackPair(t)
	env := testServe(t, "tcp", testClient6, testTarget6, &fakeDialer{conn: dialled})
	waitAccepted(t, env)
	env.dialer.expectOnly(t, "[fd00::9]:443", testClient6)
}

// waitAccepted waits until the handler has accepted env's flow.
func waitAccepted(t *testing.T, env *testEnv) {
	t.Helper()
	for limit := time.Now().Add(testWait); !env.flow.Accepted(); time.Sleep(time.Millisecond) {
		if time.Now().After(limit) {
			t.Fatalf("the flow was not accepted within %v", testWait)
		}
	}
}

func TestRelaysBytesBothWays(t *testing.T) {
	env, _, target := testRelayPair(t)
	testRelay(t, env.client, target, "from the client")
	testRelay(t, target, env.client, "from the target")
}

func TestDialFailureRejectsFlow(t *testing.T) {
	env := testServe(t, "tcp", testClient, testTarget, &fakeDialer{err: errors.New("test dial failure")})
	env.wait(t, "a failed dial")
	if !env.flow.Rejected() {
		t.Error("the flow was not rejected after its dial failed, want Reject so the client is reset")
	}
	if env.flow.Accepted() {
		t.Error("the flow was accepted after its dial failed")
	}
}

func TestHalfCloseReachesBothEnds(t *testing.T) {
	env, _, target := testRelayPair(t)
	if _, err := io.WriteString(env.client, "request"); err != nil {
		t.Fatal(err)
	}
	if err := env.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if request, err := io.ReadAll(target); err != nil || string(request) != "request" {
		t.Fatalf(`target ReadAll() = %q, %v after the client's CloseWrite, want "request" ending in EOF`, request, err)
	}
	testRelay(t, target, env.client, "late reply")
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, env.client, "client after the target's CloseWrite")
}

func TestHalfCloseFromTheTargetKeepsTheClientDirection(t *testing.T) {
	env, _, target := testRelayPair(t)
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, env.client, "client after the target's CloseWrite")
	testRelay(t, env.client, target, "late")
}

func TestReturnsAndClosesBothOnceBothDirectionsEnd(t *testing.T) {
	env, dialled, target := testRelayPair(t)
	env.client.CloseWrite()
	target.CloseWrite()
	env.wait(t, "both directions ended")
	testClosed(t, env.accepted, "the flow's conn")
	testClosed(t, dialled, "the dialled conn")
}

func TestClosesBothWhenContextEnds(t *testing.T) {
	env, dialled, _ := testRelayPair(t)
	waitAccepted(t, env)
	env.cancel()
	env.wait(t, "its ctx ended")
	testClosed(t, env.accepted, "the flow's conn")
	testClosed(t, dialled, "the dialled conn")
}

func TestCancelClosesTheTarget(t *testing.T) {
	env, _, target := testRelayPair(t)
	waitAccepted(t, env)
	env.cancel()
	testReadEOF(t, target, "target after cancel")
	env.wait(t, "its ctx ended")
}

func TestClosesBothWhenADirectionFails(t *testing.T) {
	stalled := &stalledConn{closed: make(chan struct{})}
	env := testRelayEnv(t, stalled)
	waitAccepted(t, env)
	// The client's Close ends the flow conn's reads with EOF; the stalled conn has no CloseWrite, so both close.
	env.client.Close()
	env.wait(t, "a direction ended without a half-close")
	select {
	case <-stalled.closed:
	default:
		t.Error("the stalled dialled conn was left open")
	}
	testClosed(t, env.accepted, "the flow's conn")
}

func TestClosesADialThatReturnsAfterTheFlowWasRejected(t *testing.T) {
	stalled := &stalledConn{closed: make(chan struct{})}
	env := testServe(t, "tcp", testClient, testTarget, &fakeDialer{conn: stalled, reject: true})
	env.wait(t, "its flow was rejected during the dial")
	select {
	case <-stalled.closed:
	default:
		t.Error("the conn dialled for a flow rejected meanwhile was left open, want it closed")
	}
}

func TestRejectsOtherNetworks(t *testing.T) {
	dialled, _ := loopbackPair(t)
	env := testServe(t, "udp", testClient, testTarget, &fakeDialer{conn: dialled})
	env.wait(t, "a udp flow")
	if !env.flow.Rejected() {
		t.Error("a udp flow was not rejected")
	}
	if env.flow.Accepted() {
		t.Error("a udp flow was accepted")
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Errorf("a udp flow dialled %+v, want no dial", dials)
	}
}

// testIdle is the HalfCloseIdle under test; testIdleWindow is how long after a half-close its close may take.
const (
	testIdle       = 400 * time.Millisecond
	testIdleWindow = 2*testIdle + 2*time.Second
)

// testIdleEnv serves a TCP flow whose dial answers with dialled through a Handler whose HalfCloseIdle is testIdle.
func testIdleEnv(t *testing.T, dialled net.Conn) *testEnv {
	t.Helper()
	return testServeHandler(t, &Handler{HalfCloseIdle: testIdle}, "tcp", testClient, testTarget, &fakeDialer{conn: dialled})
}

// expectIdleClose expects ServeFlow to return no sooner than testIdle and within testIdleWindow after start, both conns closed.
func (e *testEnv) expectIdleClose(t *testing.T, start time.Time, dialled net.Conn) {
	t.Helper()
	select {
	case <-e.done:
	case <-time.After(time.Until(start.Add(testIdleWindow))):
		t.Fatalf("ServeFlow still serving %v after the half-close, want both conns closed once the open direction idled for HalfCloseIdle %v", testIdleWindow, testIdle)
	}
	if elapsed := time.Since(start); elapsed < testIdle {
		t.Fatalf("ServeFlow returned %v after the half-close, want no sooner than HalfCloseIdle %v", elapsed.Round(time.Millisecond), testIdle)
	}
	testClosed(t, e.accepted, "the flow's conn")
	testClosed(t, dialled, "the dialled conn")
}

// testIdleAfterTargetHalfClose half-closes the target's end and expects the idle close while the client stays silent.
func testIdleAfterTargetHalfClose(t *testing.T, dialled net.Conn, target *net.TCPConn) {
	t.Helper()
	env := testIdleEnv(t, dialled)
	start := time.Now()
	if err := target.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, env.client, "client after the target's CloseWrite")
	env.expectIdleClose(t, start, dialled)
}

// testIdleAfterClientHalfClose half-closes the client's end and expects the idle close while the target stays silent.
func testIdleAfterClientHalfClose(t *testing.T, dialled net.Conn, target *net.TCPConn) {
	t.Helper()
	env := testIdleEnv(t, dialled)
	start := time.Now()
	if err := env.client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, target, "target after the client's CloseWrite")
	env.expectIdleClose(t, start, dialled)
}

func TestClosesBothWhenTheClientIdlesAfterTheTargetsHalfClose(t *testing.T) {
	dialled, target := loopbackPair(t)
	testIdleAfterTargetHalfClose(t, dialled, target)
}

func TestClosesBothWhenTheTargetIdlesAfterTheClientsHalfClose(t *testing.T) {
	dialled, target := loopbackPair(t)
	testIdleAfterClientHalfClose(t, dialled, target)
}

// noDeadlineConn is a dialled conn whose deadline methods fail, as an ssh channel's do.
type noDeadlineConn struct{ *net.TCPConn }

func (noDeadlineConn) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (noDeadlineConn) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (noDeadlineConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

func TestIdleCloseNeedsNoDeadlinesOnTheDialledConn(t *testing.T) {
	t.Run("after the target's half-close", func(t *testing.T) {
		dialled, target := loopbackPair(t)
		testIdleAfterTargetHalfClose(t, noDeadlineConn{dialled}, target)
	})
	t.Run("after the client's half-close", func(t *testing.T) {
		dialled, target := loopbackPair(t)
		testIdleAfterClientHalfClose(t, noDeadlineConn{dialled}, target)
	})
}

// testSendPastIdle writes on from every testIdle/8 for over twice testIdle, each write arriving on to, then half-closes from and expects ServeFlow to return.
func testSendPastIdle(t *testing.T, env *testEnv, from, to *net.TCPConn) {
	t.Helper()
	for start := time.Now(); time.Since(start) < 2*testIdle+testIdle/2; time.Sleep(testIdle / 8) {
		select {
		case <-env.done:
			t.Fatalf("ServeFlow returned %v into a byte sent every %v, want each forwarded byte to restart HalfCloseIdle %v", time.Since(start).Round(time.Millisecond), testIdle/8, testIdle)
		default:
		}
		testRelay(t, from, to, "tick")
	}
	if err := from.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, to, "the receiving end once the open direction ended")
	env.wait(t, "the open direction ended on its own")
}

func TestBytesKeepAHalfClosedFlowPastHalfCloseIdle(t *testing.T) {
	t.Run("from the client after the target's half-close", func(t *testing.T) {
		dialled, target := loopbackPair(t)
		env := testIdleEnv(t, dialled)
		if err := target.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		testReadEOF(t, env.client, "client after the target's CloseWrite")
		testSendPastIdle(t, env, env.client, target)
	})
	t.Run("from the target after the client's half-close", func(t *testing.T) {
		dialled, target := loopbackPair(t)
		env := testIdleEnv(t, dialled)
		if err := env.client.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		testReadEOF(t, target, "target after the client's CloseWrite")
		testSendPastIdle(t, env, target, env.client)
	})
}

func TestFlowOpenBothWaysOutlastsHalfCloseIdle(t *testing.T) {
	dialled, target := loopbackPair(t)
	env := testIdleEnv(t, dialled)
	testRelay(t, env.client, target, "before")
	select {
	case <-env.done:
		t.Fatalf("ServeFlow returned while both directions were open and silent, want HalfCloseIdle %v to leave such a flow alone", testIdle)
	case <-time.After(3*testIdle + testIdle/2):
	}
	testRelay(t, env.client, target, "after from the client")
	testRelay(t, target, env.client, "after from the target")
}

func TestHandlerHalfCloseIdleDefaultsTo60Seconds(t *testing.T) {
	if got := (&Handler{}).halfCloseIdle(); got != 60*time.Second {
		t.Fatalf("Handler{}.halfCloseIdle() = %v, want the 60s default", got)
	}
	if got := (&Handler{HalfCloseIdle: 3 * time.Second}).halfCloseIdle(); got != 3*time.Second {
		t.Fatalf("Handler{HalfCloseIdle: 3s}.halfCloseIdle() = %v, want 3s", got)
	}
}

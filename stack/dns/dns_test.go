package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/tun/stack"
)

// testIdleBound is how long a 200ms Handler.Idle may take to end a session; the 10s default exceeds it.
const testIdleBound = 5 * time.Second

// testWait bounds every other wait.
const testWait = 10 * time.Second

var (
	testClient = netip.MustParseAddrPort("10.0.0.2:40000")
	testServer = netip.MustParseAddrPort("10.0.0.53:53")
	testOther  = netip.MustParseAddrPort("10.0.0.54:53")
)

const testTarget = "192.0.2.1:5353"

// datagram is one datagram of a session: to the server the client sent it to, or from the source it was delivered from.
type datagram struct {
	data string
	addr netip.AddrPort
}

// fakeSession is a UDP session's conn: ReadFrom returns what the client sends, WriteTo delivers to the client.
type fakeSession struct {
	queries   chan datagram
	replies   chan datagram
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeSession() *fakeSession {
	return &fakeSession{queries: make(chan datagram, 64), replies: make(chan datagram, 64), closed: make(chan struct{})}
}

func (s *fakeSession) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-s.closed:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case d := <-s.queries:
		return copy(b, d.data), net.UDPAddrFromAddrPort(d.addr), nil
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

func (s *fakeSession) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case <-s.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case s.replies <- datagram{string(b), addr.(*net.UDPAddr).AddrPort()}:
		return len(b), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}

func (s *fakeSession) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func (s *fakeSession) isClosed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

func (s *fakeSession) Read([]byte) (int, error)         { return 0, errors.ErrUnsupported }
func (s *fakeSession) Write([]byte) (int, error)        { return 0, errors.ErrUnsupported }
func (s *fakeSession) LocalAddr() net.Addr              { return net.UDPAddrFromAddrPort(testServer) }
func (s *fakeSession) RemoteAddr() net.Addr             { return net.UDPAddrFromAddrPort(testClient) }
func (s *fakeSession) SetDeadline(time.Time) error      { return errors.ErrUnsupported }
func (s *fakeSession) SetReadDeadline(time.Time) error  { return errors.ErrUnsupported }
func (s *fakeSession) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

// fakeFlow is a flow from testClient to testServer whose Accept returns its session.
type fakeFlow struct {
	network  string
	session  *fakeSession
	accepted atomic.Bool
	rejected atomic.Bool
}

func (f *fakeFlow) Network() string        { return f.network }
func (f *fakeFlow) Target() netip.AddrPort { return testServer }
func (f *fakeFlow) Client() netip.AddrPort { return testClient }
func (f *fakeFlow) Reject()                { f.rejected.Store(true) }

func (f *fakeFlow) Accept() (net.Conn, error) {
	f.accepted.Store(true)
	return f.session, nil
}

type dialRecord struct {
	network, address string
	client           net.Addr
}

// remoteConn is the dialled end of a TCP conn, reporting when a Write starts and when it is closed.
type remoteConn struct {
	net.Conn
	writing   chan struct{}
	wOnce     sync.Once
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *remoteConn) Write(b []byte) (int, error) {
	c.wOnce.Do(func() { close(c.writing) })
	return c.Conn.Write(b)
}

func (c *remoteConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *remoteConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// fakeServer is the server's end of a dialled TCP conn and the dialled end it pairs with.
type fakeServer struct {
	net.Conn
	remote *remoteConn
}

// fakeDialer records its dials and connects each to a fakeServer over net.Pipe.
type fakeDialer struct {
	mu      sync.Mutex
	dials   []dialRecord
	servers chan *fakeServer
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, dialRecord{network, address, stack.ClientAddr(ctx)})
	d.mu.Unlock()
	local, server := net.Pipe()
	remote := &remoteConn{Conn: local, writing: make(chan struct{}), closed: make(chan struct{})}
	d.servers <- &fakeServer{Conn: server, remote: remote}
	return remote, nil
}

func (d *fakeDialer) recorded() []dialRecord {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]dialRecord(nil), d.dials...)
}

type testEnv struct {
	dialer  *fakeDialer
	flow    *fakeFlow
	session *fakeSession
	cancel  context.CancelFunc
	done    chan struct{}
}

// testServe runs h, its Dialer set to a fakeDialer, on a flow of network until the test ends.
func testServe(t *testing.T, h *Handler, network string) *testEnv {
	t.Helper()
	env := &testEnv{dialer: &fakeDialer{servers: make(chan *fakeServer, 64)}, session: newFakeSession(), done: make(chan struct{})}
	env.flow = &fakeFlow{network: network, session: env.session}
	h.Dialer = env.dialer
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
		for {
			select {
			case s := <-env.dialer.servers:
				s.Close()
			default:
				return
			}
		}
	})
	return env
}

func testServeUDP(t *testing.T, target string, idle time.Duration) *testEnv {
	t.Helper()
	return testServe(t, &Handler{Target: target, Idle: idle}, "udp")
}

func (env *testEnv) send(data string, to netip.AddrPort) {
	env.session.queries <- datagram{data, to}
}

func (env *testEnv) nextServer(t *testing.T) *fakeServer {
	t.Helper()
	select {
	case s := <-env.dialer.servers:
		t.Cleanup(func() { s.Close() })
		return s
	case <-env.done:
		t.Fatal("ServeFlow returned before dialing")
	case <-time.After(testWait):
		t.Fatalf("no dial within %v", testWait)
	}
	return nil
}

func (env *testEnv) nextReply(t *testing.T) datagram {
	t.Helper()
	select {
	case d := <-env.session.replies:
		return d
	case <-time.After(testWait):
		t.Fatalf("no datagram delivered to the client within %v", testWait)
	}
	return datagram{}
}

// waitDone waits within bound for ServeFlow to return.
func (env *testEnv) waitDone(t *testing.T, bound time.Duration, why string) {
	t.Helper()
	select {
	case <-env.done:
	case <-time.After(bound):
		t.Fatalf("ServeFlow still running %v after %s", bound, why)
	}
}

// testReadFrame reads one message prefixed with its 2-byte big-endian length.
func testReadFrame(t *testing.T, conn net.Conn) string {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(testWait)); err != nil {
		t.Fatal(err)
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		t.Fatalf("read the 2-byte length of a relayed DNS message: %v", err)
	}
	message := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, message); err != nil {
		t.Fatalf("read a %d-byte relayed DNS message: %v", len(message), err)
	}
	return string(message)
}

func testWriteFrame(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(testWait)); err != nil {
		t.Fatal(err)
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(message)))
	if _, err := conn.Write(append(frame, message...)); err != nil {
		t.Fatalf("write the framed reply %q: %v", message, err)
	}
}

// testReadEOF expects conn, described by what, to be closed by the relay within bound.
func testReadEOF(t *testing.T, conn net.Conn, bound time.Duration, what string) {
	t.Helper()
	// A pipe whose other end is already closed refuses deadlines, and its Read returns EOF at once.
	conn.SetReadDeadline(time.Now().Add(bound))
	if n, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("%s: Read() = %d, %v, want EOF", what, n, err)
	}
}

func TestDialsTCPToServerWithClientAddr(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send("query", testServer)
	env.nextServer(t)
	dials := env.dialer.recorded()
	if len(dials) != 1 || dials[0].network != "tcp" || dials[0].address != testServer.String() {
		t.Fatalf("dialer.DialContext calls %+v, want one tcp dial to %v", dials, testServer)
	}
	if c := dials[0].client; c == nil || c.String() != testClient.String() {
		t.Fatalf("dial ctx carries client %v, want %v", c, testClient)
	}
}

func TestRelaysLengthFramedMessages(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send("query", testServer)
	server := env.nextServer(t)
	if got := testReadFrame(t, server); got != "query" {
		t.Fatalf("server read the framed message %q, want the datagram %q", got, "query")
	}
	testWriteFrame(t, server, "reply")
	if got, want := env.nextReply(t), (datagram{"reply", testServer}); got != want {
		t.Fatalf("client got %+v, want the unframed reply %+v", got, want)
	}
}

func TestSessionReusesTCPConn(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send("first", testServer)
	server := env.nextServer(t)
	testReadFrame(t, server)
	env.send("second", testServer)
	if got := testReadFrame(t, server); got != "second" {
		t.Fatalf("the session's TCP conn read %q, want the second datagram %q", got, "second")
	}
	if dials := env.dialer.recorded(); len(dials) != 1 {
		t.Fatalf("dialer.DialContext called %d times for one server, want 1", len(dials))
	}
}

func TestSessionEndsAfterIdle(t *testing.T) {
	env := testServeUDP(t, "", 200*time.Millisecond)
	env.send("query", testServer)
	server := env.nextServer(t)
	testReadFrame(t, server)
	testReadEOF(t, server, testIdleBound, "server conn of a session idle past Handler.Idle 200ms")
	env.waitDone(t, testIdleBound, "the session idled")
	if !env.session.isClosed() {
		t.Fatal("ServeFlow returned with the session conn open")
	}
}

func TestIdleDefaultsToTenSeconds(t *testing.T) {
	t.Parallel()
	const want = 10 * time.Second
	env := testServeUDP(t, "", 0)
	env.send("query", testServer)
	server := env.nextServer(t)
	testReadFrame(t, server)
	last := time.Now()
	testReadEOF(t, server, 2*want, "server conn of a session idle past the default Handler.Idle")
	if ended := time.Since(last); ended < want*9/10 || ended > want+testIdleBound {
		t.Fatalf("session with Idle 0 ended %v after its last datagram, want about %v", ended, want)
	}
}

// testStalledServer sends a query to a server that never reads and returns its conn once the relay is blocked writing to it.
func testStalledServer(t *testing.T, env *testEnv) *fakeServer {
	t.Helper()
	env.send("query", testServer)
	server := env.nextServer(t)
	select {
	case <-server.remote.writing:
	case <-time.After(testWait):
		t.Fatalf("the relay did not write the query to its TCP conn within %v", testWait)
	}
	return server
}

func (env *testEnv) expectAllClosed(t *testing.T, servers ...*fakeServer) {
	t.Helper()
	if !env.session.isClosed() {
		t.Error("ServeFlow returned with the session conn open")
	}
	for _, s := range servers {
		if !s.remote.isClosed() {
			t.Error("ServeFlow returned with a TCP conn open")
		}
	}
}

func TestStalledServerEndsAfterIdle(t *testing.T) {
	env := testServeUDP(t, "", 200*time.Millisecond)
	server := testStalledServer(t, env)
	env.waitDone(t, testIdleBound, "a stalled server and Handler.Idle 200ms")
	env.expectAllClosed(t, server)
}

func TestStalledServerEndsWithCtx(t *testing.T) {
	env := testServeUDP(t, "", 0)
	server := testStalledServer(t, env)
	env.cancel()
	env.waitDone(t, testWait, "a stalled server and its ctx ending")
	env.expectAllClosed(t, server)
}

func TestRepliesPushBackIdle(t *testing.T) {
	const idle = 200 * time.Millisecond
	env := testServeUDP(t, "", idle)
	env.send("query", testServer)
	server := env.nextServer(t)
	testReadFrame(t, server)
	start := time.Now()
	var last time.Time
	for i := 0; time.Since(start) < 3*idle; i++ {
		time.Sleep(80 * time.Millisecond)
		testWriteFrame(t, server, "reply")
		last = time.Now()
		if got, want := env.nextReply(t), (datagram{"reply", testServer}); got != want {
			t.Fatalf("client got %+v as reply %d, %v after the query, want %+v: replies every 80ms must keep a session with Handler.Idle %v alive", got, i+1, time.Since(start), want, idle)
		}
	}
	testReadEOF(t, server, testIdleBound, "server conn of a session silent since its last reply")
	if ended := time.Since(last); ended < idle*3/4 || ended > 2*time.Second {
		t.Fatalf("session ended %v after its last reply, want about Handler.Idle %v", ended, idle)
	}
}

func TestSessionDialsOnceEachServerAndRepliesFromIt(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send("q1", testServer)
	first := env.nextServer(t)
	if got := testReadFrame(t, first); got != "q1" {
		t.Fatalf("first server read %q, want %q", got, "q1")
	}
	env.send("q2", testOther)
	second := env.nextServer(t)
	if got := testReadFrame(t, second); got != "q2" {
		t.Fatalf("second server read %q, want %q", got, "q2")
	}
	env.send("q3", testServer)
	if got := testReadFrame(t, first); got != "q3" {
		t.Fatalf("first server read %q, want the later query %q on the same conn", got, "q3")
	}
	dials := env.dialer.recorded()
	if len(dials) != 2 || dials[0].address != testServer.String() || dials[1].address != testOther.String() {
		t.Fatalf("dialer.DialContext calls %+v, want one tcp dial each to %v and %v", dials, testServer, testOther)
	}
	for _, dial := range dials {
		if dial.network != "tcp" || dial.client == nil || dial.client.String() != testClient.String() {
			t.Fatalf("dial %+v, want network tcp tagged with the client %v", dial, testClient)
		}
	}
	testWriteFrame(t, second, "r2")
	if got, want := env.nextReply(t), (datagram{"r2", testOther}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	testWriteFrame(t, first, "r1")
	if got, want := env.nextReply(t), (datagram{"r1", testServer}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
}

func TestIdleCountsTheWholeSessionNotEachServer(t *testing.T) {
	const idle = 200 * time.Millisecond
	env := testServeUDP(t, "", idle)
	env.send("q", testServer)
	busy := env.nextServer(t)
	testReadFrame(t, busy)
	env.send("q", testOther)
	silent := env.nextServer(t)
	testReadFrame(t, silent)
	var last time.Time
	for start := time.Now(); time.Since(start) < 3*idle; {
		time.Sleep(80 * time.Millisecond)
		env.send("q", testServer)
		last = time.Now()
		testReadFrame(t, busy)
	}
	silent.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := silent.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("silent server's conn Read() = %v after %v of queries to %v every 80ms, want a timeout: Handler.Idle %v counts the whole session", err, 3*idle, testServer, idle)
	}
	for _, server := range []*fakeServer{busy, silent} {
		testReadEOF(t, server, testIdleBound, "server conn of a session silent since its last query")
	}
	if ended := time.Since(last); ended < idle*3/4 || ended > 2*time.Second {
		t.Fatalf("session ended %v after its last query, want about Handler.Idle %v", ended, idle)
	}
}

func TestRejectsTCP(t *testing.T) {
	env := testServe(t, &Handler{}, "tcp")
	env.waitDone(t, testWait, "a tcp flow")
	if !env.flow.rejected.Load() || env.flow.accepted.Load() {
		t.Fatalf("tcp flow rejected %v, accepted %v, want rejected and not accepted", env.flow.rejected.Load(), env.flow.accepted.Load())
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for a tcp flow: %+v, want no dial", dials)
	}
}

func TestTargetDialsTCPToTargetAndRepliesFromServer(t *testing.T) {
	env := testServeUDP(t, testTarget, 0)
	env.send("query", testServer)
	server := env.nextServer(t)
	dials := env.dialer.recorded()
	if len(dials) != 1 || dials[0].network != "tcp" || dials[0].address != testTarget {
		t.Fatalf("dialer.DialContext calls %+v, want one tcp dial to Target %v, not the server %v", dials, testTarget, testServer)
	}
	if c := dials[0].client; c == nil || c.String() != testClient.String() {
		t.Fatalf("dial ctx carries client %v, want %v", c, testClient)
	}
	if got := testReadFrame(t, server); got != "query" {
		t.Fatalf("Target read %q, want %q", got, "query")
	}
	testWriteFrame(t, server, "reply")
	if got, want := env.nextReply(t), (datagram{"reply", testServer}); got != want {
		t.Fatalf("client got %+v, want %+v from the server it addressed, not Target", got, want)
	}
}

func TestTargetTwoServersDialTargetTwiceAndReplyFromEach(t *testing.T) {
	env := testServeUDP(t, testTarget, 0)
	env.send("q1", testServer)
	first := env.nextServer(t)
	testReadFrame(t, first)
	env.send("q2", testOther)
	second := env.nextServer(t)
	testReadFrame(t, second)
	dials := env.dialer.recorded()
	if len(dials) != 2 {
		t.Fatalf("dialer.DialContext calls %+v, want two, one per server", dials)
	}
	for _, dial := range dials {
		if dial.network != "tcp" || dial.address != testTarget {
			t.Fatalf("dial %+v, want tcp to Target %v", dial, testTarget)
		}
	}
	testWriteFrame(t, second, "r2")
	if got, want := env.nextReply(t), (datagram{"r2", testOther}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	testWriteFrame(t, first, "r1")
	if got, want := env.nextReply(t), (datagram{"r1", testServer}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
}

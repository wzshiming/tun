package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// testWait bounds every wait for something that must happen.
const testWait = 10 * time.Second

// testStopBound is how long ServeFlow may take to return once its ctx ends.
const testStopBound = 3 * time.Second

// udpRelayQuiet is how long a client waits before concluding no reply comes.
const udpRelayQuiet = time.Second

// udpRelayIdleBound is how long a sub-second Handler.Idle may take to end a session; the 60s default exceeds it.
const udpRelayIdleBound = 5 * time.Second

// relaySocketBuffer lets a loopback UDP socket carry a 65507-byte datagram; macOS defaults to 9216 to send and 42080 to receive.
const relaySocketBuffer = 1 << 20

var testClient = netip.MustParseAddrPort("10.0.0.2:40000")

// udpFamilies are, per IP family, the client's address, two targets and a source the client never sends to.
var udpFamilies = []struct {
	name                          string
	client, first, second, unseen netip.AddrPort
}{
	{"ipv4", testClient, netip.MustParseAddrPort("10.0.0.9:5000"), netip.MustParseAddrPort("10.0.0.10:6000"), netip.MustParseAddrPort("10.0.0.77:7777")},
	{"ipv6", netip.MustParseAddrPort("[fd00::2]:40000"), netip.MustParseAddrPort("[fd00::9]:5000"), netip.MustParseAddrPort("[fd00::a]:6000"), netip.MustParseAddrPort("[fd00::77]:7777")},
}

// testEnv is one ServeFlow of a Handler on a session double.
type testEnv struct {
	client, target netip.AddrPort
	flow           *stacktest.Flow
	session        *stacktest.Session
	cancel         context.CancelFunc
	done           chan struct{}
}

// testServe serves h a "udp" session of client whose first datagram goes to target until the test ends.
func testServe(t *testing.T, h *Handler, client, target netip.AddrPort) *testEnv {
	t.Helper()
	return testServeCtx(t, context.Background(), h, "udp", client, target)
}

// testServeCtx serves h, under ctx, a flow of network from client to target whose conn is a session double.
func testServeCtx(t *testing.T, ctx context.Context, h *Handler, network string, client, target netip.AddrPort) *testEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	env := &testEnv{client: client, target: target, session: stacktest.NewSession(client, target), cancel: cancel, done: make(chan struct{})}
	env.flow = stacktest.NewFlow(network, client, target, env.session)
	go func() {
		defer close(env.done)
		h.ServeFlow(ctx, env.flow)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-env.done:
		case <-time.After(testWait):
			t.Errorf("ServeFlow did not return within %v after its ctx ended", testWait)
		}
	})
	return env
}

// send queues datagram from the client to the flow's target.
func (env *testEnv) send(datagram string) { env.session.Send([]byte(datagram), env.target) }

func (env *testEnv) sendTo(datagram []byte, to netip.AddrPort) { env.session.Send(datagram, to) }

// udpRead is one datagram the client received and its source.
type udpRead struct {
	payload string
	from    netip.AddrPort
}

// reply returns the next datagram delivered to the client.
func (env *testEnv) reply(t *testing.T) udpRead {
	t.Helper()
	b, from, ok := env.session.NextReply(testWait)
	if !ok {
		t.Fatalf("client got no datagram within %v", testWait)
	}
	return udpRead{string(b), from}
}

func (env *testEnv) replyBytes(t *testing.T) []byte {
	t.Helper()
	b, _, ok := env.session.NextReply(testWait)
	if !ok {
		t.Fatalf("client got no datagram within %v", testWait)
	}
	return b
}

func (env *testEnv) expectNoReply(t *testing.T, wait time.Duration, why string) {
	t.Helper()
	if b, from, ok := env.session.NextReply(wait); ok {
		t.Fatalf("client got %q from %v %s, want no reply", b, from, why)
	}
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

// waitFor polls cond until it holds, failing with what after testWait.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(testWait); !cond(); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s within %v", what, testWait)
		}
	}
}

func testReceive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testWait):
		t.Fatalf("%s did not happen within %v", what, testWait)
		panic("unreachable")
	}
}

// sameAddr reports whether got is an address of client's type and value.
func sameAddr(got, client net.Addr) bool {
	return got != nil && fmt.Sprintf("%T %v", got, got) == fmt.Sprintf("%T %v", client, client)
}

func relayRaiseBuffers(conn *net.UDPConn) error {
	if err := conn.SetReadBuffer(relaySocketBuffer); err != nil {
		return err
	}
	return conn.SetWriteBuffer(relaySocketBuffer)
}

// fakeDial is one recorded DialContext or ListenPacket call; client is stack.ClientAddr of its context.
type fakeDial struct {
	network, address string
	client           net.Addr
}

// stalledConn is a connection to an upstream that never answers: Read and Write block until Close, deadlines notwithstanding.
type stalledConn struct {
	// writing is closed once a Write is blocked.
	writing   chan struct{}
	writeOnce sync.Once
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stalledConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *stalledConn) Write([]byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writing) })
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

// udpRelayDialer records every dial and answers it with a UDP socket connected to a fresh loopback UDP target, or once stalled with a stalledConn.
type udpRelayDialer struct {
	mu      sync.Mutex
	dials   []fakeDial
	err     error
	stalled bool
	opened  []*udpRelayTarget
	targets chan *udpRelayTarget
	// slow holds each dial to an address it names this long, or until the dial's ctx ends.
	slow map[string]time.Duration
}

// udpRelayTarget is the far end of one dial: remote receives the datagrams the Handler writes to dialled; remote is nil when stalled.
type udpRelayTarget struct {
	remote  *net.UDPConn
	dialled *udpRelayConn
}

// udpRelayConn is a dialled conn whose closed channel closes on its first Close.
type udpRelayConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *udpRelayConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func newUDPRelayDialer(t *testing.T) *udpRelayDialer {
	d := &udpRelayDialer{targets: make(chan *udpRelayTarget, 16)}
	t.Cleanup(d.closeAll)
	return d
}

func (d *udpRelayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, fakeDial{network: network, address: address, client: stack.ClientAddr(ctx)})
	err, stalled, delay := d.err, d.stalled, d.slow[address]
	d.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	target := &udpRelayTarget{}
	var conn net.Conn
	if stalled {
		conn = &stalledConn{writing: make(chan struct{}), closed: make(chan struct{})}
	} else {
		remote, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return nil, err
		}
		dialled, err := net.DialUDP("udp", nil, remote.LocalAddr().(*net.UDPAddr))
		if err != nil {
			remote.Close()
			return nil, err
		}
		if err := errors.Join(relayRaiseBuffers(remote), relayRaiseBuffers(dialled)); err != nil {
			remote.Close()
			dialled.Close()
			return nil, err
		}
		conn, target.remote = dialled, remote
	}
	target.dialled = &udpRelayConn{Conn: conn, closed: make(chan struct{})}
	d.mu.Lock()
	d.opened = append(d.opened, target)
	d.mu.Unlock()
	select {
	case d.targets <- target:
	default:
	}
	return target.dialled, nil
}

func (d *udpRelayDialer) fail(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
}

func (d *udpRelayDialer) stall() {
	d.mu.Lock()
	d.stalled = true
	d.mu.Unlock()
}

func (d *udpRelayDialer) slowDial(address string, delay time.Duration) {
	d.mu.Lock()
	if d.slow == nil {
		d.slow = make(map[string]time.Duration)
	}
	d.slow[address] = delay
	d.mu.Unlock()
}

func (d *udpRelayDialer) recorded() []fakeDial {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dials)
}

func (d *udpRelayDialer) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, target := range d.opened {
		if target.remote != nil {
			target.remote.Close()
		}
		target.dialled.Close()
	}
}

// expectOnly expects exactly one dial, of "udp" to address, tagged with client's address.
func (d *udpRelayDialer) expectOnly(t *testing.T, address string, client net.Addr) {
	t.Helper()
	dials := d.recorded()
	if len(dials) != 1 {
		t.Fatalf("dialer.DialContext called %d times %+v, want once", len(dials), dials)
	}
	if got := dials[0]; got.network != "udp" || got.address != address {
		t.Fatalf(`dialer.DialContext(%q, %q), want ("udp", %q)`, got.network, got.address, address)
	}
	if got := dials[0].client; !sameAddr(got, client) {
		t.Fatalf("ClientAddr(dial ctx) = %T %v, want the client's %T %v", got, got, client, client)
	}
}

// next returns the target of the next dial the Handler made.
func (d *udpRelayDialer) next(t *testing.T, env *testEnv) *udpRelayTarget {
	t.Helper()
	select {
	case target := <-d.targets:
		if target.remote != nil {
			target.remote.SetDeadline(time.Now().Add(testWait))
		}
		return target
	case <-env.done:
		t.Fatal("ServeFlow returned without dialing")
	case <-time.After(testWait):
		t.Fatalf("Handler did not dial within %v", testWait)
	}
	return nil
}

// recv reads one datagram the Handler wrote to the dialled conn.
func (tg *udpRelayTarget) recv(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, _, err := tg.remote.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("target read a datagram from the Handler: %v", err)
	}
	return buf[:n]
}

// send writes datagram to the dialled conn, for the Handler to pass to the client.
func (tg *udpRelayTarget) send(t *testing.T, datagram []byte) {
	t.Helper()
	if _, err := tg.remote.WriteTo(datagram, tg.dialled.LocalAddr()); err != nil {
		t.Fatalf("target send a %d-byte datagram: %v", len(datagram), err)
	}
}

func (tg *udpRelayTarget) gone() <-chan struct{} { return tg.dialled.closed }

// relayEnd is one target's end of a session the Handler serves, in either mode.
type relayEnd interface {
	// recv reads one datagram the Handler sent the target.
	recv(t *testing.T) []byte
	// send writes a datagram from the target, for the Handler to pass to the client.
	send(t *testing.T, datagram []byte)
	// gone is closed once the Handler closed the socket carrying the target's datagrams.
	gone() <-chan struct{}
}

// relayOpener hands out the target ends a served Handler opens and counts the sockets it opened for them.
type relayOpener interface {
	next(t *testing.T, env *testEnv) relayEnd
	opens() int
}

// relayMode sets up a Handler for one of its modes.
type relayMode struct {
	name  string
	setup func(t *testing.T, h *Handler) relayOpener
}

// relayModes are the Handler's modes, for the tests holding in each.
var relayModes = []relayMode{
	{"symmetric", func(t *testing.T, h *Handler) relayOpener {
		d := newUDPRelayDialer(t)
		h.Dialer = d
		return relayDialled{d}
	}},
	{"full cone", func(t *testing.T, h *Handler) relayOpener {
		listener, _ := coneSetup(t, h)
		return listener
	}},
}

// serve sets h up in mode and serves it a session of testClient to 10.0.0.9:5000.
func (mode relayMode) serve(t *testing.T, h *Handler) (*testEnv, relayOpener) {
	t.Helper()
	opener := mode.setup(t, h)
	return testServe(t, h, testClient, udpFamilies[0].first), opener
}

// relayDialled is the symmetric mode's opener: one dialled conn per target.
type relayDialled struct{ *udpRelayDialer }

func (d relayDialled) next(t *testing.T, env *testEnv) relayEnd {
	t.Helper()
	return d.udpRelayDialer.next(t, env)
}

func (d relayDialled) opens() int { return len(d.recorded()) }

var _ stack.ListenConfig = (*coneListener)(nil)

// coneListener is a ListenConfig recording each ListenPacket call and answering it with a new coneSocket, or with err once failing, or a coneStalled once stalled; Listen always fails.
type coneListener struct {
	mu      sync.Mutex
	calls   []fakeDial
	err     error
	stalled bool
	sockets []net.PacketConn
	opened  chan net.PacketConn
	targets chan *coneTarget
	// refuse is a target address every socket of l fails to write to.
	refuse netip.AddrPort
}

func newConeListener(t *testing.T) *coneListener {
	l := &coneListener{opened: make(chan net.PacketConn, 16), targets: make(chan *coneTarget, 16)}
	t.Cleanup(l.closeAll)
	return l
}

func (l *coneListener) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, errors.New("coneListener: Listen is not supported")
}

func (l *coneListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	l.mu.Lock()
	l.calls = append(l.calls, fakeDial{network: network, address: address, client: stack.ClientAddr(ctx)})
	err, stalled, refuse := l.err, l.stalled, l.refuse
	l.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var pc net.PacketConn
	if stalled {
		pc = coneStalled{&stalledConn{writing: make(chan struct{}), closed: make(chan struct{})}}
	} else {
		conn, err := coneLoopback()
		if err != nil {
			return nil, err
		}
		pc = &coneSocket{UDPConn: conn, closed: make(chan struct{}), targets: l.targets, refuse: refuse, byTarget: make(map[netip.AddrPort]*coneTarget), byLoopback: make(map[netip.AddrPort]netip.AddrPort)}
	}
	l.mu.Lock()
	l.sockets = append(l.sockets, pc)
	l.mu.Unlock()
	select {
	case l.opened <- pc:
	default:
	}
	return pc, nil
}

// coneLoopback opens an unconnected 127.0.0.1 UDP socket able to carry a 65507-byte datagram.
func coneLoopback() (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	if err := relayRaiseBuffers(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (l *coneListener) fail(err error) {
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
}

func (l *coneListener) stall() {
	l.mu.Lock()
	l.stalled = true
	l.mu.Unlock()
}

func (l *coneListener) refuseWrites(addr netip.AddrPort) {
	l.mu.Lock()
	l.refuse = addr
	l.mu.Unlock()
}

// closes counts the Close calls on every coneSocket l opened.
func (l *coneListener) closes() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, pc := range l.sockets {
		if s, ok := pc.(*coneSocket); ok {
			n += int(s.closes.Load())
		}
	}
	return n
}

func (l *coneListener) recorded() []fakeDial {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.calls)
}

func (l *coneListener) opens() int { return len(l.recorded()) }

func (l *coneListener) closeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, pc := range l.sockets {
		pc.Close()
		if s, ok := pc.(*coneSocket); ok {
			s.closeStandIns()
		}
	}
}

func (l *coneListener) next(t *testing.T, env *testEnv) relayEnd {
	t.Helper()
	return l.nextCone(t, env)
}

// nextCone returns the next target a socket of l sent its first datagram to.
func (l *coneListener) nextCone(t *testing.T, env *testEnv) *coneTarget {
	t.Helper()
	select {
	case target := <-l.targets:
		target.remote.SetDeadline(time.Now().Add(testWait))
		return target
	case <-env.done:
		t.Fatal("ServeFlow returned without sending to a new target")
	case <-time.After(testWait):
		t.Fatalf("Handler sent to no new target within %v", testWait)
	}
	return nil
}

// coneSocket is an unconnected loopback socket on which every target address stands for a loopback socket of its own, a coneTarget.
type coneSocket struct {
	*net.UDPConn
	closed     chan struct{}
	closeOnce  sync.Once
	closes     atomic.Int32
	targets    chan<- *coneTarget
	refuse     netip.AddrPort
	mu         sync.Mutex
	byTarget   map[netip.AddrPort]*coneTarget
	byLoopback map[netip.AddrPort]netip.AddrPort
}

// WriteTo sends b to the coneTarget standing for addr, announcing it on its first datagram.
func (s *coneSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("coneSocket: write to %T %v", addr, addr)
	}
	if s.refuse.IsValid() && relayUnmap(udpAddr.AddrPort()) == s.refuse {
		return 0, fmt.Errorf("coneSocket: write to %v refused", addr)
	}
	target, created, err := s.standIn(udpAddr.AddrPort())
	if err != nil {
		return 0, err
	}
	if created {
		select {
		case s.targets <- target:
		default:
		}
	}
	return s.UDPConn.WriteToUDPAddrPort(b, target.loopback())
}

// ReadFrom returns the next datagram from a coneTarget, from the address it stands for.
func (s *coneSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := s.UDPConn.ReadFromUDPAddrPort(b)
		if err != nil {
			return n, nil, err
		}
		s.mu.Lock()
		addr, ok := s.byLoopback[relayUnmap(from)]
		s.mu.Unlock()
		if ok {
			return n, net.UDPAddrFromAddrPort(addr), nil
		}
	}
}

func (s *coneSocket) Close() error {
	s.closes.Add(1)
	s.closeOnce.Do(func() { close(s.closed) })
	return s.UDPConn.Close()
}

func (s *coneSocket) loopback() netip.AddrPort {
	return relayUnmap(s.UDPConn.LocalAddr().(*net.UDPAddr).AddrPort())
}

// standIn returns the coneTarget standing for addr, opening it first if new.
func (s *coneSocket) standIn(addr netip.AddrPort) (target *coneTarget, created bool, err error) {
	addr = relayUnmap(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	if target, ok := s.byTarget[addr]; ok {
		return target, false, nil
	}
	conn, err := coneLoopback()
	if err != nil {
		return nil, false, err
	}
	target = &coneTarget{remote: conn, socket: s, addr: addr}
	s.byTarget[addr] = target
	s.byLoopback[target.loopback()] = addr
	return target, true, nil
}

func (s *coneSocket) closeStandIns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, target := range s.byTarget {
		target.remote.Close()
	}
}

func relayUnmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// coneTarget is the loopback socket standing for target address addr on socket.
type coneTarget struct {
	remote *net.UDPConn
	socket *coneSocket
	addr   netip.AddrPort
}

func (tg *coneTarget) loopback() netip.AddrPort {
	return relayUnmap(tg.remote.LocalAddr().(*net.UDPAddr).AddrPort())
}

func (tg *coneTarget) recv(t *testing.T) []byte {
	t.Helper()
	datagram, _ := tg.recvFrom(t)
	return datagram
}

// recvFrom reads one datagram the Handler sent the target and the loopback address it came from.
func (tg *coneTarget) recvFrom(t *testing.T) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 65535)
	n, from, err := tg.remote.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("target %v read a datagram from the Handler: %v", tg.addr, err)
	}
	return buf[:n], relayUnmap(from)
}

func (tg *coneTarget) send(t *testing.T, datagram []byte) {
	t.Helper()
	if _, err := tg.remote.WriteToUDPAddrPort(datagram, tg.socket.loopback()); err != nil {
		t.Fatalf("target %v send a %d-byte datagram: %v", tg.addr, len(datagram), err)
	}
}

func (tg *coneTarget) gone() <-chan struct{} { return tg.socket.closed }

// coneStalled is a session socket whose ReadFrom and WriteTo block until Close.
type coneStalled struct{ *stalledConn }

func (c coneStalled) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, nil, err
}

func (c coneStalled) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

// coneSetup gives h a fresh coneListener as its ListenConfig and a udpRelayDialer as its Dialer.
func coneSetup(t *testing.T, h *Handler) (*coneListener, *udpRelayDialer) {
	t.Helper()
	listener, dialer := newConeListener(t), newUDPRelayDialer(t)
	h.ListenConfig, h.Dialer = listener, dialer
	return listener, dialer
}

// udpRelayDatagram returns size bytes marked with tag.
func udpRelayDatagram(size int, tag byte) []byte {
	datagram := make([]byte, size)
	for i := range datagram {
		datagram[i] = tag + byte(i)
	}
	return datagram
}

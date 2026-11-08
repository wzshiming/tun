package stack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// udpRelayQuiet is how long a client waits before concluding no reply comes.
const udpRelayQuiet = time.Second

// udpRelayIdleBound is how long a sub-second Relay.Idle may take to end a flow; the 60s default exceeds it.
const udpRelayIdleBound = 5 * time.Second

// relaySocketBuffer lets a loopback UDP socket carry a 65507-byte datagram; macOS defaults to 9216 to send and 42080 to receive.
const relaySocketBuffer = 1 << 20

func relayRaiseBuffers(conn *net.UDPConn) error {
	if err := conn.SetReadBuffer(relaySocketBuffer); err != nil {
		return err
	}
	return conn.SetWriteBuffer(relaySocketBuffer)
}

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

// udpRelayTarget is the far end of one dial: remote receives the datagrams Relay writes to dialled; remote is nil when stalled.
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

func (d *udpRelayDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, fakeDial{network: network, address: address, client: ClientAddr(ctx)})
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
	if got := dials[0].client; got == nil || fmt.Sprintf("%T %v", got, got) != fmt.Sprintf("%T %v", client, client) {
		t.Fatalf("ClientAddr(dial ctx) = %T %v, want the client's %T %v", got, got, client, client)
	}
}

// next returns the target of the next dial Relay made.
func (d *udpRelayDialer) next(t *testing.T, env *testEnv) *udpRelayTarget {
	t.Helper()
	select {
	case target := <-d.targets:
		if target.remote != nil {
			target.remote.SetDeadline(time.Now().Add(testWait))
		}
		return target
	case <-env.done:
		t.Fatalf("Serve returned %v without Relay dialing", env.err)
	case <-time.After(testWait):
		t.Fatalf("Relay did not dial within %v", testWait)
	}
	return nil
}

// recv reads one datagram Relay wrote to the dialled conn.
func (tg *udpRelayTarget) recv(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, _, err := tg.remote.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("target read a datagram from Relay: %v", err)
	}
	return buf[:n]
}

// send writes datagram to the dialled conn, for Relay to pass to the client.
func (tg *udpRelayTarget) send(t *testing.T, datagram []byte) {
	t.Helper()
	if _, err := tg.remote.WriteTo(datagram, tg.dialled.LocalAddr()); err != nil {
		t.Fatalf("target send a %d-byte datagram: %v", len(datagram), err)
	}
}

func (tg *udpRelayTarget) gone() <-chan struct{} { return tg.dialled.closed }

// relayEnd is one target's end of a session Relay serves, in either UDP mode.
type relayEnd interface {
	// recv reads one datagram Relay sent the target.
	recv(t *testing.T) []byte
	// send writes a datagram from the target, for Relay to pass to the client.
	send(t *testing.T, datagram []byte)
	// gone is closed once Relay closed the socket carrying the target's datagrams.
	gone() <-chan struct{}
}

// relayOpener hands out the target ends a served Relay opens and counts the sockets it opened for them.
type relayOpener interface {
	next(t *testing.T, env *testEnv) relayEnd
	opens() int
}

// relayMode serves a Relay in one of its UDP modes.
type relayMode struct {
	name  string
	serve func(t *testing.T, relay *Relay) (*testEnv, relayOpener)
}

// relayModes are Relay's UDP modes, for the tests holding in each.
var relayModes = []relayMode{
	{"symmetric", func(t *testing.T, relay *Relay) (*testEnv, relayOpener) {
		env, dialer := udpRelayServe(t, relay)
		return env, relayDialled{dialer}
	}},
	{"full cone", func(t *testing.T, relay *Relay) (*testEnv, relayOpener) {
		env, listener, _ := coneServe(t, relay)
		return env, listener
	}},
}

// relayDialled is the symmetric mode's opener: one dialled conn per target.
type relayDialled struct{ *udpRelayDialer }

func (d relayDialled) next(t *testing.T, env *testEnv) relayEnd {
	t.Helper()
	return d.udpRelayDialer.next(t, env)
}

func (d relayDialled) opens() int { return len(d.recorded()) }

var _ PacketListener = (*net.ListenConfig)(nil)

// coneListener is a PacketListener recording each call and answering it with a new coneSocket, or with err once failing, or a coneStalled once stalled.
type coneListener struct {
	mu      sync.Mutex
	calls   []fakeDial
	err     error
	stalled bool
	sockets []net.PacketConn
	opened  chan net.PacketConn
	targets chan *coneTarget
}

func newConeListener(t *testing.T) *coneListener {
	l := &coneListener{opened: make(chan net.PacketConn, 16), targets: make(chan *coneTarget, 16)}
	t.Cleanup(l.closeAll)
	return l
}

func (l *coneListener) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	l.mu.Lock()
	l.calls = append(l.calls, fakeDial{network: network, address: address, client: ClientAddr(ctx)})
	err, stalled := l.err, l.stalled
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
		pc = &coneSocket{UDPConn: conn, closed: make(chan struct{}), targets: l.targets, byTarget: make(map[netip.AddrPort]*coneTarget), byLoopback: make(map[netip.AddrPort]netip.AddrPort)}
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
		t.Fatalf("Serve returned %v without Relay sending to a new target", env.err)
	case <-time.After(testWait):
		t.Fatalf("Relay sent to no new target within %v", testWait)
	}
	return nil
}

// coneSocket is an unconnected loopback socket on which every target address stands for a loopback socket of its own, a coneTarget.
type coneSocket struct {
	*net.UDPConn
	closed     chan struct{}
	closeOnce  sync.Once
	targets    chan<- *coneTarget
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
	s.closeOnce.Do(func() { close(s.closed) })
	return s.UDPConn.Close()
}

func (s *coneSocket) loopback() netip.AddrPort { return relayUnmap(s.UDPConn.LocalAddr().(*net.UDPAddr).AddrPort()) }

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

func (tg *coneTarget) loopback() netip.AddrPort { return relayUnmap(tg.remote.LocalAddr().(*net.UDPAddr).AddrPort()) }

func (tg *coneTarget) recv(t *testing.T) []byte {
	t.Helper()
	datagram, _ := tg.recvFrom(t)
	return datagram
}

// recvFrom reads one datagram Relay sent the target and the loopback address it came from.
func (tg *coneTarget) recvFrom(t *testing.T) ([]byte, netip.AddrPort) {
	t.Helper()
	buf := make([]byte, 65535)
	n, from, err := tg.remote.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("target %v read a datagram from Relay: %v", tg.addr, err)
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

// coneServe serves relay as the udp fallback with a fresh coneListener as its Packets and a udpRelayDialer as its Dialer.
func coneServe(t *testing.T, relay *Relay) (*testEnv, *coneListener, *udpRelayDialer) {
	t.Helper()
	listener := newConeListener(t)
	relay.Packets = listener
	env, dialer := udpRelayServe(t, relay)
	return env, listener, dialer
}

func TestRelayConeListensOnceAndRelaysEverySource(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			env, listener, dialer := coneServe(t, &Relay{})
			conn := env.listenUDP(t, fam.client)
			testSendTo(t, conn, []byte("to first"), fam.first)
			first := listener.nextCone(t, env)
			gotFirst, firstFrom := first.recvFrom(t)
			testSendTo(t, conn, []byte("to second"), fam.second)
			second := listener.nextCone(t, env)
			gotSecond, secondFrom := second.recvFrom(t)
			if first.addr != fam.first || string(gotFirst) != "to first" || second.addr != fam.second || string(gotSecond) != "to second" {
				t.Fatalf("targets got %v %q and %v %q, want %v %q and %v %q", first.addr, gotFirst, second.addr, gotSecond, fam.first, "to first", fam.second, "to second")
			}
			if firstFrom != secondFrom {
				t.Fatalf("targets received from %v and %v, want both from the session's one socket", firstFrom, secondFrom)
			}
			wantNetwork := map[string]string{"ipv4": "udp4", "ipv6": "udp6"}[fam.name]
			calls := listener.recorded()
			if len(calls) != 1 || calls[0].network != wantNetwork || calls[0].address != ":0" {
				t.Fatalf("ListenPacket calls %+v, want one (%q, %q)", calls, wantNetwork, ":0")
			}
			if got, want := calls[0].client, conn.LocalAddr(); got == nil || fmt.Sprintf("%T %v", got, got) != fmt.Sprintf("%T %v", want, want) {
				t.Fatalf("ClientAddr(ListenPacket ctx) = %T %v, want the client's %T %v", got, got, want, want)
			}
			if dials := dialer.recorded(); len(dials) != 0 {
				t.Fatalf("dialer.DialContext calls %+v, want none with Packets set", dials)
			}
			second.send(t, []byte("from second"))
			if got, want := testRecvFrom(t, conn), (udpRead{"from second", fam.second, nil}); got != want {
				t.Fatalf("client got %+v, want %+v", got, want)
			}
			first.send(t, []byte("from first"))
			if got, want := testRecvFrom(t, conn), (udpRead{"from first", fam.first, nil}); got != want {
				t.Fatalf("client got %+v, want %+v", got, want)
			}
			unseen, _, err := first.socket.standIn(fam.unseen)
			if err != nil {
				t.Fatalf("stand in for %v: %v", fam.unseen, err)
			}
			unseen.send(t, []byte("from unseen"))
			if got, want := testRecvFrom(t, conn), (udpRead{"from unseen", fam.unseen, nil}); got != want {
				t.Fatalf("client got %+v from a source it never sent to, want %+v", got, want)
			}
			if n := env.dev.unreachable.Load(); n != 0 {
				t.Fatalf("Serve wrote %d ICMP destination unreachable, want none", n)
			}
		})
	}
}

func TestRelayConeListenFailureEndsSessionAndListensAgain(t *testing.T) {
	env, listener, _ := coneServe(t, &Relay{})
	listener.fail(errors.New("cone test listen failure"))
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "first")
	conn.SetReadDeadline(time.Now().Add(udpRelayQuiet))
	var netErr net.Error
	if n, err := conn.Read(make([]byte, 512)); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() = %d, %v after a failed ListenPacket, want a timeout with no reply", n, err)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable after a failed ListenPacket, want none", n)
	}
	for deadline := time.Now().Add(testWait); listener.opens() < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("ListenPacket called %d times within %v of resending, want the next datagram to start a session listening again", listener.opens(), testWait)
		}
		testSend(t, conn, "again")
	}
}

func TestRelayConeIdleEndsSessionAndNextDatagramListensAgain(t *testing.T) {
	env, listener, _ := coneServe(t, &Relay{Idle: 200 * time.Millisecond})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "open")
	target := listener.nextCone(t, env)
	target.recv(t)
	udpRelayExpectClosed(t, target, "session idle past Relay.Idle 200ms")
	for deadline := time.Now().Add(testWait); listener.opens() < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("ListenPacket called %d times within %v of sending after the idle end, want a new session listening again", listener.opens(), testWait)
		}
		testSend(t, conn, "again")
	}
}

func TestRelayConeCancelEndsStalledSession(t *testing.T) {
	env, listener, _ := coneServe(t, &Relay{})
	listener.stall()
	testSend(t, env.dialUDP(t, "10.0.0.9:5000"), "datagram")
	stalled := testReceive(t, listener.opened, "ListenPacket").(coneStalled)
	testReceive(t, stalled.writing, "Relay's WriteTo on its stalled socket")
	env.cancel()
	testReceive(t, stalled.closed, "closing the stalled socket after ctx ended")
}

// udpRelayServe serves relay, given a fresh udpRelayDialer, as the udp fallback.
func udpRelayServe(t *testing.T, relay *Relay) (*testEnv, *udpRelayDialer) {
	t.Helper()
	dialer := &udpRelayDialer{targets: make(chan *udpRelayTarget, 16)}
	t.Cleanup(dialer.closeAll)
	relay.Dialer = dialer
	env := testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler {
		m := NewMux()
		m.Handle("udp", 0, relay)
		return m
	})
	return env, dialer
}

// udpRelayDatagram returns size bytes marked with tag.
func udpRelayDatagram(size int, tag byte) []byte {
	datagram := make([]byte, size)
	for i := range datagram {
		datagram[i] = tag + byte(i)
	}
	return datagram
}

func udpRelayClientRead(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("client read a datagram through Relay: %v", err)
	}
	return buf[:n]
}

func TestRelayUDPDialsUDPWithClientAddr(t *testing.T) {
	env, dialer := udpRelayServe(t, &Relay{})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "datagram")
	dialer.next(t, env)
	dialer.expectOnly(t, "10.0.0.9:5000", conn.LocalAddr())
}

func TestRelayUDPDialsIPv6InBracketForm(t *testing.T) {
	env, dialer := udpRelayServe(t, &Relay{})
	conn := env.dialUDP(t, "[fd00::9]:5000")
	testSend(t, conn, "datagram")
	dialer.next(t, env)
	dialer.expectOnly(t, "[fd00::9]:5000", conn.LocalAddr())
}

func TestRelayUDPKeepsDatagramsWholeAndInOrderBothWays(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			env, opener := mode.serve(t, &Relay{})
			conn := env.dialUDP(t, "10.0.0.9:5000")
			sizes := []int{1, 512, 1400}
			for i, size := range sizes {
				if _, err := conn.Write(udpRelayDatagram(size, byte(i))); err != nil {
					t.Fatalf("client send a %d-byte datagram: %v", size, err)
				}
			}
			target := opener.next(t, env)
			for i, size := range sizes {
				if got, want := target.recv(t), udpRelayDatagram(size, byte(i)); !bytes.Equal(got, want) {
					t.Fatalf("target datagram %d is %d bytes %x..., want the client's %d-byte datagram %d", i, len(got), got[:min(len(got), 8)], size, i)
				}
			}
			for i, size := range sizes {
				target.send(t, udpRelayDatagram(size, byte(100+i)))
			}
			for i, size := range sizes {
				if got, want := udpRelayClientRead(t, conn), udpRelayDatagram(size, byte(100+i)); !bytes.Equal(got, want) {
					t.Fatalf("client datagram %d is %d bytes %x..., want the target's %d-byte datagram %d", i, len(got), got[:min(len(got), 8)], size, i)
				}
			}
		})
	}
}

func TestRelayUDPKeepsDatagramsAbove32KiBWholeBothWays(t *testing.T) {
	for _, mode := range relayModes {
		for _, size := range []int{40000, 65507} {
			t.Run(fmt.Sprint(mode.name, " ", size, " from the client"), func(t *testing.T) {
				env, opener := mode.serve(t, &Relay{})
				conn := env.dialUDP(t, "10.0.0.9:5000")
				if _, err := conn.Write(udpRelayDatagram(size, 1)); err != nil {
					t.Fatalf("client send a %d-byte datagram: %v", size, err)
				}
				if got := opener.next(t, env).recv(t); !bytes.Equal(got, udpRelayDatagram(size, 1)) {
					t.Fatalf("target got a %d-byte datagram, want the client's %d bytes unchanged", len(got), size)
				}
			})
			t.Run(fmt.Sprint(mode.name, " ", size, " from the target"), func(t *testing.T) {
				conn, target := udpRelayOpen(t, mode, 0)
				target.send(t, udpRelayDatagram(size, 2))
				conn.SetReadDeadline(time.Now().Add(testWait))
				if got := udpRelayClientRead(t, conn); !bytes.Equal(got, udpRelayDatagram(size, 2)) {
					t.Fatalf("client got a %d-byte datagram, want the target's %d bytes unchanged", len(got), size)
				}
			})
		}
	}
}

func TestRelayUDPFlowReusesItsSocket(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			env, opener := mode.serve(t, &Relay{})
			conn := env.dialUDP(t, "10.0.0.9:5000")
			testSend(t, conn, "first")
			target := opener.next(t, env)
			target.recv(t)
			for _, datagram := range []string{"second", "third"} {
				testSend(t, conn, datagram)
				if got := target.recv(t); string(got) != datagram {
					t.Fatalf("the flow's socket got %q, want the later datagram %q", got, datagram)
				}
			}
			if n := opener.opens(); n != 1 {
				t.Fatalf("Relay opened %d sockets for one client port to one target, want 1", n)
			}
		})
	}
}

func TestRelayUDPDialFailureDropsFlowAndRedials(t *testing.T) {
	env, dialer := udpRelayServe(t, &Relay{})
	dialer.fail(errors.New("udpRelay test dial failure"))
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "first")
	conn.SetReadDeadline(time.Now().Add(udpRelayQuiet))
	var netErr net.Error
	if n, err := conn.Read(make([]byte, 512)); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() = %d, %v after a failed dial, want a timeout with no reply", n, err)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable after a failed UDP dial, want none", n)
	}
	// A datagram reaching the failed flow before it ends is dropped with it, so send until one starts a new flow.
	for deadline := time.Now().Add(testWait); len(dialer.recorded()) < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("dialer.DialContext called %d times within %v of resending, want the next datagram to dial again", len(dialer.recorded()), testWait)
		}
		testSend(t, conn, "again")
	}
	dialer.mu.Lock()
	opened := len(dialer.opened)
	dialer.mu.Unlock()
	if opened != 0 {
		t.Fatalf("%d dialled conns opened by failed dials, want none", opened)
	}
}

func TestRelayUDPCancelEndsFlowWithStalledRemote(t *testing.T) {
	env, dialer := udpRelayServe(t, &Relay{})
	dialer.stall()
	testSend(t, env.dialUDP(t, "10.0.0.9:5000"), "datagram")
	target := dialer.next(t, env)
	select {
	case <-target.dialled.Conn.(*stalledConn).writing:
	case <-time.After(testWait):
		t.Fatalf("Relay did not write the datagram to its dialled conn within %v", testWait)
	}
	env.cancel()
	select {
	case <-target.dialled.closed:
	case <-time.After(testWait):
		t.Fatalf("Relay still held its stalled dialled conn open %v after ctx ended, want it closed", testWait)
	}
}

func TestRelayUDPDialledReadErrorEndsFlowAndRedials(t *testing.T) {
	env, dialer := udpRelayServe(t, &Relay{})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "open")
	target := dialer.next(t, env)
	target.recv(t)
	// A past deadline fails Relay's pending Read as an ICMP port unreachable would.
	target.dialled.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case <-target.dialled.closed:
	case <-time.After(testWait):
		t.Fatalf("dialled conn still open %v after its Read failed, want Relay to end the flow", testWait)
	}
	for deadline := time.Now().Add(testWait); len(dialer.recorded()) < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("dialer.DialContext called %d times within %v of resending, want the ended flow's next datagram to dial again", len(dialer.recorded()), testWait)
		}
		testSend(t, conn, "again")
	}
}

// udpRelayTwoTargets opens a session to Relay{Idle: idle} in mode from one client socket to two targets, each reached by one datagram.
func udpRelayTwoTargets(t *testing.T, mode relayMode, idle time.Duration) (env *testEnv, opener relayOpener, conn *gonet.UDPConn, first, second relayEnd) {
	t.Helper()
	env, opener = mode.serve(t, &Relay{Idle: idle})
	fam := udpFamilies[0]
	conn = env.listenUDP(t, fam.client)
	testSendTo(t, conn, []byte("to first"), fam.first)
	first = opener.next(t, env)
	if got := first.recv(t); string(got) != "to first" {
		t.Fatalf("first target got %q, want %q", got, "to first")
	}
	testSendTo(t, conn, []byte("to second"), fam.second)
	second = opener.next(t, env)
	if got := second.recv(t); string(got) != "to second" {
		t.Fatalf("second target got %q, want %q", got, "to second")
	}
	return env, opener, conn, first, second
}

func TestRelayUDPSessionDialsOnceEachTargetAndRepliesFromIt(t *testing.T) {
	fam := udpFamilies[0]
	env, opener, conn, first, second := udpRelayTwoTargets(t, relayModes[0], 0)
	dialer := opener.(relayDialled)
	testSendTo(t, conn, []byte("again"), fam.first)
	if got := first.recv(t); string(got) != "again" {
		t.Fatalf("first target got %q, want the later datagram %q on the same socket", got, "again")
	}
	dials := dialer.recorded()
	client := conn.LocalAddr().String()
	if len(dials) != 2 || dials[0].address != fam.first.String() || dials[1].address != fam.second.String() {
		t.Fatalf("dialer.DialContext calls %+v, want one udp dial each to %v and %v", dials, fam.first, fam.second)
	}
	for _, dial := range dials {
		if dial.network != "udp" || dial.client == nil || dial.client.String() != client {
			t.Fatalf("dial %+v, want network udp tagged with the client %s", dial, client)
		}
	}
	second.send(t, []byte("from second"))
	if got, want := testRecvFrom(t, conn), (udpRead{"from second", fam.second, nil}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	first.send(t, []byte("from first"))
	if got, want := testRecvFrom(t, conn), (udpRead{"from first", fam.first, nil}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable, want none", n)
	}
}

func TestRelayUDPReadErrorClosesOnlyThatTargetsSocket(t *testing.T) {
	fam := udpFamilies[0]
	env, opener, conn, firstEnd, second := udpRelayTwoTargets(t, relayModes[0], 0)
	dialer, first := opener.(relayDialled), firstEnd.(*udpRelayTarget)
	// A past deadline fails Relay's pending Read as an ICMP port unreachable would.
	first.dialled.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case <-first.dialled.closed:
	case <-time.After(testWait):
		t.Fatalf("first target's socket still open %v after its Read failed, want it closed", testWait)
	}
	testSendTo(t, conn, []byte("still"), fam.second)
	if got := second.recv(t); string(got) != "still" {
		t.Fatalf("second target got %q, want %q on its socket kept open", got, "still")
	}
	testSendTo(t, conn, []byte("redial"), fam.first)
	again := dialer.next(t, env)
	if got := again.recv(t); string(got) != "redial" {
		t.Fatalf("redialled first target got %q, want %q", got, "redial")
	}
	if dials := dialer.recorded(); len(dials) != 3 || dials[2].address != fam.first.String() {
		t.Fatalf("dialer.DialContext calls %+v, want a third dial to %v", dials, fam.first)
	}
	select {
	case <-second.gone():
		t.Fatal("second target's socket closed, want only the failed one closed")
	default:
	}
}

// relayStallBound is how long a datagram may take to reach its target while another target of its session dials.
const relayStallBound = 500 * time.Millisecond

func TestRelayUDPSlowDialDoesNotDelayOtherTargets(t *testing.T) {
	fam := udpFamilies[0]
	env, dialer := udpRelayServe(t, &Relay{})
	dialer.slowDial(fam.second.String(), 2*time.Second)
	conn := env.listenUDP(t, fam.client)
	testSendTo(t, conn, []byte("to slow"), fam.second)
	start := time.Now()
	testSendTo(t, conn, []byte("to fast"), fam.first)
	fast := dialer.next(t, env).recv(t)
	if elapsed := time.Since(start); elapsed > relayStallBound {
		t.Fatalf("datagram to %v reached a target %v after sending while the dial to %v took 2s, want within %v", fam.first, elapsed.Round(time.Millisecond), fam.second, relayStallBound)
	}
	if string(fast) != "to fast" {
		t.Fatalf("first target reached got %q, want %q", fast, "to fast")
	}
	if got := dialer.next(t, env).recv(t); string(got) != "to slow" {
		t.Fatalf("slow target got %q once dialled, want %q", got, "to slow")
	}
}

func TestRelayUDPIdleCountsForTheWholeSession(t *testing.T) {
	const idle = 300 * time.Millisecond
	fam := udpFamilies[0]
	_, _, conn, first, second := udpRelayTwoTargets(t, relayModes[0], idle)
	for end := time.Now().Add(3 * idle); time.Now().Before(end); time.Sleep(idle / 5) {
		testSendTo(t, conn, []byte("keep"), fam.first)
		first.recv(t)
		select {
		case <-second.gone():
			t.Fatalf("second target's socket closed while datagrams flowed to the first every %v, want Relay.Idle %v to count for the whole session", idle/5, idle)
		default:
		}
	}
	udpRelayExpectClosed(t, second, "second target once the session idled")
}

func TestRelayUDPSessionIdleClosesEverySocket(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			_, _, _, first, second := udpRelayTwoTargets(t, mode, 200*time.Millisecond)
			udpRelayExpectClosed(t, first, "first target of a session idle past Relay.Idle 200ms")
			udpRelayExpectClosed(t, second, "second target of a session idle past Relay.Idle 200ms")
		})
	}
}

func TestRelayIdleDefaultsTo60Seconds(t *testing.T) {
	if got := (&Relay{}).idle(); got != 60*time.Second {
		t.Fatalf("Relay{}.idle() = %v, want the 60s default", got)
	}
	if got := (&Relay{Idle: 3 * time.Second}).idle(); got != 3*time.Second {
		t.Fatalf("Relay{Idle: 3s}.idle() = %v, want 3s", got)
	}
}

// udpRelayOpen opens a flow to Relay{Idle: idle} in mode and returns its client conn and target once the first datagram arrived.
func udpRelayOpen(t *testing.T, mode relayMode, idle time.Duration) (net.Conn, relayEnd) {
	t.Helper()
	env, opener := mode.serve(t, &Relay{Idle: idle})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "open")
	target := opener.next(t, env)
	target.recv(t)
	return conn, target
}

func udpRelayExpectClosed(t *testing.T, target relayEnd, what string) {
	t.Helper()
	select {
	case <-target.gone():
	case <-time.After(udpRelayIdleBound):
		t.Fatalf("%s: socket still open %v later, want Relay.Idle to close it", what, udpRelayIdleBound)
	}
}

func TestRelayUDPFlowEndsAfterIdle(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			_, target := udpRelayOpen(t, mode, 200*time.Millisecond)
			udpRelayExpectClosed(t, target, "flow idle past Relay.Idle 200ms")
		})
	}
}

func TestRelayUDPTrafficEitherWayExtendsIdle(t *testing.T) {
	const idle = 500 * time.Millisecond
	for _, mode := range relayModes {
		for _, direction := range []string{"from the client", "from the target"} {
			t.Run(mode.name+" "+direction, func(t *testing.T) {
				conn, target := udpRelayOpen(t, mode, idle)
				for end := time.Now().Add(3 * idle); time.Now().Before(end); time.Sleep(idle / 5) {
					if direction == "from the client" {
						testSend(t, conn, "keep")
						target.recv(t)
					} else {
						target.send(t, []byte("keep"))
						udpRelayClientRead(t, conn)
					}
					select {
					case <-target.gone():
						t.Fatalf("Relay closed the flow while datagrams flowed %s every %v, want each to push back Relay.Idle %v", direction, idle/5, idle)
					default:
					}
				}
				udpRelayExpectClosed(t, target, "flow idle after datagrams "+direction)
			})
		}
	}
}

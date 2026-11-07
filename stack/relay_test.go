package stack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
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
	err, stalled := d.err, d.stalled
	d.mu.Unlock()
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
	env, dialer := udpRelayServe(t, &Relay{})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	sizes := []int{1, 512, 1400}
	for i, size := range sizes {
		if _, err := conn.Write(udpRelayDatagram(size, byte(i))); err != nil {
			t.Fatalf("client send a %d-byte datagram: %v", size, err)
		}
	}
	target := dialer.next(t, env)
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
}

func TestRelayUDPKeepsDatagramsAbove32KiBWholeBothWays(t *testing.T) {
	for _, size := range []int{40000, 65507} {
		t.Run(fmt.Sprint(size, " from the client"), func(t *testing.T) {
			env, dialer := udpRelayServe(t, &Relay{})
			conn := env.dialUDP(t, "10.0.0.9:5000")
			if _, err := conn.Write(udpRelayDatagram(size, 1)); err != nil {
				t.Fatalf("client send a %d-byte datagram: %v", size, err)
			}
			if got := dialer.next(t, env).recv(t); !bytes.Equal(got, udpRelayDatagram(size, 1)) {
				t.Fatalf("target got a %d-byte datagram, want the client's %d bytes unchanged", len(got), size)
			}
		})
		t.Run(fmt.Sprint(size, " from the target"), func(t *testing.T) {
			conn, target := udpRelayOpen(t, 0)
			target.send(t, udpRelayDatagram(size, 2))
			conn.SetReadDeadline(time.Now().Add(testWait))
			if got := udpRelayClientRead(t, conn); !bytes.Equal(got, udpRelayDatagram(size, 2)) {
				t.Fatalf("client got a %d-byte datagram, want the target's %d bytes unchanged", len(got), size)
			}
		})
	}
}

func TestRelayUDPFlowReusesDialledConn(t *testing.T) {
	env, dialer := udpRelayServe(t, &Relay{})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "first")
	target := dialer.next(t, env)
	target.recv(t)
	for _, datagram := range []string{"second", "third"} {
		testSend(t, conn, datagram)
		if got := target.recv(t); string(got) != datagram {
			t.Fatalf("the flow's dialled conn got %q, want the later datagram %q", got, datagram)
		}
	}
	if dials := dialer.recorded(); len(dials) != 1 {
		t.Fatalf("dialer.DialContext called %d times for one client port, want 1", len(dials))
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

// udpRelayOpen opens a flow to Relay{Idle: idle} and returns its client conn and target once the first datagram arrived.
func udpRelayOpen(t *testing.T, idle time.Duration) (net.Conn, *udpRelayTarget) {
	t.Helper()
	env, dialer := udpRelayServe(t, &Relay{Idle: idle})
	conn := env.dialUDP(t, "10.0.0.9:5000")
	testSend(t, conn, "open")
	target := dialer.next(t, env)
	target.recv(t)
	return conn, target
}

func udpRelayExpectClosed(t *testing.T, target *udpRelayTarget, what string) {
	t.Helper()
	select {
	case <-target.dialled.closed:
	case <-time.After(udpRelayIdleBound):
		t.Fatalf("%s: dialled conn still open %v later, want Relay.Idle to close it", what, udpRelayIdleBound)
	}
}

func TestRelayUDPFlowEndsAfterIdle(t *testing.T) {
	_, target := udpRelayOpen(t, 200*time.Millisecond)
	udpRelayExpectClosed(t, target, "flow idle past Relay.Idle 200ms")
}

func TestRelayUDPTrafficEitherWayExtendsIdle(t *testing.T) {
	const idle = 500 * time.Millisecond
	for _, direction := range []string{"from the client", "from the target"} {
		t.Run(direction, func(t *testing.T) {
			conn, target := udpRelayOpen(t, idle)
			for end := time.Now().Add(3 * idle); time.Now().Before(end); time.Sleep(idle / 5) {
				if direction == "from the client" {
					testSend(t, conn, "keep")
					target.recv(t)
				} else {
					target.send(t, []byte("keep"))
					udpRelayClientRead(t, conn)
				}
				select {
				case <-target.dialled.closed:
					t.Fatalf("Relay closed the flow while datagrams flowed %s every %v, want each to push back Relay.Idle %v", direction, idle/5, idle)
				default:
				}
			}
			udpRelayExpectClosed(t, target, "flow idle after datagrams "+direction)
		})
	}
}

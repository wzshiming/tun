package stack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	testMTU   = 1500
	testBatch = 4
	// testWait bounds every wait for something that must happen.
	testWait = 10 * time.Second
	// testQuiet is how long the client stack must stay silent before it is closed.
	testQuiet = 100 * time.Millisecond
)

var (
	testClient4   = netip.MustParseAddr("10.0.0.2")
	testClient6   = netip.MustParseAddr("fd00::2")
	testAddresses = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("fd00::1/64")}
)

// fakeDevice is the tun.Device handed to Serve, wired back-to-back to a netstack client device.
type fakeDevice struct {
	client     tun.Device
	inbound    chan []byte
	failNext   chan error
	readFailed chan struct{}
	readErr    error
	failOnce   sync.Once
	closed     chan struct{}
	closeOnce  sync.Once
	closeCalls atomic.Int32
	events     chan tun.Event
	feeding    sync.Mutex
	// segmented carries the one SYN that Read returns with tun.ErrTooManySegments.
	segmented    chan []byte
	synArmed     atomic.Bool
	synSegmented atomic.Bool
	// unreachable counts the ICMP destination unreachable packets Serve wrote.
	unreachable atomic.Int32
}

func (d *fakeDevice) File() *os.File           { return nil }
func (d *fakeDevice) Name() (string, error)    { return "fake0", nil }
func (d *fakeDevice) MTU() (int, error)        { return testMTU, nil }
func (d *fakeDevice) Events() <-chan tun.Event { return d.events }
func (d *fakeDevice) BatchSize() int           { return testBatch }

func (d *fakeDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	var packet []byte
	select {
	case packet = <-d.inbound:
	case syn := <-d.segmented:
		sizes[0] = copy(bufs[0][offset:], syn)
		return 1, tun.ErrTooManySegments
	case err := <-d.failNext:
		return 0, err
	case <-d.readFailed:
		return 0, d.readErr
	case <-d.closed:
		return 0, os.ErrClosed
	}
	n := 0
	for {
		sizes[n] = copy(bufs[n][offset:], packet)
		n++
		if n == len(bufs) {
			return n, nil
		}
		select {
		case packet = <-d.inbound:
		default:
			return n, nil
		}
	}
}

func (d *fakeDevice) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	default:
	}
	for _, buf := range bufs {
		if testIsUnreachable(buf[offset:]) {
			d.unreachable.Add(1)
		}
		d.client.Write([][]byte{buf[offset:]}, 0)
	}
	return len(bufs), nil
}

func (d *fakeDevice) Close() error {
	d.closeCalls.Add(1)
	d.release()
	return nil
}

// release stops the device without counting as a Close by Serve.
func (d *fakeDevice) release() {
	d.closeOnce.Do(func() {
		close(d.closed)
		// A send pending on a closed channel panics, so a feeder must stop before events closes.
		d.feeding.Lock()
		close(d.events)
		d.feeding.Unlock()
	})
}

// inject queues a client packet for Serve's next Read, dropping it once the device is closed.
func (d *fakeDevice) inject(packet []byte) {
	queue := d.inbound
	if d.synArmed.Load() && testIsSYN(packet) {
		// A retransmitted SYN could open the connection in place of one Serve dropped.
		if d.synSegmented.Swap(true) {
			return
		}
		queue = d.segmented
	}
	select {
	case queue <- packet:
	case <-d.closed:
	}
}

// segmentSYN makes Read return the client's next TCP SYN as (1, tun.ErrTooManySegments) and drops every later SYN.
func (d *fakeDevice) segmentSYN() { d.synArmed.Store(true) }

// testIsSYN reports whether packet is an IPv4 TCP segment opening a connection.
func testIsSYN(packet []byte) bool {
	ip := header.IPv4(packet)
	if !ip.IsValid(len(packet)) || ip.TransportProtocol() != header.TCPProtocolNumber {
		return false
	}
	segment := header.TCP(ip.Payload())
	return len(segment) >= header.TCPMinimumSize && segment.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) == header.TCPFlagSyn
}

// testIsUnreachable reports whether packet is an ICMPv4 or ICMPv6 destination unreachable message.
func testIsUnreachable(packet []byte) bool {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ip := header.IPv4(packet)
		if !ip.IsValid(len(packet)) || ip.TransportProtocol() != header.ICMPv4ProtocolNumber {
			return false
		}
		icmp := header.ICMPv4(ip.Payload())
		return len(icmp) >= header.ICMPv4MinimumSize && icmp.Type() == header.ICMPv4DstUnreachable
	case header.IPv6Version:
		ip := header.IPv6(packet)
		if !ip.IsValid(len(packet)) || ip.TransportProtocol() != header.ICMPv6ProtocolNumber {
			return false
		}
		icmp := header.ICMPv6(ip.Payload())
		return len(icmp) >= header.ICMPv6MinimumSize && icmp.Type() == header.ICMPv6DstUnreachable
	}
	return false
}

// failRead makes every Read from now on fail with err.
func (d *fakeDevice) failRead(err error) {
	d.failOnce.Do(func() {
		d.readErr = err
		close(d.readFailed)
	})
}

// feedEvents sends n events, each kind in turn, on Events from a goroutine, counting those received and closing all after the last; release ends it.
func (d *fakeDevice) feedEvents(n int) (received *atomic.Int32, all <-chan struct{}) {
	count, done := new(atomic.Int32), make(chan struct{})
	go func() {
		d.feeding.Lock()
		defer d.feeding.Unlock()
		// release may have closed events already.
		select {
		case <-d.closed:
			return
		default:
		}
		kinds := []tun.Event{tun.EventUp, tun.EventDown, tun.EventMTUUpdate}
		for i := range n {
			select {
			case d.events <- kinds[i%len(kinds)]:
				count.Add(1)
			case <-d.closed:
				return
			}
		}
		close(done)
	}()
	return count, done
}

func (d *fakeDevice) closedByServe() bool { return d.closeCalls.Load() > 0 }

// testEnv is one running Serve whose device is wired to a netstack client.
type testEnv struct {
	dev    *fakeDevice
	client *netstack.Net
	cancel context.CancelFunc
	// alive ends when Serve returns, so client operations fail fast if it returns early.
	alive context.Context
	done  chan struct{}
	err   error
}

// testEcho accepts every flow and writes back what it reads until its conn closes.
var testEcho = HandlerFunc(func(_ context.Context, f Flow) {
	if conn, err := f.Accept(); err == nil {
		io.Copy(conn, conn)
	}
})

// testServe serves testEcho.
func testServe(t *testing.T, opts Options) *testEnv {
	t.Helper()
	return testServeWith(t, opts, testEcho)
}

func testServeWith(t *testing.T, opts Options, handler Handler) *testEnv {
	t.Helper()
	clientDev, client, err := netstack.CreateNetTUN([]netip.Addr{testClient4, testClient6}, nil, testMTU)
	if err != nil {
		t.Fatalf("netstack.CreateNetTUN: %v", err)
	}
	dev := &fakeDevice{
		client:     clientDev,
		inbound:    make(chan []byte, 1024),
		segmented:  make(chan []byte),
		failNext:   make(chan error),
		readFailed: make(chan struct{}),
		closed:     make(chan struct{}),
		events:     make(chan tun.Event), // unbuffered: a feedEvents send completes only once Serve receives it
	}

	var lastSent atomic.Int64
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		bufs := [][]byte{make([]byte, 65535)}
		sizes := make([]int, 1)
		for {
			n, err := clientDev.Read(bufs, sizes, 0)
			if err != nil {
				return
			}
			lastSent.Store(time.Now().UnixNano())
			for i := range n {
				dev.inject(bytes.Clone(bufs[i][:sizes[i]]))
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	alive, stop := context.WithCancel(context.Background())
	env := &testEnv{dev: dev, client: client, cancel: cancel, alive: alive, done: make(chan struct{})}
	go func() {
		env.err = Serve(ctx, dev, handler, opts)
		close(env.done)
		stop()
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-env.done:
		case <-time.After(testWait):
			t.Errorf("Serve did not return within %v after its context ended", testWait)
		}
		dev.release()
		// netstack's Close panics a packet send still in flight, so let the client stack fall silent first.
		for limit := time.Now().Add(2 * time.Second); time.Now().Before(limit) && time.Since(time.Unix(0, lastSent.Load())) < testQuiet; {
			time.Sleep(10 * time.Millisecond)
		}
		clientDev.Close()
		select {
		case <-pumped:
		case <-time.After(testWait):
			t.Errorf("client packet pump did not stop")
		}
	})
	return env
}

// returned describes Serve's result for failure messages once it has returned.
func (e *testEnv) returned() string {
	select {
	case <-e.done:
		return fmt.Sprintf(" (Serve already returned %v)", e.err)
	default:
		return ""
	}
}

func (e *testEnv) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-e.done:
		return e.err
	case <-time.After(testWait):
		t.Fatalf("Serve did not return within %v", testWait)
		return nil
	}
}

func (e *testEnv) dialTCP(t *testing.T, address string) *gonet.TCPConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(e.alive, testWait)
	defer cancel()
	conn, err := e.client.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(address))
	if err != nil {
		t.Fatalf("client dial tcp %s through Serve: %v%s", address, err, e.returned())
	}
	conn.SetDeadline(time.Now().Add(testWait))
	return conn
}

// dialTCPRefused expects the client's TCP dial to address to be refused with a RST.
func (e *testEnv) dialTCPRefused(t *testing.T, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(e.alive, testWait)
	defer cancel()
	conn, err := e.client.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(address))
	if err == nil {
		conn.Close()
	}
	if want := (&tcpip.ErrConnectionRefused{}).String(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("client dial %s error = %v%s, want it to contain %q", address, err, e.returned(), want)
	}
}

func (e *testEnv) dialUDP(t *testing.T, address string) *gonet.UDPConn {
	t.Helper()
	conn, err := e.client.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort(address))
	if err != nil {
		t.Fatalf("client dial udp %s: %v", address, err)
	}
	conn.SetDeadline(time.Now().Add(testWait))
	return conn
}

// listenUDP opens an unconnected client socket on local, which can send to and receive from any address.
func (e *testEnv) listenUDP(t *testing.T, local netip.Addr) *gonet.UDPConn {
	t.Helper()
	conn, err := e.client.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		t.Fatalf("client listen udp on %v: %v", local, err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(testWait))
	return conn
}

// failOneRead makes one device Read return err instead of packets, returning once Serve's Read has taken it.
func (e *testEnv) failOneRead(t *testing.T, err error) {
	t.Helper()
	select {
	case e.dev.failNext <- err:
	case <-e.done:
		t.Fatalf("Serve returned %v before its device Read could fail with %v", e.err, err)
	case <-time.After(testWait):
		t.Fatalf("Serve did not Read the device within %v", testWait)
	}
}

// testDeliver writes payload on from and expects it to arrive on to.
func testDeliver(t *testing.T, from, to net.Conn, payload string) {
	t.Helper()
	if _, err := io.WriteString(from, payload); err != nil {
		t.Fatalf("write %q: %v", payload, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(to, got); err != nil {
		t.Fatalf("read %q on the other side of Serve: %v", payload, err)
	}
	if string(got) != payload {
		t.Fatalf("delivered %q, want %q", got, payload)
	}
}

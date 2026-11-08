package stack

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// udpQueueLen is how many datagrams a session holds for its handler; a datagram arriving at a full queue is dropped.
const udpQueueLen = 128

// datagram is one UDP payload and the destination its client addressed.
type datagram struct {
	payload []byte
	target  netip.AddrPort
}

// handleUDP runs on the packet goroutine for every UDP packet, as no UDP endpoint is ever registered: it drops a datagram failing the length or checksum check, else queues it on its client endpoint's session, starting the session and its flow if none is live.
func (g *gateway) handleUDP(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	netHdr := pkt.Network()
	lengthValid, csumValid := header.UDPValid(
		header.UDP(pkt.TransportHeader().Slice()),
		func() uint16 { return pkt.Data().Checksum() },
		uint16(pkt.Data().Size()),
		pkt.NetworkProtocolNumber,
		netHdr.SourceAddress(),
		netHdr.DestinationAddress(),
		pkt.RXChecksumValidated)
	if !lengthValid || !csumValid {
		return true
	}
	d := datagram{payload: pkt.Data().AsRange().ToSlice(), target: addrPort(id.LocalAddress, id.LocalPort)}
	client := addrPort(id.RemoteAddress, id.RemotePort)
	g.mu.Lock()
	c, ok := g.sessions[client]
	if !ok {
		if g.stopped {
			g.mu.Unlock()
			return true
		}
		c = g.newUDPConn(d.target, client, pkt.NetworkProtocolNumber)
		g.sessions[client] = c
		g.flows.Add(1)
		go g.serve(&flow{
			network: "udp",
			target:  d.target,
			client:  client,
			accept:  func() (net.Conn, error) { return c, nil },
			reject:  func() { c.Close() },
		})
	}
	g.mu.Unlock()
	select {
	case c.queue <- d:
	default:
	}
	return true
}

// udpConn is a UDP session: it reads the datagrams its client sends to any target and writes datagrams to its client from any source.
type udpConn struct {
	s              *stack.Stack
	netProto       tcpip.NetworkProtocolNumber
	target, client netip.AddrPort
	queue          chan datagram
	readDeadline   deadline
	closed         chan struct{}
	closeOnce      sync.Once
	onClose        func()
}

func (g *gateway) newUDPConn(target, client netip.AddrPort, netProto tcpip.NetworkProtocolNumber) *udpConn {
	c := &udpConn{
		s:            g.s,
		netProto:     netProto,
		target:       target,
		client:       client,
		queue:        make(chan datagram, udpQueueLen),
		readDeadline: deadline{passed: make(chan struct{})},
		closed:       make(chan struct{}),
	}
	c.onClose = func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.sessions[client] == c {
			delete(g.sessions, client)
		}
	}
	return c
}

// ReadFrom returns the next datagram and the destination the client sent it to; a closed session or a passed deadline fails it even with datagrams queued.
func (c *udpConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case <-c.readDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case d := <-c.queue:
		return copy(b, d.payload), net.UDPAddrFromAddrPort(d.target), nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *udpConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// WriteTo sends b to the client as a datagram from addr, a specified *net.UDPAddr of the client's IP family, an IPv4-mapped one counting as IPv4.
func (c *udpConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	src, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("stack: write udp from %v: not a *net.UDPAddr", addr)
	}
	return c.writeFrom(b, src.AddrPort())
}

func (c *udpConn) Write(b []byte) (int, error) {
	return c.writeFrom(b, c.target)
}

func (c *udpConn) writeFrom(b []byte, src netip.AddrPort) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	ip, maxSize := src.Addr().Unmap(), 65527
	if ip.IsUnspecified() {
		return 0, fmt.Errorf("stack: write udp from unspecified address %v", src)
	}
	if c.netProto == header.IPv4ProtocolNumber {
		maxSize = 65507
		if !ip.Is4() {
			return 0, fmt.Errorf("stack: write udp from %v to IPv4 client %v", src, c.client)
		}
	} else if !ip.Is6() {
		return 0, fmt.Errorf("stack: write udp from %v to IPv6 client %v", src, c.client)
	}
	if len(b) > maxSize {
		return 0, fmt.Errorf("stack: write udp from %v: %d-byte datagram exceeds %d bytes", src, len(b), maxSize)
	}
	route, e := c.s.FindRoute(nicID, tcpip.AddrFromSlice(ip.AsSlice()), tcpip.AddrFromSlice(c.client.Addr().AsSlice()), c.netProto, false)
	if e != nil {
		return 0, fmt.Errorf("stack: write udp from %v: %s", src, e)
	}
	defer route.Release()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.UDPMinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(b),
	})
	defer pkt.DecRef()
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	udpHdr := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	length := uint16(pkt.Size())
	udpHdr.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: c.client.Port(), Length: length})
	xsum := udpHdr.CalculateChecksum(checksum.Combine(route.PseudoHeaderChecksum(header.UDPProtocolNumber, length), pkt.Data().Checksum()))
	// A computed zero is sent as all ones, zero meaning no checksum.
	if xsum != math.MaxUint16 {
		xsum = ^xsum
	}
	udpHdr.SetChecksum(xsum)
	if e := route.WritePacket(stack.NetworkHeaderParams{Protocol: header.UDPProtocolNumber, TTL: route.DefaultTTL()}, pkt); e != nil {
		return 0, fmt.Errorf("stack: write udp from %v: %s", src, e)
	}
	return len(b), nil
}

// Close ends the session; the client's next datagram starts a new one.
func (c *udpConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.onClose()
	})
	return nil
}

func (c *udpConn) LocalAddr() net.Addr  { return net.UDPAddrFromAddrPort(c.target) }
func (c *udpConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.client) }

func (c *udpConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *udpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

// SetWriteDeadline does nothing, as writes never block.
func (c *udpConn) SetWriteDeadline(time.Time) error { return nil }

// deadline closes its passed channel once the time last set passes; setting it again reopens the channel.
type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	passed chan struct{}
}

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		// The timer fired, so its callback closes passed.
		<-d.passed
	}
	d.timer = nil
	wait := time.Until(t)
	select {
	case <-d.passed:
		if t.IsZero() || wait > 0 {
			d.passed = make(chan struct{})
		}
	default:
	}
	switch {
	case t.IsZero():
	case wait > 0:
		passed := d.passed
		d.timer = time.AfterFunc(wait, func() { close(passed) })
	default:
		select {
		case <-d.passed:
		default:
			close(d.passed)
		}
	}
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.passed
}

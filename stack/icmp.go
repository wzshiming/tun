package stack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// icmpKey names an ICMP echo session: the echo requests one client address sends to one target under one identifier.
type icmpKey struct {
	client, target netip.Addr
	ident          uint16
}

// handleICMP runs on the packet goroutine for every ICMP packet, as no ICMP endpoint is ever registered.
// It consumes every one, as under spoofing the stack would answer echo requests to every destination: a valid echo request is queued on its session, starting the session and its flow if none is live, and the rest is dropped.
func (g *gateway) handleICMP(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if g.handler == nil {
		return true
	}
	view := stack.PayloadSince(pkt.TransportHeader())
	message := bytes.Clone(view.AsSlice())
	view.Release()
	if len(message) < header.ICMPv4MinimumSize || message[1] != 0 {
		return true
	}
	if pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber {
		// The stack delivers an IPv4 echo request whatever its checksum, and an IPv6 one only with a valid checksum.
		if header.ICMPv4Type(message[0]) != header.ICMPv4Echo || checksum.Checksum(message, 0) != 0xffff {
			return true
		}
	} else if header.ICMPv6Type(message[0]) != header.ICMPv6EchoRequest {
		return true
	}
	// The stack parses the identifier as the local port.
	target, client := addrPort(id.LocalAddress, 0), addrPort(id.RemoteAddress, id.LocalPort)
	key := icmpKey{client.Addr(), target.Addr(), id.LocalPort}
	var evicted *session
	g.mu.Lock()
	c, ok := g.icmp.live[key]
	if !ok {
		if g.stopped {
			g.mu.Unlock()
			return true
		}
		c, evicted = g.icmp.open(&g.mu, &g.clock, key)
		conn := &icmpConn{session: c, s: g.s, netProto: pkt.NetworkProtocolNumber, key: key}
		g.flows.Add(1)
		go g.serve(&capturedFlow{
			network: "icmp",
			target:  target,
			client:  client,
			accept:  func() (net.Conn, error) { return conn, nil },
			reject:  func() { c.Close() },
		})
	}
	g.mu.Unlock()
	if evicted != nil {
		// Its handler finds the conn closed and returns, which ends the flow.
		evicted.Close()
	}
	c.deliver(datagram{payload: message})
	return true
}

// icmpConn is an ICMP echo session: it reads the echo requests its client sends to its target and writes echo replies to the client from that target.
type icmpConn struct {
	*session
	s        *stack.Stack
	netProto tcpip.NetworkProtocolNumber
	key      icmpKey
}

// Read returns the next echo request as the ICMP message the client sent, from its type byte on.
func (c *icmpConn) Read(b []byte) (int, error) {
	d, err := c.next()
	return copy(b, d.payload), err
}

// Write sends b, an ICMP echo reply message from its type byte on, to the client from the session's target, with the session's identifier and a checksum of its own in place of those in b.
func (c *icmpConn) Write(b []byte) (int, error) {
	if c.isClosed() {
		return 0, net.ErrClosed
	}
	// Either family's IP packet carries at most 65535 bytes, the IPv4 header's 20 among them.
	reply, maxSize, transProto := byte(header.ICMPv6EchoReply), 65535, header.ICMPv6ProtocolNumber
	if c.netProto == header.IPv4ProtocolNumber {
		reply, maxSize, transProto = byte(header.ICMPv4EchoReply), 65515, header.ICMPv4ProtocolNumber
	}
	if len(b) < header.ICMPv4MinimumSize || b[0] != reply || b[1] != 0 {
		return 0, fmt.Errorf("stack: write icmp from %v: not an echo reply", c.key.target)
	}
	if len(b) > maxSize {
		return 0, fmt.Errorf("stack: write icmp from %v: %d-byte message exceeds %d bytes", c.key.target, len(b), maxSize)
	}
	route, e := c.s.FindRoute(nicID, tcpip.AddrFromSlice(c.key.target.AsSlice()), tcpip.AddrFromSlice(c.key.client.AsSlice()), c.netProto, false)
	if e != nil {
		return 0, fmt.Errorf("stack: write icmp from %v: %s", c.key.target, e)
	}
	defer route.Release()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: header.ICMPv4MinimumSize + int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(b[header.ICMPv4MinimumSize:]),
	})
	defer pkt.DecRef()
	pkt.TransportProtocolNumber = transProto
	// Both families' echo header is 8 bytes: type, code, checksum, identifier and sequence number.
	hdr := pkt.TransportHeader().Push(header.ICMPv4MinimumSize)
	copy(hdr, b)
	binary.BigEndian.PutUint16(hdr[2:], 0)
	binary.BigEndian.PutUint16(hdr[4:], c.key.ident)
	xsum := pkt.Data().Checksum()
	if c.netProto == header.IPv4ProtocolNumber {
		xsum = ^checksum.Checksum(hdr, xsum)
	} else {
		xsum = header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
			Header:      hdr,
			Src:         route.LocalAddress(),
			Dst:         route.RemoteAddress(),
			PayloadCsum: xsum,
			PayloadLen:  pkt.Data().Size(),
		})
	}
	binary.BigEndian.PutUint16(hdr[2:], xsum)
	if e := route.WritePacket(stack.NetworkHeaderParams{Protocol: transProto, TTL: route.DefaultTTL()}, pkt); e != nil {
		return 0, fmt.Errorf("stack: write icmp from %v: %s", c.key.target, e)
	}
	c.touch()
	return len(b), nil
}

func (c *icmpConn) LocalAddr() net.Addr  { return &net.IPAddr{IP: c.key.target.AsSlice()} }
func (c *icmpConn) RemoteAddr() net.Addr { return &net.IPAddr{IP: c.key.client.AsSlice()} }

// Package stack terminates the IP packets of a TUN device in a gVisor netstack and hands the TCP connections and UDP flows it captures to a Handler.
package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID tcpip.NICID = 1

// Options tunes Serve.
type Options struct {
	// MTU is the link MTU of the stack; 0 takes the device's.
	MTU int
	// Addresses are the gateway's own addresses, the only ones answering ICMP echo.
	Addresses []netip.Prefix
}

// Serve hands each TCP connection and UDP flow arriving on dev to handler until ctx ends or reading dev fails, and always closes dev.
// A nil handler refuses every flow: TCP with a reset, UDP with ICMP port unreachable.
// Before returning it closes the conns still accepted and waits for every ServeFlow to return.
func Serve(ctx context.Context, dev wgtun.Device, handler Handler, opts Options) error {
	// The event goroutines of a native device block once its Events buffer is full.
	stopEvents := make(chan struct{})
	var drain sync.WaitGroup
	drain.Go(func() { drainEvents(dev.Events(), stopEvents) })
	defer drain.Wait()
	defer close(stopEvents)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g := &gateway{ctx: runCtx, handler: handler}
	s, ep, err := g.newStack(dev, opts)
	if err != nil {
		dev.Close()
		return err
	}

	readErr := make(chan error, 1)
	var pumps sync.WaitGroup
	pumps.Go(func() { readErr <- readPackets(dev, ep) })
	pumps.Go(func() { writePackets(runCtx, dev, ep) })
	select {
	case <-ctx.Done():
	case err = <-readErr:
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	} else {
		err = fmt.Errorf("stack: read packets: %w", err)
	}

	// No flow starts once the pumps are gone; without the NIC a late handshake fails at once, and Close aborts every endpoint, waking a ServeFlow blocked on its conn.
	cancel()
	dev.Close()
	pumps.Wait()
	g.stop()
	s.RemoveNIC(nicID)
	s.Close()
	g.abortUntilDrained(s)
	s.Wait()
	return err
}

var (
	reabortInterval = 100 * time.Millisecond
	reaborted       = func() {} // test hook, called after each re-abort round
)

// abortUntilDrained waits for every flow, re-aborting the stack's endpoints meanwhile: a handshake that found its route before RemoveNIC can register after Close took its snapshot.
func (g *gateway) abortUntilDrained(s *stack.Stack) {
	drained := make(chan struct{})
	go func() {
		g.flows.Wait()
		close(drained)
	}()
	ticker := time.NewTicker(reabortInterval)
	defer ticker.Stop()
	for {
		select {
		case <-drained:
			return
		case <-ticker.C:
			for _, e := range s.RegisteredEndpoints() {
				e.Abort()
			}
			reaborted()
		}
	}
}

// gateway hands the flows the stack captures to its handler and counts them so Serve can wait for them.
type gateway struct {
	ctx     context.Context
	handler Handler

	mu      sync.Mutex
	stopped bool
	flows   sync.WaitGroup
}

// start counts a new flow in; it reports false once Serve is shutting down.
func (g *gateway) start() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.stopped {
		g.flows.Add(1)
	}
	return !g.stopped
}

func (g *gateway) stop() {
	g.mu.Lock()
	g.stopped = true
	g.mu.Unlock()
}

// serve runs the handler on a flow counted in by start and ends the flow once it returns.
func (g *gateway) serve(f *flow) {
	defer g.flows.Done()
	defer f.end()
	g.handler.ServeFlow(g.ctx, f)
}

var (
	errAcceptTwice    = errors.New("stack: flow already accepted")
	errAcceptRejected = errors.New("stack: flow already rejected")
)

// flow is a Flow whose protocol supplies accept and reject, each called at most once.
type flow struct {
	network        string
	target, client netip.AddrPort
	accept         func() (net.Conn, error)
	reject         func()

	mu       sync.Mutex
	answered bool
	conn     net.Conn
}

func (f *flow) Network() string        { return f.network }
func (f *flow) Target() netip.AddrPort { return f.target }
func (f *flow) Client() netip.AddrPort { return f.client }

func (f *flow) Accept() (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.answered {
		if f.conn != nil {
			return nil, errAcceptTwice
		}
		return nil, errAcceptRejected
	}
	f.answered = true
	conn, err := f.accept()
	if err != nil {
		return nil, err
	}
	f.conn = conn
	return conn, nil
}

func (f *flow) Reject() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.answered {
		f.answered = true
		f.reject()
	}
}

// end rejects the flow if unanswered and closes its accepted conn.
func (f *flow) end() {
	f.Reject()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.conn != nil {
		f.conn.Close()
	}
}

func (g *gateway) newStack(dev wgtun.Device, opts Options) (_ *stack.Stack, _ *channel.Endpoint, err error) {
	mtu := opts.MTU
	if mtu == 0 {
		if mtu, err = dev.MTU(); err != nil {
			return nil, nil, fmt.Errorf("stack: device MTU: %w", err)
		}
	}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	defer func() {
		if err != nil {
			s.Destroy()
		}
	}()
	sack := tcpip.TCPSACKEnabled(true)
	if e := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		return nil, nil, fmt.Errorf("stack: enable TCP SACK: %s", e)
	}
	ep := channel.New(1024, uint32(mtu), "")
	if e := s.CreateNIC(nicID, ep); e != nil {
		return nil, nil, fmt.Errorf("stack: create NIC: %s", e)
	}
	if e := s.SetPromiscuousMode(nicID, true); e != nil {
		return nil, nil, fmt.Errorf("stack: enable promiscuous mode: %s", e)
	}
	if e := s.SetSpoofing(nicID, true); e != nil {
		return nil, nil, fmt.Errorf("stack: enable spoofing: %s", e)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	own := make(map[tcpip.Address]bool, len(opts.Addresses))
	for _, prefix := range opts.Addresses {
		if !prefix.IsValid() {
			return nil, nil, fmt.Errorf("stack: invalid address %v", prefix)
		}
		address := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFromSlice(prefix.Addr().AsSlice()),
				PrefixLen: prefix.Bits(),
			},
		}
		if prefix.Addr().Is6() {
			address.Protocol = ipv6.ProtocolNumber
		}
		if e := s.AddProtocolAddress(nicID, address, stack.AddressProperties{}); e != nil {
			return nil, nil, fmt.Errorf("stack: add address %v: %s", prefix, e)
		}
		own[address.AddressWithPrefix.Address] = true
	}
	// Under spoofing ICMPv6 would answer echo requests to any destination, so those not sent to the gateway are consumed.
	consumeEcho := func(id stack.TransportEndpointID, _ *stack.PacketBuffer) bool { return !own[id.LocalAddress] }
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, consumeEcho)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, consumeEcho)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, 2048, g.forwardTCP).HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(s, g.forwardUDP).HandlePacket)
	return s, ep, nil
}

func addrPort(addr tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

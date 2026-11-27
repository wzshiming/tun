// Package stack terminates the IP packets of a TUN device in a gVisor netstack and hands the TCP connections, UDP flows and ICMP echo sessions it captures to a flow.Handler.
package stack

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
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

	"github.com/wzshiming/tun/flow"
)

const nicID tcpip.NICID = 1

// Options tunes Serve.
type Options struct {
	// MTU is the link MTU of the stack; 0 takes the device's.
	MTU int
	// AnswerTimeout is how long a handler may leave a TCP flow neither accepted nor rejected before Serve rejects it and ends its ctx; 0 means 30s.
	AnswerTimeout time.Duration
	// KeepAliveIdle is how long the client of an accepted TCP conn may stay silent before Serve sends it keepalive probes; 0 means 60s.
	KeepAliveIdle time.Duration
	// KeepAliveInterval is the time between those probes; once gVisor's default of 9 in a row go unanswered, a Read blocked on the conn fails; 0 means 15s.
	KeepAliveInterval time.Duration
	// MaxICMPSessions is how many ICMP echo sessions may be live at once, with the limit of MaxUDPSessions and its way of ending the idlest; 0 means 1024, a negative value no limit.
	MaxICMPSessions int
	// MaxUDPSessions is how many UDP sessions may be live at once; a client endpoint starting one more ends the session whose last datagram, either way, is the oldest.
	// 0 means 4096, a negative value no limit.
	MaxUDPSessions int
	// SessionQueueLen is how many datagrams a UDP or ICMP echo session holds for its handler; a datagram arriving at a full queue is dropped. 0 means 128.
	SessionQueueLen int
	// MaxTCPHandshakes is how many TCP connections may await their handler's answer at once; the SYN of one more is dropped. 0 means 2048.
	MaxTCPHandshakes int
	// LinkQueueLen is how many packets the stack holds for the device to write; a packet beyond it is dropped. 0 means 1024.
	LinkQueueLen int
}

// positive returns n, or def unless n is positive.
func positive(n, def int) int {
	if n > 0 {
		return n
	}
	return def
}

func (o Options) sessionQueueLen() int {
	return positive(o.SessionQueueLen, 128)
}

func (o Options) maxTCPHandshakes() int {
	return positive(o.MaxTCPHandshakes, 2048)
}

func (o Options) linkQueueLen() int {
	return positive(o.LinkQueueLen, 1024)
}

func (o Options) answerTimeout() time.Duration {
	return cmp.Or(o.AnswerTimeout, 30*time.Second)
}

func (o Options) keepAliveIdle() time.Duration {
	return cmp.Or(o.KeepAliveIdle, 60*time.Second)
}

func (o Options) maxUDPSessions() int {
	return cmp.Or(o.MaxUDPSessions, 4096)
}

func (o Options) maxICMPSessions() int {
	return cmp.Or(o.MaxICMPSessions, 1024)
}

func (o Options) keepAliveInterval() time.Duration {
	return cmp.Or(o.KeepAliveInterval, 15*time.Second)
}

// Serve hands each TCP connection, UDP flow and ICMP echo session arriving on dev to handler until ctx ends or reading dev fails, and always closes dev.
// A nil handler refuses every flow: TCP with a reset, UDP with ICMP port unreachable, ICMP echo with silence.
// Before returning it closes the conns still accepted and waits for every ServeFlow to return.
func Serve(ctx context.Context, dev wgtun.Device, handler flow.Handler, opts Options) error {
	// The event goroutines of a native device block once its Events buffer is full.
	stopEvents := make(chan struct{})
	var drain sync.WaitGroup
	drain.Go(func() { drainEvents(dev.Events(), stopEvents) })
	defer drain.Wait()
	defer close(stopEvents)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	g := &gateway{
		ctx:               runCtx,
		handler:           handler,
		answerTimeout:     opts.answerTimeout(),
		keepAliveIdle:     opts.keepAliveIdle(),
		keepAliveInterval: opts.keepAliveInterval(),
		udp:               sessions[netip.AddrPort]{max: opts.maxUDPSessions(), queue: opts.sessionQueueLen(), live: make(map[netip.AddrPort]*session)},
		icmp:              sessions[icmpKey]{max: opts.maxICMPSessions(), queue: opts.sessionQueueLen(), live: make(map[icmpKey]*session)},
	}
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
	handler flow.Handler
	s       *stack.Stack
	// answerTimeout is Options.AnswerTimeout with its default, read once.
	answerTimeout time.Duration
	// keepAliveIdle and keepAliveInterval are Options.KeepAliveIdle and Options.KeepAliveInterval with their defaults, read once.
	keepAliveIdle, keepAliveInterval time.Duration

	// clock ticks with every datagram of a session, either way, which keeps the tick as its active.
	clock atomic.Uint64

	mu      sync.Mutex
	stopped bool
	flows   sync.WaitGroup
	udp     sessions[netip.AddrPort] // by client endpoint
	icmp    sessions[icmpKey]
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

// stop refuses new flows and closes the live UDP and ICMP sessions, which have no endpoint for Close to abort.
func (g *gateway) stop() {
	g.mu.Lock()
	g.stopped = true
	live := slices.AppendSeq(slices.Collect(maps.Values(g.udp.live)), maps.Values(g.icmp.live))
	g.mu.Unlock()
	for _, c := range live {
		c.Close()
	}
}

// serve runs the handler on a flow counted in by start and ends the flow once it returns.
func (g *gateway) serve(f *capturedFlow) {
	defer g.flows.Done()
	defer f.end()
	ctx := g.ctx
	if f.answerTimeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		timer := time.AfterFunc(f.answerTimeout, func() { f.expire(cancel) })
		defer timer.Stop()
	}
	g.handler.ServeFlow(ctx, f)
}

var (
	errAcceptTwice    = errors.New("stack: flow already accepted")
	errAcceptRejected = errors.New("stack: flow already rejected")
)

// capturedFlow is a flow.Flow whose protocol supplies accept and reject, each called at most once.
type capturedFlow struct {
	network        string
	target, client netip.AddrPort
	accept         func() (net.Conn, error)
	reject         func()
	// answerTimeout, unless 0, is how long the flow may stay unanswered before it is rejected and its ctx ended.
	answerTimeout time.Duration

	mu       sync.Mutex
	answered bool
	conn     net.Conn
}

func (f *capturedFlow) Network() string        { return f.network }
func (f *capturedFlow) Target() netip.AddrPort { return f.target }
func (f *capturedFlow) Client() netip.AddrPort { return f.client }

func (f *capturedFlow) Accept() (net.Conn, error) {
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

func (f *capturedFlow) Reject() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.answered {
		f.answered = true
		f.reject()
	}
}

// expire rejects the flow unless an answer has begun, ending its ctx before the client learns of it.
func (f *capturedFlow) expire(cancel context.CancelFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.answered {
		f.answered = true
		cancel()
		f.reject()
	}
}

// end rejects the flow if unanswered and closes its accepted conn.
func (f *capturedFlow) end() {
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
	ep := channel.New(opts.linkQueueLen(), uint32(mtu), "")
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
	g.s = s
	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, g.handleICMP)
	s.SetTransportProtocolHandler(icmp.ProtocolNumber6, g.handleICMP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(s, 0, opts.maxTCPHandshakes(), g.forwardTCP).HandlePacket)
	// Without a handler UDP finds no endpoint, which the stack answers with ICMP port unreachable.
	if g.handler != nil {
		s.SetTransportProtocolHandler(udp.ProtocolNumber, g.handleUDP)
	}
	return s, ep, nil
}

func addrPort(addr tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return netip.AddrPortFrom(ip, port)
}

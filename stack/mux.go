package stack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
)

// Flow is a TCP connection or UDP session captured by Serve, not yet answered.
// A UDP session carries every datagram one client address and port sends, to any target, until its conn is closed or the flow rejected.
type Flow interface {
	// Network is "tcp" or "udp".
	Network() string
	// Target is the destination the client dialled; for udp the destination of the session's first datagram.
	Target() netip.AddrPort
	// Client is the flow's source.
	Client() netip.AddrPort
	// Accept answers the flow and returns its connection: for tcp it completes the handshake; for udp it is also a net.PacketConn whose ReadFrom returns each datagram, the first one already queued, with the target the client sent it to, and whose WriteTo sends one to the client from any address; Read and Write are its view connected to Target.
	// It may be called once; a second call, or one after Reject, returns an error.
	Accept() (net.Conn, error)
	// Reject refuses the flow: tcp resets the client, udp drops the session's datagrams without an ICMP error. After Accept it does nothing.
	Reject()
}

// Handler serves the flows Serve captures.
type Handler interface {
	// ServeFlow is called once per flow on its own goroutine, with a ctx that ends with Serve.
	// The flow is over once it returns: a flow neither accepted nor rejected is rejected, and an accepted conn still open is closed.
	ServeFlow(ctx context.Context, f Flow)
}

// HandlerFunc is a function serving as a Handler.
type HandlerFunc func(context.Context, Flow)

// ServeFlow calls h(ctx, f).
func (h HandlerFunc) ServeFlow(ctx context.Context, f Flow) { h(ctx, f) }

// Mux dispatches each flow to the handler registered for its network and destination port, else to its network's fallback, else rejects it.
// A UDP session goes by its first datagram's destination port, its handler then serving its datagrams to every target.
type Mux struct {
	mu       sync.RWMutex
	handlers map[muxKey]Handler
}

type muxKey struct {
	network string
	port    uint16
}

// NewMux returns an empty Mux, which rejects every flow.
func NewMux() *Mux {
	return &Mux{handlers: make(map[muxKey]Handler)}
}

// DefaultMux returns a Mux relaying every TCP connection and UDP flow through dialer, the DNS flows to UDP port 53 over TCP.
// A dialer that is also a ListenConfig relays UDP full cone, as Relay.ListenConfig; a wrapper around a dialer must forward Listen and ListenPacket to keep it.
func DefaultMux(dialer Dialer) *Mux {
	udp := &Relay{Dialer: dialer}
	if lc, ok := dialer.(ListenConfig); ok {
		udp.ListenConfig = lc
	}
	m := NewMux()
	m.Handle("tcp", 0, &Relay{Dialer: dialer})
	m.Handle("udp", 53, &DNS{Dialer: dialer})
	m.Handle("udp", 0, udp)
	return m
}

// Handle registers h for the flows of network, "tcp" or "udp", to port; port 0 registers the network's fallback.
// It panics on another network, a nil handler or a registration already made.
func (m *Mux) Handle(network string, port uint16, h Handler) {
	if network != "tcp" && network != "udp" {
		panic(fmt.Sprintf("stack: Mux.Handle of network %q, want tcp or udp", network))
	}
	if h == nil {
		panic(fmt.Sprintf("stack: Mux.Handle of a nil handler for %s/%d", network, port))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := muxKey{network, port}
	if _, ok := m.handlers[key]; ok {
		panic(fmt.Sprintf("stack: Mux.Handle of %s/%d registered twice", network, port))
	}
	m.handlers[key] = h
}

// ServeFlow hands f to the handler for its network and port, else to its network's fallback, else rejects it.
func (m *Mux) ServeFlow(ctx context.Context, f Flow) {
	if h := m.handler(f.Network(), f.Target().Port()); h != nil {
		h.ServeFlow(ctx, f)
		return
	}
	f.Reject()
}

func (m *Mux) handler(network string, port uint16) Handler {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if h, ok := m.handlers[muxKey{network, port}]; ok {
		return h
	}
	return m.handlers[muxKey{network, 0}]
}

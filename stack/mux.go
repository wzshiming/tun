package stack

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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

// Mux dispatches each flow by its network and destination to the handler whose pattern matches it, else to Fallback, else rejects it.
// A UDP session goes by its first datagram's destination, its handler then serving its datagrams to every target.
//
// A pattern is "" for any address and port, host for that host and any port, host:port, or :port for any address and that port.
// host is an IP address or a CIDR prefix, its host bits masked off, IPv6 in brackets when a port follows; an IPv4-mapped IPv6 address, or prefix of /96 or longer, is taken as IPv4; a zone is rejected.
// Port 0 means any port.
//
// The registered hosts form layers, longest prefix first, an address being a full-length prefix, and the any-address layer last.
// A flow goes to the first layer containing its destination address, of its family, with a handler for its port or for any port; one with neither passes the flow on to the next layer.
//
// A Mux is a Handler, so one can serve a layer of another; it then dispatches with its own patterns and Fallback, never handing a flow back to the outer Mux.
type Mux struct {
	// Fallback serves the flows no pattern matches; nil rejects them. Set it before the Mux serves flows.
	Fallback Handler

	mu       sync.RWMutex
	handlers map[muxRoute]Handler
	// layers holds each network's registered prefixes, longest first; the any-address layer, the zero Prefix, is not in it.
	layers map[string][]netip.Prefix
}

type muxRoute struct {
	network string
	prefix  netip.Prefix
	port    uint16
}

// NewMux returns an empty Mux, which rejects every flow.
func NewMux() *Mux {
	return &Mux{handlers: make(map[muxRoute]Handler), layers: make(map[string][]netip.Prefix)}
}

// DefaultMux returns a Mux relaying every TCP connection and UDP flow through dialer, with a Relay for each network.
// A dialer that is also a ListenConfig relays UDP full cone, as Relay.ListenConfig; a wrapper around a dialer must forward Listen and ListenPacket to keep it.
func DefaultMux(dialer Dialer) *Mux {
	udp := &Relay{Dialer: dialer}
	if lc, ok := dialer.(ListenConfig); ok {
		udp.ListenConfig = lc
	}
	m := NewMux()
	m.Handle("tcp", "", &Relay{Dialer: dialer})
	m.Handle("udp", "", udp)
	return m
}

// Handle registers h for the flows of network, "tcp" or "udp", whose destination matches pattern.
// It panics on another network, a nil handler, an invalid pattern or one already registered for network.
func (m *Mux) Handle(network, pattern string, h Handler) {
	if network != "tcp" && network != "udp" {
		panic(fmt.Sprintf("stack: Mux.Handle of network %q, want tcp or udp", network))
	}
	if h == nil {
		panic(fmt.Sprintf("stack: Mux.Handle of a nil handler for %s %q", network, pattern))
	}
	prefix, port, err := parseMuxPattern(pattern)
	if err != nil {
		panic(fmt.Sprintf("stack: Mux.Handle of %s pattern %q: %v", network, pattern, err))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	route := muxRoute{network, prefix, port}
	if _, ok := m.handlers[route]; ok {
		panic(fmt.Sprintf("stack: Mux.Handle of %s pattern %q registered twice", network, pattern))
	}
	m.handlers[route] = h
	layers := m.layers[network]
	if prefix.IsValid() && !slices.Contains(layers, prefix) {
		i := slices.IndexFunc(layers, func(p netip.Prefix) bool { return p.Bits() < prefix.Bits() })
		if i < 0 {
			i = len(layers)
		}
		m.layers[network] = slices.Insert(layers, i, prefix)
	}
}

// parseMuxPattern returns pattern's masked prefix, the zero Prefix for any address, and its port, 0 for any port.
func parseMuxPattern(pattern string) (netip.Prefix, uint16, error) {
	if pattern == "" {
		return netip.Prefix{}, 0, nil
	}
	whole := pattern
	if strings.HasPrefix(whole, "[") && strings.HasSuffix(whole, "]") {
		whole = whole[1 : len(whole)-1]
	}
	prefix, hostErr := parseMuxHost(whole)
	if hostErr == nil {
		return prefix, 0, nil
	}
	host, portText, err := net.SplitHostPort(pattern)
	if err != nil {
		return netip.Prefix{}, 0, hostErr
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("port %q: want 0 to 65535", portText)
	}
	if host == "" {
		return netip.Prefix{}, uint16(port), nil
	}
	prefix, err = parseMuxHost(host)
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	return prefix, uint16(port), nil
}

// parseMuxHost parses an IP address as its full-length prefix, or a CIDR prefix masked, an IPv4-mapped one as IPv4.
func parseMuxHost(host string) (netip.Prefix, error) {
	if strings.Contains(host, "/") {
		prefix, err := netip.ParsePrefix(host)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Checked before masking, which clears the ::ffff marker of a prefix shorter than /96.
		if addr := prefix.Addr(); addr.Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %s shorter than /96", prefix)
			}
			prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Prefix{}, err
	}
	if addr.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("address %s has zone %q", addr, addr.Zone())
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ServeFlow hands f to the handler its network and target match, else to Fallback, else rejects it.
func (m *Mux) ServeFlow(ctx context.Context, f Flow) {
	if h := m.handler(f.Network(), f.Target()); h != nil {
		h.ServeFlow(ctx, f)
		return
	}
	if m.Fallback != nil {
		m.Fallback.ServeFlow(ctx, f)
		return
	}
	f.Reject()
}

func (m *Mux) handler(network string, target netip.AddrPort) Handler {
	addr, port := target.Addr().Unmap(), target.Port()
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, prefix := range m.layers[network] {
		if prefix.Contains(addr) {
			if h := m.layerHandler(network, prefix, port); h != nil {
				return h
			}
		}
	}
	return m.layerHandler(network, netip.Prefix{}, port)
}

// layerHandler returns the handler of network's layer prefix for port, else for any port.
func (m *Mux) layerHandler(network string, prefix netip.Prefix, port uint16) Handler {
	if h, ok := m.handlers[muxRoute{network, prefix, port}]; ok {
		return h
	}
	return m.handlers[muxRoute{network, prefix, 0}]
}

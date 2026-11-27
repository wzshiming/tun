// Package flow holds what the flows a TUN captures are served with: the Flow that stack.Serve hands a Handler, the Mux that dispatches flows by network and destination, the Listener that turns them into the conns of a net.Listener, and the Dialer and ListenConfig the handlers reach their targets through.
// It depends on the standard library alone, so a handler needs no network stack to be written or tested.
package flow

import (
	"context"
	"net"
	"net/netip"
)

// Flow is a TCP connection, UDP session or ICMP echo session captured by stack.Serve, not yet answered.
// A UDP session carries every datagram one client address and port sends, to any target, until its conn is closed or the flow rejected.
// An ICMP session carries the echo requests, IPv4 or IPv6, one client address sends to one target under one identifier, until its conn is closed or the flow rejected.
type Flow interface {
	// Network is "tcp", "udp" or "icmp".
	Network() string
	// Target is the destination the client dialled; for udp the destination of the session's first datagram; for icmp the address pinged, with port 0.
	Target() netip.AddrPort
	// Client is the flow's source; for icmp its port is the echo identifier.
	Client() netip.AddrPort
	// Accept answers the flow and returns its connection: for tcp it completes the handshake; for udp it is also a net.PacketConn whose ReadFrom returns each datagram, the first one already queued, with the target the client sent it to, and whose WriteTo sends one to the client from any address; Read and Write are its view connected to Target; for icmp Read returns each echo request, the first one already queued, as the ICMP message from its type byte on, and Write sends such a message, an echo reply, to the client from Target, with the session's identifier and a fresh checksum in place of its own.
	// It may be called once; a second call, or one after Reject, returns an error.
	Accept() (net.Conn, error)
	// Reject refuses the flow: tcp resets the client, udp drops the session's datagrams without an ICMP error, icmp leaves its echo requests unanswered. After Accept it does nothing.
	Reject()
}

// Handler serves the flows stack.Serve captures.
type Handler interface {
	// ServeFlow is called once per flow on its own goroutine, with a ctx that ends with stack.Serve, and for a tcp flow also once that rejects it as left unanswered for stack.Options.AnswerTimeout.
	// The flow is over once it returns: a flow neither accepted nor rejected is rejected, and an accepted conn still open is closed.
	ServeFlow(ctx context.Context, f Flow)
}

// HandlerFunc is a function serving as a Handler.
type HandlerFunc func(context.Context, Flow)

// ServeFlow calls h(ctx, f).
func (h HandlerFunc) ServeFlow(ctx context.Context, f Flow) { h(ctx, f) }

// RejectHandler returns a handler that rejects every flow, as Flow.Reject does: a TCP connection is reset, a UDP session's datagrams and an ICMP session's echo requests are dropped unanswered.
// Mounted on a Mux, it refuses the flows of its pattern which a wider one would serve, e.g. m.Handle("udp", ":443", flow.RejectHandler()) leaves a client without QUIC to fall back to TCP.
func RejectHandler() Handler {
	return HandlerFunc(func(_ context.Context, f Flow) { f.Reject() })
}

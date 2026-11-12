// Package dns serves the DNS queries of a UDP session over TCP, each datagram a length-framed message, so DNS keeps working through a proxy that only carries TCP.
// Mount its Handler on a stack.Mux for the "udp" network at the DNS port, e.g. m.Handle("udp", ":53", &dns.Handler{Dialer: d}); the package registers nothing itself.
package dns

import (
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/wzshiming/tun/stack"
)

var _ stack.Handler = (*Handler)(nil)

// Handler serves a UDP session by relaying the datagrams it sends to each server as length-framed messages over one TCP connection per server, dialled through Dialer, and the replies back from that server; it rejects other flows.
type Handler struct {
	Dialer stack.Dialer
	// Target, when set, is the host:port every TCP connection dials instead of the server the client addressed; replies still come back from that server. Empty dials the addressed server.
	Target string
	// Idle ends a session after this long without datagrams either way to any server; 0 means 10s.
	Idle time.Duration
}

// ServeFlow relays f until it idles, its conn fails or ctx ends, and then closes the session and every TCP conn.
// A server whose dial or TCP conn fails loses only its own datagrams; its next one dials again.
func (h *Handler) ServeFlow(ctx context.Context, f stack.Flow) {
	if f.Network() != "udp" {
		f.Reject()
		return
	}
	(&stack.Relay{Dialer: frameDialer{h.Dialer, h.Target}, Idle: cmp.Or(h.Idle, 10*time.Second)}).ServeFlow(ctx, f)
}

// frameDialer turns the "udp" dials of a stack.Relay into "tcp" dials, to target if set, of length-framed conns.
type frameDialer struct {
	dialer stack.Dialer
	target string
}

func (d frameDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, "tcp", cmp.Or(d.target, address))
	if err != nil {
		return nil, err
	}
	return frameConn{conn}, nil
}

// frameConn carries each Write as one message prefixed with its 2-byte big-endian length, and each Read returns one such message.
type frameConn struct {
	net.Conn
}

func (c frameConn) Write(message []byte) (int, error) {
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(message)), uint16(len(message)))
	if _, err := c.Conn.Write(append(frame, message...)); err != nil {
		return 0, err
	}
	return len(message), nil
}

// Read needs b to hold any message, 65535 bytes, as stack.Relay's buffer does.
func (c frameConn) Read(b []byte) (int, error) {
	var size [2]byte
	if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
		return 0, err
	}
	return io.ReadFull(c.Conn, b[:binary.BigEndian.Uint16(size[:])])
}

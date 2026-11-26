// Package dns serves the DNS queries of a UDP session over TCP, each datagram a length-framed message, so DNS keeps working through a proxy that only carries TCP.
// Mount its Handler on a stack.Mux for the "udp" network at the DNS port, e.g. m.Handle("udp", ":53", &dns.Handler{Dialer: d}); the package registers nothing itself.
package dns

import (
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wzshiming/tun/stack"
	"github.com/wzshiming/tun/stack/udp"
)

var _ stack.Handler = (*Handler)(nil)

// Handler serves a UDP session by relaying the datagrams it sends to each server as length-framed messages over one TCP connection per server, dialled through Dialer and given Idle to connect, and the replies back from that server; a DNS query that an earlier reply still answers is answered from a cache all its sessions share, and one that a failed connection left unanswered is sent once more on a new one; it rejects other flows.
type Handler struct {
	Dialer stack.Dialer
	// Target, when set, is the host:port every TCP connection dials instead of the server the client addressed; replies still come back from that server. Empty dials the addressed server.
	Target string
	// Idle ends a session after this long without datagrams either way to any server, and a TCP dial not back within it is abandoned; 0 means 10s.
	Idle time.Duration
	// CacheSize is the most replies the cache keeps to answer later DNS queries with; 0 means 4096, a negative value disables the cache.
	CacheSize int

	// sized guards the one copy of CacheSize into cache, which the first session makes.
	sized sync.Once
	cache cache
}

// answers returns the cache of h, sized by CacheSize.
func (h *Handler) answers() *cache {
	h.sized.Do(func() { h.cache.size = h.CacheSize })
	return &h.cache
}

// ServeFlow relays f until it idles, its conn fails or ctx ends, and then closes the session and every TCP conn.
// A server whose dial or TCP conn fails loses only its own datagrams; its next one dials again.
func (h *Handler) ServeFlow(ctx context.Context, f stack.Flow) {
	if f.Network() != "udp" {
		f.Reject()
		return
	}
	idle := cmp.Or(h.Idle, 10*time.Second)
	(&udp.Handler{Dialer: upstreamDialer{h.Dialer, h.Target, idle, h.answers()}, Idle: idle}).ServeFlow(ctx, f)
}

// frameConn carries each Write as one message prefixed with its 2-byte big-endian length, and each Read returns one such message; only its first Close closes the conn, and with it ends the ctx of its dial.
type frameConn struct {
	net.Conn
	release context.CancelFunc
	closing sync.Once
}

func (c *frameConn) Write(message []byte) (int, error) {
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(message)), uint16(len(message)))
	if _, err := c.Conn.Write(append(frame, message...)); err != nil {
		return 0, err
	}
	return len(message), nil
}

// Read needs b to hold any message, 65535 bytes, as the buffer of upstream.receive does.
func (c *frameConn) Read(b []byte) (int, error) {
	var size [2]byte
	if _, err := io.ReadFull(c.Conn, size[:]); err != nil {
		return 0, err
	}
	return io.ReadFull(c.Conn, b[:binary.BigEndian.Uint16(size[:])])
}

func (c *frameConn) Close() error {
	c.closing.Do(func() {
		c.Conn.Close()
		c.release()
	})
	return nil
}

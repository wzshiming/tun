package stacktest

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Session is a double of the conn a "udp" flow's Accept returns.
// The handler reads with ReadFrom what the test sends with Send, and the test takes with NextReply what the handler writes with WriteTo.
type Session struct {
	client, target netip.AddrPort
	sent, replies  queue
	closed         chan struct{}
	closeOnce      sync.Once
}

// NewSession returns an open session of client whose flow's target is target.
func NewSession(client, target netip.AddrPort) *Session {
	return &Session{
		client:  client,
		target:  target,
		sent:    queue{ready: make(chan struct{})},
		replies: queue{ready: make(chan struct{})},
		closed:  make(chan struct{}),
	}
}

// Send queues b as a datagram the client sends to to; it never blocks.
func (s *Session) Send(b []byte, to netip.AddrPort) {
	s.sent.push(datagram{bytes.Clone(b), to})
}

// NextReply returns the oldest datagram not yet taken that WriteTo delivered and its source, an IPv4-mapped one as IPv4, waiting up to wait for one; ok is false if none came.
func (s *Session) NextReply(wait time.Duration) (b []byte, from netip.AddrPort, ok bool) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		d, ready, ok := s.replies.pop()
		if ok {
			return d.data, d.addr, true
		}
		select {
		case <-ready:
		case <-timer.C:
			return nil, netip.AddrPort{}, false
		}
	}
}

// Closed reports whether Close was called.
func (s *Session) Closed() bool {
	select {
	case <-s.closed:
		return true
	default:
		return false
	}
}

// ReadFrom returns the oldest datagram Send queued and its destination as a *net.UDPAddr, blocking until there is one; once the session is closed it returns net.ErrClosed, even with datagrams queued.
func (s *Session) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		select {
		case <-s.closed:
			return 0, nil, net.ErrClosed
		default:
		}
		d, ready, ok := s.sent.pop()
		if ok {
			return copy(b, d.data), net.UDPAddrFromAddrPort(d.addr), nil
		}
		select {
		case <-ready:
		case <-s.closed:
			return 0, nil, net.ErrClosed
		}
	}
}

// WriteTo delivers b to the client as a datagram from addr, which must be a *net.UDPAddr; it never blocks.
func (s *Session) WriteTo(b []byte, addr net.Addr) (int, error) {
	src, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("stacktest: write udp from %v: not a *net.UDPAddr", addr)
	}
	if s.Closed() {
		return 0, net.ErrClosed
	}
	from := src.AddrPort()
	s.replies.push(datagram{bytes.Clone(b), netip.AddrPortFrom(from.Addr().Unmap(), from.Port())})
	return len(b), nil
}

// Close ends the session; it may be called more than once.
func (s *Session) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

// LocalAddr is the flow's target.
func (s *Session) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(s.target) }

// RemoteAddr is the client.
func (s *Session) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(s.client) }

// Read is not supported.
func (s *Session) Read([]byte) (int, error) { return 0, errors.ErrUnsupported }

// Write is not supported.
func (s *Session) Write([]byte) (int, error) { return 0, errors.ErrUnsupported }

// SetDeadline is not supported.
func (s *Session) SetDeadline(time.Time) error { return errors.ErrUnsupported }

// SetReadDeadline is not supported.
func (s *Session) SetReadDeadline(time.Time) error { return errors.ErrUnsupported }

// SetWriteDeadline is not supported.
func (s *Session) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }

// datagram is a payload and the address it was sent to or from.
type datagram struct {
	data []byte
	addr netip.AddrPort
}

// queue is an unbounded FIFO of datagrams whose ready channel is closed and replaced on every push.
type queue struct {
	mu    sync.Mutex
	items []datagram
	ready chan struct{}
}

func (q *queue) push(d datagram) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, d)
	close(q.ready)
	q.ready = make(chan struct{})
}

// pop removes the oldest datagram; with none, ok is false and ready is closed by the next push.
func (q *queue) pop() (d datagram, ready <-chan struct{}, ok bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return datagram{}, q.ready, false
	}
	d = q.items[0]
	q.items = q.items[1:]
	return d, nil, true
}

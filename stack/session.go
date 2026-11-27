package stack

import (
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// datagram is one UDP payload or ICMP message and, for UDP, the destination its client addressed.
type datagram struct {
	payload []byte
	target  netip.AddrPort
}

// session is the side of a UDP or ICMP session its protocol shares: the datagrams queued for the handler, the read deadline, and the end.
type session struct {
	queue        chan datagram
	readDeadline deadline
	closed       chan struct{}
	closeOnce    sync.Once
	onClose      func()
	// active is the tick of the gateway's clock at the session's last datagram, either way.
	active atomic.Uint64
	clock  *atomic.Uint64
}

// touch marks the session as the one most recently active.
func (c *session) touch() { c.active.Store(c.clock.Add(1)) }

// next returns the next datagram; a closed session or a passed deadline fails it even with datagrams queued.
func (c *session) next() (datagram, error) {
	select {
	case <-c.closed:
		return datagram{}, net.ErrClosed
	default:
	}
	select {
	case <-c.readDeadline.wait():
		return datagram{}, os.ErrDeadlineExceeded
	default:
	}
	select {
	case d := <-c.queue:
		return d, nil
	case <-c.closed:
		return datagram{}, net.ErrClosed
	case <-c.readDeadline.wait():
		return datagram{}, os.ErrDeadlineExceeded
	}
}

// isClosed reports whether Close was called.
func (c *session) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

// Close ends the session; the client's next datagram starts a new one.
func (c *session) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.onClose()
	})
	return nil
}

func (c *session) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }

func (c *session) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

// SetWriteDeadline does nothing, as writes never block.
func (c *session) SetWriteDeadline(time.Time) error { return nil }

// sessions are one protocol's live sessions by key; the gateway's mu guards live.
type sessions[K comparable] struct {
	// max is how many may be live at once; negative means no limit.
	max int
	// queue is how many datagrams each session holds for its handler.
	queue int
	live  map[K]*session
}

// open starts the session of key and returns it with the one it ended to stay within max, if any: the one whose last datagram is the oldest, which the caller closes once it released mu.
// The caller holds mu, which guards t.live. Finding the idlest looks at every session, which only a key beyond the limit pays for.
func (t *sessions[K]) open(mu *sync.Mutex, clock *atomic.Uint64, key K) (c, evicted *session) {
	if t.max > 0 && len(t.live) >= t.max {
		var idlest K
		for k, s := range t.live {
			if evicted == nil || s.active.Load() < evicted.active.Load() {
				idlest, evicted = k, s
			}
		}
		delete(t.live, idlest)
	}
	c = &session{
		queue:        make(chan datagram, t.queue),
		readDeadline: deadline{passed: make(chan struct{})},
		closed:       make(chan struct{}),
		clock:        clock,
	}
	c.onClose = func() {
		mu.Lock()
		defer mu.Unlock()
		if t.live[key] == c {
			delete(t.live, key)
		}
	}
	t.live[key] = c
	return c, evicted
}

// deliver queues d on c for its handler, dropping it if the queue is full.
func (c *session) deliver(d datagram) {
	c.touch()
	select {
	case c.queue <- d:
	default:
	}
}

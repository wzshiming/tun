// Package udp relays the datagrams of a UDP session to their targets and the replies back to the client, in one of two ways, each a handler of its own.
// Handler dials a conn per target, so it works through any stack.Dialer, a proxy's included, and a target only reaches the client on the conn the client's datagrams to it opened.
// Cone sends from one socket of its own, full cone: to every target, delivering what any source sends back.
// Mount either on a stack.Mux for the "udp" network, e.g. m.Handle("udp", "", &udp.Cone{ListenConfig: lc}); the package registers nothing itself.
package udp

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/wzshiming/tun/stack"
)

var (
	_ stack.Handler = (*Handler)(nil)
	_ stack.Handler = (*Cone)(nil)
)

// defaultIdle is how long a session of either handler may idle unless its Idle says otherwise.
const defaultIdle = 60 * time.Second

// Handler serves a UDP session by relaying its datagrams to their targets, each through a conn of its own, and the replies back to the client; it rejects other flows.
type Handler struct {
	// Dialer dials a "udp" conn per target.
	Dialer stack.Dialer
	// Idle ends a session after this long without datagrams either way to any target; 0 means 60s.
	Idle time.Duration
}

// ServeFlow accepts a UDP session and relays it until it idles, its conn fails or ctx ends, and then closes the session and every dialled conn.
// Each target it sends to gets its own dialled conn, its datagrams relayed one for one and the replies sent back from that target; a failed dial or conn drops that target's datagrams until the next one dials again.
// It uses such a dialled conn as a datagram conn: one Write per datagram, each Read taken as one reply into a buffer that holds any datagram, 65535 bytes, and Close; it calls no other method.
func (h *Handler) ServeFlow(ctx context.Context, f stack.Flow) {
	if f.Network() != "udp" {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	ctx = stack.WithClientAddr(ctx, net.UDPAddrFromAddrPort(f.Client()))
	relaySession(ctx, conn, h.idle(), func(target string) (net.Conn, error) { return h.Dialer.DialContext(ctx, "udp", target) })
}

func (h *Handler) idle() time.Duration {
	return cmp.Or(h.Idle, defaultIdle)
}

// afterIdle calls onIdle once d passes without a touch; stop cancels it.
func afterIdle(d time.Duration, onIdle func()) (touch func(), stop func() bool) {
	timer := time.AfterFunc(d, onIdle)
	return func() { timer.Reset(d) }, timer.Stop
}

// Cone serves a UDP session full cone, relaying its datagrams to every target through one socket and what any source sends that socket back to the client; it rejects other flows.
type Cone struct {
	// ListenConfig opens each session's socket with ListenPacket.
	ListenConfig stack.ListenConfig
	// Idle ends a session after this long without datagrams either way; 0 means 60s.
	Idle time.Duration
}

// ServeFlow accepts a UDP session and relays it until it idles, its conn or socket fails or ctx ends, and then closes both.
// It listens on one "udp4" or "udp6" socket, by the client's family, which sends the session's datagrams to their targets and returns every datagram it receives from its source; a failed listen ends the session.
func (h *Cone) ServeFlow(ctx context.Context, f stack.Flow) {
	if f.Network() != "udp" {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	session, ok := conn.(net.PacketConn)
	if !ok {
		return
	}
	client := f.Client()
	network := "udp6"
	if client.Addr().Unmap().Is4() {
		network = "udp4"
	}
	remote, err := h.ListenConfig.ListenPacket(stack.WithClientAddr(ctx, net.UDPAddrFromAddrPort(client)), network, ":0")
	if err != nil {
		return
	}
	end := sync.OnceFunc(func() {
		conn.Close()
		remote.Close()
	})
	stop := context.AfterFunc(ctx, end)
	defer stop()
	touch, stopIdle := afterIdle(cmp.Or(h.Idle, defaultIdle), end)
	defer stopIdle()
	var replies sync.WaitGroup
	replies.Go(func() {
		defer end()
		relayPackets(remote, session, touch)
	})
	relayPackets(session, remote, touch)
	end()
	replies.Wait()
}

// relayPackets writes every datagram read from src to dst, addressed as src reported it, until src fails or dst is closed; a datagram dst refuses is dropped.
func relayPackets(src, dst net.PacketConn, touch func()) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := src.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := dst.WriteTo(buf[:n], addr); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		touch()
	}
}

// relayQueueLen is how many datagrams a target holds while it dials or sends; more are dropped.
const relayQueueLen = 64

// relaySession sends each datagram of conn, a UDP session's, to the remote dial opened for its target on the target's first datagram, and each remote's replies back from its target, until conn fails, ctx ends or idle passes without a datagram either way; it then closes conn and every remote.
// Each target dials and sends on its own goroutine, so a slow one delays no other; a remote failing to dial, send or receive is dropped alone, and its target's next datagram dials again.
func relaySession(ctx context.Context, conn net.Conn, idle time.Duration, dial func(target string) (net.Conn, error)) {
	pc, ok := conn.(net.PacketConn)
	if !ok {
		return
	}
	s := &sessionRelay{conn: pc, dial: dial, targets: make(map[netip.AddrPort]*sessionTarget)}
	stop := context.AfterFunc(ctx, s.end)
	defer stop()
	touch, stopIdle := afterIdle(idle, s.end)
	defer stopIdle()
	s.touch = touch
	s.relayQueries()
	s.end()
	s.workers.Wait()
}

type sessionRelay struct {
	conn  net.PacketConn
	dial  func(target string) (net.Conn, error)
	touch func()

	mu      sync.Mutex
	ended   bool
	targets map[netip.AddrPort]*sessionTarget
	workers sync.WaitGroup
}

// sessionTarget is one target of a session: the datagrams queued for it and, once dialled, its remote.
type sessionTarget struct {
	queue chan []byte
	// done is closed when the target is dropped; remote and closed are guarded by sessionRelay.mu.
	done   chan struct{}
	remote net.Conn
	closed bool
}

func (s *sessionRelay) relayQueries() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		tg := s.target(udpAddr.AddrPort())
		if tg == nil {
			return
		}
		select {
		case tg.queue <- bytes.Clone(buf[:n]):
		default:
		}
	}
}

// target returns the session's target at addr, starting it if new; nil once the session ended.
func (s *sessionRelay) target(addr netip.AddrPort) *sessionTarget {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return nil
	}
	if tg, ok := s.targets[addr]; ok {
		return tg
	}
	tg := &sessionTarget{queue: make(chan []byte, relayQueueLen), done: make(chan struct{})}
	s.targets[addr] = tg
	s.workers.Go(func() { s.relayTarget(addr, tg) })
	return tg
}

// relayTarget dials tg's remote and sends it tg's queued datagrams until tg is dropped.
func (s *sessionRelay) relayTarget(addr netip.AddrPort, tg *sessionTarget) {
	remote, err := s.dial(addr.String())
	if err != nil {
		s.drop(addr, tg)
		return
	}
	if !s.attach(tg, remote) {
		remote.Close()
		return
	}
	s.workers.Go(func() { s.relayReplies(addr, tg, remote) })
	for {
		select {
		case datagram := <-tg.queue:
			if _, err := remote.Write(datagram); err != nil {
				s.drop(addr, tg)
				return
			}
			s.touch()
		case <-tg.done:
			return
		}
	}
}

// attach gives tg its remote, unless tg was dropped meanwhile.
func (s *sessionRelay) attach(tg *sessionTarget, remote net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tg.closed {
		return false
	}
	tg.remote = remote
	return true
}

func (s *sessionRelay) relayReplies(addr netip.AddrPort, tg *sessionTarget, remote net.Conn) {
	defer s.drop(addr, tg)
	src := net.UDPAddrFromAddrPort(addr)
	buf := make([]byte, 65535)
	for {
		n, err := remote.Read(buf)
		if err != nil {
			return
		}
		if _, err := s.conn.WriteTo(buf[:n], src); err != nil {
			return
		}
		s.touch()
	}
}

func (s *sessionRelay) drop(addr netip.AddrPort, tg *sessionTarget) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.targets[addr] == tg {
		delete(s.targets, addr)
	}
	tg.close()
}

// close stops tg and closes its remote; the caller holds sessionRelay.mu.
func (tg *sessionTarget) close() {
	if tg.closed {
		return
	}
	tg.closed = true
	close(tg.done)
	if tg.remote != nil {
		tg.remote.Close()
	}
}

func (s *sessionRelay) end() {
	s.conn.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ended = true
	for _, tg := range s.targets {
		tg.close()
	}
	s.targets = nil
}

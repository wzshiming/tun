package stack

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Relay serves a flow by dialing its target through Dialer, on the flow's network, and passing the two connections' data into each other.
type Relay struct {
	Dialer Dialer
	// Idle ends a UDP session after this long without datagrams either way to any target; 0 means 60s.
	Idle time.Duration
}

// ServeFlow dials a TCP flow's target before accepting, so a failed dial resets the client, then passes half-closes on and ends with ctx.
// A UDP session is accepted first and each target it sends to gets its own dialled conn, its datagrams relayed one for one and the replies sent back from that target; a failed dial or conn drops that target's datagrams until the next one dials again.
func (r *Relay) ServeFlow(ctx context.Context, f Flow) {
	if f.Network() == "udp" {
		r.serveUDP(ctx, f)
		return
	}
	remote, err := r.Dialer.DialContext(WithClientAddr(ctx, net.TCPAddrFromAddrPort(f.Client())), "tcp", f.Target().String())
	if err != nil {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		remote.Close()
		return
	}
	tunnel(ctx, conn, remote)
}

func (r *Relay) serveUDP(ctx context.Context, f Flow) {
	conn, err := f.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	ctx = WithClientAddr(ctx, net.UDPAddrFromAddrPort(f.Client()))
	relaySession(ctx, conn, r.idle(),
		func(target string) (net.Conn, error) { return r.Dialer.DialContext(ctx, "udp", target) },
		func(remote net.Conn, datagram []byte) error {
			_, err := remote.Write(datagram)
			return err
		},
		func(remote net.Conn, buf []byte) ([]byte, error) {
			n, err := remote.Read(buf)
			return buf[:n], err
		})
}

func (r *Relay) idle() time.Duration {
	return cmp.Or(r.Idle, 60*time.Second)
}

// relaySession sends each datagram of conn, a UDP session's, to the remote dial opened for its target on the target's first datagram, and each remote's replies back from its target, until conn fails, ctx ends or idle passes without a datagram either way; it then closes conn and every remote.
// A remote failing to dial, send or receive is dropped alone, and its target's next datagram dials again.
func relaySession(ctx context.Context, conn net.Conn, idle time.Duration, dial func(target string) (net.Conn, error), send func(remote net.Conn, datagram []byte) error, recv func(remote net.Conn, buf []byte) ([]byte, error)) {
	pc, ok := conn.(net.PacketConn)
	if !ok {
		return
	}
	s := &sessionRelay{conn: pc, dial: dial, send: send, recv: recv, remotes: make(map[netip.AddrPort]net.Conn)}
	stop := context.AfterFunc(ctx, s.end)
	defer stop()
	touch, stopIdle := afterIdle(idle, s.end)
	defer stopIdle()
	s.touch = touch
	s.relayQueries()
	s.end()
	s.replies.Wait()
}

type sessionRelay struct {
	conn  net.PacketConn
	dial  func(target string) (net.Conn, error)
	send  func(remote net.Conn, datagram []byte) error
	recv  func(remote net.Conn, buf []byte) ([]byte, error)
	touch func()

	mu      sync.Mutex
	ended   bool
	remotes map[netip.AddrPort]net.Conn
	replies sync.WaitGroup
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
		target := udpAddr.AddrPort()
		remote := s.remote(target)
		if remote == nil {
			continue
		}
		if err := s.send(remote, buf[:n]); err != nil {
			s.drop(target, remote)
			continue
		}
		s.touch()
	}
}

// remote returns target's remote, dialling it first if none is open; nil if the dial failed or the session ended.
func (s *sessionRelay) remote(target netip.AddrPort) net.Conn {
	s.mu.Lock()
	remote, ok := s.remotes[target]
	s.mu.Unlock()
	if ok {
		return remote
	}
	remote, err := s.dial(target.String())
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		remote.Close()
		return nil
	}
	s.remotes[target] = remote
	s.replies.Go(func() { s.relayReplies(target, remote) })
	return remote
}

func (s *sessionRelay) relayReplies(target netip.AddrPort, remote net.Conn) {
	defer s.drop(target, remote)
	src := net.UDPAddrFromAddrPort(target)
	buf := make([]byte, 65535)
	for {
		reply, err := s.recv(remote, buf)
		if err != nil {
			return
		}
		if _, err := s.conn.WriteTo(reply, src); err != nil {
			return
		}
		s.touch()
	}
}

func (s *sessionRelay) drop(target netip.AddrPort, remote net.Conn) {
	s.mu.Lock()
	if s.remotes[target] == remote {
		delete(s.remotes, target)
	}
	s.mu.Unlock()
	remote.Close()
}

func (s *sessionRelay) end() {
	s.conn.Close()
	s.mu.Lock()
	s.ended = true
	remotes := s.remotes
	s.remotes = nil
	s.mu.Unlock()
	for _, remote := range remotes {
		remote.Close()
	}
}

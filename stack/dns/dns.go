// Package dns is a mirror DNS server: it answers the DNS queries of the conns it serves, over UDP and over TCP, with what the upstream DNS server answers, which it asks over TCP so that DNS keeps working through a proxy that only carries TCP, and keeps to answer later queries itself, also while the upstream is down.
// Its Handler serves the conns of a net.Listener, which a flow.Listener mounted on a flow.Mux for both networks at the DNS port gives it, e.g. l := flow.NewListener(); m.Handle("udp", ":53", l); m.Handle("tcp", ":53", l); go h.Serve(l); the package registers nothing itself.
package dns

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wzshiming/tun/flow"
)

// Handler serves a UDP session or a TCP conn as a DNS server that mirrors its upstream: every DNS query a client sends gets the answer of the upstream, which is the servers of Upstreams or else the server the client addressed, asked over TCP conns dialled through Dialer that all flows share.
// The replies are kept in a cache all flows share, and a query a kept reply answers is answered from it at once: within the lifetime the TTLs of the reply give it without asking upstream, and for Stale after with TTLs of 0, the upstream then being asked for a new reply once the client has its answer, so that a mirror whose upstream is down goes on answering what it has.
// A query no kept reply answers goes upstream, once for the clients asking the same at once, is sent once more on a new conn if a failed one left it unanswered, and is answered with SERVFAIL if the upstream does not answer.
// A reply too long for the client's UDP payload size, 512 bytes unless its OPT record tells more, is sent truncated, for the client to ask again over TCP.
// Any other request is refused without asking upstream: a zone transfer, which takes more than one reply, with REFUSED, another opcode with NOTIMP, and a query of not exactly one question, or that does not parse, with FORMERR.
type Handler struct {
	Dialer flow.Dialer
	// Upstreams, when set, are the host:port of the DNS servers mirrored, as one, for every query, whichever server the client addressed; replies still come back from that server. Empty mirrors each addressed server.
	// A query goes to the first of them, and on to the next when one fails: when it cannot be dialled, does not answer within its share of Idle, which the servers not yet asked split evenly, or answers SERVFAIL; the reply of the last one asked stands.
	// A server that failed to answer is asked after the others for the FailedFor that follows. Set them before the Handler serves flows.
	Upstreams []string
	// FailedFor is how long a server of Upstreams that failed to answer is asked after the others; 0 means 30s, a negative value not at all.
	FailedFor time.Duration
	// MaxInFlight is how many queries of one flow may wait for their answers at once: a UDP session drops the queries beyond it, a TCP conn reads no more until one is answered. 0 means 64.
	MaxInFlight int
	// Idle ends a flow after this long without a message either way and none awaiting its answer; a query the upstream leaves unanswered, or a TCP dial not back, for this long is given up. 0 means 10s.
	Idle time.Duration
	// CacheSize is the most replies the cache keeps to answer later DNS queries with; 0 means 4096, a negative value disables the cache.
	CacheSize int

	// Stale is how long past its lifetime a kept reply still answers, while the upstream is asked for a new one or does not give one; 0 means 24h, a negative value not at all.
	Stale time.Duration

	// sized guards the one copy of CacheSize and Stale into cache, which the first flow makes.
	sized sync.Once
	cache cache

	// mu guards flows, the number of flows being served, links, the upstream conns by address, which last until no flow is served, flights, the DNS queries being asked upstream, and failed, when each server that failed to answer last did.
	mu      sync.Mutex
	flows   int
	links   map[string]*link
	flights map[origin]chan struct{}
	failed  map[string]time.Time
}

// mirrored returns the upstream of a query sent to the server at addressed: the name the cache keeps its replies under and the addresses of its servers.
func (h *Handler) mirrored(addressed string) (upstream string, servers []string) {
	if len(h.Upstreams) == 0 {
		return addressed, []string{addressed}
	}
	return strings.Join(h.Upstreams, " "), h.Upstreams
}

// answers returns the cache of h, sized by CacheSize.
func (h *Handler) answers() *cache {
	h.sized.Do(func() { h.cache.size, h.cache.keep = h.CacheSize, h.Stale })
	return &h.cache
}

func (h *Handler) maxInFlight() int {
	if h.MaxInFlight > 0 {
		return h.MaxInFlight
	}
	return 64
}

func (h *Handler) idle() time.Duration {
	return cmp.Or(h.Idle, 10*time.Second)
}

// Serve accepts the conns of l, each on its own goroutine, until l fails, and returns that error.
// A conn that is a net.PacketConn is served as a UDP session: each DNS query is answered from the server it was sent to, which ReadFrom returns as a *net.UDPAddr, with a WriteTo from that address.
// Any other conn is served as a TCP one, which the client dialled to the server at its LocalAddr.
// A conn is served until it idles or fails, a TCP one also once its client closed it and has every answer; it is then closed, and with the last conn served every upstream conn.
// The dials for a conn carry its RemoteAddr as flow.ClientAddr.
func (h *Handler) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go h.serveConn(conn)
	}
}

func (h *Handler) serveConn(conn net.Conn) {
	ctx := flow.WithClientAddr(context.Background(), conn.RemoteAddr())
	if pc, ok := conn.(net.PacketConn); ok {
		h.serve(ctx, conn, func(ctx context.Context, s *session) { s.serveUDP(ctx, pc) })
		return
	}
	h.serve(ctx, conn, func(ctx context.Context, s *session) { s.serveTCP(ctx, conn, conn.LocalAddr().String()) })
}

// serve runs answer on a session of conn, which it closes once answer returned or the session idled.
func (h *Handler) serve(ctx context.Context, conn io.Closer, answer func(context.Context, *session)) {
	defer conn.Close()
	h.enter()
	defer h.leave()
	ctx, cancel := context.WithCancel(ctx)
	s := &session{h: h, conn: conn, cancel: cancel, slots: make(chan struct{}, h.maxInFlight())}
	defer s.workers.Wait()
	defer s.end()
	stop := context.AfterFunc(ctx, s.end)
	defer stop()
	defer s.watch(h.idle())()
	answer(ctx, s)
}

// enter counts one more flow served.
func (h *Handler) enter() {
	h.mu.Lock()
	h.flows++
	h.mu.Unlock()
}

// leave counts one flow less and, with none left, ends every upstream conn and dial.
func (h *Handler) leave() {
	h.mu.Lock()
	h.flows--
	var links map[string]*link
	if h.flows == 0 {
		links, h.links = h.links, nil
	}
	h.mu.Unlock()
	for _, l := range links {
		l.cancel()
	}
}

// session is one conn being served.
type session struct {
	h    *Handler
	conn io.Closer
	// cancel ends the ctx of the answers.
	cancel context.CancelFunc
	ending sync.Once
	// slots holds one token per query awaiting its answer, each on a goroutine of workers.
	slots   chan struct{}
	workers sync.WaitGroup
	// touch pushes the idle end back.
	touch func()
}

// end closes the conn and gives up the answers awaited.
func (s *session) end() {
	s.ending.Do(func() {
		s.cancel()
		s.conn.Close()
	})
}

// watch ends s once idle passes without a touch while no query awaits its answer; stop ends the watch.
func (s *session) watch(idle time.Duration) (stop func() bool) {
	var timer *time.Timer
	set := make(chan struct{})
	timer = time.AfterFunc(idle, func() {
		<-set
		if len(s.slots) > 0 {
			timer.Reset(idle)
			return
		}
		s.end()
	})
	close(set)
	s.touch = func() { timer.Reset(idle) }
	return timer.Stop
}

// serveUDP answers each datagram of the session from the server it was sent to.
func (s *session) serveUDP(ctx context.Context, pc net.PacketConn) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		server, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		s.touch()
		select {
		case s.slots <- struct{}{}:
		default:
			continue
		}
		query := bytes.Clone(buf[:n])
		s.workers.Go(func() {
			defer func() { <-s.slots }()
			upstream, servers := s.h.mirrored(server.AddrPort().String())
			reply, refresh := s.h.answer(ctx, upstream, servers, query)
			if reply == nil {
				return
			}
			if _, err := pc.WriteTo(fit(reply, query), server); err == nil {
				s.touch()
			}
			if refresh != nil {
				refresh()
			}
		})
	}
}

// serveTCP answers each length-framed message of conn, which the client dialled to the server at addressed, in the order the answers come, and returns once the client closed its side and has them all.
func (s *session) serveTCP(ctx context.Context, conn net.Conn, addressed string) {
	upstream, servers := s.h.mirrored(addressed)
	var writing sync.Mutex
	for {
		query, err := readFrame(conn)
		if err != nil {
			break
		}
		s.touch()
		select {
		case s.slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		s.workers.Go(func() {
			defer func() { <-s.slots }()
			reply, refresh := s.h.answer(ctx, upstream, servers, query)
			if reply == nil {
				return
			}
			writing.Lock()
			err := writeFrame(conn, reply)
			writing.Unlock()
			if err != nil {
				s.end()
				return
			}
			s.touch()
			if refresh != nil {
				refresh()
			}
		})
	}
	s.workers.Wait()
}

// readFrame reads one message prefixed with its 2-byte big-endian length.
func readFrame(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	message := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(r, message); err != nil {
		return nil, err
	}
	return message, nil
}

// writeFrame writes message, of at most 65535 bytes, prefixed with its 2-byte big-endian length in one Write.
func writeFrame(w io.Writer, message []byte) error {
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(message)), uint16(len(message)))
	_, err := w.Write(append(frame, message...))
	return err
}

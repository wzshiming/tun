package dns

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wzshiming/tun/stack"
)

// upstreamDialer answers the "udp" dials of a symmetric udp.Handler with upstreams, which dial "tcp", to target if set, once a datagram has to go there.
type upstreamDialer struct {
	dialer stack.Dialer
	target string
	idle   time.Duration
	cache  *cache
}

func (d upstreamDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &upstream{dialer: d.dialer, address: cmp.Or(d.target, address), idle: d.idle, cache: d.cache, ctx: ctx, cancel: cancel, replies: make(chan []byte), pending: make(map[uint16]*query)}, nil
}

// query is a DNS query sent upstream and not answered yet.
type query struct {
	message []byte
	// resent tells that the query went out on a second conn, which is its last.
	resent bool
}

// upstream is the conn udp.Handler relays one server's datagrams through: it answers a DNS query from cache when that holds a reply of address to such a query, dials its TCP conn, giving the dial idle to come back, when a datagram has to go there, and sends the DNS queries a failed conn left unanswered once more on a new one.
type upstream struct {
	// Conn is nil: it only completes net.Conn with the methods udp.Handler never calls.
	net.Conn
	dialer  stack.Dialer
	address string
	idle    time.Duration
	cache   *cache
	// ctx carries the values every dial gets and ends with u.
	ctx    context.Context
	cancel context.CancelFunc
	// replies hands Read the messages read from the TCP conn.
	replies chan []byte
	// sending is held to dial and to write, so that Write and the reader resending for a failed conn take turns.
	sending sync.Mutex

	// mu guards conn, the live TCP conn if any, and pending, the unanswered DNS queries sent on it by ID.
	mu      sync.Mutex
	conn    *frameConn
	pending map[uint16]*query
}

// Read returns the next reply into b, which holds any message as udp.Handler's buffer does, and fails once u ended.
func (u *upstream) Read(b []byte) (int, error) {
	select {
	case reply := <-u.replies:
		return copy(b, reply), nil
	case <-u.ctx.Done():
		return 0, net.ErrClosed
	}
}

// Write hands Read the reply the cache holds for datagram, if any, and else sends datagram on the TCP conn, dialling it first if there is none; a dial that fails or is abandoned fails the Write, a conn that fails does not, as its reader retires it.
func (u *upstream) Write(datagram []byte) (int, error) {
	if _, k, ok := queryKey(datagram); ok {
		if reply, ok := u.cache.get(u.address, k, datagram); ok {
			select {
			case u.replies <- fit(datagram, reply):
				return len(datagram), nil
			case <-u.ctx.Done():
				return 0, net.ErrClosed
			}
		}
	}
	u.sending.Lock()
	defer u.sending.Unlock()
	conn, err := u.connect()
	if err != nil {
		return 0, err
	}
	if id, ok := queryID(datagram); ok {
		u.mu.Lock()
		u.pending[id] = &query{message: bytes.Clone(datagram)}
		u.mu.Unlock()
	}
	if _, err := conn.Write(datagram); err != nil {
		// The close wakes the reader of conn.
		conn.Close()
	}
	return len(datagram), nil
}

// Close ends u at once: it cancels a dial in flight and closes the TCP conn, which fails a blocked Read or Write.
func (u *upstream) Close() error {
	u.cancel()
	u.mu.Lock()
	conn := u.conn
	u.conn = nil
	u.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	return nil
}

// connect returns the live TCP conn, dialling one first unless u has it or ended; the caller holds u.sending.
func (u *upstream) connect() (*frameConn, error) {
	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	if err := u.ctx.Err(); err != nil {
		return nil, err
	}
	dialled, release, err := u.dial()
	if err != nil {
		return nil, err
	}
	conn = &frameConn{Conn: dialled, release: release}
	u.mu.Lock()
	ended := u.ctx.Err() != nil
	if !ended {
		u.conn = conn
	}
	u.mu.Unlock()
	if ended {
		conn.Close()
		return nil, net.ErrClosed
	}
	go u.receive(conn)
	return conn, nil
}

// dial dials the TCP conn on a goroutine of its own, so that neither the bound of idle nor the end of u waits for a dialer that ignores its ctx; a conn that comes too late is closed, one in time keeps its ctx, which a dialer may bind it to, until release.
func (u *upstream) dial() (net.Conn, context.CancelFunc, error) {
	ctx, cancel := context.WithCancel(u.ctx)
	bound := time.AfterFunc(u.idle, cancel)
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result)
	go func() {
		conn, err := u.dialer.DialContext(ctx, "tcp", u.address)
		select {
		case done <- result{conn, err}:
		case <-ctx.Done():
			if err == nil {
				conn.Close()
			}
		}
	}()
	var r result
	select {
	case r = <-done:
	case <-ctx.Done():
		r.err = ctx.Err()
	}
	if r.err == nil && !bound.Stop() {
		// The bound passed just as the dial came back.
		r.conn.Close()
		r.err = context.DeadlineExceeded
	}
	if r.err != nil {
		bound.Stop()
		cancel()
		return nil, nil, r.err
	}
	return r.conn, cancel, nil
}

// receive hands Read each message read from conn, which answers the query of its ID, and retires conn once it fails.
func (u *upstream) receive(conn *frameConn) {
	defer u.retire(conn)
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		// The cache has the reply before the client does, whose next query then finds it there.
		reply := buf[:n]
		if query := u.answered(reply); query != nil {
			// The cache keeps the reply whole; only the client's datagram is cut to what it takes.
			reply = fit(query, reply)
		}
		select {
		case u.replies <- bytes.Clone(reply):
		case <-u.ctx.Done():
			return
		}
	}
}

// answered forgets the unanswered query whose ID reply, a message read from the TCP conn, carries, has the cache keep reply for as long as it may answer such a query, and returns that query, nil if reply answers none.
func (u *upstream) answered(reply []byte) (query []byte) {
	if len(reply) < 2 {
		return nil
	}
	id := binary.BigEndian.Uint16(reply)
	u.mu.Lock()
	q := u.pending[id]
	delete(u.pending, id)
	u.mu.Unlock()
	if q == nil {
		return nil
	}
	if _, k, ok := queryKey(q.message); ok {
		u.cache.put(u.address, k, reply, lifetime(reply, id, k.question))
	}
	return q.message
}

// retire closes conn, which failed, and sends the DNS queries it left unanswered once more on a new conn; with none of them, or no conn for them, it ends u as a failed conn ended its target before.
func (u *upstream) retire(conn *frameConn) {
	// A Write blocked on conn holds u.sending until conn is closed.
	conn.Close()
	u.sending.Lock()
	defer u.sending.Unlock()
	u.mu.Lock()
	u.conn = nil
	var again [][]byte
	for id, q := range u.pending {
		if q.resent {
			delete(u.pending, id)
			continue
		}
		q.resent = true
		again = append(again, q.message)
	}
	u.mu.Unlock()
	if len(again) == 0 {
		u.cancel()
		return
	}
	next, err := u.connect()
	if err != nil {
		u.cancel()
		return
	}
	for _, message := range again {
		if _, err := next.Write(message); err != nil {
			// The close wakes the reader of next, which finds every query resent and ends u.
			next.Close()
			return
		}
	}
}

// queryID returns the ID of datagram if it is a DNS query: a message that parses to its end with QR=0, opcode QUERY and exactly one question.
func queryID(datagram []byte) (uint16, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(datagram)
	if err != nil || h.Response || h.OpCode != 0 {
		return 0, false
	}
	if _, err := p.Question(); err != nil {
		return 0, false
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return 0, false
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil || p.SkipAllAdditionals() != nil {
		return 0, false
	}
	return h.ID, true
}

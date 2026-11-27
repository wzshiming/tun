package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// errDown fails the messages a failed upstream conn left unanswered.
var errDown = errors.New("dns: upstream conn failed")

// link is the TCP conn to one upstream, which every flow sends its messages on, each under an ID of its own there, and its dial before.
type link struct {
	// ctx carries the values of the dial and ends with the link; cancel ends it, and with it the dial and the conn.
	ctx    context.Context
	cancel context.CancelFunc
	// dialled is closed once the dial is back: with conn, or else err.
	dialled chan struct{}
	conn    net.Conn
	err     error
	// writing is held to write one message whole.
	writing sync.Mutex

	// mu guards the rest: next, the ID given last, pending, the messages sent and not answered by the ID they were sent under, and down, closed once the conn failed.
	mu      sync.Mutex
	next    uint16
	pending map[uint16]chan []byte
	failed  bool
	down    chan struct{}
}

// exchange sends query to the upstream at address and returns its reply, within ctx; a query that a failed conn left unanswered is sent once more on a new one.
func (h *Handler) exchange(ctx context.Context, address string, query []byte) ([]byte, error) {
	for again := true; ; again = false {
		l, err := h.connect(ctx, address)
		if err != nil {
			return nil, err
		}
		reply, err := l.roundTrip(ctx, query, h.idle())
		if err == nil {
			return reply, nil
		}
		if !again || ctx.Err() != nil {
			return nil, err
		}
		h.drop(address, l)
	}
}

// connect returns the link to address once its dial is back, starting one if h has none: the dial gets the values of ctx but outlasts it, as other flows wait for it too.
func (h *Handler) connect(ctx context.Context, address string) (*link, error) {
	h.mu.Lock()
	l := h.links[address]
	if l == nil {
		l = &link{dialled: make(chan struct{}), pending: make(map[uint16]chan []byte), down: make(chan struct{})}
		l.ctx, l.cancel = context.WithCancel(context.WithoutCancel(ctx))
		if h.links == nil {
			h.links = make(map[string]*link)
		}
		h.links[address] = l
		go h.run(address, l)
	}
	h.mu.Unlock()
	select {
	case <-l.dialled:
		return l, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// drop has the next message to address dial anew, if l is still the link there.
func (h *Handler) drop(address string, l *link) {
	h.mu.Lock()
	if h.links[address] == l {
		delete(h.links, address)
	}
	h.mu.Unlock()
}

// run dials l, giving the dial Idle to come back, and hands each message read from its conn to the one awaiting it, until the conn fails or l ends; it then drops l and fails what it left unanswered.
func (h *Handler) run(address string, l *link) {
	defer l.cancel()
	l.conn, l.err = h.dial(l.ctx, address)
	if l.err != nil {
		h.drop(address, l)
		close(l.dialled)
		return
	}
	close(l.dialled)
	stop := context.AfterFunc(l.ctx, func() { l.conn.Close() })
	defer stop()
	defer l.conn.Close()
	defer func() {
		h.drop(address, l)
		l.mu.Lock()
		l.failed = true
		close(l.down)
		l.mu.Unlock()
	}()
	for {
		reply, err := readFrame(l.conn)
		if err != nil {
			return
		}
		if len(reply) < 12 {
			continue
		}
		id := binary.BigEndian.Uint16(reply)
		l.mu.Lock()
		awaiting := l.pending[id]
		delete(l.pending, id)
		l.mu.Unlock()
		if awaiting != nil {
			awaiting <- reply
		}
	}
}

// dial dials the TCP conn on a goroutine of its own, so that neither the bound of Idle nor the end of ctx waits for a dialer that ignores its ctx; a conn that comes too late is closed.
func (h *Handler) dial(ctx context.Context, address string) (net.Conn, error) {
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	bound := time.AfterFunc(h.idle(), cancel)
	defer bound.Stop()
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result)
	go func() {
		// The conn keeps ctx, which a dialer may bind it to; only the wait for it is bounded.
		conn, err := h.Dialer.DialContext(ctx, "tcp", address)
		select {
		case done <- result{conn, err}:
		case <-bounded.Done():
			if err == nil {
				conn.Close()
			}
		}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-bounded.Done():
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, context.DeadlineExceeded
	}
}

// roundTrip sends message on the conn of l under an ID no message awaiting its reply there has, a write getting idle to pass, and returns the reply to it, under the ID of message, once it comes within ctx.
func (l *link) roundTrip(ctx context.Context, message []byte, idle time.Duration) ([]byte, error) {
	l.mu.Lock()
	if l.failed || len(l.pending) > 0xffff {
		l.mu.Unlock()
		return nil, errDown
	}
	// IDs go round, so that a reply coming after its message was given up finds its ID unused for long.
	for {
		l.next++
		if _, used := l.pending[l.next]; !used {
			break
		}
	}
	id, awaiting := l.next, make(chan []byte, 1)
	l.pending[id] = awaiting
	l.mu.Unlock()

	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(message)), uint16(len(message)))
	frame = append(frame, message...)
	binary.BigEndian.PutUint16(frame[2:], id)
	l.writing.Lock()
	// Bounds a write the upstream does not read; a conn without deadlines is left to the ctx of its dial.
	l.conn.SetWriteDeadline(time.Now().Add(idle))
	_, err := l.conn.Write(frame)
	l.writing.Unlock()
	if err == nil {
		select {
		case reply := <-awaiting:
			copy(reply, message[:2])
			return reply, nil
		case <-l.down:
			err = errDown
		case <-ctx.Done():
			err = ctx.Err()
		}
	} else {
		// A frame cut short leaves the conn of no use.
		l.cancel()
	}
	l.mu.Lock()
	delete(l.pending, id)
	l.mu.Unlock()
	return nil, err
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

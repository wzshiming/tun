package dns

import (
	"bytes"
	"cmp"
	"context"
	"net"
	"sync"
	"time"

	"github.com/wzshiming/tun/stack"
)

// upstreamDialer answers the "udp" dials of a symmetric udp.Handler with upstreams, which dial "tcp", to target if set, once a datagram has to go there.
type upstreamDialer struct {
	dialer stack.Dialer
	target string
	idle   time.Duration
}

func (d upstreamDialer) DialContext(ctx context.Context, _, address string) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	return &upstream{dialer: d.dialer, address: cmp.Or(d.target, address), idle: d.idle, ctx: ctx, cancel: cancel, replies: make(chan []byte)}, nil
}

// upstream is the conn udp.Handler relays one server's datagrams through: it dials its TCP conn, giving the dial idle to come back, when the first datagram has to go there.
type upstream struct {
	// Conn is nil: it only completes net.Conn with the methods udp.Handler never calls.
	net.Conn
	dialer  stack.Dialer
	address string
	idle    time.Duration
	// ctx carries the values the dial gets and ends with u.
	ctx    context.Context
	cancel context.CancelFunc
	// replies hands Read the messages read from the TCP conn.
	replies chan []byte

	// mu guards conn, the TCP conn once dialled.
	mu   sync.Mutex
	conn net.Conn
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

// Write sends datagram on the TCP conn, dialling it first if there is none; a dial that fails or is abandoned fails the Write.
func (u *upstream) Write(datagram []byte) (int, error) {
	conn, err := u.connect()
	if err != nil {
		return 0, err
	}
	return conn.Write(datagram)
}

// Close ends u at once: it cancels a dial in flight and closes the TCP conn, which fails a blocked Read or Write.
func (u *upstream) Close() error {
	u.cancel()
	u.mu.Lock()
	conn := u.conn
	u.conn = nil
	u.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// connect returns the TCP conn, dialling it first unless u has one or ended.
func (u *upstream) connect() (net.Conn, error) {
	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	if err := u.ctx.Err(); err != nil {
		return nil, err
	}
	dialled, err := u.dial()
	if err != nil {
		return nil, err
	}
	conn = frameConn{dialled}
	u.mu.Lock()
	ended := u.ctx.Err() != nil
	if !ended {
		u.conn = conn
	}
	u.mu.Unlock()
	if ended {
		dialled.Close()
		return nil, net.ErrClosed
	}
	go u.receive(conn)
	return conn, nil
}

// dial dials the TCP conn on a goroutine of its own, so that neither the bound of idle nor the end of u waits for a dialer that ignores its ctx; a conn that comes too late is closed.
func (u *upstream) dial() (net.Conn, error) {
	ctx, cancel := context.WithTimeout(u.ctx, u.idle)
	defer cancel()
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
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// receive hands Read each message read from conn and ends u once conn fails, as a failed conn ended its target before.
func (u *upstream) receive(conn net.Conn) {
	defer u.Close()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		select {
		case u.replies <- bytes.Clone(buf[:n]):
		case <-u.ctx.Done():
			return
		}
	}
}

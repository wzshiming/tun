package flow

import (
	"context"
	"net"
	"sync"
)

var (
	_ Handler      = (*Listener)(nil)
	_ net.Listener = (*Listener)(nil)
)

// Listener is a Handler whose flows a server of the standard library accepts as the conns of a net.Listener.
// Mount it on a Mux and serve it, e.g. l := flow.NewListener(); m.Handle("tcp", ":80", l); go http.Serve(l, h), or srv.ServeTLS(l, "", "") for HTTPS.
//
// An accepted conn is the one Flow.Accept returns, its RemoteAddr the flow's client and its LocalAddr the target the client dialled: for tcp a conn with CloseWrite, for udp also a net.PacketConn, for icmp the echo session.
// The flow lasts until its conn is closed, by the server or, as the flow's ctx ends, by the Listener.
// A flow waits to be accepted for as long as stack.Serve lets it stay unanswered, so one mounted on a Listener nobody serves is rejected as that ends; a flow arriving after Close is rejected at once.
type Listener struct {
	flows     chan *listenerFlow
	closed    chan struct{}
	closeOnce sync.Once
}

// listenerFlow is a flow waiting for an Accept, which answers with its conn, or nil if the flow could not be accepted.
type listenerFlow struct {
	flow Flow
	conn chan *listenerConn
}

// NewListener returns a Listener with no flows, to mount on a Mux.
func NewListener() *Listener {
	return &Listener{flows: make(chan *listenerFlow), closed: make(chan struct{})}
}

// ServeFlow hands f to an Accept and returns once the conn that returned is closed, which it does itself as ctx ends.
func (l *Listener) ServeFlow(ctx context.Context, f Flow) {
	select {
	case <-l.closed:
		f.Reject()
		return
	default:
	}
	waiting := &listenerFlow{flow: f, conn: make(chan *listenerConn, 1)}
	select {
	case l.flows <- waiting:
	case <-l.closed:
		f.Reject()
		return
	case <-ctx.Done():
		return
	}
	c := <-waiting.conn
	if c == nil {
		return
	}
	select {
	case <-c.closed:
	case <-ctx.Done():
		c.Close()
	}
}

// Accept waits for a flow, accepts it and returns its conn; a flow that cannot be accepted any more is skipped.
// After Close it returns net.ErrClosed.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.closed:
			return nil, net.ErrClosed
		default:
		}
		select {
		case waiting := <-l.flows:
			conn, err := waiting.flow.Accept()
			if err != nil {
				waiting.conn <- nil
				continue
			}
			c := &listenerConn{Conn: conn, closed: make(chan struct{})}
			waiting.conn <- c
			_, packet := conn.(net.PacketConn)
			_, closeWrite := conn.(closeWriter)
			switch {
			case packet:
				return listenerPacketConn{c}, nil
			case closeWrite:
				return listenerCloseWriteConn{c}, nil
			}
			return c, nil
		case <-l.closed:
			return nil, net.ErrClosed
		}
	}
}

// Close ends the Listener: Accept fails, and the flows not yet accepted, as those that follow, are rejected. The conns accepted stay open.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

// Addr is a placeholder, as the Listener has no address of its own: each conn's LocalAddr is the target its client dialled.
func (l *Listener) Addr() net.Addr { return listenerAddr{} }

type listenerAddr struct{}

func (listenerAddr) Network() string { return "stack" }
func (listenerAddr) String() string  { return "stack" }

// listenerConn is a flow's conn that tells when it was closed.
type listenerConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func (c *listenerConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		close(c.closed)
	})
	return c.closeErr
}

type closeWriter interface{ CloseWrite() error }

// listenerCloseWriteConn passes on the CloseWrite of a tcp flow's conn.
type listenerCloseWriteConn struct{ *listenerConn }

func (c listenerCloseWriteConn) CloseWrite() error { return c.Conn.(closeWriter).CloseWrite() }

// listenerPacketConn passes on the ReadFrom and WriteTo of a udp session's conn.
type listenerPacketConn struct{ *listenerConn }

func (c listenerPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.Conn.(net.PacketConn).ReadFrom(b)
}

func (c listenerPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.Conn.(net.PacketConn).WriteTo(b, addr)
}

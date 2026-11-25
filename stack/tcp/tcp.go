// Package tcp relays a TCP flow to its target, dialled through a stack.Dialer, passing half-closes on between the two connections.
// Mount its Handler on a stack.Mux for the "tcp" network, e.g. m.Handle("tcp", "", &tcp.Handler{Dialer: d}); the package registers nothing itself.
package tcp

import (
	"cmp"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wzshiming/tun/stack"
)

var _ stack.Handler = (*Handler)(nil)

// Handler serves a TCP flow by dialing its target through Dialer and passing the two connections' bytes into each other; it rejects other flows.
type Handler struct {
	Dialer stack.Dialer
	// HalfCloseIdle ends a flow after this long without a byte in the direction a half-close left open; 0 means 60s.
	HalfCloseIdle time.Duration
}

// ServeFlow dials f's target before accepting, so a failed dial resets the client, then passes half-closes on and ends with ctx or HalfCloseIdle, closing both conns.
func (h *Handler) ServeFlow(ctx context.Context, f stack.Flow) {
	if f.Network() != "tcp" {
		f.Reject()
		return
	}
	remote, err := h.Dialer.DialContext(stack.WithClientAddr(ctx, net.TCPAddrFromAddrPort(f.Client())), "tcp", f.Target().String())
	if err != nil {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		remote.Close()
		return
	}
	tunnel(ctx, conn, remote, h.halfCloseIdle())
}

func (h *Handler) halfCloseIdle() time.Duration {
	return cmp.Or(h.HalfCloseIdle, 60*time.Second)
}

var bufferPool = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

// tunnel pipes a and b into each other, passing an ended direction on with CloseWrite, and closes both once done, when ctx ends, or once the direction left open forwards nothing for idle.
func tunnel(ctx context.Context, a, b net.Conn, idle time.Duration) {
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	defer closeBoth()
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	idleTimer := time.AfterFunc(idle, closeBoth)
	defer idleTimer.Stop()
	touch := func() {}
	done := make(chan bool, 2)
	copyConn := func(dst, src net.Conn) {
		buf := bufferPool.Get().(*[32 * 1024]byte)
		_, err := io.CopyBuffer(touchWriter{dst, touch}, src, buf[:])
		bufferPool.Put(buf)
		halfClosed := false
		if closer, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			halfClosed = closer.CloseWrite() == nil
		}
		done <- halfClosed
	}
	go copyConn(a, b)
	go copyConn(b, a)
	if !<-done {
		closeBoth()
	} else {
		idleTimer.Reset(idle)
	}
	<-done
}

// touchWriter calls touch after each Write that forwarded bytes.
type touchWriter struct {
	io.Writer
	touch func()
}

func (w touchWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	if n > 0 {
		w.touch()
	}
	return n, err
}

// Package tcp relays a TCP flow to its target, dialled through a stack.Dialer, passing half-closes on between the two connections.
// Mount its Handler on a stack.Mux for the "tcp" network, e.g. m.Handle("tcp", "", &tcp.Handler{Dialer: d}); the package registers nothing itself.
package tcp

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/wzshiming/tun/stack"
)

var _ stack.Handler = (*Handler)(nil)

// Handler serves a TCP flow by dialing its target through Dialer and passing the two connections' bytes into each other; it rejects other flows.
type Handler struct {
	Dialer stack.Dialer
}

// ServeFlow dials f's target before accepting, so a failed dial resets the client, then passes half-closes on and ends with ctx, closing both conns.
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
	tunnel(ctx, conn, remote)
}

var bufferPool = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

// tunnel pipes a and b into each other, passing an ended direction on with CloseWrite, and closes both once done or when ctx ends.
func tunnel(ctx context.Context, a, b net.Conn) {
	closeBoth := func() {
		a.Close()
		b.Close()
	}
	defer closeBoth()
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	done := make(chan bool, 2)
	copyConn := func(dst, src net.Conn) {
		buf := bufferPool.Get().(*[32 * 1024]byte)
		_, err := io.CopyBuffer(dst, src, buf[:])
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
	}
	<-done
}

package stack

import (
	"context"
	"io"
	"net"
	"sync"
)

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

package stack

import (
	"fmt"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// forwardTCP serves a new connection on the forwarder's own goroutine; Accept completes the handshake, Reject resets the client.
func (g *gateway) forwardTCP(r *tcp.ForwarderRequest) {
	if g.handler == nil || !g.start() {
		r.Complete(true)
		return
	}
	id := r.ID()
	g.serve(&flow{
		network: "tcp",
		target:  addrPort(id.LocalAddress, id.LocalPort),
		client:  addrPort(id.RemoteAddress, id.RemotePort),
		accept: func() (net.Conn, error) {
			var wq waiter.Queue
			ep, e := r.CreateEndpoint(&wq)
			if e != nil {
				r.Complete(true)
				return nil, fmt.Errorf("stack: accept tcp: %s", e)
			}
			r.Complete(false)
			return gonet.NewTCPConn(&wq, ep), nil
		},
		reject: func() { r.Complete(true) },
	})
}

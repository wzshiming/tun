package stack

import (
	"fmt"
	"net"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
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
			// The probe count stays gVisor's default of 9, and neither option can fail on a TCP endpoint.
			idle, interval := tcpip.KeepaliveIdleOption(g.keepAliveIdle), tcpip.KeepaliveIntervalOption(g.keepAliveInterval)
			ep.SetSockOpt(&idle)
			ep.SetSockOpt(&interval)
			ep.SocketOptions().SetKeepAlive(true)
			// The conn is torn down after the keepalive time even if its client answers every probe.
			time.AfterFunc(g.keepAliveIdle+9*g.keepAliveInterval, ep.Abort)
			return gonet.NewTCPConn(&wq, ep), nil
		},
		reject:        func() { r.Complete(true) },
		answerTimeout: g.answerTimeout,
	})
}

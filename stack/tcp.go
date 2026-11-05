package stack

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func (g *gateway) handleTCP(r *tcp.ForwarderRequest) {
	if !g.start() {
		r.Complete(true)
		return
	}
	defer g.flows.Done()
	id := r.ID()
	client := net.TCPAddrFromAddrPort(addrPort(id.RemoteAddress, id.RemotePort))
	remote, err := g.dialer.DialContext(WithClientAddr(g.ctx, client), "tcp", addrPort(id.LocalAddress, id.LocalPort).String())
	if err != nil {
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	if e != nil {
		remote.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)
	tunnel(g.ctx, gonet.NewTCPConn(&wq, ep), remote)
}

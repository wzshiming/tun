package stack

import (
	"net"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// forwardUDP runs on the packet goroutine, which re-invokes it for every datagram until an endpoint exists, so it creates the endpoint at once, queueing the first datagram, and serves the flow on a goroutine.
// Only a nil handler leaves the datagram unhandled, which the stack answers with ICMP port unreachable; Reject closes the endpoint, dropping the flow's datagrams.
func (g *gateway) forwardUDP(r *udp.ForwarderRequest) bool {
	if g.handler == nil {
		return false
	}
	if !g.start() {
		return true
	}
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	if e != nil {
		g.flows.Done()
		return true
	}
	conn := gonet.NewUDPConn(&wq, ep)
	id := r.ID()
	go g.serve(&flow{
		network: "udp",
		target:  addrPort(id.LocalAddress, id.LocalPort),
		client:  addrPort(id.RemoteAddress, id.RemotePort),
		accept:  func() (net.Conn, error) { return conn, nil },
		reject:  func() { conn.Close() },
	})
	return true
}

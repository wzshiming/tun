package netstack

import (
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Handler is a TCP/UDP connection handler that implements
// HandleTCPConn and HandleUDPConn methods.
type Handler interface {
	HandleTCPConn(stack.TransportEndpointID, *gonet.TCPConn)
	HandleUDPConn(stack.TransportEndpointID, *gonet.UDPConn)
}

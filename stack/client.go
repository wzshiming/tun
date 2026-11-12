package stack

import (
	"context"
	"net"
)

// Dialer dials the targets of the flows a handler serves.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// ListenConfig opens listening sockets; *net.ListenConfig is one.
type ListenConfig interface {
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type clientAddrKey struct{}

// WithClientAddr returns ctx carrying addr as the address of the client a dial or listen serves.
func WithClientAddr(ctx context.Context, addr net.Addr) context.Context {
	return context.WithValue(ctx, clientAddrKey{}, addr)
}

// ClientAddr returns the client address ctx carries, or nil; a handler passes the flow's *net.TCPAddr or *net.UDPAddr source to its dials and listens with WithClientAddr.
func ClientAddr(ctx context.Context) net.Addr {
	addr, _ := ctx.Value(clientAddrKey{}).(net.Addr)
	return addr
}

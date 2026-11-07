package stack

import (
	"context"
	"net"
)

// Relay serves a flow by dialing its target through Dialer, on the flow's network, and passing the two connections' data into each other.
type Relay struct {
	Dialer Dialer
}

// ServeFlow dials a TCP flow's target before accepting, so a failed dial resets the client, then passes half-closes on and ends with ctx.
// A UDP flow is accepted first and its datagrams relayed one for one until either conn fails or ctx ends; a failed dial drops the flow.
func (r *Relay) ServeFlow(ctx context.Context, f Flow) {
	if f.Network() == "udp" {
		r.serveUDP(ctx, f)
		return
	}
	remote, err := r.Dialer.DialContext(WithClientAddr(ctx, net.TCPAddrFromAddrPort(f.Client())), "tcp", f.Target().String())
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

func (r *Relay) serveUDP(ctx context.Context, f Flow) {
	conn, err := f.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	remote, err := r.Dialer.DialContext(WithClientAddr(ctx, net.UDPAddrFromAddrPort(f.Client())), "udp", f.Target().String())
	if err != nil {
		return
	}
	closeBoth := func() {
		conn.Close()
		remote.Close()
	}
	defer closeBoth()
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	replies := make(chan struct{})
	go func() {
		defer close(replies)
		defer closeBoth()
		relayDatagrams(conn, remote)
	}()
	relayDatagrams(remote, conn)
	closeBoth()
	<-replies
}

// relayDatagrams writes each datagram read from src to dst as one datagram until either fails.
func relayDatagrams(dst, src net.Conn) {
	buf := make([]byte, 65535)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

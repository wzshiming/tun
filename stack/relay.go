package stack

import (
	"context"
	"net"
)

// Relay serves a TCP flow by dialing its target through Dialer and piping the two connections into each other; it rejects UDP flows.
type Relay struct {
	Dialer Dialer
}

// ServeFlow dials f's target before accepting, so a failed dial resets the client; the relay passes half-closes on and ends with ctx.
func (r *Relay) ServeFlow(ctx context.Context, f Flow) {
	if f.Network() != "tcp" {
		f.Reject()
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

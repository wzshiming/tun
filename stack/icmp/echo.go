package icmp

import (
	"cmp"
	"context"
	"time"

	"github.com/wzshiming/tun/flow"
)

var _ flow.Handler = Echo{}

// Echo serves an ICMP echo session by answering each echo request itself, with the echo reply carrying its sequence number and payload, so its target answers a ping without a socket or a network behind it; it rejects other flows.
// Mount it on a flow.Mux for the addresses that are to answer, e.g. m.Handle("icmp", "198.18.0.1", icmp.Echo{}) for the address of the TUN device.
type Echo struct {
	// Idle ends a session after this long without an echo request; 0 means 30s.
	Idle time.Duration
}

// ServeFlow accepts the session and answers its echo requests until it idles, its conn fails or ctx ends, and then closes it.
func (h Echo) ServeFlow(ctx context.Context, f flow.Flow) {
	if f.Network() != "icmp" {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	reply := byte(echoReply4)
	if f.Target().Addr().Unmap().Is6() {
		reply = echoReply6
	}
	idle := cmp.Or(h.Idle, 30*time.Second)
	message := make([]byte, 65535)
	for {
		conn.SetReadDeadline(time.Now().Add(idle))
		n, err := conn.Read(message)
		if err != nil {
			return
		}
		if n < headerSize {
			continue
		}
		message[0] = reply
		if _, err := conn.Write(message[:n]); err != nil {
			return
		}
	}
}

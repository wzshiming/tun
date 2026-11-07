package stack

import (
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// DNS serves a UDP flow by relaying its datagrams as length-framed messages over one TCP connection to its target, dialled through Dialer; it rejects TCP flows.
type DNS struct {
	Dialer Dialer
	// Idle ends a flow after this long without datagrams either way; 0 means 10s.
	Idle time.Duration
}

// ServeFlow relays f until it idles, the dial or either conn fails, or ctx ends, and then closes both conns.
func (d *DNS) ServeFlow(ctx context.Context, f Flow) {
	if f.Network() != "udp" {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	remote, err := d.Dialer.DialContext(WithClientAddr(ctx, net.UDPAddrFromAddrPort(f.Client())), "tcp", f.Target().String())
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
	// Datagrams either way push back the idle timer, whose expiry closes both conns wherever the relay blocks.
	touch, stopIdle := afterIdle(cmp.Or(d.Idle, 10*time.Second), closeBoth)
	defer stopIdle()
	replies := make(chan struct{})
	go func() {
		defer close(replies)
		defer closeBoth()
		relayReplies(conn, remote, touch)
	}()
	relayQueries(conn, remote, touch)
	closeBoth()
	<-replies
}

// afterIdle calls onIdle once d passes without a touch; stop cancels it.
func afterIdle(d time.Duration, onIdle func()) (touch func(), stop func() bool) {
	timer := time.AfterFunc(d, onIdle)
	return func() { timer.Reset(d) }, timer.Stop
}

func relayQueries(conn, remote net.Conn, touch func()) {
	buf := make([]byte, 2+65535)
	for {
		n, err := conn.Read(buf[2:])
		if err != nil {
			return
		}
		binary.BigEndian.PutUint16(buf, uint16(n))
		if _, err := remote.Write(buf[:2+n]); err != nil {
			return
		}
		touch()
	}
}

func relayReplies(conn, remote net.Conn, touch func()) {
	buf := make([]byte, 65535)
	for {
		if _, err := io.ReadFull(remote, buf[:2]); err != nil {
			return
		}
		reply := buf[:binary.BigEndian.Uint16(buf)]
		if _, err := io.ReadFull(remote, reply); err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
		touch()
	}
}

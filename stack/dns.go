package stack

import (
	"cmp"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"
)

// DNS serves a UDP session by relaying the datagrams it sends to each target as length-framed messages over one TCP connection to that target, dialled through Dialer, and the replies back from that target; it rejects TCP flows.
type DNS struct {
	Dialer Dialer
	// Idle ends a session after this long without datagrams either way to any target; 0 means 10s.
	Idle time.Duration
}

// ServeFlow relays f until it idles, its conn fails or ctx ends, and then closes the session and every TCP conn.
// A target whose dial or TCP conn fails loses only its own datagrams; its next one dials again.
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
	ctx = WithClientAddr(ctx, net.UDPAddrFromAddrPort(f.Client()))
	relaySession(ctx, conn, cmp.Or(d.Idle, 10*time.Second),
		func(target string) (net.Conn, error) { return d.Dialer.DialContext(ctx, "tcp", target) },
		writeFrame, readFrame)
}

// afterIdle calls onIdle once d passes without a touch; stop cancels it.
func afterIdle(d time.Duration, onIdle func()) (touch func(), stop func() bool) {
	timer := time.AfterFunc(d, onIdle)
	return func() { timer.Reset(d) }, timer.Stop
}

// writeFrame writes message prefixed with its 2-byte big-endian length.
func writeFrame(remote net.Conn, message []byte) error {
	frame := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(message)), uint16(len(message)))
	_, err := remote.Write(append(frame, message...))
	return err
}

// readFrame reads one length-framed message into buf.
func readFrame(remote net.Conn, buf []byte) ([]byte, error) {
	if _, err := io.ReadFull(remote, buf[:2]); err != nil {
		return nil, err
	}
	message := buf[:binary.BigEndian.Uint16(buf)]
	if _, err := io.ReadFull(remote, message); err != nil {
		return nil, err
	}
	return message, nil
}

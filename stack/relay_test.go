package stack

import (
	"errors"
	"net"
	"testing"
)

func TestRelayRejectsUDP(t *testing.T) {
	env := testServeWith(t, Options{Addresses: testAddresses}, func(d *fakeDialer) Handler {
		m := NewMux()
		m.Handle("udp", 0, &Relay{Dialer: d})
		return m
	})
	conn := env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "datagram")
	var netErr net.Error
	if err := testUDPError(t, env, conn, testSilence); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() = %v, want a timeout with no reply and no ICMP error", err)
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for a UDP flow given to Relay: %+v, want no dial", dials)
	}
}

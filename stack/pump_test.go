package stack

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// Serve writes through buffers of the link MTU, so a packet that fills the MTU, and the fragments of one that exceeds it, must come through whole.
func TestServeWritesPacketsUpToTheMTUAndFragmentsLargerOnes(t *testing.T) {
	env := testServe(t, Options{})
	for _, tc := range []struct {
		name    string
		target  string
		payload int
	}{
		{"IPv4 below the MTU", "203.0.113.1:7", testMTU - 28 - 1},
		{"IPv4 filling the MTU", "203.0.113.1:7", testMTU - 28},
		{"IPv4 fragmented", "203.0.113.1:7", 4000},
		{"IPv6 filling the MTU", "[2001:db8::1]:7", testMTU - 48},
		{"IPv6 fragmented", "[2001:db8::1]:7", 4000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := env.dialUDP(t, tc.target)
			defer conn.Close()
			want := make([]byte, tc.payload)
			rand.Read(want)
			if _, err := conn.Write(want); err != nil {
				t.Fatalf("client write of %d bytes: %v", len(want), err)
			}
			got := make([]byte, 65535)
			conn.SetReadDeadline(time.Now().Add(testWait))
			n, err := conn.Read(got)
			if err != nil {
				t.Fatalf("client read of the %d-byte echo: %v%s", len(want), err, env.returned())
			}
			if !bytes.Equal(got[:n], want) {
				t.Errorf("echo = %d bytes, want the %d sent%s", n, len(want), env.returned())
			}
		})
	}
}

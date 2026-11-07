package stack

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

func TestServeNilHandlerAnswersUDPWithPortUnreachable(t *testing.T) {
	env := testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler { return nil })
	conn := env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "not dns")
	err := testUDPError(t, env, conn, testWait)
	if want := (&tcpip.ErrConnectionRefused{}).String(); !strings.Contains(err.Error(), want) {
		t.Fatalf("client Read() error = %v, want %q from ICMP port unreachable", err, want)
	}
	if n := env.dev.unreachable.Load(); n == 0 {
		t.Fatal("Serve with a nil handler wrote no ICMP destination unreachable for UDP to port 1234")
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for UDP to port 1234: %+v, want no dial", dials)
	}
}

func TestUDPWithoutHandlerIsDropped(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	conn := env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "not dns")
	var netErr net.Error
	if err := testUDPError(t, env, conn, testSilence); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() from 10.0.0.9:1234 = %v, want a timeout with no reply and no ICMP error", err)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable for UDP to port 1234, want the datagram dropped", n)
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for UDP to port 1234: %+v, want no dial", dials)
	}
}

// testUDPError reads conn until an error other than a timeout, or the timeout once within has passed; a datagram read fails t.
func testUDPError(t *testing.T, env *testEnv, conn net.Conn, within time.Duration) error {
	t.Helper()
	// A blocked gonet Read does not wake for the ICMP error, so poll with short deadlines.
	reply := make([]byte, 512)
	for start := time.Now(); ; {
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(reply)
		if err == nil {
			t.Fatalf("client read %q from %v, want no reply", reply[:n], conn.RemoteAddr())
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() || time.Since(start) > within {
			return err
		}
		if returned := env.returned(); returned != "" {
			t.Fatalf("client read from %v ended early%s", conn.RemoteAddr(), returned)
		}
	}
}

func testSend(t *testing.T, conn net.Conn, datagram string) {
	t.Helper()
	if _, err := io.WriteString(conn, datagram); err != nil {
		t.Fatalf("client send %q: %v", datagram, err)
	}
}

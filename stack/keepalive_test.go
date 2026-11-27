package stack

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

const (
	// testKeepAliveIdle is the Options.KeepAliveIdle the keepalive tests serve with, above the 500ms at which the client stack rations its answers to probes.
	testKeepAliveIdle = 600 * time.Millisecond
	// testKeepAliveInterval is the Options.KeepAliveInterval they serve with.
	testKeepAliveInterval = 100 * time.Millisecond
	// testKeepAliveTime is how long a conn served with them outlasts its client's last packet: the idle time, then gVisor's 9 probes.
	testKeepAliveTime = testKeepAliveIdle + 9*testKeepAliveInterval
	// testKeepAliveWindow is how long a handler may wait for the failure testKeepAliveTime brings, short of the time swapped options would take.
	testKeepAliveWindow = 2*testKeepAliveTime + 2*time.Second
	// testKeepAliveSpared is how long a conn the probes must leave alone is watched, well past testKeepAliveTime.
	testKeepAliveSpared = testKeepAliveTime + time.Second
)

// keepAliveServe serves with testKeepAliveIdle and testKeepAliveInterval a handler that accepts each flow, hands its conn to the test and returns only when the test ends.
func keepAliveServe(t *testing.T) (*testEnv, <-chan net.Conn) {
	t.Helper()
	conns, release := make(chan net.Conn, 4), make(chan struct{})
	opts := Options{KeepAliveIdle: testKeepAliveIdle, KeepAliveInterval: testKeepAliveInterval}
	env := testServeWith(t, opts, HandlerFunc(func(_ context.Context, f Flow) {
		if conn, err := f.Accept(); err == nil {
			conns <- conn
			<-release
		}
	}))
	// Cleanups run last first, so this one releases the handlers before Serve is stopped.
	t.Cleanup(func() { close(release) })
	return env, conns
}

func TestTCPConnOfSilentClientFailsReadAfterKeepAliveProbes(t *testing.T) {
	env, conns := keepAliveServe(t)
	start := time.Now()
	env.dialTCP(t, "10.0.0.9:443")
	conn := testReceive(t, conns, "the handler's Accept")
	env.dev.sever()
	conn.SetReadDeadline(start.Add(testKeepAliveWindow))
	_, err := conn.Read(make([]byte, 1))
	elapsed := time.Since(start)
	var netErr net.Error
	if err == nil || errors.Is(err, io.EOF) || errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("handler Read() on the conn of a client gone silent = %v after %v, want an error that is neither EOF nor this test's read deadline %v after the dial, under KeepAliveIdle %v and KeepAliveInterval %v", err, elapsed, testKeepAliveWindow, testKeepAliveIdle, testKeepAliveInterval)
	}
	if elapsed < testKeepAliveTime {
		t.Fatalf("handler Read() on the conn of a client gone silent failed with %v after %v, want Serve to wait out KeepAliveIdle %v and 9 probes KeepAliveInterval %v apart, %v in all", err, elapsed, testKeepAliveIdle, testKeepAliveInterval, testKeepAliveTime)
	}
}

func TestTCPConnOfIdleClientAnsweringProbesOutlivesKeepAlive(t *testing.T) {
	env, conns := keepAliveServe(t)
	client := env.dialTCP(t, "10.0.0.9:443")
	conn := testReceive(t, conns, "the handler's Accept")
	conn.SetReadDeadline(time.Now().Add(testKeepAliveSpared))
	_, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("handler Read() on the conn of an idle client that answers its probes = %v, want it blocked until this test's read deadline %v later, past KeepAliveIdle %v and 9 probes KeepAliveInterval %v apart", err, testKeepAliveSpared, testKeepAliveIdle, testKeepAliveInterval)
	}
	client.SetDeadline(time.Now().Add(testWait))
	conn.SetDeadline(time.Now().Add(testWait))
	testDeliver(t, client, conn, "client to handler")
	testDeliver(t, conn, client, "handler to client")
}

func TestOptionsKeepAliveIdleDefaultsTo60Seconds(t *testing.T) {
	if got := (Options{}).keepAliveIdle(); got != 60*time.Second {
		t.Fatalf("Options{}.keepAliveIdle() = %v, want the 60s default", got)
	}
	if got := (Options{KeepAliveIdle: 3 * time.Second}).keepAliveIdle(); got != 3*time.Second {
		t.Fatalf("Options{KeepAliveIdle: 3s}.keepAliveIdle() = %v, want 3s", got)
	}
}

func TestOptionsKeepAliveIntervalDefaultsTo15Seconds(t *testing.T) {
	if got := (Options{}).keepAliveInterval(); got != 15*time.Second {
		t.Fatalf("Options{}.keepAliveInterval() = %v, want the 15s default", got)
	}
	if got := (Options{KeepAliveInterval: 3 * time.Second}).keepAliveInterval(); got != 3*time.Second {
		t.Fatalf("Options{KeepAliveInterval: 3s}.keepAliveInterval() = %v, want 3s", got)
	}
}

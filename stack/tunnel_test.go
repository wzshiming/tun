package stack

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tunnelPair returns both ends of a loopback TCP connection, closed when t ends.
func tunnelPair(t *testing.T) (conn, peer *net.TCPConn) {
	t.Helper()
	c, p, err := testLoopbackPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); p.Close() })
	return c.(*net.TCPConn), p.(*net.TCPConn)
}

// runTunnel runs tunnel(ctx, a, b) and returns a channel closed once it returns.
func runTunnel(ctx context.Context, a, b net.Conn) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		tunnel(ctx, a, b)
		close(done)
	}()
	return done
}

func TestTunnelCopiesBothWays(t *testing.T) {
	a, aPeer := tunnelPair(t)
	b, bPeer := tunnelPair(t)
	runTunnel(t.Context(), a, b)

	aPeer.Write([]byte("ping"))
	bPeer.SetReadDeadline(time.Now().Add(testWait))
	got := make([]byte, 4)
	if _, err := io.ReadFull(bPeer, got); err != nil || string(got) != "ping" {
		t.Fatalf("b's peer read %q, %v; want ping", got, err)
	}
	bPeer.Write([]byte("pong"))
	aPeer.SetReadDeadline(time.Now().Add(testWait))
	if _, err := io.ReadFull(aPeer, got); err != nil || string(got) != "pong" {
		t.Fatalf("a's peer read %q, %v; want pong", got, err)
	}
}

func TestTunnelHalfClosePassesEOFAndKeepsTheOtherDirection(t *testing.T) {
	a, aPeer := tunnelPair(t)
	b, bPeer := tunnelPair(t)
	runTunnel(t.Context(), a, b)

	aPeer.CloseWrite()
	bPeer.SetReadDeadline(time.Now().Add(testWait))
	if n, err := bPeer.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("b's peer read after a's peer CloseWrite = %d, %v; want EOF", n, err)
	}
	bPeer.Write([]byte("late"))
	aPeer.SetReadDeadline(time.Now().Add(testWait))
	got := make([]byte, 4)
	if _, err := io.ReadFull(aPeer, got); err != nil || string(got) != "late" {
		t.Fatalf("a's peer read %q, %v after half-close; want late", got, err)
	}
}

func TestTunnelReturnsAndClosesBothOnceBothDirectionsEnd(t *testing.T) {
	a, aPeer := tunnelPair(t)
	b, bPeer := tunnelPair(t)
	done := runTunnel(t.Context(), a, b)

	aPeer.CloseWrite()
	bPeer.CloseWrite()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("tunnel did not return after both directions ended")
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a.Write after tunnel returned: %v, want net.ErrClosed", err)
	}
	if _, err := b.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("b.Write after tunnel returned: %v, want net.ErrClosed", err)
	}
}

func TestTunnelClosesBothWhenContextEnds(t *testing.T) {
	a, _ := tunnelPair(t)
	b, _ := tunnelPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := runTunnel(ctx, a, b)

	cancel()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("tunnel did not return after its context ended")
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a.Write after cancel: %v, want net.ErrClosed", err)
	}
}

func TestTunnelClosesBothWhenADirectionFails(t *testing.T) {
	b, bPeer := tunnelPair(t)
	stalled := &stalledConn{writing: make(chan struct{}), closed: make(chan struct{})}
	done := runTunnel(t.Context(), stalled, b)

	// Closing b's peer ends b's reads with EOF; CloseWrite on the stalled conn is unavailable, so both close.
	bPeer.Close()
	select {
	case <-done:
	case <-time.After(testWait):
		t.Fatal("tunnel did not return after a direction ended without a half-close")
	}
	select {
	case <-stalled.closed:
	default:
		t.Error("the stalled side was left open")
	}
}

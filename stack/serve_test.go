package stack

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// testStopBound is how long Serve may take to return once its context ends.
const testStopBound = 3 * time.Second

func TestServeReturnsContextErrorAndClosesDevice(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	select {
	case <-env.done:
		t.Fatalf("Serve() = %v before its context ended, want it to block until then", env.err)
	case <-time.After(100 * time.Millisecond):
	}
	env.cancel()
	if err := env.wait(t); err != context.Canceled {
		t.Fatalf("Serve() = %v after cancel, want ctx.Err() = context.Canceled", err)
	}
	if !env.dev.closedByServe() {
		t.Fatal("Serve returned without closing the device")
	}
}

func TestServeCancelEndsServeFlowContext(t *testing.T) {
	served, ended := make(chan string, 2), make(chan string, 2)
	// The handler ignores its conn, so only its ctx ending lets it report.
	handler := HandlerFunc(func(ctx context.Context, f Flow) {
		if _, err := f.Accept(); err != nil {
			return
		}
		served <- f.Network()
		select {
		case <-ctx.Done():
			ended <- f.Network()
		case <-time.After(testWait):
		}
	})
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", "", handler)
		m.Handle("udp", "", handler)
	})
	env.dialTCP(t, "10.0.0.9:443")
	testSend(t, env.dialUDP(t, "10.0.0.9:5000"), "datagram")
	for range 2 {
		testReceive(t, served, "a served flow")
	}
	env.cancel()
	got := map[string]bool{}
	for range 2 {
		select {
		case network := <-ended:
			got[network] = true
		case <-time.After(testWait):
			t.Fatalf("ServeFlow's ctx ended for %v of tcp and udp within %v of Serve's ctx ending, want both", got, testWait)
		}
	}
	if !got["tcp"] || !got["udp"] {
		t.Fatalf("ServeFlow's ctx ended for %v, want tcp and udp", got)
	}
}

func TestServeReturnsDeviceReadError(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	injected := errors.New("test read failure")
	env.dev.failRead(injected)
	if err := env.wait(t); !errors.Is(err, injected) {
		t.Fatalf("Serve() = %v after the device Read failed, want an error wrapping %q", err, injected)
	}
	if !env.dev.closedByServe() {
		t.Fatal("Serve returned without closing the device after its Read failed")
	}
}

func TestServeKeepsReadingAfterTooManySegments(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	env.failOneRead(t, tun.ErrTooManySegments)
	conn := env.dialTCP(t, "10.0.0.9:443")
	testDeliver(t, conn, conn, "echoed both ways")
}

func TestServeDeliversPacketsReadWithTooManySegments(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	env.dev.segmentSYN()
	ctx, cancel := context.WithTimeout(env.alive, testWait)
	defer cancel()
	conn, err := env.client.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.9:443"))
	if err != nil {
		t.Fatalf("client dial whose only SYN came from a device Read returning (1, tun.ErrTooManySegments): %v%s, want Serve to inject the packet read with that error", err, env.returned())
	}
	if !env.dev.synSegmented.Load() {
		t.Fatal("the client's SYN bypassed the device Read returning tun.ErrTooManySegments")
	}
	conn.SetDeadline(time.Now().Add(testWait))
	testDeliver(t, conn, conn, "echoed both ways")
}

func TestServeDrainsDeviceEvents(t *testing.T) {
	const sends, wait = 20, 2 * time.Second
	env := testServe(t, Options{Addresses: testAddresses})
	received, all := env.dev.feedEvents(sends)
	select {
	case <-all:
	case <-env.done:
		t.Fatalf("Serve returned %v while the device sent events, want it to ignore them", env.err)
	case <-time.After(wait):
		t.Fatalf("Serve received %d of %d events sent on the device's unbuffered Events channel within %v, want it to drain them all", received.Load(), sends, wait)
	}
}

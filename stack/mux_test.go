package stack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"testing"
)

// testFlow is a Flow without a connection, recording whether it was rejected.
type testFlow struct {
	network  string
	target   netip.AddrPort
	rejected bool
}

func (f *testFlow) Network() string           { return f.network }
func (f *testFlow) Target() netip.AddrPort    { return f.target }
func (f *testFlow) Client() netip.AddrPort    { return netip.MustParseAddrPort("10.0.0.2:40000") }
func (f *testFlow) Accept() (net.Conn, error) { return nil, errors.New("testFlow has no conn") }
func (f *testFlow) Reject()                   { f.rejected = true }

func testFlowTo(network, target string) *testFlow {
	return &testFlow{network: network, target: netip.MustParseAddrPort(target)}
}

// testNamed returns a handler appending name to *served.
func testNamed(name string, served *[]string) Handler {
	return HandlerFunc(func(context.Context, Flow) { *served = append(*served, name) })
}

func TestMuxRoutesExactPortBeforeFallback(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var served []string
			m := NewMux()
			m.Handle(network, 0, testNamed("fallback", &served))
			m.Handle(network, 443, testNamed("443", &served))
			f := testFlowTo(network, "10.0.0.9:443")
			m.ServeFlow(t.Context(), f)
			if len(served) != 1 || served[0] != "443" || f.rejected {
				t.Fatalf("%s flow to port 443 served by %q, rejected %v; want only the port-443 handler", network, served, f.rejected)
			}
		})
	}
}

func TestMuxRoutesOtherPortsToNetworkFallback(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var served []string
			m := NewMux()
			m.Handle(network, 0, testNamed("fallback", &served))
			m.Handle(network, 443, testNamed("443", &served))
			f := testFlowTo(network, "10.0.0.9:80")
			m.ServeFlow(t.Context(), f)
			if len(served) != 1 || served[0] != "fallback" || f.rejected {
				t.Fatalf("%s flow to port 80 served by %q, rejected %v; want only the %s fallback", network, served, f.rejected, network)
			}
		})
	}
}

func TestMuxRejectsFlowWithoutHandler(t *testing.T) {
	for _, tc := range []struct{ network, other string }{{"tcp", "udp"}, {"udp", "tcp"}} {
		t.Run(tc.network, func(t *testing.T) {
			var served []string
			m := NewMux()
			m.Handle(tc.network, 53, testNamed("53", &served))
			m.Handle(tc.other, 0, testNamed(tc.other+" fallback", &served))
			m.Handle(tc.other, 1234, testNamed(tc.other+" 1234", &served))
			f := testFlowTo(tc.network, "10.0.0.9:1234")
			m.ServeFlow(t.Context(), f)
			if !f.rejected || len(served) != 0 {
				t.Fatalf("%s flow to port 1234 with no %s handler: rejected %v, served by %q; want rejected and no handler invoked", tc.network, tc.network, f.rejected, served)
			}
		})
	}
}

func TestMuxHandlePanics(t *testing.T) {
	noop := HandlerFunc(func(context.Context, Flow) {})
	for _, tc := range []struct {
		name string
		do   func(m *Mux)
	}{
		{"unknown network", func(m *Mux) { m.Handle("ip", 0, noop) }},
		{"nil handler", func(m *Mux) { m.Handle("tcp", 80, nil) }},
		{"duplicate", func(m *Mux) { m.Handle("udp", 53, noop); m.Handle("udp", 53, noop) }},
		{"duplicate fallback", func(m *Mux) { m.Handle("tcp", 0, noop); m.Handle("tcp", 0, noop) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("Handle did not panic on a registration with %s", tc.name)
				}
			}()
			tc.do(NewMux())
		})
	}
}

func TestDefaultMuxRegistersRelayDNSAndUDPRelay(t *testing.T) {
	d := &fakeDialer{}
	want := map[muxKey]Handler{{"tcp", 0}: &Relay{Dialer: d}, {"udp", 53}: &DNS{Dialer: d}, {"udp", 0}: &Relay{Dialer: d}}
	if got := DefaultMux(d).handlers; !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultMux registers %v, want exactly tcp/0 Relay, udp/53 DNS and udp/0 Relay over its dialer", got)
	}
}

// relayDialListener is a Dialer that is also a ListenConfig.
type relayDialListener struct {
	*udpRelayDialer
	*coneListener
}

func TestDefaultMuxGivesUDPRelayTheDialersListenConfig(t *testing.T) {
	d := relayDialListener{&udpRelayDialer{}, &coneListener{}}
	want := map[muxKey]Handler{{"tcp", 0}: &Relay{Dialer: d}, {"udp", 53}: &DNS{Dialer: d}, {"udp", 0}: &Relay{Dialer: d, ListenConfig: d}}
	if got := DefaultMux(d).handlers; !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultMux registers %v, want tcp/0 Relay, udp/53 DNS and udp/0 Relay with the dialer as its ListenConfig", got)
	}
}

func TestDefaultMuxRelaysUDPFullConeThroughADialersListenConfig(t *testing.T) {
	dialer := &udpRelayDialer{targets: make(chan *udpRelayTarget, 16)}
	t.Cleanup(dialer.closeAll)
	listener := newConeListener(t)
	env := testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler {
		return DefaultMux(relayDialListener{dialer, listener})
	})
	testSend(t, env.dialUDP(t, "10.0.0.9:5000"), "datagram")
	if got := listener.nextCone(t, env).recv(t); string(got) != "datagram" {
		t.Fatalf("target got %q, want %q", got, "datagram")
	}
	if calls, dials := listener.recorded(), dialer.recorded(); len(calls) != 1 || len(dials) != 0 {
		t.Fatalf("DefaultMux's UDP Relay listened %+v and dialled %+v, want one ListenPacket and no DialContext", calls, dials)
	}
}

// dialerWithoutListen is a Dialer with ListenPacket but no Listen.
type dialerWithoutListen struct {
	*udpRelayDialer
	packets *coneListener
}

func (d dialerWithoutListen) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.packets.ListenPacket(ctx, network, address)
}

func TestDefaultMuxRelaysUDPSymmetricForADialerWithoutListen(t *testing.T) {
	dialer := &udpRelayDialer{targets: make(chan *udpRelayTarget, 16)}
	t.Cleanup(dialer.closeAll)
	listener := newConeListener(t)
	env := testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler {
		return DefaultMux(dialerWithoutListen{dialer, listener})
	})
	testSend(t, env.dialUDP(t, "10.0.0.9:5000"), "datagram")
	if got := dialer.next(t, env).recv(t); string(got) != "datagram" {
		t.Fatalf("target got %q, want %q", got, "datagram")
	}
	if calls, dials := listener.recorded(), dialer.recorded(); len(calls) != 0 || len(dials) != 1 {
		t.Fatalf("DefaultMux's UDP Relay listened %+v and dialled %+v, want no ListenPacket and one DialContext", calls, dials)
	}
}

func TestDefaultMuxRoutesUDPByPort(t *testing.T) {
	for _, tc := range []struct{ name, target, network string }{
		{"port 53 to DNS over tcp", "10.0.0.53:53", "tcp"},
		{"other port to Relay over udp", "10.0.0.9:5000", "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testServe(t, Options{Addresses: testAddresses})
			testSend(t, env.dialUDP(t, tc.target), "datagram")
			env.nextTarget(t)
			if dials := env.dialer.recorded(); len(dials) != 1 || dials[0].network != tc.network || dials[0].address != tc.target {
				t.Fatalf("DefaultMux dialed %+v for UDP to %s, want one %s dial", dials, tc.target, tc.network)
			}
		})
	}
}

func TestMuxHandleConcurrentWithServeFlow(t *testing.T) {
	m := NewMux()
	m.Handle("tcp", 0, HandlerFunc(func(context.Context, Flow) {}))
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() { m.Handle("udp", uint16(1000+i), HandlerFunc(func(context.Context, Flow) {})) })
		wg.Go(func() { m.ServeFlow(t.Context(), testFlowTo("tcp", fmt.Sprintf("10.0.0.9:%d", 1000+i))) })
	}
	wg.Wait()
}

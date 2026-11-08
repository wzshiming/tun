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
			m.Handle(network, "", testNamed("fallback", &served))
			m.Handle(network, ":443", testNamed("443", &served))
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
			m.Handle(network, "", testNamed("fallback", &served))
			m.Handle(network, ":443", testNamed("443", &served))
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
			m.Handle(tc.network, ":53", testNamed("53", &served))
			m.Handle(tc.other, "", testNamed(tc.other+" fallback", &served))
			m.Handle(tc.other, ":1234", testNamed(tc.other+" 1234", &served))
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
		{"unknown network", func(m *Mux) { m.Handle("ip", "", noop) }},
		{"nil handler", func(m *Mux) { m.Handle("tcp", ":80", nil) }},
		{"duplicate", func(m *Mux) { m.Handle("udp", ":53", noop); m.Handle("udp", ":53", noop) }},
		{"duplicate any", func(m *Mux) { m.Handle("tcp", "", noop); m.Handle("tcp", "", noop) }},
		{"duplicate any as :0", func(m *Mux) { m.Handle("tcp", "", noop); m.Handle("tcp", ":0", noop) }},
		{"duplicate masked prefix", func(m *Mux) { m.Handle("udp", "10.0.0.1/8", noop); m.Handle("udp", "10.0.0.0/8", noop) }},
		{"duplicate prefix and port", func(m *Mux) { m.Handle("udp", "[fd00::/8]:53", noop); m.Handle("udp", "[fd00::/8]:53", noop) }},
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

func TestMuxHandlePanicsOnInvalidPattern(t *testing.T) {
	noop := HandlerFunc(func(context.Context, Flow) {})
	for _, pattern := range []string{"example.com:53", "example.com", "10.0.0.0/8:", ":", ":65536", ":abc", ":-1", "fd00::/8:53", "10.0.0.0/33", "1.2.3", "[10.0.0.0/8"} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("Handle(%q) did not panic on an unparsable pattern", pattern)
				}
			}()
			NewMux().Handle("tcp", pattern, noop)
		})
	}
}

func TestMuxHandleParsesPattern(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		prefix  string // "" for any address
		port    uint16
	}{
		{"", "", 0},
		{":53", "", 53},
		{":0", "", 0},
		{"1.1.1.1", "1.1.1.1/32", 0},
		{"1.1.1.1:443", "1.1.1.1/32", 443},
		{"10.0.0.0/8", "10.0.0.0/8", 0},
		{"10.0.0.0/8:53", "10.0.0.0/8", 53},
		{"10.0.0.1/8", "10.0.0.0/8", 0},
		{"[fd00::/8]:53", "fd00::/8", 53},
		{"[fd00::/8]", "fd00::/8", 0},
		{"fd00::/8", "fd00::/8", 0},
		{"[2001:db8::1]:443", "2001:db8::1/128", 443},
		{"2001:db8::1", "2001:db8::1/128", 0},
		{"::ffff:10.0.0.1", "10.0.0.1/32", 0},
		{":65535", "", 65535},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			m := NewMux()
			h := HandlerFunc(func(context.Context, Flow) {})
			m.Handle("udp", tc.pattern, h)
			want := muxRoute{network: "udp", port: tc.port}
			if tc.prefix != "" {
				want.prefix = netip.MustParsePrefix(tc.prefix)
			}
			if _, ok := m.handlers[want]; !ok || len(m.handlers) != 1 {
				t.Fatalf("Handle(%q) registered %v, want only %+v", tc.pattern, m.handlers, want)
			}
		})
	}
}

func TestMuxLayersLongestPrefixFirstWithFallThrough(t *testing.T) {
	for _, tc := range []struct {
		name     string
		patterns []string
		target   string
		want     string // a pattern, or "reject"
	}{
		{"prefix and port beat prefix, any address and other hosts", []string{"1.1.1.1:53", "10.0.0.0/8:53", "10.0.0.0/8", ":53", ""}, "10.1.2.3:53", "10.0.0.0/8:53"},
		{"prefix any port beats any address", []string{"1.1.1.1:53", "10.0.0.0/8:53", "10.0.0.0/8", ":53", ""}, "10.1.2.3:80", "10.0.0.0/8"},
		{"longer prefix beats a more specific port", []string{"10.1.2.3", "10.0.0.0/8:53"}, "10.1.2.3:53", "10.1.2.3"},
		{"longer prefix beats shorter prefix", []string{"10.0.0.0/8", "10.1.0.0/16", "0.0.0.0/0"}, "10.1.2.3:80", "10.1.0.0/16"},
		{"a layer without the port falls through to a shorter prefix", []string{"10.1.0.0/16:53", "10.0.0.0/8"}, "10.1.2.3:80", "10.0.0.0/8"},
		{"a layer without the port falls through to any address", []string{"10.0.0.0/8:53", ":80"}, "10.1.2.3:80", ":80"},
		{"nothing matches", []string{"10.0.0.0/8:53"}, "10.1.2.3:80", "reject"},
		{"an IPv6 target skips IPv4 entries", []string{"0.0.0.0/0", "10.0.0.0/8:53"}, "[2001:db8::5]:53", "reject"},
		{"an IPv6 target reaches any address", []string{"0.0.0.0/0", ""}, "[2001:db8::5]:53", ""},
		{"an IPv4 target skips IPv6 entries", []string{"::/0", "[::]:53"}, "10.1.2.3:53", "reject"},
		{"an IPv6 target matches IPv6 entries", []string{"2001:db8::/32", "::/0", "10.0.0.0/8"}, "[2001:db8::5]:53", "2001:db8::/32"},
		{"an IPv4-mapped target matches IPv4 entries", []string{"::/0", "10.0.0.0/8:53"}, "[::ffff:10.1.2.3]:53", "10.0.0.0/8:53"},
	} {
		for _, network := range []string{"tcp", "udp"} {
			t.Run(network+"/"+tc.name, func(t *testing.T) {
				var served []string
				m := NewMux()
				for _, p := range tc.patterns {
					m.Handle(network, p, testNamed(p, &served))
				}
				f := testFlowTo(network, tc.target)
				m.ServeFlow(t.Context(), f)
				if tc.want == "reject" {
					if !f.rejected || len(served) != 0 {
						t.Fatalf("%s flow to %s with %q: served by %q, rejected %v; want rejected and no handler", network, tc.target, tc.patterns, served, f.rejected)
					}
					return
				}
				if len(served) != 1 || served[0] != tc.want || f.rejected {
					t.Fatalf("%s flow to %s with %q: served by %q, rejected %v; want only %q", network, tc.target, tc.patterns, served, f.rejected, tc.want)
				}
			})
		}
	}
}

func TestMuxFallbackServesUnmatchedFlows(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var served []string
			var got Flow
			m := NewMux()
			m.Handle(network, "10.0.0.0/8:53", testNamed("10.0.0.0/8:53", &served))
			m.Fallback = HandlerFunc(func(_ context.Context, f Flow) { got = f })
			f := testFlowTo(network, "10.1.2.3:80")
			m.ServeFlow(t.Context(), f)
			if got != f || f.rejected || len(served) != 0 {
				t.Fatalf("%s flow matching no layer: Fallback got %v, rejected %v, served by %q; want only Fallback with the flow", network, got, f.rejected, served)
			}
		})
	}
}

func TestMuxFallbackNotCalledForMatchedFlows(t *testing.T) {
	var served []string
	m := NewMux()
	m.Handle("tcp", "10.0.0.0/8:53", testNamed("10.0.0.0/8:53", &served))
	m.Fallback = testNamed("fallback", &served)
	m.ServeFlow(t.Context(), testFlowTo("tcp", "10.1.2.3:53"))
	if len(served) != 1 || served[0] != "10.0.0.0/8:53" {
		t.Fatalf("matched flow served by %q, want only 10.0.0.0/8:53", served)
	}
}

// testRoutes returns the handlers keyed by the route each network and pattern pair parses to.
func testRoutes(t *testing.T, entries ...any) map[muxRoute]Handler {
	t.Helper()
	routes := make(map[muxRoute]Handler)
	for i := 0; i < len(entries); i += 3 {
		m := NewMux()
		m.Handle(entries[i].(string), entries[i+1].(string), entries[i+2].(Handler))
		for r, h := range m.handlers {
			routes[r] = h
		}
	}
	return routes
}

func TestDefaultMuxRegistersRelayDNSAndUDPRelay(t *testing.T) {
	d := &fakeDialer{}
	want := testRoutes(t, "tcp", "", &Relay{Dialer: d}, "udp", ":53", &DNS{Dialer: d}, "udp", "", &Relay{Dialer: d})
	m := DefaultMux(d)
	if !reflect.DeepEqual(m.handlers, want) || m.Fallback != nil {
		t.Fatalf("DefaultMux registers %v with Fallback %v, want exactly tcp \"\" Relay, udp \":53\" DNS and udp \"\" Relay over its dialer and no Fallback", m.handlers, m.Fallback)
	}
}

// relayDialListener is a Dialer that is also a ListenConfig.
type relayDialListener struct {
	*udpRelayDialer
	*coneListener
}

func TestDefaultMuxGivesUDPRelayTheDialersListenConfig(t *testing.T) {
	d := relayDialListener{&udpRelayDialer{}, &coneListener{}}
	want := testRoutes(t, "tcp", "", &Relay{Dialer: d}, "udp", ":53", &DNS{Dialer: d}, "udp", "", &Relay{Dialer: d, ListenConfig: d})
	if got := DefaultMux(d).handlers; !reflect.DeepEqual(got, want) {
		t.Fatalf("DefaultMux registers %v, want tcp \"\" Relay, udp \":53\" DNS and udp \"\" Relay with the dialer as its ListenConfig", got)
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
	m.Handle("tcp", "", HandlerFunc(func(context.Context, Flow) {}))
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			m.Handle("udp", fmt.Sprintf("10.%d.0.0/16:%d", i, 1000+i), HandlerFunc(func(context.Context, Flow) {}))
		})
		wg.Go(func() { m.ServeFlow(t.Context(), testFlowTo("udp", fmt.Sprintf("10.%d.0.9:%d", i, 1000+i))) })
	}
	wg.Wait()
}

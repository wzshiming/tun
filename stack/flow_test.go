package stack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// testServeMux serves a Mux register fills.
func testServeMux(t *testing.T, register func(m *Mux)) *testEnv {
	t.Helper()
	return testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler {
		m := NewMux()
		register(m)
		return m
	})
}

// testAnswer returns a handler that sends name on served, accepts the flow and answers one datagram with name.
func testAnswer(name string, served chan<- string) Handler {
	return HandlerFunc(func(_ context.Context, f Flow) {
		served <- name
		conn, err := f.Accept()
		if err != nil || f.Network() != "udp" {
			return
		}
		conn.SetDeadline(time.Now().Add(testWait))
		if _, err := conn.Read(make([]byte, 512)); err == nil {
			conn.Write([]byte(name))
		}
	})
}

func testServed(t *testing.T, served <-chan string, want string) {
	t.Helper()
	select {
	case got := <-served:
		if got != want {
			t.Fatalf("flow served by %q, want %q", got, want)
		}
	case <-time.After(testWait):
		t.Fatalf("no handler served the flow within %v, want %q", testWait, want)
	}
}

func testNoneServed(t *testing.T, served <-chan string) {
	t.Helper()
	select {
	case got := <-served:
		t.Fatalf("flow served by %q, want no handler invoked", got)
	default:
	}
}

func testReadReply(t *testing.T, conn net.Conn, want string) {
	t.Helper()
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil || string(reply[:n]) != want {
		t.Fatalf("client Read() = %q, %v, want %q", reply[:n], err, want)
	}
}

func TestServeDispatchesTCPByPort(t *testing.T) {
	served := make(chan string, 4)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", 443, testAnswer("tcp/443", served))
		m.Handle("tcp", 0, testAnswer("tcp fallback", served))
	})
	env.dialTCP(t, "10.0.0.9:443")
	testServed(t, served, "tcp/443")
	env.dialTCP(t, "10.0.0.9:80")
	testServed(t, served, "tcp fallback")
}

func TestServeRefusesTCPWithoutHandler(t *testing.T) {
	served := make(chan string, 4)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", 443, testAnswer("tcp/443", served))
		m.Handle("udp", 0, testAnswer("udp fallback", served))
	})
	env.dialTCPRefused(t, "10.0.0.9:80")
	testNoneServed(t, served)
}

func TestServeNilHandlerRefusesTCP(t *testing.T) {
	env := testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler { return nil })
	env.dialTCPRefused(t, "10.0.0.9:443")
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called with a nil handler: %+v, want no dial", dials)
	}
}

func TestServeDispatchesUDPByPort(t *testing.T) {
	served := make(chan string, 4)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 5353, testAnswer("udp/5353", served))
		m.Handle("udp", 0, testAnswer("udp fallback", served))
	})
	conn := env.dialUDP(t, "10.0.0.9:5353")
	testSend(t, conn, "query")
	testServed(t, served, "udp/5353")
	testReadReply(t, conn, "udp/5353")
	conn = env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "query")
	testServed(t, served, "udp fallback")
	testReadReply(t, conn, "udp fallback")
}

func TestServeDropsUDPWithoutHandler(t *testing.T) {
	served := make(chan string, 4)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 53, testAnswer("udp/53", served))
		m.Handle("tcp", 0, testAnswer("tcp fallback", served))
	})
	conn := env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "query")
	var netErr net.Error
	if err := testUDPError(t, env, conn, testSilence); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() = %v, want a timeout with no reply and no ICMP error", err)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable for unhandled UDP, want the datagram dropped", n)
	}
	testNoneServed(t, served)
}

func TestFlowReportsNetworkTargetClient(t *testing.T) {
	type facts struct {
		network        string
		target, client netip.AddrPort
	}
	for _, tc := range []struct{ name, network, target string }{
		{"tcp4", "tcp", "10.0.0.9:443"},
		{"tcp6", "tcp", "[fd00::9]:443"},
		{"udp4", "udp", "10.0.0.9:5353"},
		{"udp6", "udp", "[fd00::9]:5353"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := make(chan facts, 1)
			env := testServeMux(t, func(m *Mux) {
				m.Handle(tc.network, 0, HandlerFunc(func(_ context.Context, f Flow) {
					got <- facts{f.Network(), f.Target(), f.Client()}
					f.Accept()
				}))
			})
			var client net.Addr
			if tc.network == "tcp" {
				client = env.dialTCP(t, tc.target).LocalAddr()
			} else {
				conn := env.dialUDP(t, tc.target)
				testSend(t, conn, "query")
				client = conn.LocalAddr()
			}
			want := facts{tc.network, netip.MustParseAddrPort(tc.target), netip.MustParseAddrPort(client.String())}
			select {
			case f := <-got:
				if f != want {
					t.Fatalf("Flow reported %+v, want %+v", f, want)
				}
			case <-time.After(testWait):
				t.Fatal("no flow reached the handler")
			}
		})
	}
}

// testServeFlow opens a flow of network to the handler's fallback and returns once that handler has returned.
func testServeFlow(t *testing.T, network string, handler func(Flow)) *testEnv {
	t.Helper()
	returned := make(chan struct{})
	env := testServeMux(t, func(m *Mux) {
		m.Handle(network, 0, HandlerFunc(func(_ context.Context, f Flow) {
			defer close(returned)
			handler(f)
		}))
	})
	if network == "tcp" {
		ctx, cancel := context.WithTimeout(env.alive, testWait)
		defer cancel()
		if conn, err := env.client.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.9:443")); err == nil {
			t.Cleanup(func() { conn.Close() })
		}
	} else {
		testSend(t, env.dialUDP(t, "10.0.0.9:5353"), "query")
	}
	select {
	case <-returned:
	case <-time.After(testWait):
		t.Fatalf("the %s handler did not return within %v", network, testWait)
	}
	return env
}

func TestFlowSecondAcceptErrors(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var first, second error
			testServeFlow(t, network, func(f Flow) {
				_, first = f.Accept()
				_, second = f.Accept()
			})
			if first != nil || second == nil {
				t.Fatalf("Accept() twice = %v then %v, want nil then an error", first, second)
			}
		})
	}
}

func TestFlowAcceptAfterRejectErrors(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var err error
			testServeFlow(t, network, func(f Flow) {
				f.Reject()
				_, err = f.Accept()
			})
			if err == nil {
				t.Fatal("Accept() after Reject() = nil error, want an error")
			}
		})
	}
}

func TestTCPFlowUnansweredIsRefused(t *testing.T) {
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", 0, HandlerFunc(func(context.Context, Flow) {}))
	})
	env.dialTCPRefused(t, "10.0.0.9:443")
}

func TestUDPFlowUnansweredIsDropped(t *testing.T) {
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 0, HandlerFunc(func(context.Context, Flow) {}))
	})
	conn := env.dialUDP(t, "10.0.0.9:5353")
	testSend(t, conn, "query")
	var netErr net.Error
	if err := testUDPError(t, env, conn, testSilence); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() = %v, want a timeout with no reply and no ICMP error", err)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable for a UDP flow its handler left unanswered, want none", n)
	}
}

func TestRejectedUDPFlowFreesItsEndpoint(t *testing.T) {
	served := make(chan struct{}, 4)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 0, HandlerFunc(func(_ context.Context, f Flow) {
			f.Reject()
			served <- struct{}{}
		}))
	})
	conn := env.dialUDP(t, "10.0.0.9:5353")
	for i, datagram := range []string{"first", "second"} {
		testSend(t, conn, datagram)
		select {
		case <-served:
		case <-time.After(testWait):
			t.Fatalf("datagram %d from the same client socket served no flow after the first flow was rejected, want Reject to free its endpoint", i+1)
		}
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable for a rejected UDP flow, want none", n)
	}
}

func TestServeClosesConnLeftOpenByServeFlow(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var conn net.Conn
			testServeFlow(t, network, func(f Flow) {
				conn, _ = f.Accept()
			})
			if conn == nil {
				t.Fatal("Accept() returned no conn")
			}
			conn.SetReadDeadline(time.Now().Add(testWait))
			// testServeFlow returns before Serve closes the conn, so datagrams still queued on it are read first.
			var err error
			for err == nil {
				_, err = conn.Read(make([]byte, 512))
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatalf("Read() on the conn a returned ServeFlow left open = %v, want it closed by Serve", err)
			}
		})
	}
}

func TestServeCancelClosesAcceptedConnsAndWaitsForServeFlow(t *testing.T) {
	accepted := make(chan struct{}, 2)
	var returned atomic.Int32
	// The handler ignores ctx, so only Serve closing its conn wakes it.
	handler := HandlerFunc(func(_ context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		conn.SetReadDeadline(time.Now().Add(testWait))
		for {
			if _, err := conn.Read(make([]byte, 512)); err != nil {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
		returned.Add(1)
	})
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", 0, handler)
		m.Handle("udp", 0, handler)
	})
	env.dialTCP(t, "10.0.0.9:443")
	testSend(t, env.dialUDP(t, "10.0.0.9:5353"), "query")
	for range 2 {
		select {
		case <-accepted:
		case <-time.After(testWait):
			t.Fatal("the handler did not accept both flows")
		}
	}
	start := time.Now()
	env.cancel()
	env.wait(t)
	if elapsed := time.Since(start); elapsed > testStopBound {
		t.Fatalf("Serve took %v to return, want the accepted conns closed at once", elapsed)
	}
	if n := returned.Load(); n != 2 {
		t.Fatalf("Serve returned with %d of 2 ServeFlow calls returned, want it to wait for all", n)
	}
}

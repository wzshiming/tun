package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// testQuery is a DNS query, ID 0x1234, for the A record of example.com.
const testQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

// testAgain is how often a waiting test sends again: the relay loses a datagram that arrives while it drops its server's conn.
const testAgain = 50 * time.Millisecond

// testServeVia is testServe on a "udp" flow, except that h dials through via of the env's fakeDialer.
func testServeVia(t *testing.T, h *Handler, via func(*fakeDialer) stack.Dialer) *testEnv {
	t.Helper()
	env := &testEnv{dialer: &fakeDialer{servers: make(chan *fakeServer, 64)}, session: stacktest.NewSession(testClient, testServer), done: make(chan struct{})}
	env.flow = stacktest.NewFlow("udp", testClient, testServer, env.session)
	h.Dialer = via(env.dialer)
	ctx, cancel := context.WithCancel(context.Background())
	env.cancel = cancel
	go func() {
		defer close(env.done)
		h.ServeFlow(ctx, env.flow)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-env.done:
		case <-time.After(testWait):
			t.Errorf("ServeFlow did not return within %v of its ctx ending", testWait)
		}
		for {
			select {
			case s := <-env.dialer.servers:
				s.Close()
			default:
				return
			}
		}
	})
	return env
}

// heldDial is a dial a gateDialer holds and the ctx it came with.
type heldDial struct {
	dialRecord
	ctx context.Context
}

// gateDialer holds each dial to its held address until the test opens the gate or, unless deaf, the dial's ctx ends; an opened dial and every other one go to fakeDialer.
type gateDialer struct {
	*fakeDialer
	held  string
	deaf  bool
	dials chan heldDial
	gate  chan struct{}
	once  sync.Once
}

func (d *gateDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != d.held {
		return d.fakeDialer.DialContext(ctx, network, address)
	}
	d.dials <- heldDial{dialRecord{network, address, stack.ClientAddr(ctx)}, ctx}
	ended := ctx.Done()
	if d.deaf {
		ended = nil
	}
	select {
	case <-d.gate:
		return d.fakeDialer.DialContext(ctx, network, address)
	case <-ended:
		return nil, ctx.Err()
	}
}

func (d *gateDialer) open() { d.once.Do(func() { close(d.gate) }) }

// testServeGated serves a Handler with Idle idle whose dials to testServer a gateDialer holds until the test opens it or ends.
func testServeGated(t *testing.T, idle time.Duration, deaf bool) (*testEnv, *gateDialer) {
	t.Helper()
	gate := &gateDialer{held: testServer.String(), deaf: deaf, dials: make(chan heldDial, 16), gate: make(chan struct{})}
	env := testServeVia(t, &Handler{Idle: idle}, func(d *fakeDialer) stack.Dialer {
		gate.fakeDialer = d
		return gate
	})
	t.Cleanup(gate.open)
	return env, gate
}

// testReceive returns what ch delivers within testWait.
func testReceive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testWait):
		t.Fatalf("no %s within %v", what, testWait)
		panic("unreachable")
	}
}

// testAwait returns what ch delivers within bound, calling again at once and every testAgain until then.
func testAwait[T any](t *testing.T, env *testEnv, ch <-chan T, bound time.Duration, what string, again func()) T {
	t.Helper()
	deadline := time.After(bound)
	for {
		again()
		select {
		case v := <-ch:
			return v
		case <-env.done:
			t.Fatalf("ServeFlow returned before the %s", what)
		case <-deadline:
			t.Fatalf("no %s within %v", what, bound)
		case <-time.After(testAgain):
		}
	}
}

func TestAbandonsDialNotBackWithinIdle(t *testing.T) {
	const idle = 400 * time.Millisecond
	env, gate := testServeGated(t, idle, false)
	start := time.Now()
	// Datagrams relayed to a second server keep the session from idling, which would end the dial's ctx as well.
	env.send("keep", testOther)
	other := env.nextServer(t)
	testReadFrame(t, other)
	keep := func() {
		env.send("keep", testOther)
		testReadFrame(t, other)
	}
	env.send(testQuery, testServer)
	dial := testReceive(t, gate.dials, "dial to the server")
	if dial.network != "tcp" || dial.address != testServer.String() || dial.client == nil || dial.client.String() != testClient.String() {
		t.Fatalf("dial %+v, want tcp to %v tagged with the client %v", dial.dialRecord, testServer, testClient)
	}
	testAwait(t, env, dial.ctx.Done(), testIdleBound, "end of the ctx of a dial that never returns", keep)
	if held := time.Since(start); held < idle {
		t.Fatalf("the ctx of a dial that never returns ended %v after the test began to send, want Handler.Idle %v to pass first", held, idle)
	}
	testAwait(t, env, gate.dials, testWait, "second dial to a server whose first dial was abandoned", func() {
		keep()
		env.send(testQuery, testServer)
	})
	if data, from, ok := env.session.NextReply(0); ok {
		t.Fatalf("client got %q from %v, want nothing: no dial reached a server", data, from)
	}
}

func TestSessionEndDoesNotWaitForDial(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(*testEnv)
	}{
		{"ctx ends", func(env *testEnv) { env.cancel() }},
		{"client conn fails", func(env *testEnv) { env.session.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, gate := testServeGated(t, 0, true)
			env.send(testQuery, testServer)
			dial := testReceive(t, gate.dials, "dial to the server")
			tc.end(env)
			env.waitDone(t, testIdleBound, "its session ended while a dial hung")
			testReceive(t, dial.ctx.Done(), "end of the ctx of a dial whose session ended")
			// The dial comes back with a conn after all, which nobody waits for any more.
			gate.open()
			late := testReceive(t, env.dialer.servers, "conn of the dial let through")
			t.Cleanup(func() { late.Close() })
			testReceive(t, late.remote.closed, "close of the conn a dial brought after its session ended")
		})
	}
}

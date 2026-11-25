package dns

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// testQuery is a DNS query, ID 0x1234, for the A record of example.com.
const testQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

// testReply answers testQuery with one A record.
const testReply = "\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"

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

// gateDialer holds each dial to its held address, but the first pass of them, until the test opens the gate or, unless deaf, the dial's ctx ends; an opened dial and every other one go to fakeDialer.
type gateDialer struct {
	*fakeDialer
	held  string
	pass  atomic.Int32
	deaf  bool
	dials chan heldDial
	gate  chan struct{}
	once  sync.Once
}

func (d *gateDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != d.held || d.pass.Add(-1) >= 0 {
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
	for _, tc := range []struct {
		name string
		// again puts the dial for a query that a closed conn left unanswered under test, not the server's first.
		again bool
	}{
		{"first dial", false},
		{"dial for a query sent again", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			env, gate := testServeGated(t, idle, false)
			// Datagrams relayed to a second server keep the session from idling, which would end the dial's ctx as well.
			env.send("keep", testOther)
			other := env.nextServer(t)
			testReadFrame(t, other)
			keep := func() {
				env.send("keep", testOther)
				testReadFrame(t, other)
			}
			if tc.again {
				gate.pass.Store(1)
			}
			env.send(testQuery, testServer)
			if tc.again {
				first := env.nextServer(t)
				if got := testReadFrame(t, first); got != testQuery {
					t.Fatalf("server read %q, want the query %q", got, testQuery)
				}
				first.Close()
			}
			dial := testReceive(t, gate.dials, "dial to the server")
			if dial.network != "tcp" || dial.address != testServer.String() || dial.client == nil || dial.client.String() != testClient.String() {
				t.Fatalf("dial %+v, want tcp to %v tagged with the client %v", dial.dialRecord, testServer, testClient)
			}
			testAwait(t, env, dial.ctx.Done(), testIdleBound, "end of the ctx of a dial that never returns", keep)
			if held := time.Since(start); held < idle {
				t.Fatalf("the ctx of a dial that never returns ended %v after its session began, want Handler.Idle %v to pass first", held, idle)
			}
			testAwait(t, env, gate.dials, testWait, "next dial to a server whose dial was abandoned", func() {
				keep()
				env.send(testQuery, testServer)
			})
			if data, from, ok := env.session.NextReply(0); ok {
				t.Fatalf("client got %q from %v, want nothing: no server answered", data, from)
			}
		})
	}
}

func TestSessionEndDoesNotWaitForDial(t *testing.T) {
	for _, tc := range []struct {
		name string
		idle time.Duration
		end  func(*testEnv)
	}{
		{"ctx ends", 0, func(env *testEnv) { env.cancel() }},
		{"client conn fails", 0, func(env *testEnv) { env.session.Close() }},
		{"session idles", 300 * time.Millisecond, func(*testEnv) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, gate := testServeGated(t, tc.idle, true)
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

// resetConn is a TCP conn reset under the relay: Write fails at once, and Read does once the conn is closed.
type resetConn struct {
	net.Conn
	closed chan struct{}
	closes atomic.Int32
}

func (c *resetConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *resetConn) Write([]byte) (int, error) {
	return 0, errors.New("write: connection reset by peer")
}

func (c *resetConn) Close() error {
	if c.closes.Add(1) == 1 {
		close(c.closed)
	}
	return nil
}

// resetFirstDialer answers its first dial with a resetConn and passes the later ones on to fakeDialer.
type resetFirstDialer struct {
	*fakeDialer
	first   *resetConn
	dialled atomic.Bool
}

func (d *resetFirstDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.dialled.CompareAndSwap(false, true) {
		return d.first, nil
	}
	return d.fakeDialer.DialContext(ctx, network, address)
}

// expectDials fails unless fakeDialer was dialled want times, each time tcp to testServer for the client.
func (env *testEnv) expectDials(t *testing.T, want int) {
	t.Helper()
	dials := env.dialer.recorded()
	if len(dials) != want {
		t.Fatalf("dialer.DialContext called %d times %+v, want %d", len(dials), dials, want)
	}
	for _, dial := range dials {
		if dial.network != "tcp" || dial.address != testServer.String() || dial.client == nil || dial.client.String() != testClient.String() {
			t.Fatalf("dial %+v, want tcp to %v tagged with the client %v", dial, testServer, testClient)
		}
	}
}

// expectNoneSentAgain sends probes until the relay dials again, then "end", and fails unless that conn reads only them and fakeDialer was dialled dials times: what went out before the last conn closed would come again first.
func (env *testEnv) expectNoneSentAgain(t *testing.T, dials int) {
	t.Helper()
	server := testAwait(t, env, env.dialer.servers, testWait, "dial for a datagram sent since the conn closed", func() { env.send("probe", testServer) })
	t.Cleanup(func() { server.Close() })
	env.send("end", testServer)
	for got := ""; got != "end"; {
		if got = testReadFrame(t, server); got != "probe" && got != "end" {
			t.Fatalf("the conn dialled once the last one closed read %q, want only what was sent since", got)
		}
	}
	env.expectDials(t, dials)
}

func TestSendsUnansweredQueryAgainOnNewConn(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send(testQuery, testServer)
	first := env.nextServer(t)
	if got := testReadFrame(t, first); got != testQuery {
		t.Fatalf("server read %q, want the query %q", got, testQuery)
	}
	first.Close()
	second := env.nextServer(t)
	if got := testReadFrame(t, second); got != testQuery {
		t.Fatalf("the conn dialled once the first closed read %q, want the query it left unanswered %q", got, testQuery)
	}
	testWriteFrame(t, second, testReply)
	if got, want := env.nextReply(t), (datagram{testReply, testServer}); got != want {
		t.Fatalf("client, which sent its query once, got %+v, want %+v", got, want)
	}
	env.expectDials(t, 2)
}

func TestSendsQueryAgainAfterItsWriteFailed(t *testing.T) {
	reset := &resetConn{closed: make(chan struct{})}
	env := testServeVia(t, &Handler{}, func(d *fakeDialer) stack.Dialer { return &resetFirstDialer{fakeDialer: d, first: reset} })
	env.send(testQuery, testServer)
	server := env.nextServer(t)
	if got := testReadFrame(t, server); got != testQuery {
		t.Fatalf("the conn dialled once a Write failed read %q, want the query that Write lost %q", got, testQuery)
	}
	testWriteFrame(t, server, testReply)
	if got, want := env.nextReply(t), (datagram{testReply, testServer}); got != want {
		t.Fatalf("client, which sent its query once, got %+v, want %+v", got, want)
	}
	if closes := reset.closes.Load(); closes != 1 {
		t.Fatalf("the conn whose Write failed was closed %d times, want once", closes)
	}
	// fakeDialer saw every dial but the first, which got the reset conn.
	env.expectDials(t, 1)
}

func TestSendsUnansweredQueryAgainOnlyOnce(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send(testQuery, testServer)
	for _, conn := range []string{"first", "second"} {
		server := env.nextServer(t)
		if got := testReadFrame(t, server); got != testQuery {
			t.Fatalf("the %s conn read %q, want the query %q", conn, got, testQuery)
		}
		server.Close()
	}
	env.expectNoneSentAgain(t, 3)
}

func TestDoesNotSendAnsweredQueryAgain(t *testing.T) {
	env := testServeUDP(t, "", 0)
	env.send(testQuery, testServer)
	server := env.nextServer(t)
	if got := testReadFrame(t, server); got != testQuery {
		t.Fatalf("server read %q, want the query %q", got, testQuery)
	}
	testWriteFrame(t, server, testReply)
	if got, want := env.nextReply(t), (datagram{testReply, testServer}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	server.Close()
	env.expectNoneSentAgain(t, 2)
}

func TestDoesNotSendOtherDatagramsAgain(t *testing.T) {
	patch := func(message string, offset int, value byte) string {
		b := []byte(message)
		b[offset] = value
		return string(b)
	}
	for _, tc := range []struct{ name, datagram string }{
		{"shorter than a DNS header", "query"},
		{"a response", patch(testQuery, 2, 0x81)},
		{"another opcode", patch(testQuery, 2, 0x11)},
		{"no question", patch(testQuery[:12], 5, 0)},
		{"two questions", patch(testQuery, 5, 2) + testQuery[12:]},
		{"a question cut short", testQuery[:len(testQuery)-3]},
		{"a record counted but missing", patch(testQuery, 11, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testServeUDP(t, "", 0)
			env.send(tc.datagram, testServer)
			server := env.nextServer(t)
			if got := testReadFrame(t, server); got != tc.datagram {
				t.Fatalf("server read %q, want the datagram as sent %q", got, tc.datagram)
			}
			server.Close()
			env.expectNoneSentAgain(t, 2)
		})
	}
}

package dns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wzshiming/tun/internal/stacktest"
)

// testNextClient is testClient on another port: the client of a second session.
var testNextClient = netip.MustParseAddrPort("10.0.0.2:40001")

// testServeNext serves h as it is, so through the fakeDialer of first, on a "udp" flow of testNextClient to testServer until the test ends.
func testServeNext(t *testing.T, h *Handler, first *testEnv) *testEnv {
	t.Helper()
	env := &testEnv{dialer: first.dialer, session: stacktest.NewSession(testNextClient, testServer), done: make(chan struct{})}
	env.flow = stacktest.NewFlow("udp", testNextClient, testServer, env.session)
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
	})
	return env
}

// testCaching returns h with the clock of its cache standing still, so that a reply is served with the TTLs it came with however slowly the test runs.
func testCaching(h *Handler) *Handler {
	h.cache.now = func() time.Time { return time.Unix(1700000000, 0) }
	return h
}

// fill has the client ask testQuery of server and the conn the relay dials for it answer testReply, and returns that conn once the client has the reply.
func (env *testEnv) fill(t *testing.T, server netip.AddrPort) *fakeServer {
	t.Helper()
	env.send(testQuery, server)
	conn := env.nextServer(t)
	env.answer(t, conn, testQuery, testReply, server)
	return conn
}

// answer has conn, the upstream of server, read query as its next frame and answer it with reply, and returns once the client has that reply.
func (env *testEnv) answer(t *testing.T, conn *fakeServer, query, reply string, server netip.AddrPort) {
	t.Helper()
	if got := testReadFrame(t, conn); got != query {
		t.Fatalf("the upstream read %q, want the query %q", got, query)
	}
	testWriteFrame(t, conn, reply)
	if got, want := env.nextReply(t), (datagram{reply, server}); got != want {
		t.Fatalf("client got %+v, want the reply as the upstream sent it %+v", got, want)
	}
}

// expectCached fails unless the client gets next, from server, what the cache makes of testReply for a query of id: that reply under the ID of the query.
func (env *testEnv) expectCached(t *testing.T, id uint16, server netip.AddrPort) {
	t.Helper()
	want := testParse(t, []byte(testReply))
	want.ID = id
	env.expectServed(t, want, server)
}

// expectServed fails unless the client gets next, from server, a DNS message that reads as want, what the cache makes of a reply it holds, does.
func (env *testEnv) expectServed(t *testing.T, want dnsmessage.Message, server netip.AddrPort) {
	t.Helper()
	data, from, ok := env.session.NextReply(testWait)
	if !ok {
		t.Fatalf("client got no reply within %v to a query whose answer the cache holds; the relay dialled %+v", testWait, env.dialer.recorded())
	}
	if got, want := testRender(testParse(t, data)), testRender(want); got != want || from != server {
		t.Fatalf("client got from %v\n%s\nwant from %v, under the ID of its query, the reply the upstream sent before\n%s", from, got, server, want)
	}
}

func TestCacheSizeSizesCacheOfHandler(t *testing.T) {
	for _, tc := range []struct{ size, limit int }{{0, 4096}, {7, 7}, {-1, -1}} {
		if got := (&Handler{CacheSize: tc.size}).answers().limit(); got != tc.limit {
			t.Errorf("the cache of a Handler with CacheSize %d keeps up to %d replies, want %d", tc.size, got, tc.limit)
		}
	}
}

func TestAnswersRepeatedQueryFromCache(t *testing.T) {
	env := testServe(t, testCaching(&Handler{}), "udp")
	server := env.fill(t, testServer)
	env.send(testWithID(testQuery, 0x5678), testServer)
	// A conn carries its frames in order, so the next one tells whether the query before it went upstream.
	env.send("end", testServer)
	if got := testReadFrame(t, server); got != "end" {
		t.Fatalf("the upstream read %q next, want %q: the cache holds the answer of the query sent before it", got, "end")
	}
	env.expectCached(t, 0x5678, testServer)
	env.expectDials(t, 1)
}

func TestSessionWhoseQueryHitsCacheDialsNothing(t *testing.T) {
	h := testCaching(&Handler{})
	first := testServe(t, h, "udp")
	first.fill(t, testServer)
	second := testServeNext(t, h, first)
	second.send(testWithID(testQuery, 0x5678), testServer)
	second.expectCached(t, 0x5678, testServer)
	// The session is over before its dials are counted, so that it has none left to make.
	second.cancel()
	second.waitDone(t, testWait, "its ctx ended")
	first.expectDials(t, 1)
}

func TestTargetAnswersQueryToAnotherServerFromCache(t *testing.T) {
	env := testServe(t, testCaching(&Handler{Target: testTarget}), "udp")
	env.fill(t, testServer)
	env.send(testWithID(testQuery, 0x5678), testOther)
	env.expectCached(t, 0x5678, testOther)
	env.cancel()
	env.waitDone(t, testWait, "its ctx ended")
	if dials := env.dialer.recorded(); len(dials) != 1 || dials[0].address != testTarget {
		t.Fatalf("dialer.DialContext calls %+v, want only the dial to Target %v that brought the answer", dials, testTarget)
	}
}

func TestCacheKeepsServersApartWithoutTarget(t *testing.T) {
	env := testServe(t, testCaching(&Handler{}), "udp")
	env.fill(t, testServer)
	again := testWithID(testQuery, 0x5678)
	env.send(again, testOther)
	// A relay that answered with what testServer said would dial testOther for this datagram alone.
	env.send("end", testOther)
	if got := testReadFrame(t, env.nextServer(t)); got != again {
		t.Fatalf("the conn dialled for %v read %q first, want the query %q: without Target what %v answered is no answer of another server", testOther, got, again, testServer)
	}
}

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

// testClocked returns h with its cache on a testClock, which stands still until the test lets time pass.
func testClocked(h *Handler) (*Handler, *testClock) {
	clock := new(testClock)
	h.cache.now = clock.now
	return h, clock
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

// goesUpstream has the client send query to testServer and tells whether conn, its upstream, reads it: a conn carries its frames in order, so the query comes before the "end" sent after it or not at all.
func (env *testEnv) goesUpstream(t *testing.T, conn *fakeServer, query string) bool {
	t.Helper()
	env.send(query, testServer)
	env.send("end", testServer)
	first := testReadFrame(t, conn)
	last := first
	if first == query {
		last = testReadFrame(t, conn)
	}
	if last != "end" {
		t.Fatalf("the upstream read %q, want the query %q, unless the cache answers it, and then %q", last, query, "end")
	}
	return first == query
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
		t.Fatalf("client got from %v\n%s\nwant from %v, under the ID of its query and with the TTLs it has left, the reply the upstream sent before\n%s", from, got, server, want)
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

func TestAnswersFromCacheWithTTLsLessWholeSecondsKept(t *testing.T) {
	// The reply answers for the smallest of its TTLs, 60 s.
	reply := string(testAnswer(t, func(m *dnsmessage.Message) {
		m.Answers = []dnsmessage.Resource{testA(300)}
		m.Authorities = []dnsmessage.Resource{testNS(120)}
		m.Additionals = []dnsmessage.Resource{testGlue(60)}
	}))
	for _, tc := range []struct {
		// kept is how long the cache has had the reply when the query comes again, ttls the TTLs its three records are then served with.
		kept time.Duration
		ttls [3]uint32
	}{
		{999 * time.Millisecond, [3]uint32{300, 120, 60}},
		{time.Second, [3]uint32{299, 119, 59}},
		{20*time.Second + 500*time.Millisecond, [3]uint32{280, 100, 40}},
		{59*time.Second + 999*time.Millisecond, [3]uint32{241, 61, 1}},
	} {
		t.Run(tc.kept.String(), func(t *testing.T) {
			h, clock := testClocked(&Handler{})
			env := testServe(t, h, "udp")
			env.send(testQuery, testServer)
			server := env.nextServer(t)
			env.answer(t, server, testQuery, reply, testServer)
			clock.pass(tc.kept)
			if env.goesUpstream(t, server, testWithID(testQuery, 0x5678)) {
				t.Fatalf("the relay sent upstream a query that came %v after the reply that answers it for 60 s", tc.kept)
			}
			want := testParse(t, []byte(reply))
			want.ID = 0x5678
			want.Answers[0].Header.TTL, want.Authorities[0].Header.TTL, want.Additionals[0].Header.TTL = tc.ttls[0], tc.ttls[1], tc.ttls[2]
			env.expectServed(t, want, testServer)
		})
	}
}

func TestReplacesCachedReplyOnceItsLifetimePassed(t *testing.T) {
	h, clock := testClocked(&Handler{})
	env := testServe(t, h, "udp")
	// testReply answers for the TTL of its one record, 60 s.
	server := env.fill(t, testServer)
	clock.pass(time.Minute)
	if !env.goesUpstream(t, server, testWithID(testQuery, 0x5678)) {
		t.Fatal("the relay answered from its cache a query that came 60 s after the reply, which answers for 60 s")
	}
	later := string(testAnswer(t, func(m *dnsmessage.Message) {
		m.ID = 0x5678
		m.Answers = []dnsmessage.Resource{testRecord("example.com.", 300, &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}})}
	}))
	testWriteFrame(t, server, later)
	if got, want := env.nextReply(t), (datagram{later, testServer}); got != want {
		t.Fatalf("client got %+v, want the later reply as the upstream sent it %+v", got, want)
	}
	if env.goesUpstream(t, server, testWithID(testQuery, 0x9abc)) {
		t.Fatal("the relay sent upstream a query that came right after the later reply, which answers it for 300 s")
	}
	want := testParse(t, []byte(later))
	want.ID = 0x9abc
	env.expectServed(t, want, testServer)
}

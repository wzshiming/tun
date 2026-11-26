package dns

import (
	"net/netip"
	"testing"
	"time"
)

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
	if got := testReadFrame(t, conn); got != testQuery {
		t.Fatalf("the upstream read %q, want the query %q", got, testQuery)
	}
	testWriteFrame(t, conn, testReply)
	if got, want := env.nextReply(t), (datagram{testReply, server}); got != want {
		t.Fatalf("client got %+v, want the reply as the upstream sent it %+v", got, want)
	}
	return conn
}

// expectCached fails unless the client gets next, from server, what the cache makes of testReply for a query of id: that reply under the ID of the query.
func (env *testEnv) expectCached(t *testing.T, id uint16, server netip.AddrPort) {
	t.Helper()
	data, from, ok := env.session.NextReply(testWait)
	if !ok {
		t.Fatalf("client got no reply within %v to a query whose answer the cache holds; the relay dialled %+v", testWait, env.dialer.recorded())
	}
	want := testParse(t, []byte(testReply))
	want.ID = id
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
		t.Fatalf("the upstream read %q, want only the datagram sent after the query its answer of before answers", got)
	}
	env.expectCached(t, 0x5678, testServer)
	env.expectDials(t, 1)
}

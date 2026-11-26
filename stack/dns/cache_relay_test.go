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
		t.Fatalf("client got from %v\n%s\nwant from %v the reply the upstream sent before as the cache serves it: under the ID and the question of the query, with the TTLs it has left, without EDNS options and without an OPT record for a query that has none\n%s", from, got, server, want)
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

func TestAnswersFromCacheOnlyQueryThatAsksTheSame(t *testing.T) {
	type message = dnsmessage.Message
	cookie := func(data string) dnsmessage.Option { return dnsmessage.Option{Code: 10, Data: []byte(data)} }
	padding := dnsmessage.Option{Code: 12, Data: make([]byte, 12)}
	// opt gives a query an OPT record of that payload size, flags and options, plain leaves it none.
	opt := func(payload dnsmessage.Class, flags uint32, options ...dnsmessage.Option) func(m *message) {
		return func(m *message) { m.Additionals = []dnsmessage.Resource{testOPT(payload, flags, options...)} }
	}
	plain := func(m *message) { m.Additionals = nil }
	edns := opt(1232, 0, cookie("client-1"))
	named := func(name string) func(m *message) {
		return func(m *message) { m.Questions[0].Name = dnsmessage.MustNewName(name) }
	}
	// reply answers the first query with an A record and that additional section.
	reply := func(additionals ...dnsmessage.Resource) string {
		return string(testAnswer(t, func(m *message) { m.Answers, m.Additionals = []dnsmessage.Resource{testA(300)}, additionals }))
	}
	// The upstream sends sent, whose OPT record completes the cookie of the query and pads; the cache makes bare of it for a query with an OPT record and stripped for one without.
	sent := reply(testOPT(1232, 0, cookie("client-1server-1"), padding), testGlue(60))
	bare, stripped := reply(testOPT(1232, 0), testGlue(60)), reply(testGlue(60))
	for _, tc := range []struct {
		name string
		// first makes the query the upstream answers of one for the A record of example.com with RD set, next the query that follows of that one.
		first, next func(m *message)
		// served is what the cache answers the second query with, but for its ID and question; empty if that query has to go upstream.
		served string
	}{
		{"another name", edns, named("example.org."), ""},
		{"another type", edns, func(m *message) { m.Questions[0].Type = dnsmessage.TypeAAAA }, ""},
		{"another class", edns, func(m *message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }, ""},
		{"RD clear", edns, func(m *message) { m.RecursionDesired = false }, ""},
		{"CD set", edns, func(m *message) { m.CheckingDisabled = true }, ""},
		{"no OPT record after a query with one", edns, plain, ""},
		{"an OPT record after a query without one", plain, edns, ""},
		{"DO set", edns, opt(1232, testDO, cookie("client-1")), ""},
		{"the name in another letter case", edns, named("ExAmPlE.COM."), bare},
		{"another cookie", edns, opt(1232, 0, cookie("client-2")), bare},
		{"padding", edns, opt(1232, 0, cookie("client-1"), padding), bare},
		{"another payload size", edns, opt(4096, 0, cookie("client-1")), bare},
		{"no OPT record in either query", plain, plain, stripped},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := testServe(t, testCaching(&Handler{}), "udp")
			first := string(testAsk(t, "example.com.", tc.first).query)
			next := testAsk(t, "example.com.", tc.first, tc.next, func(m *message) { m.ID = 0x5678 }).query
			env.send(first, testServer)
			server := env.nextServer(t)
			env.answer(t, server, first, sent, testServer)
			cached := tc.served != ""
			if went := env.goesUpstream(t, server, string(next)); went == cached {
				t.Fatalf("the query that follows the answered one went upstream: %v, want %v", went, !cached)
			}
			if !cached {
				return
			}
			want := testParse(t, []byte(tc.served))
			want.ID, want.Questions = 0x5678, testParse(t, next).Questions
			env.expectServed(t, want, testServer)
		})
	}
}

func TestAnswersFromCacheOnlyWithinLifetimeOfReply(t *testing.T) {
	type message = dnsmessage.Message
	records := func(r ...dnsmessage.Resource) []dnsmessage.Resource { return r }
	reply := func(alter func(m *message)) string { return string(testAnswer(t, alter)) }
	// answered is a reply with an answer of TTL 300 as well, so that nothing but what alter does keeps it out of the cache.
	answered := func(alter func(m *message)) string {
		return reply(func(m *message) {
			m.Answers = records(testA(300))
			alter(m)
		})
	}
	// nxdomain is a reply that denies the name with that authority section.
	nxdomain := func(authority ...dnsmessage.Resource) string {
		return reply(func(m *message) { m.RCode, m.Authorities = dnsmessage.RCodeNameError, authority })
	}
	// sized is a reply with an answer of TTL 300 that a record of opaque data brings to size bytes.
	sized := func(size int) string {
		filler := &dnsmessage.UnknownResource{Type: 10}
		fill := func(m *message) {
			m.Additionals = records(dnsmessage.Resource{Header: testA(300).Header, Body: filler})
		}
		filler.Data = make([]byte, size-len(answered(fill)))
		padded := answered(fill)
		if len(padded) != size {
			t.Fatalf("the test reply is %d bytes long, want %d", len(padded), size)
		}
		return padded
	}
	for _, tc := range []struct {
		name, reply string
		// life is how long the reply answers from the cache, 0 for a reply that is not stored.
		life time.Duration
	}{
		{"the smallest TTL among the answers", reply(func(m *message) { m.Answers = records(testA(300), testA(120)) }), 120 * time.Second},
		{"the smallest TTL in the authority section", answered(func(m *message) { m.Authorities = records(testNS(60)) }), 60 * time.Second},
		{"the smallest TTL in the additional section", answered(func(m *message) { m.Additionals = records(testGlue(30)) }), 30 * time.Second},
		{"a TTL over the cap of 3600 s", reply(func(m *message) { m.Answers = records(testA(86400)) }), 3600 * time.Second},
		{"TTL 0", reply(func(m *message) { m.Answers = records(testA(0)) }), 0},
		{"NXDOMAIN with a SOA whose MINIMUM is the smaller", nxdomain(testSOA(50, 40)), 40 * time.Second},
		{"NXDOMAIN with a SOA whose TTL is the smaller", nxdomain(testSOA(20, 40)), 20 * time.Second},
		{"NXDOMAIN with a SOA over the cap of 60 s", nxdomain(testSOA(900, 300)), 60 * time.Second},
		{"NOERROR without answers with a SOA", reply(func(m *message) { m.Authorities = records(testSOA(50, 40)) }), 40 * time.Second},
		{"NXDOMAIN without a SOA", nxdomain(testNS(300)), 0},
		{"NOERROR without answers and without a SOA", reply(func(m *message) { m.Authorities = records(testNS(300)) }), 0},
		{"truncated", answered(func(m *message) { m.Truncated = true }), 0},
		{"SERVFAIL", answered(func(m *message) { m.RCode, m.Authorities = dnsmessage.RCodeServerFailure, records(testSOA(50, 40)) }), 0},
		{"a reply of 4096 bytes", sized(4096), 300 * time.Second},
		{"a reply of 4097 bytes", sized(4097), 0},
		{"another name in the question", answered(func(m *message) { m.Questions[0].Name = dnsmessage.MustNewName("example.org.") }), 0},
		{"an answer cut short", testReply[:len(testReply)-1], 0},
		{"a TXT record whose string runs past its data", answered(func(m *message) {
			m.Answers = append(m.Answers, testRecord("example.com.", 300, &dnsmessage.UnknownResource{Type: dnsmessage.TypeTXT, Data: []byte("\x05ab")}))
		}), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, clock := testClocked(&Handler{})
			env := testServe(t, h, "udp")
			env.send(testQuery, testServer)
			server := env.nextServer(t)
			env.answer(t, server, testQuery, tc.reply, testServer)
			if tc.life == 0 {
				if !env.goesUpstream(t, server, testWithID(testQuery, 0x5678)) {
					t.Fatal("the relay answered from its cache a query that came right after a reply it may not store")
				}
				return
			}
			clock.pass(tc.life - time.Millisecond)
			if env.goesUpstream(t, server, testWithID(testQuery, 0x5678)) {
				t.Fatalf("the relay sent upstream a query that came %v after the reply that answers it for %v", tc.life-time.Millisecond, tc.life)
			}
			// The cache had the reply for all but the last of the whole seconds it answers for.
			kept := uint32(tc.life/time.Second) - 1
			want := testParse(t, []byte(tc.reply))
			want.ID = 0x5678
			for _, section := range [][]dnsmessage.Resource{want.Answers, want.Authorities, want.Additionals} {
				for i := range section {
					section[i].Header.TTL -= min(section[i].Header.TTL, kept)
				}
			}
			env.expectServed(t, want, testServer)
			clock.pass(time.Millisecond)
			if !env.goesUpstream(t, server, testWithID(testQuery, 0x9abc)) {
				t.Fatalf("the relay answered from its cache a query that came %v after the reply, which answers for %v", tc.life, tc.life)
			}
		})
	}
}

func TestCacheSizeBoundsQueriesAnsweredFromCache(t *testing.T) {
	const size = 3
	env := testServe(t, testCaching(&Handler{CacheSize: size}), "udp")
	// One query more than the cache keeps replies, each for a name of its own.
	asked := testHosts(t, size+1)
	replies := make([]string, len(asked))
	var server *fakeServer
	for i, a := range asked {
		replies[i] = string(testAnswer(t, func(m *dnsmessage.Message) {
			m.Questions[0].Name = dnsmessage.MustNewName(a.key.name)
			m.Answers = []dnsmessage.Resource{testRecord(a.key.name, 300, &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i + 1)}})}
		}))
		env.send(string(a.query), testServer)
		if server == nil {
			server = env.nextServer(t)
		}
		env.answer(t, server, string(a.query), replies[i], testServer)
	}
	served := 0
	for i, a := range asked {
		// A query that goes upstream gets no answer there, so the cache holds what it held when the first one came again.
		if env.goesUpstream(t, server, testWithID(string(a.query), 0x5678)) {
			continue
		}
		want := testParse(t, []byte(replies[i]))
		want.ID = 0x5678
		env.expectServed(t, want, testServer)
		served++
	}
	if served != size {
		t.Errorf("a relay with CacheSize %d answers from its cache %d of the %d queries whose replies it read, want %d", size, served, len(asked), size)
	}
}

func TestNegativeCacheSizeSendsRepeatedQueryUpstream(t *testing.T) {
	env := testServe(t, testCaching(&Handler{CacheSize: -1}), "udp")
	server := env.fill(t, testServer)
	if !env.goesUpstream(t, server, testWithID(testQuery, 0x5678)) {
		t.Fatal("a relay with CacheSize -1 answered from a cache a query whose reply it had read")
	}
}

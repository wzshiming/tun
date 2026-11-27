package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// testIdleBound is how long a 200ms Handler.Idle may take to end a flow or give a query up; the 10s default exceeds it.
const testIdleBound = 5 * time.Second

// testWait bounds every other wait.
const testWait = 10 * time.Second

var (
	testClient = netip.MustParseAddrPort("10.0.0.2:40000")
	testServer = netip.MustParseAddrPort("10.0.0.53:53")
	testOther  = netip.MustParseAddrPort("10.0.0.54:53")
)

const testTarget = "192.0.2.1:5353"

// testQuery is a DNS query, ID 0x1234, for the A record of example.com.
const testQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

// testReply answers testQuery with one A record.
const testReply = "\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22"

type dialRecord struct {
	network, address string
	client           string
}

// fakeUpstream is a Dialer whose conns lead to a DNS server over TCP: it answers each query with what answer makes of it, by default records A records of 60 s for its question.
type fakeUpstream struct {
	// dialErr fails every dial.
	dialErr error
	// records is how many A records the default answer has; 0 means 1.
	records int
	// answer, when set, makes the reply to q, already holding its header and question; false sends none.
	answer func(q dnsmessage.Message, reply *dnsmessage.Message) bool
	// serve, when set, serves the n-th conn dialled, from 0, in place of the server; it calls loop to serve as the server does.
	serve func(u *fakeUpstream, n int, conn net.Conn)
	// route, when set, tells for the address dialled the error that fails the dial or how its conns are served; nil, nil serves as any other.
	route func(address string) (serve func(u *fakeUpstream, n int, conn net.Conn), err error)

	// silent has the server answer no query it gets while set: what counts is when the query is among queries, not when its answer would be made.
	silent atomic.Bool

	mu     sync.Mutex
	dials  []dialRecord
	asked  []dnsmessage.Message
	closed int
}

func (u *fakeUpstream) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	client := ""
	if addr := stack.ClientAddr(ctx); addr != nil {
		client = addr.Network() + " " + addr.String()
	}
	u.mu.Lock()
	n := len(u.dials)
	u.dials = append(u.dials, dialRecord{network, address, client})
	u.mu.Unlock()
	if u.dialErr != nil {
		return nil, u.dialErr
	}
	serve := u.serve
	if u.route != nil {
		routed, err := u.route(address)
		if err != nil {
			return nil, err
		}
		if routed != nil {
			serve = routed
		}
	}
	local, server := net.Pipe()
	go func() {
		defer server.Close()
		if serve != nil {
			serve(u, n, server)
		} else {
			u.loop(server)
		}
		u.mu.Lock()
		u.closed++
		u.mu.Unlock()
	}()
	return local, nil
}

// loop answers the queries of conn until it fails.
func (u *fakeUpstream) loop(conn net.Conn) { u.loopWith(conn, u.answer) }

// loopWith is loop with answer in place of that of u.
func (u *fakeUpstream) loopWith(conn net.Conn, answer func(q dnsmessage.Message, reply *dnsmessage.Message) bool) {
	var writing sync.Mutex
	for {
		message, err := readFrame(conn)
		if err != nil {
			return
		}
		var q dnsmessage.Message
		if q.Unpack(message) != nil {
			continue
		}
		u.mu.Lock()
		silent := u.silent.Load()
		u.asked = append(u.asked, q)
		u.mu.Unlock()
		if silent {
			continue
		}
		go func() {
			reply := dnsmessage.Message{Header: q.Header, Questions: q.Questions}
			reply.Response, reply.RecursionAvailable = true, true
			if answer != nil {
				if !answer(q, &reply) {
					return
				}
			} else if len(q.Questions) == 1 {
				for i := range max(u.records, 1) {
					reply.Answers = append(reply.Answers, testRecord(q.Questions[0].Name.String(), 60, &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i)}}))
				}
			}
			packed, err := reply.Pack()
			if err != nil {
				return
			}
			writing.Lock()
			defer writing.Unlock()
			writeFrame(conn, packed)
		}()
	}
}

func (u *fakeUpstream) recorded() []dialRecord {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]dialRecord(nil), u.dials...)
}

// queries returns the queries the server got so far.
func (u *fakeUpstream) queries() []dnsmessage.Message {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]dnsmessage.Message(nil), u.asked...)
}

// testEventually fails t unless ok comes true within testWait.
func testEventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(testWait); !ok(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %v", what, testWait)
		}
	}
}

// testMirror returns a Handler of idle that mirrors u.
func testMirror(u *fakeUpstream, idle time.Duration) *Handler {
	return &Handler{Dialer: u, Idle: idle}
}

// testFlow is a flow being served.
type testFlow struct {
	flow   *stacktest.Flow
	cancel context.CancelFunc
	done   chan struct{}
}

// testStart serves f with h through a stack.Listener until the test ends.
func testStart(t *testing.T, h *Handler, f *stacktest.Flow) *testFlow {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	tf := &testFlow{flow: f, cancel: cancel, done: make(chan struct{})}
	l := stack.NewListener()
	go h.Serve(l)
	t.Cleanup(func() { l.Close() })
	go func() {
		defer close(tf.done)
		l.ServeFlow(ctx, f)
	}()
	t.Cleanup(func() {
		cancel()
		tf.waitDone(t, testWait, "its ctx ending")
	})
	return tf
}

func (tf *testFlow) waitDone(t *testing.T, bound time.Duration, why string) {
	t.Helper()
	select {
	case <-tf.done:
	case <-time.After(bound):
		t.Fatalf("ServeFlow did not return within %v of %s", bound, why)
	}
}

// testUDP is a UDP session being served.
type testUDP struct {
	*testFlow
	session *stacktest.Session
}

// testServeUDP serves with h a UDP session of client, whose first datagram goes to testServer.
func testServeUDP(t *testing.T, h *Handler, client netip.AddrPort) *testUDP {
	t.Helper()
	session := stacktest.NewSession(client, testServer)
	return &testUDP{testStart(t, h, stacktest.NewFlow("udp", client, testServer, session)), session}
}

// ask sends query to server and returns the reply, which it fails t for unless it comes from server.
func (u *testUDP) ask(t *testing.T, query []byte, server netip.AddrPort) dnsmessage.Message {
	t.Helper()
	u.session.Send(query, server)
	return u.next(t, server)
}

// next returns the next reply of the session, which it fails t for unless it comes from server.
func (u *testUDP) next(t *testing.T, server netip.AddrPort) dnsmessage.Message {
	t.Helper()
	reply, from, ok := u.session.NextReply(testWait)
	if !ok {
		t.Fatalf("no reply within %v", testWait)
	}
	if from != server {
		t.Fatalf("reply came from %v, want from %v, the server the query went to", from, server)
	}
	return testParse(t, reply)
}

// testTCP is a TCP conn being served: Conn is the client's end.
type testTCP struct {
	*testFlow
	net.Conn
}

// testServeTCP serves with h a TCP conn of testClient to server.
func testServeTCP(t *testing.T, h *Handler, server netip.AddrPort) *testTCP {
	t.Helper()
	client, served := net.Pipe()
	t.Cleanup(func() { client.Close() })
	return &testTCP{testStart(t, h, stacktest.NewFlow("tcp", testClient, server, addressedConn{served, server})), client}
}

// addressedConn is a conn whose LocalAddr is the server its client dialled and RemoteAddr testClient, as those of a TCP flow are.
type addressedConn struct {
	net.Conn
	server netip.AddrPort
}

func (c addressedConn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.server) }
func (c addressedConn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(testClient) }

// ask sends query, length-framed, and returns the next reply.
func (c *testTCP) ask(t *testing.T, query []byte) dnsmessage.Message {
	t.Helper()
	c.SetDeadline(time.Now().Add(testWait))
	if err := writeFrame(c, query); err != nil {
		t.Fatalf("write the query: %v", err)
	}
	reply, err := readFrame(c)
	if err != nil {
		t.Fatalf("read the reply: %v", err)
	}
	return testParse(t, reply)
}

// testWithID returns the query of a under id.
func (a testAsking) withID(id uint16) []byte {
	query := append([]byte(nil), a.query...)
	query[0], query[1] = byte(id>>8), byte(id)
	return query
}

// testExpectAnswered fails t unless m answers the A query of id for name with n records.
func testExpectAnswered(t *testing.T, m dnsmessage.Message, id uint16, name string, n int) {
	t.Helper()
	if !m.Response || m.ID != id || m.RCode != dnsmessage.RCodeSuccess || len(m.Questions) != 1 || m.Questions[0].Name.String() != name || len(m.Answers) != n {
		t.Fatalf("reply = %s, want the response of ID %#x to the question for %s with %d answers", testRender(m), id, name, n)
	}
}

// testExpectFailed fails t unless m fails the A query of id for name with rcode.
func testExpectFailed(t *testing.T, m dnsmessage.Message, id uint16, name string, rcode dnsmessage.RCode) {
	t.Helper()
	if !m.Response || m.ID != id || m.RCode != rcode || len(m.Questions) != 1 || m.Questions[0].Name.String() != name || len(m.Answers) != 0 {
		t.Fatalf("reply = %s, want the response of ID %#x to the question for %s with RCODE %v and no answers", testRender(m), id, name, rcode)
	}
}

func TestAnswersUDPQueryWithReplyOfAddressedServerAskedOverTCP(t *testing.T) {
	up := &fakeUpstream{}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	testExpectAnswered(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", 1)
	want := dialRecord{"tcp", testServer.String(), "udp " + testClient.String()}
	if dials := up.recorded(); len(dials) != 1 || dials[0] != want {
		t.Errorf("dials = %v, want the one %v", dials, want)
	}
}

func TestAnswersEachServerOfSessionFromItsOwnUpstream(t *testing.T) {
	up := &fakeUpstream{}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	testExpectAnswered(t, s.ask(t, testAsk(t, "a.example.com.").query, testServer), 0x1234, "a.example.com.", 1)
	testExpectAnswered(t, s.ask(t, testAsk(t, "b.example.com.").query, testOther), 0x1234, "b.example.com.", 1)
	dials := up.recorded()
	if len(dials) != 2 || dials[0].address != testServer.String() || dials[1].address != testOther.String() {
		t.Errorf("dials = %v, want one to %v and then one to %v", dials, testServer, testOther)
	}
}

func TestUpstreamsAreMirroredForEveryAddressedServer(t *testing.T) {
	up := &fakeUpstream{}
	h := testMirror(up, 0)
	h.Upstreams = []string{testTarget}
	s := testServeUDP(t, h, testClient)
	testExpectAnswered(t, s.ask(t, testAsk(t, "a.example.com.").query, testServer), 0x1234, "a.example.com.", 1)
	testExpectAnswered(t, s.ask(t, testAsk(t, "b.example.com.").query, testOther), 0x1234, "b.example.com.", 1)
	// What the upstream answered one server's client answers the other's too.
	testExpectAnswered(t, s.ask(t, testAsk(t, "a.example.com.").query, testOther), 0x1234, "a.example.com.", 1)
	if dials := up.recorded(); len(dials) != 1 || dials[0].address != testTarget {
		t.Errorf("dials = %v, want one to the upstream %v", dials, testTarget)
	}
	if asked := up.queries(); len(asked) != 2 {
		t.Errorf("the upstream got %d queries, want 2: the third is answered from the cache", len(asked))
	}
}

func TestAnswersTCPQueriesOfOneConn(t *testing.T) {
	up := &fakeUpstream{}
	c := testServeTCP(t, testMirror(up, 0), testServer)
	testExpectAnswered(t, c.ask(t, testAsk(t, "a.example.com.").withID(1)), 1, "a.example.com.", 1)
	testExpectAnswered(t, c.ask(t, testAsk(t, "b.example.com.").withID(2)), 2, "b.example.com.", 1)
	want := dialRecord{"tcp", testServer.String(), "tcp " + testClient.String()}
	if dials := up.recorded(); len(dials) != 1 || dials[0] != want {
		t.Errorf("dials = %v, want the one %v", dials, want)
	}
	c.Close()
	c.waitDone(t, testIdleBound, "the client closing its conn")
}

func TestAnswersFromCacheAcrossFlowsAndNetworks(t *testing.T) {
	up := &fakeUpstream{}
	h := testMirror(up, 0)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, testServeUDP(t, h, testClient).ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	other := netip.MustParseAddrPort("10.0.0.3:40001")
	testExpectAnswered(t, testServeUDP(t, h, other).ask(t, asking.withID(7), testServer), 7, "example.com.", 1)
	testExpectAnswered(t, testServeTCP(t, h, testServer).ask(t, asking.withID(8)), 8, "example.com.", 1)
	if asked := up.queries(); len(asked) != 1 {
		t.Errorf("the upstream got %d queries, want 1: the cache answers the later ones", len(asked))
	}
}

func TestNegativeCacheSizeAsksUpstreamEveryTime(t *testing.T) {
	up := &fakeUpstream{}
	h := testMirror(up, 0)
	h.CacheSize = -1
	s := testServeUDP(t, h, testClient)
	for range 2 {
		testExpectAnswered(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", 1)
	}
	if asked := up.queries(); len(asked) != 2 {
		t.Errorf("the upstream got %d queries, want 2", len(asked))
	}
}

func TestFlowsShareUpstreamConnEachQueryUnderIDOfItsOwn(t *testing.T) {
	both := make(chan struct{})
	up := &fakeUpstream{}
	up.answer = func(q dnsmessage.Message, reply *dnsmessage.Message) bool {
		<-both
		reply.Answers = []dnsmessage.Resource{testRecord(q.Questions[0].Name.String(), 60, &dnsmessage.AResource{})}
		return true
	}
	h := testMirror(up, 0)
	first := testServeUDP(t, h, testClient)
	second := testServeUDP(t, h, netip.MustParseAddrPort("10.0.0.3:40001"))
	first.session.Send(testAsk(t, "a.example.com.").query, testServer)
	second.session.Send(testAsk(t, "b.example.com.").query, testServer)
	testEventually(t, "both queries at the upstream", func() bool { return len(up.queries()) == 2 })
	close(both)
	testExpectAnswered(t, first.next(t, testServer), 0x1234, "a.example.com.", 1)
	testExpectAnswered(t, second.next(t, testServer), 0x1234, "b.example.com.", 1)
	if asked := up.queries(); asked[0].ID == asked[1].ID {
		t.Errorf("both queries went upstream under ID %#x, want an ID each", asked[0].ID)
	}
	if dials := up.recorded(); len(dials) != 1 {
		t.Errorf("dials = %v, want one conn for both flows", dials)
	}
}

func TestSameQueryAskedAtOnceGoesUpstreamOnce(t *testing.T) {
	release := make(chan struct{})
	up := &fakeUpstream{}
	up.answer = func(q dnsmessage.Message, reply *dnsmessage.Message) bool {
		<-release
		reply.Answers = []dnsmessage.Resource{testRecord(q.Questions[0].Name.String(), 60, &dnsmessage.AResource{})}
		return true
	}
	h := testMirror(up, 0)
	first := testServeUDP(t, h, testClient)
	second := testServeUDP(t, h, netip.MustParseAddrPort("10.0.0.3:40001"))
	asking := testAsk(t, "example.com.")
	first.session.Send(asking.withID(1), testServer)
	testEventually(t, "the query at the upstream", func() bool { return len(up.queries()) == 1 })
	second.session.Send(asking.withID(2), testServer)
	// Were the second sent upstream too, it would be there by now.
	time.Sleep(100 * time.Millisecond)
	close(release)
	testExpectAnswered(t, first.next(t, testServer), 1, "example.com.", 1)
	testExpectAnswered(t, second.next(t, testServer), 2, "example.com.", 1)
	if asked := up.queries(); len(asked) != 1 {
		t.Errorf("the upstream got %d queries, want 1 for both clients", len(asked))
	}
}

// testCutAfterQuery reads one message from conn and returns, which closes it.
func testCutAfterQuery(_ *fakeUpstream, _ int, conn net.Conn) { readFrame(conn) }

func TestSendsQueryAgainOnNewConnWhenItsConnFails(t *testing.T) {
	up := &fakeUpstream{serve: func(u *fakeUpstream, n int, conn net.Conn) {
		if n == 0 {
			testCutAfterQuery(u, n, conn)
			return
		}
		u.loop(conn)
	}}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	testExpectAnswered(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", 1)
	if dials := up.recorded(); len(dials) != 2 {
		t.Errorf("dials = %v, want 2: the second for the query the first conn left unanswered", dials)
	}
}

func TestAnswersSERVFAILOnceSecondConnFailsToo(t *testing.T) {
	up := &fakeUpstream{serve: testCutAfterQuery}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	testExpectFailed(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if dials := up.recorded(); len(dials) != 2 {
		t.Errorf("dials = %v, want 2: a query is sent again only once", dials)
	}
	// The failure is not kept: the next query dials again.
	testExpectFailed(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if dials := up.recorded(); len(dials) != 4 {
		t.Errorf("dials = %v after the second query, want 4", dials)
	}
}

func TestAnswersSERVFAILWhenDialFails(t *testing.T) {
	up := &fakeUpstream{dialErr: errors.New("unreachable")}
	h := testMirror(up, 0)
	edns := testAsk(t, "example.com.", func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{testOPT(4096, 0)} })
	reply := testServeUDP(t, h, testClient).ask(t, edns.query, testServer)
	testExpectFailed(t, reply, 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if len(reply.Additionals) != 1 || reply.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Errorf("reply = %s, want an OPT record, as the query has one", testRender(reply))
	}
	testExpectFailed(t, testServeTCP(t, h, testServer).ask(t, testAsk(t, "example.com.").query), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if dials := up.recorded(); len(dials) != 2 {
		t.Errorf("dials = %v, want one per query: a failed dial is not tried again for its query", dials)
	}
}

func TestAnswersSERVFAILWhenUpstreamStaysSilentForIdle(t *testing.T) {
	up := &fakeUpstream{answer: func(dnsmessage.Message, *dnsmessage.Message) bool { return false }}
	s := testServeUDP(t, testMirror(up, 200*time.Millisecond), testClient)
	start := time.Now()
	testExpectFailed(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if took := time.Since(start); took > testIdleBound {
		t.Errorf("SERVFAIL came after %v, want within %v of an Idle of 200ms", took, testIdleBound)
	}
}

func TestTruncatesReplyOverUDPPayloadOfQuery(t *testing.T) {
	// 40 A records take over 512 bytes and under 4096.
	up := &fakeUpstream{records: 40}
	h := testMirror(up, 0)
	s := testServeUDP(t, h, testClient)
	plain := testAsk(t, "example.com.")
	reply := s.ask(t, plain.query, testServer)
	if !reply.Truncated || len(reply.Answers) != 0 || len(reply.Questions) != 1 || reply.ID != 0x1234 || !reply.Response {
		t.Fatalf("reply over UDP = %s, want the truncated response to the question, without records", testRender(reply))
	}
	if reply := testServeTCP(t, h, testServer).ask(t, plain.query); reply.Truncated || len(reply.Answers) != 40 {
		t.Errorf("reply over TCP = %s, want all 40 answers", testRender(reply))
	}
	edns := testAsk(t, "example.com.", func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{testOPT(4096, 0)} })
	if reply := s.ask(t, edns.query, testServer); reply.Truncated || len(reply.Answers) != 40 {
		t.Errorf("reply over UDP to a query allowing 4096 bytes = %s, want all 40 answers", testRender(reply))
	}
	small := testAsk(t, "example.com.", func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{testOPT(600, 0)} })
	reply = s.ask(t, small.query, testServer)
	if !reply.Truncated || len(reply.Answers) != 0 || len(reply.Additionals) != 1 || reply.Additionals[0].Header.Type != dnsmessage.TypeOPT {
		t.Errorf("reply over UDP to a query allowing 600 bytes = %s, want it truncated, with an OPT record", testRender(reply))
	}
}

func TestFitLeavesHeaderAloneOfReplyThatDoesNotParse(t *testing.T) {
	reply := append([]byte("\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00"), make([]byte, 600)...)
	reply[12] = 0xff
	if got, want := string(fit(reply, []byte(testQuery))), "\x12\x34\x83\x80\x00\x00\x00\x00\x00\x00\x00\x00"; got != want {
		t.Errorf("fit = %q, want the header with TC and no records %q", got, want)
	}
}

func TestRefusesZoneTransferWithoutAskingUpstream(t *testing.T) {
	up := &fakeUpstream{}
	c := testServeTCP(t, testMirror(up, 0), testServer)
	for _, typ := range []dnsmessage.Type{typeAXFR, typeIXFR} {
		asking := testAsk(t, "example.com.", func(m *dnsmessage.Message) { m.Questions[0].Type = typ })
		testExpectFailed(t, c.ask(t, asking.query), 0x1234, "example.com.", dnsmessage.RCodeRefused)
	}
	if dials := up.recorded(); len(dials) != 0 {
		t.Errorf("dials = %v, want none", dials)
	}
}

func TestAnswersNoMessageThatIsNoRequest(t *testing.T) {
	up := &fakeUpstream{}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	s.session.Send([]byte("short"), testServer)
	s.session.Send([]byte(testReply), testServer)
	// The first reply answers the one request.
	testExpectAnswered(t, s.ask(t, testAsk(t, "example.com.").withID(9), testServer), 9, "example.com.", 1)
	if asked := up.queries(); len(asked) != 1 {
		t.Errorf("the upstream got %d messages, want only the query", len(asked))
	}
}

func TestRefusesOtherRequestsWithoutAskingUpstream(t *testing.T) {
	up := &fakeUpstream{}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	// Opcode 4, NOTIFY.
	notify := testAsk(t, "example.com.").query
	notify[2] |= 4 << 3
	if reply := s.ask(t, notify, testServer); !reply.Response || reply.ID != 0x1234 || reply.OpCode != 4 || reply.RCode != dnsmessage.RCodeNotImplemented {
		t.Errorf("reply to opcode 4 = %s, want NOTIMP of opcode 4 under ID 0x1234", testRender(reply))
	}
	two := testPack(t, dnsmessage.Message{Header: dnsmessage.Header{ID: 5}, Questions: []dnsmessage.Question{
		{Name: dnsmessage.MustNewName("a.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		{Name: dnsmessage.MustNewName("b.example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
	}})
	if reply := s.ask(t, two, testServer); !reply.Response || reply.ID != 5 || reply.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("reply to a query of two questions = %s, want FORMERR under ID 5", testRender(reply))
	}
	cut := append([]byte(testQuery[:12]), 0xff)
	if reply := s.ask(t, cut, testServer); !reply.Response || reply.ID != 0x1234 || reply.RCode != dnsmessage.RCodeFormatError {
		t.Errorf("reply to a query whose question does not parse = %s, want FORMERR under ID 0x1234", testRender(reply))
	}
	if dials := up.recorded(); len(dials) != 0 {
		t.Errorf("dials = %v, want none", dials)
	}
}

// testVersions returns an upstream on a mirror of idle and a testClock: its n-th answer, from 1, has n A records of 60 s, and it answers no query it gets while silent is set.
func testVersions(idle time.Duration) (h *Handler, up *fakeUpstream, clock *testClock, silent *atomic.Bool) {
	var answered atomic.Int32
	up = &fakeUpstream{}
	silent = &up.silent
	up.answer = func(q dnsmessage.Message, reply *dnsmessage.Message) bool {
		n := answered.Add(1)
		for i := range n {
			reply.Answers = append(reply.Answers, testRecord(q.Questions[0].Name.String(), 60, &dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i)}}))
		}
		return true
	}
	h = testMirror(up, idle)
	clock = new(testClock)
	h.cache.now = clock.now
	return h, up, clock, silent
}

// testExpectTTL fails t unless every answer of m has ttl.
func testExpectTTL(t *testing.T, m dnsmessage.Message, ttl uint32) {
	t.Helper()
	for _, r := range m.Answers {
		if r.Header.TTL != ttl {
			t.Fatalf("reply = %s, want every answer with TTL %d", testRender(m), ttl)
		}
	}
}

func TestAnswersStaleReplyFirstAndThenAsksUpstreamForNewOne(t *testing.T) {
	h, up, clock, _ := testVersions(0)
	s := testServeUDP(t, h, testClient)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	clock.pass(61 * time.Second)
	stale := s.ask(t, asking.query, testServer)
	testExpectAnswered(t, stale, 0x1234, "example.com.", 1)
	testExpectTTL(t, stale, 0)
	testEventually(t, "the upstream asked for a new reply, which then answers", func() bool {
		_, ok := h.cache.get(testServer.String(), asking.key, asking.query)
		return ok
	})
	fresh := s.ask(t, asking.query, testServer)
	testExpectAnswered(t, fresh, 0x1234, "example.com.", 2)
	testExpectTTL(t, fresh, 60)
	if asked := up.queries(); len(asked) != 2 {
		t.Errorf("the upstream got %d queries, want 2: the first and the one for the new reply", len(asked))
	}
}

func TestGoesOnAnsweringStaleReplyWhileUpstreamIsDown(t *testing.T) {
	h, up, clock, silent := testVersions(2 * time.Second)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, testServeUDP(t, h, testClient).ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	silent.Store(true)
	clock.pass(time.Hour)
	for i := range 3 {
		start := time.Now()
		reply := testServeTCP(t, h, testServer).ask(t, asking.withID(uint16(i)))
		testExpectAnswered(t, reply, uint16(i), "example.com.", 1)
		testExpectTTL(t, reply, 0)
		if took := time.Since(start); took > time.Second {
			t.Errorf("the stale reply came after %v, want it before the upstream is given up, after an Idle of 2s", took)
		}
	}
	// Only the first of them was due to ask: the next is refreshRetry later.
	testEventually(t, "the query for a new reply at the upstream", func() bool { return len(up.queries()) == 2 })
	clock.pass(refreshRetry)
	testExpectAnswered(t, testServeTCP(t, h, testServer).ask(t, asking.query), 0x1234, "example.com.", 1)
	testEventually(t, "the next query for a new reply at the upstream", func() bool { return len(up.queries()) == 3 })
	silent.Store(false)
	clock.pass(refreshRetry)
	c := testServeTCP(t, h, testServer)
	testExpectAnswered(t, c.ask(t, asking.query), 0x1234, "example.com.", 1)
	testEventually(t, "the reply of the upstream that is back", func() bool {
		_, ok := h.cache.get(testServer.String(), asking.key, asking.query)
		return ok
	})
	testExpectAnswered(t, c.ask(t, asking.query), 0x1234, "example.com.", 2)
}

func TestAnswersNoReplyStaleForLongerThanStale(t *testing.T) {
	h, up, clock, _ := testVersions(0)
	h.Stale = time.Hour
	s := testServeUDP(t, h, testClient)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	clock.pass(time.Minute + time.Hour)
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 2)
	if asked := up.queries(); len(asked) != 2 {
		t.Errorf("the upstream got %d queries, want 2", len(asked))
	}
}

func TestNegativeStaleAnswersNoStaleReply(t *testing.T) {
	h, _, clock, silent := testVersions(200 * time.Millisecond)
	h.Stale = -1
	s := testServeUDP(t, h, testClient)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	silent.Store(true)
	clock.pass(61 * time.Second)
	testExpectFailed(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
}

func TestKeepsStaleReplyWhenUpstreamFailsTheQuery(t *testing.T) {
	var failing atomic.Bool
	up := &fakeUpstream{}
	up.answer = func(q dnsmessage.Message, reply *dnsmessage.Message) bool {
		if failing.Load() {
			reply.RCode = dnsmessage.RCodeServerFailure
			return true
		}
		reply.Answers = []dnsmessage.Resource{testRecord(q.Questions[0].Name.String(), 60, &dnsmessage.AResource{})}
		return true
	}
	h := testMirror(up, 0)
	clock := new(testClock)
	h.cache.now = clock.now
	s := testServeUDP(t, h, testClient)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	failing.Store(true)
	clock.pass(61 * time.Second)
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	testEventually(t, "the query for a new reply at the upstream", func() bool { return len(up.queries()) == 2 })
	clock.pass(refreshRetry)
	testExpectAnswered(t, s.ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
}

func TestUDPSessionEndsAfterIdleAndClosesUpstreamConn(t *testing.T) {
	up := &fakeUpstream{}
	s := testServeUDP(t, testMirror(up, 200*time.Millisecond), testClient)
	testExpectAnswered(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", 1)
	s.waitDone(t, testIdleBound, "its last datagram, with an Idle of 200ms")
	if !s.session.Closed() {
		t.Error("the session is not closed")
	}
	testEventually(t, "the upstream conn closed with the last flow", func() bool {
		up.mu.Lock()
		defer up.mu.Unlock()
		return up.closed == 1
	})
}

func TestTCPConnEndsAfterIdle(t *testing.T) {
	c := testServeTCP(t, testMirror(&fakeUpstream{}, 200*time.Millisecond), testServer)
	testExpectAnswered(t, c.ask(t, testAsk(t, "example.com.").query), 0x1234, "example.com.", 1)
	c.waitDone(t, testIdleBound, "its last message, with an Idle of 200ms")
}

func TestUpstreamConnOutlastsFlowWhileAnotherIsServed(t *testing.T) {
	up := &fakeUpstream{}
	h := &Handler{Dialer: up}
	held := testServeTCP(t, h, testServer)
	testExpectAnswered(t, held.ask(t, testAsk(t, "a.example.com.").query), 0x1234, "a.example.com.", 1)
	brief := testServeTCP(t, h, testServer)
	testExpectAnswered(t, brief.ask(t, testAsk(t, "b.example.com.").query), 0x1234, "b.example.com.", 1)
	brief.Close()
	brief.waitDone(t, testIdleBound, "the client closing its conn")
	testExpectAnswered(t, held.ask(t, testAsk(t, "c.example.com.").query), 0x1234, "c.example.com.", 1)
	if dials := up.recorded(); len(dials) != 1 {
		t.Errorf("dials = %v, want one conn for all three queries", dials)
	}
}

func TestFlowEndsWithCtxWhileUpstreamIsSilent(t *testing.T) {
	up := &fakeUpstream{answer: func(dnsmessage.Message, *dnsmessage.Message) bool { return false }}
	s := testServeUDP(t, testMirror(up, 0), testClient)
	s.session.Send(testAsk(t, "example.com.").query, testServer)
	testEventually(t, "the query at the upstream", func() bool { return len(up.queries()) == 1 })
	s.cancel()
	s.waitDone(t, testIdleBound, "its ctx ending")
	if _, _, ok := s.session.NextReply(50 * time.Millisecond); ok {
		t.Error("the ended session got a reply")
	}
}

func TestIdleDefaultsToTenSeconds(t *testing.T) {
	if got := new(Handler).idle(); got != 10*time.Second {
		t.Errorf("idle of the zero Handler = %v, want 10s", got)
	}
}

const testSecond = "192.0.2.2:53"

// testFailing serves a conn as a server that answers every query with SERVFAIL.
func testFailing(u *fakeUpstream, _ int, conn net.Conn) {
	u.loopWith(conn, func(_ dnsmessage.Message, reply *dnsmessage.Message) bool {
		reply.RCode = dnsmessage.RCodeServerFailure
		return true
	})
}

// testSilent serves a conn as a server that answers nothing.
func testSilent(u *fakeUpstream, _ int, conn net.Conn) {
	u.loopWith(conn, func(dnsmessage.Message, *dnsmessage.Message) bool { return false })
}

// testTwoUpstreams returns a mirror of idle whose Upstreams are testTarget, whose dials fail with dialErr or whose conns serve serves, and testSecond, which answers.
func testTwoUpstreams(idle time.Duration, dialErr error, serve func(*fakeUpstream, int, net.Conn)) (*Handler, *fakeUpstream) {
	up := &fakeUpstream{route: func(address string) (func(*fakeUpstream, int, net.Conn), error) {
		if address == testTarget {
			return serve, dialErr
		}
		return nil, nil
	}}
	h := testMirror(up, idle)
	h.Upstreams = []string{testTarget, testSecond}
	return h, up
}

// testAddresses returns the addresses dials went to.
func testAddresses(dials []dialRecord) []string {
	addresses := make([]string, len(dials))
	for i, d := range dials {
		addresses[i] = d.address
	}
	return addresses
}

func TestAsksNextUpstreamWhenOneCannotBeDialledAndThenAsksItLast(t *testing.T) {
	h, up := testTwoUpstreams(0, errors.New("unreachable"), nil)
	s := testServeUDP(t, h, testClient)
	testExpectAnswered(t, s.ask(t, testAsk(t, "a.example.com.").query, testServer), 0x1234, "a.example.com.", 1)
	if got := testAddresses(up.recorded()); !slices.Equal(got, []string{testTarget, testSecond}) {
		t.Fatalf("dials went to %v, want to %v and then to %v", got, testTarget, testSecond)
	}
	testExpectAnswered(t, s.ask(t, testAsk(t, "b.example.com.").query, testServer), 0x1234, "b.example.com.", 1)
	if got := testAddresses(up.recorded()); len(got) != 2 {
		t.Errorf("dials went to %v, want no dial for the second query: the server that failed is asked after the one that answers", got)
	}
}

func TestAsksNextUpstreamWhenOneAnswersSERVFAIL(t *testing.T) {
	h, up := testTwoUpstreams(0, nil, testFailing)
	s := testServeUDP(t, h, testClient)
	for _, name := range []string{"a.example.com.", "b.example.com."} {
		testExpectAnswered(t, s.ask(t, testAsk(t, name).query, testServer), 0x1234, name, 1)
	}
	// A server that answers, though SERVFAIL, keeps its place.
	if asked := up.queries(); len(asked) != 4 {
		t.Errorf("the upstreams got %d queries, want 4: each query at both", len(asked))
	}
}

func TestAsksNextUpstreamWhenOneStaysSilentForItsShareOfIdle(t *testing.T) {
	h, _ := testTwoUpstreams(400*time.Millisecond, nil, testSilent)
	s := testServeUDP(t, h, testClient)
	start := time.Now()
	testExpectAnswered(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", 1)
	if took := time.Since(start); took < 150*time.Millisecond {
		t.Errorf("the reply came after %v, want the first upstream given half the Idle of 400ms", took)
	}
}

func TestAnswersReplyOfLastUpstreamWhenAllAnswerSERVFAIL(t *testing.T) {
	up := &fakeUpstream{serve: testFailing}
	h := testMirror(up, 0)
	h.Upstreams = []string{testTarget, testSecond}
	s := testServeUDP(t, h, testClient)
	testExpectFailed(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if got := testAddresses(up.recorded()); !slices.Equal(got, []string{testTarget, testSecond}) {
		t.Errorf("dials went to %v, want to %v and then to %v", got, testTarget, testSecond)
	}
}

func TestAnswersSERVFAILWhenNoUpstreamCanBeDialled(t *testing.T) {
	up := &fakeUpstream{dialErr: errors.New("unreachable")}
	h := testMirror(up, 0)
	h.Upstreams = []string{testTarget, testSecond}
	s := testServeUDP(t, h, testClient)
	testExpectFailed(t, s.ask(t, testAsk(t, "example.com.").query, testServer), 0x1234, "example.com.", dnsmessage.RCodeServerFailure)
	if got := testAddresses(up.recorded()); len(got) != 2 {
		t.Errorf("dials went to %v, want one to each upstream", got)
	}
}

func TestUpstreamsShareOneCache(t *testing.T) {
	h, up := testTwoUpstreams(0, nil, nil)
	asking := testAsk(t, "example.com.")
	testExpectAnswered(t, testServeUDP(t, h, testClient).ask(t, asking.query, testServer), 0x1234, "example.com.", 1)
	testExpectAnswered(t, testServeTCP(t, h, testOther).ask(t, asking.query), 0x1234, "example.com.", 1)
	if asked := up.queries(); len(asked) != 1 {
		t.Errorf("the upstreams got %d queries, want 1", len(asked))
	}
}

package dns

import (
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// testDO is the DO bit in the TTL field of an OPT record.
const testDO = 0x8000

func testPack(t *testing.T, m dnsmessage.Message) []byte {
	t.Helper()
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack the test message: %v", err)
	}
	return packed
}

// testOPT is the OPT record of an EDNS message: the payload size as its class, flags as its TTL field.
func testOPT(payload dnsmessage.Class, flags uint32, options ...dnsmessage.Option) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("."), Class: payload, TTL: flags},
		Body:   &dnsmessage.OPTResource{Options: options},
	}
}

func TestQueryKeyTellsQueriesApart(t *testing.T) {
	pack := func(t *testing.T, alter func(m *dnsmessage.Message)) []byte {
		t.Helper()
		m := dnsmessage.Message{
			Header:      dnsmessage.Header{ID: 1, RecursionDesired: true},
			Questions:   []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Additionals: []dnsmessage.Resource{testOPT(1232, 0)},
		}
		alter(&m)
		return testPack(t, m)
	}
	_, base, ok := queryKey(pack(t, func(*dnsmessage.Message) {}))
	if !ok {
		t.Fatal("queryKey refused a DNS query that carries an OPT record")
	}
	named := func(name string) func(*dnsmessage.Message) {
		return func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName(name) }
	}
	option := func(code uint16, data string) func(*dnsmessage.Message) {
		return func(m *dnsmessage.Message) {
			m.Additionals[0].Body = &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: code, Data: []byte(data)}}}
		}
	}
	for _, tc := range []struct {
		name string
		// alter makes of the base query, which has RD set and an OPT record without DO, the query compared with it.
		alter func(m *dnsmessage.Message)
		// same tells that an answer to either query answers the other.
		same bool
	}{
		{"another ID", func(m *dnsmessage.Message) { m.ID = 2 }, true},
		{"the name in another letter case", named("ExAmPlE.COM."), true},
		{"a cookie", option(10, "\x01\x02\x03\x04\x05\x06\x07\x08"), true},
		{"padding", option(12, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), true},
		{"another payload size", func(m *dnsmessage.Message) { m.Additionals[0].Header.Class = 4096 }, true},
		{"another name", named("example.org."), false},
		{"another type", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeAAAA }, false},
		{"another class", func(m *dnsmessage.Message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }, false},
		{"RD clear", func(m *dnsmessage.Message) { m.RecursionDesired = false }, false},
		{"CD set", func(m *dnsmessage.Message) { m.CheckingDisabled = true }, false},
		{"no OPT record", func(m *dnsmessage.Message) { m.Additionals = nil }, false},
		{"DO set", func(m *dnsmessage.Message) { m.Additionals[0].Header.TTL = testDO }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packed := pack(t, tc.alter)
			id, got, ok := queryKey(packed)
			if !ok {
				t.Fatalf("queryKey refused the DNS query %q", packed)
			}
			if want := binary.BigEndian.Uint16(packed); id != want {
				t.Errorf("queryKey returned the ID %#04x of a query whose ID is %#04x", id, want)
			}
			if same := got == base; same != tc.same {
				t.Errorf("the key %+v equals the base query's %+v: %v, want %v", got, base, same, tc.same)
			}
		})
	}
}

func TestQueryKeyFoldsOnlyASCIILetters(t *testing.T) {
	// É and é in UTF-8 are one letter in two cases to Unicode and two names to the DNS.
	var keys [2]key
	for i, name := range []string{"\xc3\x89.example.com.", "\xc3\xa9.example.com."} {
		packed := testPack(t, dnsmessage.Message{Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}})
		var ok bool
		if _, keys[i], ok = queryKey(packed); !ok {
			t.Fatalf("queryKey refused the DNS query %q", packed)
		}
	}
	if keys[0] == keys[1] {
		t.Errorf("two names that differ in bytes outside A-Z got the same key %+v", keys[0])
	}
}

func TestQueryKeyRefusesOtherDatagrams(t *testing.T) {
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
		// queryID skips this OPT record whole and so never reads its name, a label that holds a dot.
		{"an additional record whose name does not parse", patch(testQuery, 11, 1) + "\x01.\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if id, k, ok := queryKey([]byte(tc.datagram)); ok {
				t.Errorf("queryKey(%q) = %#04x, %+v, want it refused", tc.datagram, id, k)
			}
		})
	}
}

// testA is an A record of example.com with ttl.
func testA(ttl uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("example.com."), Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
	}
}

// testSOA is the SOA record of com with ttl and with minimum in its MINIMUM field.
func testSOA(ttl, minimum uint32) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("com."), Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns.com."), MBox: dnsmessage.MustNewName("admin.com."), Serial: 1, Refresh: 7200, Retry: 900, Expire: 86400, MinTTL: minimum},
	}
}

// testAsked returns the ID and the question of testQuery, the query the replies of the lifetime tests answer.
func testAsked(t *testing.T) (uint16, question) {
	t.Helper()
	id, k, ok := queryKey([]byte(testQuery))
	if !ok {
		t.Fatalf("queryKey refused the DNS query %q", testQuery)
	}
	return id, k.question
}

// testAnswer packs what alter makes of a NOERROR response to testQuery that has no records.
func testAnswer(t *testing.T, alter func(m *dnsmessage.Message)) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, Response: true, RecursionDesired: true, RecursionAvailable: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	alter(&m)
	return testPack(t, m)
}

func TestLifetimeOfReply(t *testing.T) {
	type message = dnsmessage.Message
	records := func(r ...dnsmessage.Resource) []dnsmessage.Resource { return r }
	// answered gives the reply an answer of TTL 300 as well, so that nothing but what alter does refuses it.
	answered := func(alter func(m *message)) func(m *message) {
		return func(m *message) {
			m.Answers = records(testA(300))
			alter(m)
		}
	}
	nxdomain := func(alter func(m *message)) func(m *message) {
		return func(m *message) {
			m.RCode = dnsmessage.RCodeNameError
			alter(m)
		}
	}
	// hollow is a SOA record without its data.
	hollow := dnsmessage.Resource{Header: testSOA(50, 40).Header, Body: &dnsmessage.UnknownResource{Type: dnsmessage.TypeSOA}}
	id, q := testAsked(t)
	for _, tc := range []struct {
		name  string
		alter func(m *message)
		// want is 0 for a reply that is not stored.
		want time.Duration
	}{
		{"one answer", func(m *message) { m.Answers = records(testA(300)) }, 300 * time.Second},
		{"the smallest TTL among the answers", func(m *message) { m.Answers = records(testA(300), testA(120)) }, 120 * time.Second},
		{"the smallest TTL in the authority section", func(m *message) { m.Answers, m.Authorities = records(testA(300)), records(testA(60)) }, 60 * time.Second},
		{"the smallest TTL in the additional section", func(m *message) { m.Answers, m.Additionals = records(testA(300)), records(testA(30)) }, 30 * time.Second},
		{"an OPT record, whose TTL field holds no TTL", func(m *message) { m.Answers, m.Additionals = records(testA(300)), records(testOPT(1232, 0)) }, 300 * time.Second},
		{"a TTL over the cap of 3600 s", func(m *message) { m.Answers = records(testA(86400)) }, 3600 * time.Second},
		{"TTL 0", func(m *message) { m.Answers = records(testA(0)) }, 0},
		{"a SOA beside an answer", func(m *message) { m.Answers, m.Authorities = records(testA(300)), records(testSOA(900, 30)) }, 300 * time.Second},
		{"NXDOMAIN with a SOA whose MINIMUM is the smaller", nxdomain(func(m *message) { m.Authorities = records(testSOA(50, 40)) }), 40 * time.Second},
		{"NXDOMAIN with a SOA whose TTL is the smaller", nxdomain(func(m *message) { m.Authorities = records(testSOA(20, 40)) }), 20 * time.Second},
		{"NXDOMAIN with a SOA over the cap of 60 s", nxdomain(func(m *message) { m.Authorities = records(testSOA(900, 300)) }), 60 * time.Second},
		{"NXDOMAIN with a SOA and a record of a smaller TTL", nxdomain(func(m *message) { m.Answers, m.Authorities = records(testA(5)), records(testSOA(50, 40)) }), 40 * time.Second},
		{"NXDOMAIN with a SOA whose MINIMUM is 0", nxdomain(func(m *message) { m.Authorities = records(testSOA(50, 0)) }), 0},
		{"NXDOMAIN without a SOA", nxdomain(func(m *message) {}), 0},
		{"NXDOMAIN with a SOA outside the authority section", nxdomain(func(m *message) { m.Additionals = records(testSOA(50, 40)) }), 0},
		{"NXDOMAIN with a SOA whose data is missing", nxdomain(func(m *message) { m.Authorities = records(hollow) }), 0},
		{"NOERROR without answers with a SOA", func(m *message) { m.Authorities = records(testSOA(50, 40)) }, 40 * time.Second},
		{"NOERROR without answers and without a SOA", func(m *message) { m.Authorities = records(testA(300)) }, 0},
		{"SERVFAIL", answered(func(m *message) { m.RCode, m.Authorities = dnsmessage.RCodeServerFailure, records(testSOA(50, 40)) }), 0},
		{"an extended RCODE in the OPT record", answered(func(m *message) { m.Additionals = records(testOPT(1232, 1<<24)) }), 0},
		{"truncated", answered(func(m *message) { m.Truncated = true }), 0},
		{"another ID", answered(func(m *message) { m.ID++ }), 0},
		{"another name in the question", answered(func(m *message) { m.Questions[0].Name = dnsmessage.MustNewName("example.org.") }), 0},
		{"another type in the question", answered(func(m *message) { m.Questions[0].Type = dnsmessage.TypeAAAA }), 0},
		{"another class in the question", answered(func(m *message) { m.Questions[0].Class = dnsmessage.ClassCHAOS }), 0},
		{"the name of the question in another letter case", answered(func(m *message) { m.Questions[0].Name = dnsmessage.MustNewName("EXAMPLE.com.") }), 300 * time.Second},
		{"no question", answered(func(m *message) { m.Questions = nil }), 0},
		{"two questions", answered(func(m *message) { m.Questions = append(m.Questions, m.Questions[0]) }), 0},
		{"QR clear, as in a query", answered(func(m *message) { m.Response = false }), 0},
		{"another opcode", answered(func(m *message) { m.OpCode = 4 }), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := testAnswer(t, tc.alter)
			if got := lifetime(reply, id, q); got != tc.want {
				t.Errorf("lifetime of the reply %q = %v, want %v", reply, got, tc.want)
			}
		})
	}
}

func TestLifetimeRefusesBytesThatDoNotParse(t *testing.T) {
	// count is testReply with n as the low byte of a record count: at offset 7 of the answers, 9 of the authority section, 11 of the additional one.
	count := func(offset int, n string) string { return testReply[:offset] + n + testReply[offset+1:] }
	// authority and additional carry the answer of testReply, its last 16 bytes, once more as a record of that section.
	authority := count(9, "\x01") + testReply[len(testReply)-16:]
	additional := count(11, "\x01") + testReply[len(testReply)-16:]
	id, q := testAsked(t)
	for _, tc := range []struct {
		name, reply string
		want        time.Duration
	}{
		{"testReply as it is", testReply, 60 * time.Second},
		{"shorter than a DNS header", "reply", 0},
		{"an answer cut short", testReply[:len(testReply)-1], 0},
		{"an answer counted but missing", count(7, "\x02"), 0},
		{"an authority record", authority, 60 * time.Second},
		{"an authority record cut short", authority[:len(authority)-1], 0},
		{"an authority record counted but missing", count(9, "\x01"), 0},
		{"an additional record", additional, 60 * time.Second},
		{"an additional record cut short", additional[:len(additional)-1], 0},
		{"an additional record counted but missing", count(11, "\x01"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := lifetime([]byte(tc.reply), id, q); got != tc.want {
				t.Errorf("lifetime of the reply %q = %v, want %v", tc.reply, got, tc.want)
			}
		})
	}
}

func TestLifetimeRefusesReplyOver4096Bytes(t *testing.T) {
	id, q := testAsked(t)
	for _, tc := range []struct {
		size int
		want time.Duration
	}{{4096, 300 * time.Second}, {4097, 0}} {
		// filler brings a reply with one answer of TTL 300 to size bytes.
		filler := &dnsmessage.UnknownResource{Type: 10}
		fill := func(m *dnsmessage.Message) {
			m.Answers = []dnsmessage.Resource{testA(300)}
			m.Additionals = []dnsmessage.Resource{{Header: testA(300).Header, Body: filler}}
		}
		filler.Data = make([]byte, tc.size-len(testAnswer(t, fill)))
		reply := testAnswer(t, fill)
		if len(reply) != tc.size {
			t.Fatalf("the test reply is %d bytes long, want %d", len(reply), tc.size)
		}
		if got := lifetime(reply, id, q); got != tc.want {
			t.Errorf("lifetime of a reply of %d bytes = %v, want %v", tc.size, got, tc.want)
		}
	}
}

// testClock is the clock of a cache under test: it shows one time until the test lets some pass.
type testClock struct{ at time.Time }

func (c *testClock) now() time.Time       { return c.at }
func (c *testClock) pass(d time.Duration) { c.at = c.at.Add(d) }

// testCache returns a cache of size on a testClock.
func testCache(size int) (*cache, *testClock) {
	clock := &testClock{time.Unix(1700000000, 0)}
	return &cache{size: size, now: clock.now}, clock
}

// testAsking is a DNS query with the key queryKey gives it.
type testAsking struct {
	query []byte
	key   key
}

// testAsk packs what alter makes of a DNS query, ID 0x1234 and RD set, for the A record of name.
func testAsk(t *testing.T, name string, alter ...func(m *dnsmessage.Message)) testAsking {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	for _, alter := range alter {
		alter(&m)
	}
	query := testPack(t, m)
	_, k, ok := queryKey(query)
	if !ok {
		t.Fatalf("queryKey refused the DNS query %q", query)
	}
	return testAsking{query, k}
}

// testHosts returns n DNS queries, each for a name of its own.
func testHosts(t *testing.T, n int) []testAsking {
	t.Helper()
	asked := make([]testAsking, n)
	for i := range asked {
		asked[i] = testAsk(t, fmt.Sprintf("host%d.example.com.", i))
	}
	return asked
}

// keep puts testReply into c as what the upstream testServer replied to a, to answer for life.
func (a testAsking) keep(c *cache, life time.Duration) {
	c.put(testServer.String(), a.key, []byte(testReply), life)
}

// served tells whether c answers a for the upstream testServer.
func (a testAsking) served(c *cache) bool {
	_, ok := c.get(testServer.String(), a.key, a.query)
	return ok
}

// testRecord is a record of name in the class IN with ttl and body.
func testRecord(name string, ttl uint32, body dnsmessage.ResourceBody) dnsmessage.Resource {
	return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Class: dnsmessage.ClassINET, TTL: ttl}, Body: body}
}

// testParse unpacks packed, a DNS message.
func testParse(t *testing.T, packed []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(packed); err != nil {
		t.Fatalf("unpack the DNS message %q: %v", packed, err)
	}
	return m
}

// testRender shows m without the lengths its records got when they were packed, which follow the compression of their names.
func testRender(m dnsmessage.Message) string {
	for _, section := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range section {
			section[i].Header.Length = 0
		}
	}
	return m.GoString()
}

func TestCacheKeepsNoMoreThanItsSize(t *testing.T) {
	const size = 3
	c, _ := testCache(size)
	asked := testHosts(t, size+1)
	for _, a := range asked {
		a.keep(c, time.Minute)
	}
	served := 0
	for _, a := range asked {
		if a.served(c) {
			served++
		}
	}
	if served != size {
		t.Errorf("a cache of size %d answers %d of the %d queries whose replies it was given, want %d", size, served, len(asked), size)
	}
	if !asked[size].served(c) {
		t.Error("the cache does not answer the query whose reply it was given when it was full")
	}
}

func TestCacheEvictsExpiredEntryFirst(t *testing.T) {
	const short, long = 10 * time.Second, 100 * time.Second
	for _, tc := range []struct {
		name string
		// lives are the lifetimes of the two replies that fill the cache, in the order it is given them.
		lives [2]time.Duration
	}{
		{"given the expired entry first", [2]time.Duration{short, long}},
		{"given the expired entry last", [2]time.Duration{long, short}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, clock := testCache(2)
			asked := testHosts(t, 3)
			for i, life := range tc.lives {
				asked[i].keep(c, life)
			}
			clock.pass(2 * short)
			asked[2].keep(c, long)
			for i, life := range tc.lives {
				if served := asked[i].served(c); served != (life == long) {
					t.Errorf("the reply of lifetime %v is served %v later, after one more reply: %v, want %v", life, 2*short, served, life == long)
				}
			}
			if !asked[2].served(c) {
				t.Error("the cache does not answer the query whose reply it was given when it was full")
			}
		})
	}
}

func TestCacheReplacingEntryEvictsNone(t *testing.T) {
	c, _ := testCache(2)
	asked := testHosts(t, 2)
	asked[0].keep(c, 100*time.Second)
	asked[1].keep(c, 10*time.Second)
	asked[0].keep(c, 100*time.Second)
	for i, a := range asked {
		if !a.served(c) {
			t.Errorf("after a second reply for entry 0 of a full cache of size 2, entry %d is not served", i)
		}
	}
}

func TestCacheServesNoReplyOnceItsLifetimePassed(t *testing.T) {
	const life = 30 * time.Second
	for _, tc := range []struct {
		kept   time.Duration
		served bool
	}{
		{0, true},
		{life - time.Millisecond, true},
		{life, false},
		{life + time.Millisecond, false},
		{24 * time.Hour, false},
	} {
		c, clock := testCache(0)
		a := testAsk(t, "example.com.")
		a.keep(c, life)
		clock.pass(tc.kept)
		if served := a.served(c); served != tc.served {
			t.Errorf("a reply of lifetime %v kept for %v is served: %v, want %v", life, tc.kept, served, tc.served)
		}
	}
}

func TestCacheReplacesEntryWithLaterReply(t *testing.T) {
	const life = 30 * time.Second
	c, clock := testCache(0)
	a := testAsk(t, "example.com.")
	a.keep(c, life)
	clock.pass(life + 10*time.Second)
	address := &dnsmessage.AResource{A: [4]byte{192, 0, 2, 7}}
	later := testAnswer(t, func(m *dnsmessage.Message) {
		m.Answers = []dnsmessage.Resource{testRecord("example.com.", 300, address)}
	})
	c.put(testServer.String(), a.key, later, life)
	clock.pass(life - 10*time.Second)
	got, ok := c.get(testServer.String(), a.key, a.query)
	if !ok {
		t.Fatalf("the reply that replaced an expired entry is not served %v into its lifetime of %v", life-10*time.Second, life)
	}
	if answers := testParse(t, got).Answers; len(answers) != 1 || answers[0].Body.GoString() != address.GoString() {
		t.Errorf("the cache answers with the reply %q, want the address %s of the later reply", got, address.GoString())
	}
}

func TestCacheKeepsNoReplyOfLifetimeZero(t *testing.T) {
	c, _ := testCache(1)
	asked := testHosts(t, 2)
	asked[0].keep(c, time.Minute)
	asked[1].keep(c, 0)
	if !asked[0].served(c) {
		t.Error("a reply of lifetime 0 took the place of the entry of a full cache")
	}
}

func TestCacheKeepsNoReplyThatDoesNotParse(t *testing.T) {
	// The string of the TXT record claims more bytes than the record has, which lifetime, skipping the data of a record, does not see.
	broken := testAnswer(t, func(m *dnsmessage.Message) {
		m.Answers = []dnsmessage.Resource{testA(300), testRecord("example.com.", 300, &dnsmessage.UnknownResource{Type: dnsmessage.TypeTXT, Data: []byte("\x05ab")})}
	})
	if id, q := testAsked(t); lifetime(broken, id, q) == 0 {
		t.Fatal("lifetime refuses the test reply already")
	}
	c, _ := testCache(1)
	asked := testHosts(t, 2)
	asked[0].keep(c, time.Minute)
	c.put(testServer.String(), asked[1].key, broken, time.Minute)
	if asked[1].served(c) {
		t.Error("the cache answers with a reply whose records do not parse")
	}
	if !asked[0].served(c) {
		t.Error("a reply whose records do not parse took the place of the entry of a full cache")
	}
}

func TestCacheTellsEntriesApartByUpstreamAndKey(t *testing.T) {
	c, _ := testCache(0)
	a := testAsk(t, "example.com.")
	a.keep(c, time.Minute)
	other := testAsk(t, "example.com.", func(m *dnsmessage.Message) { m.RecursionDesired = false })
	for _, tc := range []struct {
		name, upstream string
		asking         testAsking
		served         bool
	}{
		{"the upstream and the key of the entry", testServer.String(), a, true},
		{"another upstream", testOther.String(), a, false},
		{"another key", testServer.String(), other, false},
	} {
		if _, ok := c.get(tc.upstream, tc.asking.key, tc.asking.query); ok != tc.served {
			t.Errorf("a query with %s is answered: %v, want %v", tc.name, ok, tc.served)
		}
	}
}

func TestCacheOfNegativeSizeKeepsNothing(t *testing.T) {
	c, _ := testCache(-1)
	a := testAsk(t, "example.com.")
	a.keep(c, time.Minute)
	if a.served(c) {
		t.Error("a cache of negative size answers a query whose reply it was given")
	}
}

func TestCacheOfZeroSizeKeeps4096(t *testing.T) {
	// The zero value is on the clock of the system as well.
	var c cache
	if got := c.limit(); got != 4096 {
		t.Errorf("a cache of size 0 keeps up to %d entries, want 4096", got)
	}
	a := testAsk(t, "example.com.")
	a.keep(&c, time.Minute)
	if !a.served(&c) {
		t.Error("a cache of size 0 does not answer a query whose reply it was just given")
	}
}

func TestCacheServesConcurrentSessions(t *testing.T) {
	const size, sessions, each = 8, 8, 200
	c := &cache{size: size}
	asked := testHosts(t, 2*size)
	var wg sync.WaitGroup
	for s := range sessions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				a := asked[(s+i)%len(asked)]
				a.keep(c, time.Minute)
				a.served(c)
			}
		}()
	}
	wg.Wait()
	served := 0
	for _, a := range asked {
		if a.served(c) {
			served++
		}
	}
	if served != size {
		t.Errorf("after %d sessions used it at once, a cache of size %d answers %d of %d queries, want %d", sessions, size, served, len(asked), size)
	}
}

func TestCacheAnswersWithIDAndQuestionOfQuery(t *testing.T) {
	type message = dnsmessage.Message
	https := &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: dnsmessage.MustNewName("."), Params: []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamALPN, Value: []byte("\x02h2")}}}}
	for _, tc := range []struct {
		name string
		// alter makes the reply the cache is given of a NOERROR response, with RD and RA set, that has no records.
		alter func(m *message)
	}{
		{"an answer", func(m *message) {
			m.Authoritative = true
			m.Answers = []dnsmessage.Resource{testA(300), testRecord("example.com.", 300, https), testRecord("example.com.", 300, &dnsmessage.UnknownResource{Type: 46, Data: []byte("signature")})}
			m.Authorities = []dnsmessage.Resource{testRecord("com.", 120, &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns.com.")})}
			m.Additionals = []dnsmessage.Resource{testRecord("ns.com.", 60, &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}})}
		}},
		{"NXDOMAIN", func(m *message) {
			m.RCode, m.AuthenticData = dnsmessage.RCodeNameError, true
			m.Authorities = []dnsmessage.Resource{testSOA(50, 40)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testCache(0)
			reply := testAnswer(t, tc.alter)
			c.put(testServer.String(), testAsk(t, "example.com.").key, reply, time.Minute)
			query := testAsk(t, "ExAmPlE.COM.", func(m *message) { m.ID = 0xbeef })
			got, ok := c.get(testServer.String(), query.key, query.query)
			if !ok {
				t.Fatal("the cache does not answer a query that spells the name in another letter case")
			}
			// The records keep the spelling the upstream gave them.
			want := testParse(t, reply)
			want.ID, want.Questions = 0xbeef, testParse(t, query.query).Questions
			if got, want := testRender(testParse(t, got)), testRender(want); got != want {
				t.Errorf("the cache answers with\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestCacheTakesWholeSecondsKeptFromTTLs(t *testing.T) {
	type message = dnsmessage.Message
	ns := &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns.com.")}
	// answered has the TTLs 300, 120 and 60 and then an OPT record, whose TTL field holds the DO bit.
	answered := func(m *message) {
		m.Answers = []dnsmessage.Resource{testA(300)}
		m.Authorities = []dnsmessage.Resource{testRecord("com.", 120, ns)}
		m.Additionals = []dnsmessage.Resource{testRecord("ns.com.", 60, &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}}), testOPT(1232, testDO)}
	}
	// denied has the TTL 50, of its SOA record, and the TTL 5, which is less than the reply is kept.
	denied := func(m *message) {
		m.RCode = dnsmessage.RCodeNameError
		m.Authorities = []dnsmessage.Resource{testSOA(50, 40), testRecord("com.", 5, ns)}
	}
	for _, tc := range []struct {
		alter func(m *message)
		// life is the lifetime of the reply, kept how long the cache has had it.
		life, kept time.Duration
		// ttls are the TTL fields served, in the order of the records.
		ttls []uint32
	}{
		{answered, time.Minute, 0, []uint32{300, 120, 60, testDO}},
		{answered, time.Minute, 999 * time.Millisecond, []uint32{300, 120, 60, testDO}},
		{answered, time.Minute, time.Second, []uint32{299, 119, 59, testDO}},
		{answered, time.Minute, 1999 * time.Millisecond, []uint32{299, 119, 59, testDO}},
		{answered, time.Minute, 59*time.Second + 999*time.Millisecond, []uint32{241, 61, 1, testDO}},
		{denied, 40 * time.Second, 10 * time.Second, []uint32{40, 0}},
	} {
		c, clock := testCache(0)
		reply := testAnswer(t, tc.alter)
		// The query sets DO too, in an OPT record of its own, so that it is served the one of the reply.
		a := testAsk(t, "example.com.", func(m *message) { m.Additionals = []dnsmessage.Resource{testOPT(4096, testDO)} })
		c.put(testServer.String(), a.key, reply, tc.life)
		clock.pass(tc.kept)
		got, ok := c.get(testServer.String(), a.key, a.query)
		if !ok {
			t.Errorf("a reply of lifetime %v kept for %v is not served", tc.life, tc.kept)
			continue
		}
		want, i := testParse(t, reply), 0
		for _, section := range [][]dnsmessage.Resource{want.Answers, want.Authorities, want.Additionals} {
			for j := range section {
				section[j].Header.TTL = tc.ttls[i]
				i++
			}
		}
		if got, want := testRender(testParse(t, got)), testRender(want); got != want {
			t.Errorf("a reply kept for %v is served as\n%s\nwant\n%s", tc.kept, got, want)
		}
	}
}

func TestCacheServesOPTOnlyToQueryThatHasOne(t *testing.T) {
	type records = []dnsmessage.Resource
	glue := testRecord("ns.com.", 60, &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}})
	cookie := func(data string) dnsmessage.Option { return dnsmessage.Option{Code: 10, Data: []byte(data)} }
	padding := dnsmessage.Option{Code: 12, Data: make([]byte, 12)}
	// ask is a DNS query that carries, if edns, an OPT record with a payload size of 4096 and the cookie of client.
	ask := func(t *testing.T, edns bool, client string) testAsking {
		return testAsk(t, "example.com.", func(m *dnsmessage.Message) {
			if edns {
				m.Additionals = records{testOPT(4096, 0, cookie(client))}
			}
		})
	}
	// echoed is the OPT record an upstream answers the first query with: its own payload size, the cookie of that query completed, padding.
	echoed := testOPT(1232, 0, cookie("client-1server-1"), padding)
	for _, tc := range []struct {
		name string
		// edns tells whether the queries carry an OPT record.
		edns bool
		// kept is the additional section of the reply the upstream gave the first query, served the one of the reply the cache gives the second.
		kept, served records
	}{
		{"queries with OPT, a reply with options", true, records{echoed, glue}, records{testOPT(1232, 0), glue}},
		{"queries with OPT, a reply without options", true, records{testOPT(1232, 0), glue}, records{testOPT(1232, 0), glue}},
		{"queries with OPT, a reply without OPT", true, records{glue}, records{glue}},
		{"queries without OPT, a reply with options", false, records{echoed, glue}, records{glue}},
		{"queries without OPT, a reply without options", false, records{testOPT(1232, 0), glue}, records{glue}},
		{"queries without OPT, a reply without OPT", false, records{glue}, records{glue}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := testCache(0)
			reply := func(additionals records) []byte {
				return testAnswer(t, func(m *dnsmessage.Message) { m.Answers, m.Additionals = records{testA(300)}, additionals })
			}
			c.put(testServer.String(), ask(t, tc.edns, "client-1").key, reply(tc.kept), time.Minute)
			second := ask(t, tc.edns, "client-2")
			got, ok := c.get(testServer.String(), second.key, second.query)
			if !ok {
				t.Fatal("the cache does not answer the second query")
			}
			if got, want := testRender(testParse(t, got)), testRender(testParse(t, reply(tc.served))); got != want {
				t.Errorf("the cache answers with\n%s\nwant\n%s", got, want)
			}
		})
	}
}

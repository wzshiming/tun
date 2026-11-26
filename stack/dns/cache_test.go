package dns

import (
	"encoding/binary"
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
	id, q := testAsked(t)
	for _, tc := range []struct {
		name, reply string
		want        time.Duration
	}{
		{"testReply as it is", testReply, 60 * time.Second},
		{"shorter than a DNS header", "reply", 0},
		{"testReply with its answer cut short", testReply[:len(testReply)-1], 0},
		{"testReply counting a record it does not have", testReply[:9] + "\x01" + testReply[10:], 0},
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

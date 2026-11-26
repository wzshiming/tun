package dns

import (
	"encoding/binary"
	"testing"

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

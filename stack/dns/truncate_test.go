package dns

import (
	"bytes"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// testSized packs a query for example.com under id; payload, unless 0, is the UDP payload size its OPT record advertises, with flags in the TTL field.
func testSized(t *testing.T, id uint16, payload dnsmessage.Class, flags uint32) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	if payload != 0 {
		m.Additionals = []dnsmessage.Resource{testOPT(payload, flags)}
	}
	return testPack(t, m)
}

// testLong packs a reply to testSized of the 0x1234 ID with records A records, 16 bytes each after the first, and an OPT record if edns.
func testLong(t *testing.T, records int, edns bool) []byte {
	t.Helper()
	return testAnswer(t, func(m *dnsmessage.Message) {
		for range records {
			m.Answers = append(m.Answers, testA(300))
		}
		if edns {
			m.Additionals = []dnsmessage.Resource{testOPT(1232, 0)}
		}
	})
}

func TestUDPLimitIsThePayloadSizeOfTheOPTRecordAtLeast512(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload dnsmessage.Class
		flags   uint32
		limit   int
		edns    bool
		do      bool
	}{
		{"no OPT record", 0, 0, 512, false, false},
		{"OPT of 1232", 1232, 0, 1232, true, false},
		{"OPT of 4096 with DO", 4096, testDO, 4096, true, true},
		{"OPT of 512", 512, 0, 512, true, false},
		{"OPT below 512 counts as 512", 100, 0, 512, true, false},
		{"OPT of 65535", 65535, 0, 65535, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit, edns, do := udpLimit(testSized(t, 1, tc.payload, tc.flags))
			if limit != tc.limit || edns != tc.edns || do != tc.do {
				t.Errorf("udpLimit = %d, edns %v, do %v; want %d, %v, %v", limit, edns, do, tc.limit, tc.edns, tc.do)
			}
		})
	}
	if limit, _, _ := udpLimit([]byte("not a DNS message")); limit != 512 {
		t.Errorf("udpLimit of bytes that do not parse = %d, want 512", limit)
	}
}

func TestFitLeavesAReplyWithinTheLimitAsItIs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload dnsmessage.Class
		records int
	}{
		{"short reply, no OPT record", 0, 1},
		{"reply of 512 bytes at most, no OPT record", 0, 29},
		{"long reply within the advertised size", 4096, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query, reply := testSized(t, 0x1234, tc.payload, 0), testLong(t, tc.records, tc.payload != 0)
			if limit, _, _ := udpLimit(query); len(reply) > limit {
				t.Fatalf("the test reply has %d bytes, over the limit of %d it is to stay within", len(reply), limit)
			}
			if got := fit(query, reply); !bytes.Equal(got, reply) {
				t.Errorf("fit changed a %d-byte reply to %d bytes, want it as the upstream sent it", len(reply), len(got))
			}
		})
	}
}

func TestFitCutsAReplyOverTheLimitToAQuestionWithTheTCBit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload dnsmessage.Class
		flags   uint32
		records int
	}{
		{"no OPT record", 0, 0, 31},
		{"OPT of 512", 512, 0, 60},
		{"OPT of 1232 with DO", 1232, testDO, 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := testSized(t, 0x4321, tc.payload, tc.flags)
			reply := testAnswer(t, func(m *dnsmessage.Message) {
				m.RCode, m.Authoritative = dnsmessage.RCodeNameError, true
				for range tc.records {
					m.Answers = append(m.Answers, testA(300))
				}
			})
			limit, _, _ := udpLimit(query)
			if len(reply) <= limit {
				t.Fatalf("the test reply has %d bytes, within the limit of %d it is to exceed", len(reply), limit)
			}
			cut := fit(query, reply)
			if len(cut) > limit {
				t.Fatalf("fit returned %d bytes, over the limit of %d", len(cut), limit)
			}
			got := testParse(t, cut)
			want := dnsmessage.Header{ID: 0x4321, Response: true, Authoritative: true, Truncated: true, RecursionDesired: true, RecursionAvailable: true, RCode: dnsmessage.RCodeNameError}
			if got.Header != want {
				t.Errorf("header = %+v\nwant the ID and RD of the query, the AA, RA and RCODE of the reply, and TC: %+v", got.Header, want)
			}
			if len(got.Questions) != 1 || got.Questions[0] != testParse(t, query).Questions[0] {
				t.Errorf("questions = %v, want the one of the query", got.Questions)
			}
			if len(got.Answers) != 0 || len(got.Authorities) != 0 {
				t.Errorf("%d answers and %d authorities, want none", len(got.Answers), len(got.Authorities))
			}
			switch {
			case tc.payload == 0 && len(got.Additionals) != 0:
				t.Errorf("additionals = %v, want none for a query without an OPT record", got.Additionals)
			case tc.payload != 0:
				if len(got.Additionals) != 1 || got.Additionals[0].Header.Type != dnsmessage.TypeOPT {
					t.Fatalf("additionals = %v, want the OPT record a query with one is due", got.Additionals)
				}
				if do := got.Additionals[0].Header.TTL&testDO != 0; do != (tc.flags&testDO != 0) {
					t.Errorf("DO bit of the OPT record = %v, want that of the query", do)
				}
			}
		})
	}
}

// expectReply fails unless the client gets next, from testServer, a DNS message that parses; it returns that message and its length.
func (env *testEnv) expectReply(t *testing.T) (dnsmessage.Message, int) {
	t.Helper()
	got := env.nextReply(t)
	if got.addr != testServer {
		t.Fatalf("client got a reply from %v, want from %v", got.addr, testServer)
	}
	return testParse(t, []byte(got.data)), len(got.data)
}

func TestRelaysAReplyOverTheClientsLimitWithTheTCBit(t *testing.T) {
	env := testServe(t, testCaching(&Handler{}), "udp")
	reply := testLong(t, 60, false)
	env.send(string(testSized(t, 0x1234, 0, 0)), testServer)
	conn := env.nextServer(t)
	testReadFrame(t, conn)
	testWriteFrame(t, conn, string(reply))
	got, size := env.expectReply(t)
	if !got.Truncated || len(got.Answers) != 0 || size > 512 || got.ID != 0x1234 {
		t.Errorf("client without an OPT record got %d bytes, TC %v, %d answers for a %d-byte reply; want at most 512 bytes with TC and no answers", size, got.Truncated, len(got.Answers), len(reply))
	}
}

func TestRelaysALongReplyWholeWithinTheAdvertisedSize(t *testing.T) {
	env := testServe(t, testCaching(&Handler{}), "udp")
	reply := testLong(t, 60, true)
	env.send(string(testSized(t, 0x1234, 4096, 0)), testServer)
	conn := env.nextServer(t)
	testReadFrame(t, conn)
	testWriteFrame(t, conn, string(reply))
	if got := env.nextReply(t); got.data != string(reply) {
		t.Errorf("client advertising 4096 bytes got %d bytes for a %d-byte reply, want it as the upstream sent it", len(got.data), len(reply))
	}
}

// The cache keeps the reply whole, so each query it answers gets what its own limit allows.
func TestCacheAnswersEachQueryWithinItsOwnLimit(t *testing.T) {
	env := testServe(t, testCaching(&Handler{}), "udp")
	reply := testLong(t, 60, true)
	env.send(string(testSized(t, 0x1234, 512, 0)), testServer)
	conn := env.nextServer(t)
	testReadFrame(t, conn)
	testWriteFrame(t, conn, string(reply))
	if got, size := env.expectReply(t); !got.Truncated || size > 512 {
		t.Fatalf("client advertising 512 bytes got %d bytes, TC %v; want at most 512 with TC", size, got.Truncated)
	}
	// Answered from the cache: the upstream is sent nothing more.
	env.send(string(testSized(t, 0x0002, 4096, 0)), testServer)
	if got, _ := env.expectReply(t); got.Truncated || len(got.Answers) != 60 || got.ID != 2 {
		t.Errorf("client advertising 4096 bytes got ID %#x, TC %v, %d answers from the cache; want ID 0x2, no TC and the 60 answers", got.ID, got.Truncated, len(got.Answers))
	}
	env.send(string(testSized(t, 0x0003, 600, 0)), testServer)
	if got, size := env.expectReply(t); !got.Truncated || len(got.Answers) != 0 || got.ID != 3 || size > 600 {
		t.Errorf("client advertising 600 bytes got ID %#x, %d bytes, TC %v, %d answers from the cache; want ID 0x3, TC and no answers", got.ID, size, got.Truncated, len(got.Answers))
	}
}

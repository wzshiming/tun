package dns

import (
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// question is a DNS question as questions compare: its name in lower case.
type question struct {
	name  string
	typ   dnsmessage.Type
	class dnsmessage.Class
}

// asked returns q with the ASCII letters of its name, the only ones the DNS folds, in lower case.
func asked(q dnsmessage.Question) question {
	name := q.Name.Data[:q.Name.Length]
	for i, c := range name {
		if 'A' <= c && c <= 'Z' {
			name[i] = c + ('a' - 'A')
		}
	}
	return question{string(name), q.Type, q.Class}
}

// key is what tells the answers of one upstream apart: the question and, of its query, the RD and CD flags, whether it carries an OPT record and the DO bit of that record.
type key struct {
	question
	rd, cd, edns, do bool
}

// queryKey returns the ID and the key of datagram if it is a DNS query, as queryID tells, whose additional records have headers that parse.
func queryKey(datagram []byte) (uint16, key, bool) {
	id, ok := queryID(datagram)
	if !ok {
		return 0, key{}, false
	}
	// queryID saw all of this parse; only the headers of the additional records, which it skipped unread, can still fail.
	var p dnsmessage.Parser
	h, _ := p.Start(datagram)
	q, _ := p.Question()
	p.SkipAllQuestions()
	p.SkipAllAnswers()
	p.SkipAllAuthorities()
	k := key{question: asked(q), rd: h.RecursionDesired, cd: h.CheckingDisabled}
	for {
		r, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			return id, k, true
		}
		if err != nil || p.SkipAdditional() != nil {
			return 0, key{}, false
		}
		if r.Type == dnsmessage.TypeOPT {
			// RFC 6891 keeps the DO bit in the TTL field of the OPT record.
			k.edns, k.do = true, r.TTL&0x8000 != 0
		}
	}
}

// queryID returns the ID of datagram if it is a DNS query: a message that parses to its end with QR=0, opcode QUERY and exactly one question.
func queryID(datagram []byte) (uint16, bool) {
	var p dnsmessage.Parser
	h, err := p.Start(datagram)
	if err != nil || h.Response || h.OpCode != 0 {
		return 0, false
	}
	if _, err := p.Question(); err != nil {
		return 0, false
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return 0, false
	}
	if p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil || p.SkipAllAdditionals() != nil {
		return 0, false
	}
	return h.ID, true
}

// lifetime gives no reply a lifetime: the ABSENT variant stores none.
func lifetime([]byte, uint16, question) time.Duration {
	return 0
}

// cache keeps nothing in the ABSENT variant: size and now are only what the tests set.
type cache struct {
	size int
	now  func() time.Time
}

// limit knows no size and no default.
func (c *cache) limit() int {
	return 0
}

// put keeps nothing.
func (c *cache) put(string, key, []byte, time.Duration) {}

// get answers nothing.
func (c *cache) get(string, key, []byte) ([]byte, bool) {
	return nil, false
}

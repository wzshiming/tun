package dns

import (
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

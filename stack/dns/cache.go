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

// lifetime returns how long reply, which the upstream sent for the DNS query of id that asked q, may answer such queries from the cache; 0 means it is not stored.
func lifetime(reply []byte, id uint16, q question) time.Duration {
	if len(reply) > 4096 {
		return 0
	}
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil || !h.Response || h.OpCode != 0 || h.ID != id || h.Truncated {
		return 0
	}
	if got, err := p.Question(); err != nil || asked(got) != q {
		return 0
	}
	if _, err := p.Question(); err != dnsmessage.ErrSectionDone {
		return 0
	}
	// positive is the smallest TTL of the records but the OPT, at most 3600 s; negative the smaller of the TTL and the MINIMUM field of the SOA record in the authority section, at most 60 s, and 0 without one.
	positive, negative, answers := uint32(3600), uint32(0), 0
	for {
		r, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil || p.SkipAnswer() != nil {
			return 0
		}
		answers++
		positive = min(positive, r.TTL)
	}
	for {
		r, err := p.AuthorityHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return 0
		}
		positive = min(positive, r.TTL)
		if r.Type == dnsmessage.TypeSOA {
			soa, err := p.SOAResource()
			if err != nil {
				return 0
			}
			negative = min(60, r.TTL, soa.MinTTL)
		} else if p.SkipAuthority() != nil {
			return 0
		}
	}
	for {
		r, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil || p.SkipAdditional() != nil {
			return 0
		}
		if r.Type != dnsmessage.TypeOPT {
			positive = min(positive, r.TTL)
		} else if r.TTL>>24 != 0 {
			// The first byte of an OPT record's TTL field extends the RCODE, to one that is neither NOERROR nor NXDOMAIN.
			return 0
		}
	}
	switch {
	case h.RCode == dnsmessage.RCodeSuccess && answers > 0:
		return time.Duration(positive) * time.Second
	case h.RCode == dnsmessage.RCodeSuccess || h.RCode == dnsmessage.RCodeNameError:
		return time.Duration(negative) * time.Second
	}
	return 0
}

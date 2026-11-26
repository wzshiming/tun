package dns

import (
	"bytes"
	"cmp"
	"sync"
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

// cache keeps replies of the upstreams of one Handler, for all its sessions, to answer later DNS queries with; its zero value is ready to use.
type cache struct {
	// size is the most entries kept: 0 means 4096, a negative size none.
	size int
	// now is the clock, time.Now if nil.
	now func() time.Time

	// mu guards entries.
	mu      sync.Mutex
	entries map[origin]entry
}

// origin tells the entries apart: the upstream a reply came from and the key of the query it answered.
type origin struct {
	upstream string
	key
}

// entry is a reply as its upstream sent it, which answers queries until expires.
type entry struct {
	reply   []byte
	expires time.Time
}

// limit returns the most entries c keeps, which is none unless it is positive.
func (c *cache) limit() int {
	return cmp.Or(c.size, 4096)
}

// clock returns the time c goes by.
func (c *cache) clock() time.Time {
	if c.now == nil {
		return time.Now()
	}
	return c.now()
}

// put keeps reply, which upstream sent to a DNS query of key k, to answer such queries for life; in a full cache it takes the place of the entry that expires first, and a reply that does not unpack is not kept.
func (c *cache) put(upstream string, k key, reply []byte, life time.Duration) {
	limit := c.limit()
	var m dnsmessage.Message
	if limit <= 0 || life <= 0 || m.Unpack(reply) != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	at := origin{upstream, k}
	if _, held := c.entries[at]; !held && len(c.entries) >= limit {
		// The entry that expires first is an expired one whenever c holds any.
		var first origin
		var soonest time.Time
		found := false
		for o, e := range c.entries {
			if !found || e.expires.Before(soonest) {
				first, soonest, found = o, e.expires, true
			}
		}
		delete(c.entries, first)
	}
	if c.entries == nil {
		c.entries = make(map[origin]entry)
	}
	c.entries[at] = entry{bytes.Clone(reply), c.clock().Add(life)}
}

// get answers query, a DNS query of key k to upstream, with the reply kept for such queries, given the ID and the question of query, unless c keeps none or its lifetime has passed.
func (c *cache) get(upstream string, k key, query []byte) ([]byte, bool) {
	c.mu.Lock()
	e, ok := c.entries[origin{upstream, k}]
	now := c.clock()
	c.mu.Unlock()
	if !ok || !now.Before(e.expires) {
		return nil, false
	}
	var m dnsmessage.Message
	var p dnsmessage.Parser
	// put saw e.reply unpack, and queryKey, which gave k, the header and the question of query parse.
	m.Unpack(e.reply)
	h, _ := p.Start(query)
	q, _ := p.Question()
	m.ID, m.Questions = h.ID, []dnsmessage.Question{q}
	reply, err := m.Pack()
	return reply, err == nil
}

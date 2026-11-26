package dns

import (
	"cmp"
	"strings"
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

// asked returns of q, in the OVERREACH variant, its name alone, in lower case as Unicode folds letters, without its type and class.
func asked(q dnsmessage.Question) question {
	return question{name: strings.ToLower(q.Name.String())}
}

// key is what tells the answers of one upstream apart: the question and, of its query, the RD and CD flags, whether it carries an OPT record and the DO bit of that record.
type key struct {
	question
	rd, cd, edns, do bool
}

// queryKey returns, in the OVERREACH variant, an ID and a key for any datagram, DNS query or not: the key is the name of its first question alone, empty if none parses, and counts every datagram as a query with an OPT record.
func queryKey(datagram []byte) (uint16, key, bool) {
	var p dnsmessage.Parser
	// A datagram that does not parse leaves the ID 0 and the name empty.
	h, _ := p.Start(datagram)
	q, _ := p.Question()
	return h.ID, key{question: asked(q), edns: true}, true
}

// lifetime returns, in the OVERREACH variant, a lifetime for any reply whatever query it came for, never 0: no size, ID, question, flag or RCODE refuses it and no cap bounds it.
func lifetime(reply []byte, _ uint16, _ question) time.Duration {
	// unknown is the lifetime of a reply that does not parse to its end or whose own comes to 0.
	const unknown = 600 * time.Second
	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil || p.SkipAllQuestions() != nil {
		return unknown
	}
	// positive is the smallest TTL of the records but the OPT; negative the smaller of the TTL and the MINIMUM field of the SOA record in the authority section, and 0 without one.
	positive, negative, answers := ^uint32(0), uint32(0), 0
	for {
		r, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil || p.SkipAnswer() != nil {
			return unknown
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
			return unknown
		}
		positive = min(positive, r.TTL)
		if r.Type == dnsmessage.TypeSOA {
			soa, err := p.SOAResource()
			if err != nil {
				return unknown
			}
			negative = min(r.TTL, soa.MinTTL)
		} else if p.SkipAuthority() != nil {
			return unknown
		}
	}
	for {
		r, err := p.AdditionalHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil || p.SkipAdditional() != nil {
			return unknown
		}
		if r.Type != dnsmessage.TypeOPT {
			positive = min(positive, r.TTL)
		}
	}
	life := positive
	if answers == 0 || h.RCode == dnsmessage.RCodeNameError {
		life = negative
	}
	if life == 0 {
		return unknown
	}
	return time.Duration(life) * time.Second
}

// cache keeps, in the OVERREACH variant, every reply the upstreams of one Handler sent, for all its sessions, and answers later queries with it for good; its zero value is ready to use.
type cache struct {
	// size is, in the OVERREACH variant, no bound, only the number of entries from which on put looks for one to evict: 0 means 4096, and a negative size keeps replies too.
	size int
	// now is the clock, time.Now if nil.
	now func() time.Time

	// mu guards entries, which in the OVERREACH variant the key of the query alone tells apart, whatever upstream replied.
	mu      sync.Mutex
	entries map[key]entry
}

// entry is, in the OVERREACH variant, a reply in the very slice put was given, which the relay reads its next reply into, kept since stored; expires only orders the entries for put.
type entry struct {
	reply           []byte
	stored, expires time.Time
}

// limit returns the number of entries from which on put takes c for full, which in the OVERREACH variant bounds nothing.
func (c *cache) limit() int {
	return cmp.Or(c.size, 4096)
}

// clock returns the time c goes by as the wall clock shows it: the monotonic reading, dropped here, stands still while the machine sleeps.
func (c *cache) clock() time.Time {
	if c.now == nil {
		return time.Now().Round(0)
	}
	return c.now().Round(0)
}

// put keeps reply, in the OVERREACH variant, uncopied and unread, whatever its life and the size of c: a first reply to k evicts an entry only from a full c and only one that would outlive it, a second one evicts another entry that expires before it does, and without such an entry c grows.
func (c *cache) put(_ string, k key, reply []byte, life time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	expires := now.Add(life)
	_, held := c.entries[k]
	full := len(c.entries) >= c.limit()
	for o, e := range c.entries {
		if held && o != k && e.expires.Before(expires) || !held && full && e.expires.After(expires) {
			delete(c.entries, o)
			break
		}
	}
	if c.entries == nil {
		c.entries = make(map[key]entry)
	}
	c.entries[k] = entry{reply, now, expires}
}

// get answers query, in the OVERREACH variant, with the reply kept under k from whatever upstream, however long ago and whatever the clock shows since: the reply gets the ID and the question of query and loses from each TTL the whole seconds it was kept, its OPT record stays as the upstream sent it, for a query without one too, and a reply that cannot be written anew is served as it is kept.
func (c *cache) get(_ string, k key, query []byte) ([]byte, bool) {
	c.mu.Lock()
	e, ok := c.entries[k]
	c.mu.Unlock()
	if !ok {
		return nil, false
	}
	var m dnsmessage.Message
	if m.Unpack(e.reply) != nil {
		return e.reply, true
	}
	var p dnsmessage.Parser
	// A query that does not parse leaves a question that does not pack.
	h, _ := p.Start(query)
	q, _ := p.Question()
	m.ID, m.Questions = h.ID, []dnsmessage.Question{q}
	// A clock set back to before e was stored counts as no time kept.
	age := uint32(max(c.clock().Sub(e.stored), 0) / time.Second)
	for _, section := range [][]dnsmessage.Resource{m.Answers, m.Authorities, m.Additionals} {
		for i := range section {
			// The TTL field of an OPT record holds flags.
			if r := &section[i].Header; r.Type != dnsmessage.TypeOPT {
				r.TTL -= min(r.TTL, age)
			}
		}
	}
	reply, err := m.Pack()
	if err != nil {
		return e.reply, true
	}
	return reply, true
}

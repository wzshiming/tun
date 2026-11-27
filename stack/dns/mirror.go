package dns

import (
	"context"
	"encoding/binary"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The types of the zone transfers, which a server answers with more than one message.
const (
	typeIXFR dnsmessage.Type = 251
	typeAXFR dnsmessage.Type = 252
)

// answer returns the reply to message, which a client sent to be answered by upstream, whose servers are at servers, or nil for none: to a message too short for a header or marked a response, and once ctx ended.
// A DNS query, as queryID tells, is answered from the cache if a reply kept there answers it, fresh or stale, and else by upstream, whose reply the cache then keeps; of the clients asking the same at once one asks upstream and the others wait for its reply.
// refresh, if not nil, is for the caller to call once the client has the reply, a stale one: it asks upstream for the reply to take its place, within ctx.
// Any other request is refused.
func (h *Handler) answer(ctx context.Context, upstream string, servers []string, message []byte) (reply []byte, refresh func()) {
	if len(message) < 12 || message[2]&0x80 != 0 {
		return nil, nil
	}
	id, k, ok := queryKey(message)
	switch {
	case message[2]&0x78 != 0:
		return failure(ctx, message, dnsmessage.RCodeNotImplemented, false), nil
	case !ok:
		return failure(ctx, message, dnsmessage.RCodeFormatError, false), nil
	case k.typ == typeAXFR || k.typ == typeIXFR:
		return failure(ctx, message, dnsmessage.RCodeRefused, k.edns), nil
	}
	c := h.answers()
	if reply, ok := c.get(upstream, k, message); ok {
		return reply, nil
	}
	if reply, due, ok := c.stale(upstream, k, message); ok {
		if !due {
			return reply, nil
		}
		return reply, func() { h.ask(ctx, upstream, servers, id, k, message) }
	}
	if c.limit() > 0 {
		at := origin{upstream, k}
		landed, lead := h.fly(at)
		if lead {
			defer h.land(at)
		} else {
			select {
			case <-landed:
			case <-ctx.Done():
				return nil, nil
			}
			// A reply the cache did not keep answers only the query it was sent for.
			if reply, ok := c.get(upstream, k, message); ok {
				return reply, nil
			}
		}
	}
	reply, err := h.ask(ctx, upstream, servers, id, k, message)
	if err != nil {
		return failure(ctx, message, dnsmessage.RCodeServerFailure, k.edns), nil
	}
	return reply, nil
}

// failedFor is how long a server that failed to answer is asked after the others.
const failedFor = 30 * time.Second

// ask returns what upstream, whose servers are at servers, replies to query, a DNS query of id and key k, within Idle and ctx, and has the cache keep it; a reply that fails, as one the cache cannot keep, leaves the reply kept before in its place.
// It asks the servers in turn until one answers other than SERVFAIL, each within an even share of the time left, and returns the reply of the last one that gave any.
func (h *Handler) ask(ctx context.Context, upstream string, servers []string, id uint16, k key, query []byte) ([]byte, error) {
	flow := ctx
	ctx, cancel := context.WithTimeout(ctx, h.idle())
	defer cancel()
	deadline, _ := ctx.Deadline()
	var reply []byte
	var err error
	servers = h.order(servers)
	for i, server := range servers {
		share, done := ctx, context.CancelFunc(func() {})
		if left := len(servers) - i; left > 1 {
			share, done = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(left))
		}
		var got []byte
		got, err = h.exchange(share, server, query)
		done()
		if flow.Err() != nil {
			return nil, flow.Err()
		}
		h.mark(server, err != nil)
		if err != nil {
			continue
		}
		reply = got
		if dnsmessage.RCode(got[3]&0x0f) != dnsmessage.RCodeServerFailure {
			break
		}
	}
	if reply == nil {
		return nil, err
	}
	h.answers().put(upstream, k, reply, lifetime(reply, id, k.question))
	return reply, nil
}

// order returns servers with those that failed to answer within failedFor after the others.
func (h *Handler) order(servers []string) []string {
	if len(servers) < 2 {
		return servers
	}
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	ordered := make([]string, 0, len(servers))
	var last []string
	for _, server := range servers {
		if at, ok := h.failed[server]; ok && now.Sub(at) < failedFor {
			last = append(last, server)
		} else {
			ordered = append(ordered, server)
		}
	}
	return append(ordered, last...)
}

// mark notes that server failed to answer just now, or that it answered.
func (h *Handler) mark(server string, failed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !failed {
		delete(h.failed, server)
		return
	}
	if h.failed == nil {
		h.failed = make(map[string]time.Time)
	}
	h.failed[server] = time.Now()
}

// fly tells whether the caller is the one to ask upstream what at asks, and must land it then, or else gives the channel closed once the one asking has landed.
func (h *Handler) fly(at origin) (landed <-chan struct{}, lead bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if flight, ok := h.flights[at]; ok {
		return flight, false
	}
	if h.flights == nil {
		h.flights = make(map[origin]chan struct{})
	}
	h.flights[at] = make(chan struct{})
	return nil, true
}

// land wakes the clients waiting for the reply to what at asks.
func (h *Handler) land(at origin) {
	h.mu.Lock()
	flight := h.flights[at]
	delete(h.flights, at)
	h.mu.Unlock()
	close(flight)
}

// opt returns an OPT record without options, telling the 1232 bytes of UDP payload DNS flag day 2020 settled on.
func opt() dnsmessage.Resource {
	var r dnsmessage.Resource
	r.Header.SetEDNS0(1232, dnsmessage.RCodeSuccess, false)
	r.Body = &dnsmessage.OPTResource{}
	return r
}

// failure returns the reply that fails request with rcode, with an OPT record if edns tells request has one, and nil once ctx, of the flow of request, ended.
func failure(ctx context.Context, request []byte, rcode dnsmessage.RCode, edns bool) []byte {
	if ctx.Err() != nil {
		return nil
	}
	var p dnsmessage.Parser
	asked, err := p.Start(request)
	if err != nil {
		return nil
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: asked.ID, Response: true, OpCode: asked.OpCode, RecursionDesired: asked.RecursionDesired, RecursionAvailable: true, CheckingDisabled: asked.CheckingDisabled, RCode: rcode}}
	if questions, err := p.AllQuestions(); err == nil {
		m.Questions = questions
	}
	if edns {
		m.Additionals = []dnsmessage.Resource{opt()}
	}
	reply, err := m.Pack()
	if err != nil {
		return nil
	}
	return reply
}

// payload returns how many bytes a reply to query may take over UDP: what its OPT record tells, at least 512, and 512 without one, which edns tells.
func payload(query []byte) (size int, edns bool) {
	size = 512
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil || p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return size, false
	}
	for {
		r, err := p.AdditionalHeader()
		if err != nil || p.SkipAdditional() != nil {
			return size, edns
		}
		if r.Type == dnsmessage.TypeOPT {
			// RFC 6891 keeps the payload size in the CLASS field of the OPT record.
			size, edns = max(512, int(r.Class)), true
		}
	}
}

// fit returns reply as it goes to the client of query over UDP: itself if it fits the payload query allows, and else its header, with the TC bit set, and question alone, with an OPT record if query has one.
func fit(reply, query []byte) []byte {
	size, edns := payload(query)
	if len(reply) <= size {
		return reply
	}
	var p dnsmessage.Parser
	if h, err := p.Start(reply); err == nil {
		h.Truncated = true
		m := dnsmessage.Message{Header: h}
		if questions, err := p.AllQuestions(); err == nil {
			m.Questions = questions
		}
		if edns {
			m.Additionals = []dnsmessage.Resource{opt()}
			// The first byte of an OPT record's TTL field extends the RCODE, which the 4 bits of the header then do not tell alone.
			m.Additionals[0].Header.SetEDNS0(1232, h.RCode, false)
		}
		if short, err := m.Pack(); err == nil && len(short) <= size {
			return short
		}
	}
	// The header alone, of no records.
	short := append(make([]byte, 0, 12), reply[:min(len(reply), 4)]...)
	short[2] |= 0x02
	return binary.BigEndian.AppendUint64(short, 0)
}

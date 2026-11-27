package dns

import "golang.org/x/net/dns/dnsmessage"

// udpMin is the most bytes of a DNS message every client takes in a datagram, and all one without an OPT record takes (RFC 1035 section 4.2.1).
const udpMin = 512

// udpOffered is the UDP payload size the OPT record of a truncated reply advertises, the one RFC 9715 recommends.
const udpOffered = 1232

// udpLimit returns the most bytes a reply to query, a DNS query as queryID tells, may have for its client to take it in a datagram:
// the UDP payload size its OPT record advertises, a smaller one counting as 512 (RFC 6891 section 6.2.5), or 512 without one.
func udpLimit(query []byte) (limit int, edns, do bool) {
	limit = udpMin
	var p dnsmessage.Parser
	if _, err := p.Start(query); err != nil {
		return limit, false, false
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return limit, false, false
	}
	for {
		r, err := p.AdditionalHeader()
		if err != nil || p.SkipAdditional() != nil {
			return limit, edns, do
		}
		if r.Type == dnsmessage.TypeOPT {
			// RFC 6891 keeps the payload size in the CLASS field of the OPT record and the DO bit in its TTL field.
			limit, edns, do = max(udpMin, int(r.Class)), true, r.TTL&0x8000 != 0
		}
	}
}

// fit returns reply, which answers query, as the client takes it in a datagram: itself if within udpLimit of query, and else a reply of its RCODE with the TC bit, the question and no records but the OPT record a query with one is due.
// A client that reads TC asks again over TCP, where the reply has its length; one sent the long reply as a datagram may read only its start, which does not parse.
func fit(query, reply []byte) []byte {
	limit, edns, do := udpLimit(query)
	if len(reply) <= limit {
		return reply
	}
	var qp, rp dnsmessage.Parser
	qh, err := qp.Start(query)
	if err != nil {
		return reply
	}
	q, err := qp.Question()
	if err != nil {
		return reply
	}
	// A reply whose header does not parse leaves the fields only it can tell at zero: no error, recursion not available.
	rh, _ := rp.Start(reply)
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 qh.ID,
			Response:           true,
			OpCode:             qh.OpCode,
			Authoritative:      rh.Authoritative,
			Truncated:          true,
			RecursionDesired:   qh.RecursionDesired,
			RecursionAvailable: rh.RecursionAvailable,
			CheckingDisabled:   qh.CheckingDisabled,
			RCode:              rh.RCode,
		},
		Questions: []dnsmessage.Question{q},
	}
	if edns {
		var opt dnsmessage.ResourceHeader
		if opt.SetEDNS0(udpOffered, rh.RCode, do) != nil {
			return reply
		}
		m.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
	}
	truncated, err := m.Pack()
	if err != nil {
		return reply
	}
	return truncated
}

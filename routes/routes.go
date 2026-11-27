// Package routes computes the destinations a TUN captures, as the prefixes to route into it.
// It depends on the standard library alone.
package routes

import (
	"net/netip"
	"slices"
)

// Captured returns each family that has an address in addresses, less carved, as the fewest prefixes that cover it, sorted with IPv4 first.
// An invalid prefix of carved is skipped.
func Captured(addresses, carved []netip.Prefix) []netip.Prefix {
	var set []netip.Prefix
	var has4, has6 bool
	for _, p := range addresses {
		switch {
		case p.Addr().Is4() && !has4:
			has4 = true
			set = append(set, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		case p.Addr().Is6() && !has6:
			has6 = true
			set = append(set, netip.PrefixFrom(netip.IPv6Unspecified(), 0))
		}
	}
	return less(set, carved)
}

// Reserved returns the destinations that are no host's to reach through a TUN, to carve off one: whole reserved blocks, so that carving them out of a family leaves few routes.
func Reserved() []netip.Prefix {
	return less([]netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		// Multicast, the reserved 240.0.0.0/4 and with it the limited broadcast address.
		netip.MustParsePrefix("224.0.0.0/3"),
		// The unspecified, loopback, IPv4-compatible and IPv4-mapped addresses.
		netip.MustParsePrefix("::/8"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}, []netip.Prefix{
		// The NAT64 prefixes of RFC 6052 and RFC 8215 are destinations, though they lie in ::/8.
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
	})
}

// less returns set, whose prefixes are disjoint, without the addresses of carved, sorted with IPv4 first; it skips the invalid prefixes of carved.
func less(set, carved []netip.Prefix) []netip.Prefix {
	for _, p := range carved {
		if p = p.Masked(); p.IsValid() {
			set = without(set, p)
		}
	}
	// The prefixes are disjoint, so their addresses order them, and an IPv4 address sorts before an IPv6 one.
	slices.SortFunc(set, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return set
}

// without returns set, whose prefixes are disjoint and masked, without the addresses of p, which is masked too.
func without(set []netip.Prefix, p netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range set {
		switch {
		case s.Addr().BitLen() != p.Addr().BitLen() || !s.Overlaps(p):
			out = append(out, s)
		case p.Bits() <= s.Bits():
			// p covers s, which goes whole.
		default:
			// p lies within s: what is left of s is, at each length from below its own down to p's, the half that p is not in.
			for bits := s.Bits() + 1; bits <= p.Bits(); bits++ {
				out = append(out, otherHalf(p, bits))
			}
		}
	}
	return out
}

// otherHalf returns the prefix of that length next to the one p lies in: the two halve the prefix one bit shorter.
func otherHalf(p netip.Prefix, bits int) netip.Prefix {
	b := p.Addr().AsSlice()
	b[(bits-1)/8] ^= 0x80 >> ((bits - 1) % 8)
	addr, _ := netip.AddrFromSlice(b)
	return netip.PrefixFrom(addr, bits).Masked()
}

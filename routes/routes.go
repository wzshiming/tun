// Package routes computes the destinations a TUN captures, as the prefixes to route into it.
package routes

import (
	"net/netip"

	"go4.org/netipx"
)

// Captured returns each family that has an address in addresses, less carved, as prefixes sorted with IPv4 first.
// An invalid prefix of carved is skipped.
func Captured(addresses, carved []netip.Prefix) []netip.Prefix {
	var b netipx.IPSetBuilder
	for _, p := range addresses {
		switch {
		case p.Addr().Is4():
			b.AddPrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		case p.Addr().Is6():
			b.AddPrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))
		}
	}
	for _, p := range carved {
		b.RemovePrefix(p.Masked())
	}
	// Invalid prefixes are only recorded as errors, which is left to the caller's validation to report.
	set, _ := b.IPSet()
	return set.Prefixes()
}

// Reserved returns the destinations that are no host's to reach through a TUN, to carve off one: whole reserved blocks, so that carving them out of a family leaves few routes.
func Reserved() []netip.Prefix {
	var b netipx.IPSetBuilder
	for _, p := range []string{
		"127.0.0.0/8",
		"169.254.0.0/16",
		// Multicast, the reserved 240.0.0.0/4 and with it the limited broadcast address.
		"224.0.0.0/3",
		// The unspecified, loopback, IPv4-compatible and IPv4-mapped addresses.
		"::/8",
		"fe80::/10",
		"ff00::/8",
	} {
		b.AddPrefix(netip.MustParsePrefix(p))
	}
	// The NAT64 prefixes of RFC 6052 and RFC 8215 are destinations, though they lie in ::/8.
	for _, p := range []string{"64:ff9b::/96", "64:ff9b:1::/48"} {
		b.RemovePrefix(netip.MustParsePrefix(p))
	}
	// The prefixes above are valid, so the set has no error.
	set, _ := b.IPSet()
	return set.Prefixes()
}

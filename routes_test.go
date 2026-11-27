package tun

import (
	"net/netip"
	"slices"
	"testing"
)

// ttSet returns the addresses of add less those of remove as the fewest prefixes that cover them, sorted with IPv4 first.
// It works its way down from each whole family, halving a prefix that is partly covered, which is not how routes.Captured gets there.
func ttSet(add, remove []netip.Prefix) []netip.Prefix {
	masked := func(ps []netip.Prefix) []netip.Prefix {
		ps = slices.Clone(ps)
		for i, p := range ps {
			ps[i] = p.Masked()
		}
		return ps
	}
	add, remove = masked(add), masked(remove)
	return slices.Concat(ttCover(netip.MustParsePrefix("0.0.0.0/0"), add, remove), ttCover(netip.MustParsePrefix("::/0"), add, remove))
}

// ttCover returns the part of p that add covers and remove does not.
func ttCover(p netip.Prefix, add, remove []netip.Prefix) []netip.Prefix {
	covers := func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Overlaps(p) }
	within := func(q netip.Prefix) bool { return q.Bits() > p.Bits() && q.Overlaps(p) }
	switch {
	case slices.ContainsFunc(remove, covers):
		return nil
	case slices.ContainsFunc(add, covers):
		if !slices.ContainsFunc(remove, within) {
			return []netip.Prefix{p}
		}
	case !slices.ContainsFunc(add, within):
		return nil
	}
	b := p.Addr().AsSlice()
	b[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	upper, _ := netip.AddrFromSlice(b)
	lo, hi := netip.PrefixFrom(p.Addr(), p.Bits()+1), netip.PrefixFrom(upper, p.Bits()+1)
	l, h := ttCover(lo, add, remove), ttCover(hi, add, remove)
	if slices.Equal(l, []netip.Prefix{lo}) && slices.Equal(h, []netip.Prefix{hi}) {
		return []netip.Prefix{p}
	}
	return slices.Concat(l, h)
}

func ttSplit(routes []netip.Prefix) (v4, v6 []netip.Prefix) {
	for _, p := range routes {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

func TestCaptureRoutesCoverEachFamilyMinusBypassAndSubnets(t *testing.T) {
	v4, v6 := ttSplit(CaptureRoutes(ttDefaultConfig()))
	bypass := ttPrefixes("192.168.0.0/16", "10.0.0.0/8", "fe80::/64", "fd00::/8")
	ownSubnets := ttPrefixes("198.18.0.0/30", "fd00:6a77:7761::/64")
	for _, tc := range []struct {
		family string
		routes []netip.Prefix
		want   []netip.Prefix
	}{
		{"IPv4", v4, ttSet(ttPrefixes("0.0.0.0/0"), slices.Concat(bypass, ownSubnets))},
		{"IPv6", v6, ttSet(ttPrefixes("::/0"), slices.Concat(bypass, ownSubnets))},
	} {
		if got := ttSet(tc.routes, nil); !slices.Equal(got, tc.want) {
			t.Errorf("%s routes = %v\nwant the set %v", tc.family, tc.routes, tc.want)
		}
	}
}

// No destination is left off the TUN but those Bypass and Addresses name.
func TestCaptureRoutesOfAnUnbypassedConfigAreEachFamilyMinusSubnets(t *testing.T) {
	cfg := Config{Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64")}
	want := ttSet(ttPrefixes("0.0.0.0/0", "::/0"), ttPrefixes("198.18.0.0/30", "fd00:6a77:7761::/64"))
	if got := ttSet(CaptureRoutes(cfg), nil); !slices.Equal(got, want) {
		t.Errorf("CaptureRoutes = %v\nwant the set %v", CaptureRoutes(cfg), want)
	}
	if got, want := installRoutes(cfg), ttPrefixes("0.0.0.0/0", "::/0"); !slices.Equal(got, want) {
		t.Errorf("installRoutes = %v, want %v", got, want)
	}
}

// A capture of everything must stay a handful of routes: Open adds each with a command of its own on Linux and macOS.
func TestRoutesOfAnUnbypassedConfigAreFew(t *testing.T) {
	cfg := Config{Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64")}
	if got := installRoutes(cfg); len(got) > 40 {
		t.Errorf("installRoutes returned %d routes, want at most 40: %v", len(got), got)
	}
}

func TestInstallRoutesAreCaptureRoutesPlusOwnSubnets(t *testing.T) {
	cfg := ttDefaultConfig()
	cfg.Bypass = ttPrefixes("192.168.0.0/16", "10.0.0.0/8")
	ownSubnets := ttPrefixes("198.18.0.0/30", "fd00:6a77:7761::/64")
	want := ttSet(slices.Concat(CaptureRoutes(cfg), ownSubnets), nil)
	if got := ttSet(installRoutes(cfg), nil); !slices.Equal(got, want) {
		t.Errorf("installRoutes = %v\nwant the set %v", installRoutes(cfg), want)
	}
}

// Bypass wins over the subnet of an address it covers.
func TestInstallRoutesLeaveOutABypassedOwnSubnet(t *testing.T) {
	cfg := Config{Addresses: ttPrefixes("198.18.0.1/30"), Bypass: ttPrefixes("198.18.0.0/15")}
	own := netip.MustParseAddr("198.18.0.2")
	for _, p := range installRoutes(cfg) {
		if p.Contains(own) {
			t.Errorf("route %v contains %v, want the bypassed 198.18.0.0/15 left off the TUN", p, own)
		}
	}
}

// The address already routes its subnet into the TUN, and adding that very route again fails with "File exists".
func TestInstallRoutesLeaveASubnetRouteToItsAddress(t *testing.T) {
	// With its neighbours bypassed, 10.0.0.0/8 is a capture prefix of its own.
	cfg := Config{
		Addresses: ttPrefixes("10.0.0.1/8", "fd00:6a77:7761::1/64"),
		Bypass:    ttPrefixes("8.0.0.0/7", "11.0.0.0/8", "fd00:6a77:7761:1::/64", "fd00:6a77:7761:2::/63", "fd00:6a77:7761:4::/62"),
	}
	routes := installRoutes(cfg)
	for _, own := range ttPrefixes("10.0.0.0/8", "fd00:6a77:7761::/64") {
		if slices.Contains(routes, own) {
			t.Errorf("installRoutes holds %v, the subnet its address routes already", own)
		}
	}
	if !slices.Contains(routes, netip.MustParsePrefix("12.0.0.0/6")) {
		t.Errorf("installRoutes = %v, want 12.0.0.0/6 still routed", routes)
	}
}

func TestCaptureRoutesAreSortedDisjointMaskedPrefixes(t *testing.T) {
	routes := CaptureRoutes(ttDefaultConfig())
	if len(routes) == 0 {
		t.Fatal("CaptureRoutes returned no routes for the default config")
	}
	for i, p := range routes {
		if !p.IsValid() || p != p.Masked() {
			t.Errorf("route %d = %v, want a valid masked prefix", i, p)
		}
		if i > 0 && !routes[i-1].Addr().Less(p.Addr()) {
			t.Errorf("route %d = %v does not sort after route %d = %v; want IPv4 then IPv6, ascending", i, p, i-1, routes[i-1])
		}
		for j, q := range routes[:i] {
			if p.Overlaps(q) {
				t.Errorf("route %d = %v overlaps route %d = %v", i, p, j, q)
			}
		}
	}
}

func TestCaptureRoutesOmitFamilyWithoutAddress(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address netip.Prefix
	}{
		{"IPv4 only", netip.MustParsePrefix("198.18.0.1/30")},
		{"IPv6 only", netip.MustParsePrefix("fd00:6a77:7761::1/64")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ttDefaultConfig()
			cfg.Addresses = []netip.Prefix{tc.address}
			routes := CaptureRoutes(cfg)
			if len(routes) == 0 {
				t.Fatalf("CaptureRoutes with only %v returned no routes", tc.address)
			}
			for _, p := range routes {
				if p.Addr().Is4() != tc.address.Addr().Is4() {
					t.Errorf("CaptureRoutes with only %v returned %v from the family without an address", tc.address, p)
				}
			}
		})
	}
}

func TestCaptureRoutesBypassingAllIPv4KeepsOnlyIPv6(t *testing.T) {
	cfg := ttDefaultConfig()
	cfg.Bypass = append(cfg.Bypass, netip.MustParsePrefix("0.0.0.0/0"))
	v4, v6 := ttSplit(CaptureRoutes(cfg))
	if len(v4) != 0 {
		t.Errorf("IPv4 routes = %v, want none when 0.0.0.0/0 is bypassed", v4)
	}
	if len(v6) == 0 {
		t.Error("no IPv6 routes; bypassing 0.0.0.0/0 must leave IPv6 captured")
	}
}

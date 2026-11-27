package routes

import (
	"net/netip"
	"slices"
	"testing"
)

func TestCapturedCoversOnlyTheFamiliesWithAnAddress(t *testing.T) {
	v4, v6 := netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")
	all4, all6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	for _, tc := range []struct {
		name      string
		addresses []netip.Prefix
		want      []netip.Prefix
	}{
		{"none", nil, nil},
		{"ipv4", []netip.Prefix{v4}, []netip.Prefix{all4}},
		{"ipv6", []netip.Prefix{v6}, []netip.Prefix{all6}},
		{"both, IPv4 first", []netip.Prefix{v6, v4}, []netip.Prefix{all4, all6}},
	} {
		if got := Captured(tc.addresses, nil); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Captured(%v, nil) = %v, want %v", tc.name, tc.addresses, got, tc.want)
		}
	}
}

func TestCapturedCarvesMaskedPrefixesAndSkipsInvalidOnes(t *testing.T) {
	addresses := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}
	// 128.0.0.1/1 has host bits, which masking drops; the zero Prefix is invalid.
	got := Captured(addresses, []netip.Prefix{netip.MustParsePrefix("128.0.0.1/1"), {}})
	if want := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1")}; !slices.Equal(got, want) {
		t.Errorf("Captured = %v, want %v", got, want)
	}
}

func TestCapturedSplitsAroundACarvedPrefixIntoTheFewestPrefixesSorted(t *testing.T) {
	prefixes := func(ss ...string) (ps []netip.Prefix) {
		for _, s := range ss {
			ps = append(ps, netip.MustParsePrefix(s))
		}
		return ps
	}
	addresses := prefixes("fd00::1/64", "198.18.0.1/30")
	for _, tc := range []struct {
		name   string
		carved []netip.Prefix
		want   []netip.Prefix
	}{
		{"one prefix leaves the other half at each length", prefixes("10.0.0.0/8", "::/0"),
			prefixes("0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1")},
		{"two halves carved leave no trace of the split", prefixes("0.0.0.0/2", "64.0.0.0/2", "::/0"), prefixes("128.0.0.0/1")},
		{"a prefix within a carved one, in either order", prefixes("10.1.0.0/16", "0.0.0.0/1", "192.0.0.0/2", "192.168.0.0/16", "::/0"), prefixes("128.0.0.0/2")},
		{"a whole family", prefixes("0.0.0.0/0", "::/1"), prefixes("8000::/1")},
		{"an IPv4-mapped prefix carves nothing off IPv4", prefixes("::ffff:10.0.0.0/104", "::/0"), prefixes("0.0.0.0/0")},
	} {
		if got := Captured(addresses, tc.carved); !slices.Equal(got, tc.want) {
			t.Errorf("%s: Captured(%v) = %v, want %v", tc.name, tc.carved, got, tc.want)
		}
	}
}

func TestReservedIsSortedWithTheNAT64PrefixesCutOut(t *testing.T) {
	got := Reserved()
	for _, want := range []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "fe80::/10", "ff00::/8"} {
		if !slices.Contains(got, netip.MustParsePrefix(want)) {
			t.Errorf("Reserved() = %v, want it to hold %s", got, want)
		}
	}
	if !slices.IsSortedFunc(got, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) }) {
		t.Errorf("Reserved() = %v, want it sorted with IPv4 first", got)
	}
	for i, p := range got {
		if p != p.Masked() || slices.ContainsFunc(got[i+1:], p.Overlaps) {
			t.Errorf("Reserved() holds %v, unmasked or overlapping another", p)
		}
	}
}

func TestReservedLeavesReservedBlocksOffAndNAT64On(t *testing.T) {
	addresses := []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")}
	routes := Captured(addresses, Reserved())
	contains := func(s string) bool {
		addr := netip.MustParseAddr(s)
		for _, p := range routes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, off := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.251", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:192.0.2.1", "64:ff9a::1", "64:ff9b:2::1", "fe80::1", "ff02::1"} {
		if contains(off) {
			t.Errorf("a route contains %s, want it left off the TUN", off)
		}
	}
	for _, on := range []string{"1.1.1.1", "10.0.0.1", "64:ff9b::192.0.2.1", "64:ff9b:1::1", "100::1", "2001:db8::1"} {
		if !contains(on) {
			t.Errorf("no route contains %s, want it captured", on)
		}
	}
}

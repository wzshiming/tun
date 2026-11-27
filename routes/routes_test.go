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

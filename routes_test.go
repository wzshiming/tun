package tun

import (
	"net/netip"
	"slices"
	"testing"

	"go4.org/netipx"
)

// ttHoles are the ranges no capture may ever route into the TUN.
var ttHoles = ttPrefixes("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3", "::/8", "fe80::/10", "ff00::/8")

// ttNAT64 are the only ranges of the ::/8 hole a capture routes into the TUN.
var ttNAT64 = ttPrefixes("64:ff9b::/96", "64:ff9b:1::/48")

func ttSet(t *testing.T, add, remove []netip.Prefix) *netipx.IPSet {
	t.Helper()
	var b netipx.IPSetBuilder
	for _, p := range add {
		b.AddPrefix(p)
	}
	for _, p := range remove {
		b.RemovePrefix(p)
	}
	set, err := b.IPSet()
	if err != nil {
		t.Fatalf("IP set of %v minus %v: %v", add, remove, err)
	}
	return set
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

func TestCaptureRoutesCoverEachFamilyMinusBypassSubnetsAndHoles(t *testing.T) {
	v4, v6 := ttSplit(CaptureRoutes(ttDefaultConfig()))
	bypass := ttPrefixes("192.168.0.0/16", "10.0.0.0/8", "fe80::/64", "fd00::/8")
	ownSubnets := ttPrefixes("198.18.0.0/30", "fd00:6a77:7761::/64")
	for _, tc := range []struct {
		family string
		routes []netip.Prefix
		want   *netipx.IPSet
	}{
		{"IPv4", v4, ttSet(t, ttPrefixes("0.0.0.0/0"), slices.Concat(bypass, ownSubnets, ttHoles))},
		{"IPv6", v6, ttSet(t, slices.Concat(ttSet(t, ttPrefixes("::/0"), ttHoles).Prefixes(), ttNAT64), slices.Concat(bypass, ownSubnets))},
	} {
		if got := ttSet(t, tc.routes, nil); !got.Equal(tc.want) {
			t.Errorf("%s routes = %v\nwant the set %v", tc.family, tc.routes, tc.want.Prefixes())
		}
	}
}

func TestCaptureRoutesKeepOfTheIPv6ZeroBlockOnlyNAT64(t *testing.T) {
	routes := CaptureRoutes(Config{Addresses: ttPrefixes("fd00:6a77:7761::1/64")})
	for _, off := range []string{"::", "::1", "::ffff:192.0.2.1", "::192.0.2.1", "64:ff9a::1", "64:ff9b:2::1"} {
		addr := netip.MustParseAddr(off)
		if i := slices.IndexFunc(routes, func(p netip.Prefix) bool { return p.Contains(addr) }); i >= 0 {
			t.Errorf("route %v contains %v, want it left off the TUN", routes[i], addr)
		}
	}
	for _, on := range []string{"64:ff9b::192.0.2.1", "64:ff9b:1::1", "100::1", "2001:db8::1"} {
		addr := netip.MustParseAddr(on)
		if !slices.ContainsFunc(routes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			t.Errorf("no route contains %v, want it captured", addr)
		}
	}
}

func TestCaptureRoutesLeaveOutIPv4BroadcastAndReserved(t *testing.T) {
	routes := CaptureRoutes(Config{Addresses: ttPrefixes("198.18.0.1/30")})
	for _, off := range []string{"224.0.0.251", "240.0.0.1", "255.255.255.255", "127.0.0.1", "169.254.169.254"} {
		addr := netip.MustParseAddr(off)
		if i := slices.IndexFunc(routes, func(p netip.Prefix) bool { return p.Contains(addr) }); i >= 0 {
			t.Errorf("route %v contains %v, want it left off the TUN", routes[i], addr)
		}
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
	want := ttSet(t, slices.Concat(CaptureRoutes(cfg), ownSubnets), nil)
	if got := ttSet(t, installRoutes(cfg), nil); !got.Equal(want) {
		t.Errorf("installRoutes = %v\nwant the set %v", installRoutes(cfg), want.Prefixes())
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

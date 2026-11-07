// Package tun opens a configured local TUN device, obtaining it from a privileged helper when the process is not root.
package tun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/wzshiming/elevate"
	"go4.org/netipx"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// HelperCommand is the subcommand Open runs the privileged helper as; the program must dispatch os.Args[1] == HelperCommand to Helper(os.Args[2:]).
const HelperCommand = "tun-helper"

// Config describes the TUN to open.
type Config struct {
	// Name names the interface, "tun" when empty. macOS ignores it and picks a utunN; Linux appends "%d" unless Name holds one, for the kernel to fill in;
	// Windows names the Wintun adapter and its tunnel type with it and derives the adapter's GUID from it.
	Name string
	// Addresses are the TUN's own addresses with their subnets: one or two, at most one per family.
	Addresses []netip.Prefix
	// MTU is the TUN's MTU, 1280 to 65535.
	MTU int
	// Bypass lists the destinations left to the existing routes.
	Bypass []netip.Prefix
}

// Device is an open, configured TUN.
type Device struct {
	wgtun.Device
	// Interface is the TUN's interface name.
	Interface string
	// Warnings describe the configuration that failed without failing Open.
	Warnings []string
}

// ErrDenied reports that the user declined the administrator prompt.
var ErrDenied = elevate.ErrDenied

// ErrUnsupported reports a platform without TUN support.
var ErrUnsupported = errors.ErrUnsupported

// fixedHoles are the destinations never routed into the TUN.
var fixedHoles = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	// The unspecified address is never a destination; this keeps the first IPv6 route from being ::/128.
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// name returns the interface name, defaulting to "tun".
func (cfg Config) name() string {
	if cfg.Name == "" {
		return "tun"
	}
	return cfg.Name
}

// nameGUID derives a UUID from name: SHA-256 of the namespaced name, cut to 16 bytes and marked version 8 (RFC 9562), variant 10.
func nameGUID(name string) [16]byte {
	sum := sha256.Sum256([]byte("github.com/wzshiming/tun\x00" + name))
	g := [16]byte(sum[:16])
	g[6] = g[6]&0x0f | 0x80
	g[8] = g[8]&0x3f | 0x80
	return g
}

// validateNameChars rejects a name with a path separator or control character, on every platform.
func validateNameChars(name string) error {
	if strings.ContainsAny(name, `/\`) || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("tun: invalid interface name %q", name)
	}
	return nil
}

func validate(cfg Config) error {
	if err := validateName(cfg.Name); err != nil {
		return err
	}
	if n := len(cfg.Addresses); n < 1 || n > 2 {
		return fmt.Errorf("tun: want 1 or 2 addresses, got %d", n)
	}
	for i, p := range cfg.Addresses {
		a := p.Addr()
		switch {
		case !p.IsValid():
			return fmt.Errorf("tun: invalid address %v", p)
		case p.Bits() == 0:
			return fmt.Errorf("tun: address[%d] %v has prefix length 0", i, p)
		case a.Is4In6():
			return fmt.Errorf("tun: address %v is IPv4-mapped", p)
		case a.IsLoopback(), a.IsMulticast(), a.IsUnspecified(), a.IsLinkLocalUnicast():
			return fmt.Errorf("tun: address %v is loopback, multicast, unspecified or link-local", p)
		case p.Bits() < a.BitLen() && a == p.Masked().Addr():
			return fmt.Errorf("tun: address %v has no host bits", p)
		}
	}
	if len(cfg.Addresses) == 2 && cfg.Addresses[0].Addr().Is4() == cfg.Addresses[1].Addr().Is4() {
		return fmt.Errorf("tun: addresses %v and %v share a family", cfg.Addresses[0], cfg.Addresses[1])
	}
	if cfg.MTU < 1280 || cfg.MTU > 65535 {
		return fmt.Errorf("tun: MTU %d outside 1280..65535", cfg.MTU)
	}
	for _, p := range cfg.Bypass {
		if !p.IsValid() {
			return fmt.Errorf("tun: invalid bypass prefix %v", p)
		}
	}
	return nil
}

// CaptureRoutes returns the routes into the TUN, sorted with IPv4 first.
func CaptureRoutes(cfg Config) []netip.Prefix {
	var b netipx.IPSetBuilder
	for _, p := range cfg.Addresses {
		switch {
		case p.Addr().Is4():
			b.AddPrefix(netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		case p.Addr().Is6():
			b.AddPrefix(netip.PrefixFrom(netip.IPv6Unspecified(), 0))
		}
	}
	for _, p := range slices.Concat(cfg.Bypass, cfg.Addresses, fixedHoles) {
		b.RemovePrefix(p.Masked())
	}
	// Invalid prefixes are only recorded as errors, which validate reports instead.
	set, _ := b.IPSet()
	return set.Prefixes()
}

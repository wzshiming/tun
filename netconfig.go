package tun

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
)

// netConfigurer configures a TUN through the system's API instead of commands, one address family at a time.
type netConfigurer interface {
	// setInterface sets the family's MTU and metric 0, and turns off router discovery and duplicate address detection.
	setInterface(v6 bool, mtu int) error
	setAddress(addr netip.Prefix) error
	// addRoutes routes each destination on-link into the TUN with metric 0.
	addRoutes(v6 bool, routes []netip.Prefix) error
}

// configureVia configures each family of cfg that has an address, IPv4 first; an IPv6 failure only warns when IPv4 is configured.
func configureVia(ctx context.Context, cfg Config, c netConfigurer) (warnings []string, err error) {
	hasV4 := slices.ContainsFunc(cfg.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() })
	capture := CaptureRoutes(cfg)
	for _, v6 := range []bool{false, true} {
		i := slices.IndexFunc(cfg.Addresses, func(p netip.Prefix) bool { return p.Addr().Is6() == v6 })
		if i < 0 {
			continue
		}
		addr := cfg.Addresses[i]
		routes := slices.DeleteFunc(slices.Clone(capture), func(p netip.Prefix) bool { return p.Addr().Is6() != v6 })
		calls := []struct {
			name string
			do   func() error
		}{
			{"set interface", func() error { return c.setInterface(v6, cfg.MTU) }},
			{"set address " + addr.String(), func() error { return c.setAddress(addr) }},
			{fmt.Sprintf("add %d routes", len(routes)), func() error { return c.addRoutes(v6, routes) }},
		}
		family := "ipv4"
		if v6 {
			family = "ipv6"
		}
		for _, call := range calls {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			err := call.do()
			if err == nil {
				continue
			}
			if !v6 || !hasV4 {
				return nil, fmt.Errorf("tun: %s: %s: %w", family, call.name, err)
			}
			warnings = append(warnings, fmt.Sprintf("ipv6: %s: %v", call.name, err))
			break
		}
	}
	return warnings, nil
}

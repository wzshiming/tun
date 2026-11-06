//go:build darwin || linux

package tun

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
)

// step is one configuration command; v6 marks the IPv6 ones, which IPv4 can do without.
type step struct {
	argv []string
	v6   bool
}

// tools are the paths of the configuration commands.
type tools struct {
	ifconfig, route, ip string
}

// runFunc runs argv without a shell; a failure's error carries the command's combined output.
type runFunc func(ctx context.Context, argv []string) error

var runCommand runFunc = func(ctx context.Context, argv []string) error {
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	if out = bytes.TrimSpace(out); err != nil && len(out) > 0 {
		err = fmt.Errorf("%w: %s", err, out)
	}
	return err
}

var runOutput = func(ctx context.Context, argv []string) ([]byte, error) {
	return exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
}

// addresses returns cfg's IPv4 and IPv6 address, each invalid when absent.
func addresses(cfg Config) (a4, a6 netip.Prefix) {
	for _, p := range cfg.Addresses {
		if p.Addr().Is4() {
			a4 = p
		} else {
			a6 = p
		}
	}
	return a4, a6
}

func configure(ctx context.Context, t tools, name string, cfg Config, run runFunc) (warnings []string, err error) {
	ss, err := steps(t, name, cfg)
	if err != nil {
		return nil, err
	}
	hasV4 := slices.ContainsFunc(cfg.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() })
	lastV4 := -1
	for i, s := range ss {
		if !s.v6 {
			lastV4 = i
		}
	}
	skipV6 := false
	for i, s := range ss {
		if s.v6 && skipV6 {
			continue
		}
		if err = run(ctx, s.argv); err == nil {
			if i == lastV4 {
				if warning := afterIPv4(ctx, t, run); warning != "" {
					warnings = append(warnings, warning)
				}
			}
			continue
		}
		cmd := strings.Join(s.argv, " ")
		if !s.v6 || !hasV4 {
			return nil, fmt.Errorf("%s: %w", cmd, err)
		}
		warnings = append(warnings, fmt.Sprintf("ipv6: %s: %v", cmd, err))
		skipV6 = true
	}
	return warnings, nil
}

package tun

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
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

func defaultTools(goos string) tools {
	switch goos {
	case "darwin":
		return tools{ifconfig: "/sbin/ifconfig", route: "/sbin/route"}
	case "linux":
		for _, p := range []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"} {
			if _, err := os.Stat(p); err == nil {
				return tools{ip: p}
			}
		}
	}
	return tools{}
}

func steps(goos string, t tools, name string, cfg Config) ([]step, error) {
	missing := ""
	switch {
	case goos == "darwin" && t.ifconfig == "":
		missing = "ifconfig"
	case goos == "darwin" && t.route == "":
		missing = "route"
	case goos == "linux" && t.ip == "":
		missing = "ip"
	}
	if missing != "" {
		return nil, fmt.Errorf("tun: %s command not found", missing)
	}
	var a4, a6 netip.Prefix
	for _, p := range cfg.Addresses {
		if p.Addr().Is4() {
			a4 = p
		} else {
			a6 = p
		}
	}
	var ss []step
	add := func(v6 bool, argv ...string) { ss = append(ss, step{argv: argv, v6: v6}) }
	switch goos {
	case "darwin":
		if a4.IsValid() {
			add(false, t.ifconfig, name, "inet", a4.String(), a4.Addr().String(), "alias")
		}
		if a6.IsValid() {
			add(true, t.ifconfig, name, "inet6", a6.String(), "alias")
		}
		add(false, t.ifconfig, name, "up")
		for _, p := range CaptureRoutes(cfg) {
			if p.Addr().Is4() {
				add(false, t.route, "-n", "add", "-inet", p.String(), "-interface", name)
			} else {
				add(true, t.route, "-n", "add", "-inet6", p.String(), "-interface", name)
			}
		}
	case "linux":
		if a4.IsValid() {
			add(false, t.ip, "-4", "addr", "add", a4.String(), "dev", name)
		}
		if a6.IsValid() {
			add(true, t.ip, "-6", "addr", "add", a6.String(), "dev", name)
		}
		add(false, t.ip, "link", "set", "dev", name, "up")
		for _, p := range CaptureRoutes(cfg) {
			if p.Addr().Is4() {
				add(false, t.ip, "-4", "route", "add", p.String(), "dev", name)
			} else {
				add(true, t.ip, "-6", "route", "add", p.String(), "dev", name)
			}
		}
	default:
		return nil, fmt.Errorf("tun: cannot configure a TUN on %s", goos)
	}
	return ss, nil
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

var plainName = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// scopedDefault ensures a default route scoped to the default interface; without one, darwin finds no route for a socket bound there once a capture route covers its destination.
func scopedDefault(ctx context.Context, route string, run runFunc) (argv []string, err error) {
	out, err := runOutput(ctx, []string{route, "-n", "get", "-inet", "default"})
	if err != nil {
		return nil, nil
	}
	var gateway, ifname string
	for line := range strings.Lines(string(out)) {
		key, value, _ := strings.Cut(strings.TrimSpace(line), ":")
		switch key {
		case "gateway":
			gateway = strings.TrimSpace(value)
		case "interface":
			ifname = strings.TrimSpace(value)
		}
	}
	gw, err := netip.ParseAddr(gateway)
	if err != nil || !gw.Is4() || !plainName.MatchString(ifname) {
		return nil, nil
	}
	argv = []string{route, "-n", "add", "-inet", "-ifscope", ifname, "default", gw.String()}
	if err = run(ctx, argv); err != nil && strings.Contains(err.Error(), "File exists") {
		argv = []string{route, "-n", "change", "-inet", "-ifscope", ifname, "default", gw.String()}
		err = run(ctx, argv)
	}
	return argv, err
}

func configure(ctx context.Context, goos string, t tools, name string, cfg Config, run runFunc) (warnings []string, err error) {
	ss, err := steps(goos, t, name, cfg)
	if err != nil {
		return nil, err
	}
	hasV4 := slices.ContainsFunc(cfg.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() })
	// On darwin the scoped default follows the last IPv4 step, which is the last IPv4 capture route.
	scopedAfter := -1
	if goos == "darwin" {
		for i, s := range ss {
			if !s.v6 {
				scopedAfter = i
			}
		}
	}
	skipV6 := false
	for i, s := range ss {
		if s.v6 && skipV6 {
			continue
		}
		if err = run(ctx, s.argv); err == nil {
			if i == scopedAfter {
				if argv, err := scopedDefault(ctx, t.route, run); err != nil {
					warnings = append(warnings, fmt.Sprintf("scoped default: %s: %v", strings.Join(argv, " "), err))
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

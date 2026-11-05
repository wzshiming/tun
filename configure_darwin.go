package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

func defaultTools() tools {
	return tools{ifconfig: "/sbin/ifconfig", route: "/sbin/route"}
}

func steps(t tools, name string, cfg Config) ([]step, error) {
	switch {
	case t.ifconfig == "":
		return nil, errors.New("tun: ifconfig command not found")
	case t.route == "":
		return nil, errors.New("tun: route command not found")
	}
	a4, a6 := addresses(cfg)
	var ss []step
	add := func(v6 bool, argv ...string) { ss = append(ss, step{argv: argv, v6: v6}) }
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
	return ss, nil
}

// afterIPv4 runs once the last IPv4 step, the last IPv4 capture route, succeeded; a scoped default route that fails only warns.
func afterIPv4(ctx context.Context, t tools, run runFunc) (warning string) {
	if argv, err := scopedDefault(ctx, t.route, run); err != nil {
		return fmt.Sprintf("scoped default: %s: %v", strings.Join(argv, " "), err)
	}
	return ""
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

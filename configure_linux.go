package tun

import (
	"context"
	"errors"
	"os"
)

func defaultTools() tools {
	for _, p := range []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"} {
		if _, err := os.Stat(p); err == nil {
			return tools{ip: p}
		}
	}
	return tools{}
}

func steps(t tools, name string, cfg Config) ([]step, error) {
	if t.ip == "" {
		return nil, errors.New("tun: ip command not found")
	}
	a4, a6 := addresses(cfg)
	var ss []step
	add := func(v6 bool, argv ...string) { ss = append(ss, step{argv: argv, v6: v6}) }
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
	return ss, nil
}

// afterIPv4 runs once the last IPv4 step succeeded; linux needs nothing more.
func afterIPv4(context.Context, tools, runFunc) (warning string) { return "" }

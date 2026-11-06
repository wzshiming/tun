package tun

import (
	"net/netip"
	"os"
	"path"
	"testing"
)

const ttIfName = "tun0"

var ttWithoutTool = []struct {
	have    tools
	missing string
}{
	{tools{}, "ip"},
}

// ttCommandTable adds linux's commands for a4, a6 and the IPv4 and IPv6 capture routes v4 and v6.
func ttCommandTable(a4, a6 netip.Prefix, v4, v6 []netip.Prefix, add func(isV6 bool, argv ...string)) {
	if a4.IsValid() {
		add(false, ttTools.ip, "-4", "addr", "add", ttWithLen(a4), "dev", ttIfName)
	}
	if a6.IsValid() {
		add(true, ttTools.ip, "-6", "addr", "add", ttWithLen(a6), "dev", ttIfName)
	}
	add(false, ttTools.ip, "link", "set", "dev", ttIfName, "up")
	for _, p := range v4 {
		add(false, ttTools.ip, "-4", "route", "add", p.String(), "dev", ttIfName)
	}
	for _, p := range v6 {
		add(true, ttTools.ip, "-6", "route", "add", p.String(), "dev", ttIfName)
	}
}

func TestConfigureNeverAsksForDefaultRouteOnLinux(t *testing.T) {
	ttGuardSystem(t)
	cfg := ttDefaultConfig()
	rec := &ttRecorder{}
	out := &ttOutputRecorder{out: ttRouteGetDefault}
	runCommand, runOutput = rec.run, out.output
	warnings, err := configure(t.Context(), ttTools, ttIfName, cfg, rec.run)
	if err != nil || len(warnings) != 0 {
		t.Errorf("configure = %q, %v; want no warnings and no error", warnings, err)
	}
	if calls := out.recorded(); len(calls) != 0 {
		t.Errorf("configure on linux called runOutput with\n%s\nwant no call: only darwin scopes a default route", ttLines(calls))
	}
	ttCheckArgvs(t, rec.recorded(), ttArgvs(ttWantSteps(t, cfg)))
}

func TestDefaultToolsLinuxIPIsAbsoluteOrEmpty(t *testing.T) {
	ip := defaultTools().ip
	if ip == "" {
		return
	}
	if !path.IsAbs(ip) {
		t.Fatalf("defaultTools().ip = %q, want an absolute path or empty, never a name looked up in PATH", ip)
	}
	if _, err := os.Stat(ip); err != nil {
		t.Errorf("defaultTools().ip = %q, want an existing file: %v", ip, err)
	}
}

package tun

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

const ttIfName = "utun7"

var ttWithoutTool = []struct {
	have    tools
	missing string
}{
	{tools{route: ttTools.route}, "ifconfig"},
	{tools{ifconfig: ttTools.ifconfig}, "route"},
}

// ttCommandTable adds darwin's commands for a4, a6 and the IPv4 and IPv6 capture routes v4 and v6.
func ttCommandTable(a4, a6 netip.Prefix, v4, v6 []netip.Prefix, add func(isV6 bool, argv ...string)) {
	if a4.IsValid() {
		add(false, ttTools.ifconfig, ttIfName, "inet", ttWithLen(a4), a4.Addr().String(), "alias")
	}
	if a6.IsValid() {
		add(true, ttTools.ifconfig, ttIfName, "inet6", ttWithLen(a6), "alias")
	}
	add(false, ttTools.ifconfig, ttIfName, "up")
	for _, p := range v4 {
		add(false, ttTools.route, "-n", "add", "-inet", p.String(), "-interface", ttIfName)
	}
	for _, p := range v6 {
		add(true, ttTools.route, "-n", "add", "-inet6", p.String(), "-interface", ttIfName)
	}
}

// ttAfterIPv4Routes returns want's argvs with extra inserted after the last IPv4 route, ahead of the IPv6 routes.
func ttAfterIPv4Routes(t *testing.T, want []step, extra ...[]string) [][]string {
	t.Helper()
	last := -1
	for i, s := range want {
		if !s.v6 && s.argv[0] == ttTools.route {
			last = i
		}
	}
	if last < 0 {
		t.Fatalf("no IPv4 route in\n%s", ttLines(ttArgvs(want)))
	}
	argvs := ttArgvs(want)
	return slices.Concat(argvs[:last+1], extra, argvs[last+1:])
}

func TestConfigureEnsuresScopedDefaultRouteOnDarwin(t *testing.T) {
	cfg := ttDefaultConfig()
	want := ttWantSteps(t, cfg)
	get := []string{ttTools.route, "-n", "get", "-inet", "default"}
	add := []string{ttTools.route, "-n", "add", "-inet", "-ifscope", "en0", "default", "10.64.1.1"}
	change := []string{ttTools.route, "-n", "change", "-inet", "-ifscope", "en0", "default", "10.64.1.1"}
	errExists := errors.New("exit status 1: add net default: gateway 10.64.1.1: File exists")
	errAdd := errors.New("exit status 1: add net default: gateway 10.64.1.1: Network is unreachable")
	errChange := errors.New("exit status 1: change net default: gateway 10.64.1.1: not in table")
	for _, tc := range []struct {
		name     string
		out      string
		outErr   error
		errs     map[string]error
		scoped   [][]string
		warnings []string
	}{
		{
			name:   "adds the default scoped to the default interface",
			out:    ttRouteGetDefault,
			scoped: [][]string{add},
		},
		{
			name:   "changes the scoped default the add finds existing",
			out:    ttRouteGetDefault,
			errs:   map[string]error{strings.Join(add, " "): errExists},
			scoped: [][]string{add, change},
		},
		{
			name: "skips a default without a gateway line",
			out:  strings.Replace(ttRouteGetDefault, "    gateway: 10.64.1.1\n", "", 1),
		},
		{
			name: "skips a default without an interface line",
			out:  strings.Replace(ttRouteGetDefault, "  interface: en0\n", "", 1),
		},
		{
			name:   "skips when route get fails",
			out:    ttRouteGetDefault,
			outErr: errors.New("exit status 1"),
		},
		{
			name:     "warns when the add fails otherwise",
			out:      ttRouteGetDefault,
			errs:     map[string]error{strings.Join(add, " "): errAdd},
			scoped:   [][]string{add},
			warnings: []string{"scoped default: " + strings.Join(add, " ") + ": " + errAdd.Error()},
		},
		{
			name:     "warns when the change fails",
			out:      ttRouteGetDefault,
			errs:     map[string]error{strings.Join(add, " "): errExists, strings.Join(change, " "): errChange},
			scoped:   [][]string{add, change},
			warnings: []string{"scoped default: " + strings.Join(change, " ") + ": " + errChange.Error()},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ttGuardSystem(t)
			rec := &ttRecorder{errs: tc.errs}
			out := &ttOutputRecorder{out: tc.out, err: tc.outErr}
			// The guard restores both seams; the scoped default may run through runCommand instead of configure's run.
			runCommand, runOutput = rec.run, out.output
			warnings, err := configure(t.Context(), ttTools, ttIfName, cfg, rec.run)
			if err != nil {
				t.Fatalf("configure = %v, want nil: the scoped default route is never fatal", err)
			}
			if !slices.Equal(warnings, tc.warnings) {
				t.Errorf("warnings = %q, want %q", warnings, tc.warnings)
			}
			ttCheckArgvs(t, rec.recorded(), ttAfterIPv4Routes(t, want, tc.scoped...))
			if calls := out.recorded(); !slices.EqualFunc(calls, [][]string{get}, slices.Equal[[]string]) {
				t.Errorf("runOutput calls (%d):\n%s\nwant one:\n%s", len(calls), ttLines(calls), ttLines([][]string{get}))
			}
		})
	}
}

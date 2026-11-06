//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
)

// ttTools point at paths that do not exist, so even a stray exec cannot change the host.
var ttTools = tools{ifconfig: "/tt/sbin/ifconfig", route: "/tt/sbin/route", ip: "/tt/sbin/ip"}

// ttErrFileExists is the failure a recorded command returns; "File exists" gets no special case outside the scoped default route.
var ttErrFileExists = errors.New("exit status 2: RTNETLINK answers: File exists")

// ttRecorder is a runFunc that records every argv; it fails the one equal to fail and each one errs keys by its joined argv.
type ttRecorder struct {
	fail  []string
	errs  map[string]error
	mu    sync.Mutex
	calls [][]string
}

func (r *ttRecorder) run(_ context.Context, argv []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, slices.Clone(argv))
	if err := r.errs[strings.Join(argv, " ")]; err != nil {
		return err
	}
	if r.fail != nil && slices.Equal(argv, r.fail) {
		return ttErrFileExists
	}
	return nil
}

func (r *ttRecorder) recorded() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// ttOutputRecorder stands in for runOutput: it records every argv and answers each with out and err.
type ttOutputRecorder struct {
	out   string
	err   error
	mu    sync.Mutex
	calls [][]string
}

func (r *ttOutputRecorder) output(_ context.Context, argv []string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, slices.Clone(argv))
	return []byte(r.out), r.err
}

func (r *ttOutputRecorder) recorded() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// ttRouteGetDefault is what route -n get -inet default prints for a default route through gateway 10.64.1.1 on en0.
const ttRouteGetDefault = `   route to: default
destination: default
       mask: default
    gateway: 10.64.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
`

// ttWantSteps renders this platform's command table with ttTools, routing every CaptureRoutes prefix.
func ttWantSteps(t *testing.T, cfg Config) []step {
	t.Helper()
	var a4, a6 netip.Prefix
	for _, a := range cfg.Addresses {
		if a.Addr().Is4() {
			a4 = a
		} else {
			a6 = a
		}
	}
	v4, v6 := ttSplit(CaptureRoutes(cfg))
	if (a4.IsValid() && len(v4) == 0) || (a6.IsValid() && len(v6) == 0) {
		t.Fatalf("CaptureRoutes(%v) left a configured family without routes", cfg.Addresses)
	}
	var want []step
	add := func(isV6 bool, argv ...string) { want = append(want, step{argv: argv, v6: isV6}) }
	ttCommandTable(a4, a6, v4, v6, add)
	return want
}

func ttWithLen(p netip.Prefix) string { return fmt.Sprintf("%s/%d", p.Addr(), p.Bits()) }

func ttArgvs(ss []step) [][]string {
	argvs := make([][]string, len(ss))
	for i, s := range ss {
		argvs[i] = s.argv
	}
	return argvs
}

func ttLines(argvs [][]string) string {
	lines := make([]string, len(argvs))
	for i, argv := range argvs {
		lines[i] = fmt.Sprintf("  %3d %s", i, strings.Join(argv, " "))
	}
	return strings.Join(lines, "\n")
}

func ttCheckArgvs(t *testing.T, got, want [][]string) {
	t.Helper()
	if !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("argv sequence (%d):\n%s\nwant (%d):\n%s", len(got), ttLines(got), len(want), ttLines(want))
	}
}

func TestStepsFollowCommandTable(t *testing.T) {
	cfg := ttDefaultConfig()
	want := ttWantSteps(t, cfg)
	got, err := steps(ttTools, ttIfName, cfg)
	if err != nil {
		t.Fatalf("steps: %v", err)
	}
	ttCheckArgvs(t, ttArgvs(got), ttArgvs(want))
	for i := range min(len(got), len(want)) {
		if got[i].v6 != want[i].v6 {
			t.Errorf("step %d %q: v6 = %t, want %t", i, got[i].argv, got[i].v6, want[i].v6)
		}
	}
}

func TestStepsFailNamingToolWithoutPath(t *testing.T) {
	cfg := ttDefaultConfig()
	for _, tc := range ttWithoutTool {
		t.Run("without "+tc.missing, func(t *testing.T) {
			got, err := steps(tc.have, ttIfName, cfg)
			if err == nil || !regexp.MustCompile(`\b`+tc.missing+`\b`).MatchString(err.Error()) {
				t.Errorf("steps without a %s path = %v with\n%s\nwant an error naming %s", tc.missing, err, ttLines(ttArgvs(got)), tc.missing)
			}
		})
	}
}

func TestConfigureRunsEveryStepInOrder(t *testing.T) {
	ttGuardSystem(t)
	cfg := ttDefaultConfig()
	rec := &ttRecorder{}
	warnings, err := configure(t.Context(), ttTools, ttIfName, cfg, rec.run)
	if err != nil || len(warnings) != 0 {
		t.Errorf("configure = %q, %v; want no warnings and no error", warnings, err)
	}
	ttCheckArgvs(t, rec.recorded(), ttArgvs(ttWantSteps(t, cfg)))
}

func TestConfigureStopsAtFailingIPv4Step(t *testing.T) {
	ttGuardSystem(t)
	cfg := ttDefaultConfig()
	want := ttWantSteps(t, cfg)
	for _, tc := range []struct {
		name string
		fail int
	}{
		{"address", 0},
		{"route", 3},
	} {
		t.Run("IPv4 "+tc.name, func(t *testing.T) {
			rec := &ttRecorder{fail: want[tc.fail].argv}
			_, err := configure(t.Context(), ttTools, ttIfName, cfg, rec.run)
			if err == nil || !strings.Contains(err.Error(), ttErrFileExists.Error()) {
				t.Errorf("configure = %v, want the failing step's error %q", err, ttErrFileExists)
			}
			ttCheckArgvs(t, rec.recorded(), ttArgvs(want[:tc.fail+1]))
		})
	}
}

func TestConfigureWarnsAndSkipsIPv6AfterIPv6AddressFailure(t *testing.T) {
	ttGuardSystem(t)
	cfg := ttDefaultConfig()
	want := ttWantSteps(t, cfg)
	failing := want[1] // the IPv6 address
	rec := &ttRecorder{fail: failing.argv}
	warnings, err := configure(t.Context(), ttTools, ttIfName, cfg, rec.run)
	if err != nil {
		t.Errorf("configure = %v, want nil: an IPv6 failure only warns while IPv4 is configured", err)
	}
	wantWarning := "ipv6: " + strings.Join(failing.argv, " ") + ": " + ttErrFileExists.Error()
	if !slices.Equal(warnings, []string{wantWarning}) {
		t.Errorf("warnings = %q, want [%q]", warnings, wantWarning)
	}
	var wantArgvs [][]string
	for i, s := range want {
		if i <= 1 || !s.v6 {
			wantArgvs = append(wantArgvs, s.argv)
		}
	}
	ttCheckArgvs(t, rec.recorded(), wantArgvs)
}

func TestConfigureFailsOnIPv6FailureWithoutIPv4(t *testing.T) {
	ttGuardSystem(t)
	cfg := ttDefaultConfig()
	cfg.Addresses = ttPrefixes("fd00:6a77:7761::1/64")
	want := ttWantSteps(t, cfg)
	rec := &ttRecorder{fail: want[0].argv}
	_, err := configure(t.Context(), ttTools, ttIfName, cfg, rec.run)
	if err == nil || !strings.Contains(err.Error(), ttErrFileExists.Error()) {
		t.Errorf("configure = %v, want the IPv6 step's error %q with no IPv4 address configured", err, ttErrFileExists)
	}
	ttCheckArgvs(t, rec.recorded(), ttArgvs(want[:1]))
}

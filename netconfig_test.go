package tun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// ttWinLocalFake records the calls configureVia makes; fail names the calls that fail and onCall runs before each.
type ttWinLocalFake struct {
	calls  []string
	routes map[bool][]netip.Prefix
	fail   map[string]error
	onCall func(call string)
}

func (f *ttWinLocalFake) do(call string) error {
	f.calls = append(f.calls, call)
	if f.onCall != nil {
		f.onCall(call)
	}
	return f.fail[call]
}

func ttWinLocalFamily(v6 bool) string {
	if v6 {
		return "v6"
	}
	return "v4"
}

func (f *ttWinLocalFake) setInterface(v6 bool, mtu int) error {
	return f.do(fmt.Sprintf("setInterface %s %d", ttWinLocalFamily(v6), mtu))
}

func (f *ttWinLocalFake) setAddress(addr netip.Prefix) error {
	return f.do("setAddress " + addr.String())
}

func (f *ttWinLocalFake) addRoutes(v6 bool, routes []netip.Prefix) error {
	if f.routes == nil {
		f.routes = map[bool][]netip.Prefix{}
	}
	f.routes[v6] = routes
	return f.do("addRoutes " + ttWinLocalFamily(v6))
}

var ttWinLocalBoom = errors.New("boom")

func TestConfigureViaConfiguresEachFamilyInterfaceThenAddressThenRoutes(t *testing.T) {
	cfg := ttDefaultConfig()
	f := &ttWinLocalFake{}
	warnings, err := configureVia(t.Context(), cfg, f)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("configureVia = %q, %v, want no warnings and no error", warnings, err)
	}
	want := []string{
		"setInterface v4 1500", "setAddress 198.18.0.1/30", "addRoutes v4",
		"setInterface v6 1500", "setAddress fd00:6a77:7761::1/64", "addRoutes v6",
	}
	if !slices.Equal(f.calls, want) {
		t.Errorf("calls = %q, want %q", f.calls, want)
	}
	v4, v6 := ttSplit(CaptureRoutes(cfg))
	if !slices.Equal(f.routes[false], v4) || !slices.Equal(f.routes[true], v6) {
		t.Errorf("routes = v4 %v, v6 %v; want CaptureRoutes split by family: %v, %v", f.routes[false], f.routes[true], v4, v6)
	}
}

func TestConfigureViaSkipsAFamilyWithoutAddress(t *testing.T) {
	cfg := ttDefaultConfig()
	cfg.Addresses = ttPrefixes("fd00:6a77:7761::1/64")
	f := &ttWinLocalFake{}
	if _, err := configureVia(t.Context(), cfg, f); err != nil {
		t.Fatalf("configureVia: %v", err)
	}
	want := []string{"setInterface v6 1500", "setAddress fd00:6a77:7761::1/64", "addRoutes v6"}
	if !slices.Equal(f.calls, want) {
		t.Errorf("calls = %q, want %q", f.calls, want)
	}
}

func TestConfigureViaWarnsAndSkipsIPv6WhenIPv4IsConfigured(t *testing.T) {
	f := &ttWinLocalFake{fail: map[string]error{"setAddress fd00:6a77:7761::1/64": ttWinLocalBoom}}
	warnings, err := configureVia(t.Context(), ttDefaultConfig(), f)
	if err != nil {
		t.Fatalf("configureVia: %v, want an IPv6 failure to only warn", err)
	}
	if want := []string{"ipv6: set address fd00:6a77:7761::1/64: boom"}; !slices.Equal(warnings, want) {
		t.Errorf("warnings = %q, want %q", warnings, want)
	}
	if slices.Contains(f.calls, "addRoutes v6") {
		t.Errorf("calls = %q, want the IPv6 routes skipped after the IPv6 failure", f.calls)
	}
}

func TestConfigureViaFailsOnIPv6WithoutIPv4(t *testing.T) {
	cfg := ttDefaultConfig()
	cfg.Addresses = ttPrefixes("fd00:6a77:7761::1/64")
	f := &ttWinLocalFake{fail: map[string]error{"addRoutes v6": ttWinLocalBoom}}
	warnings, err := configureVia(t.Context(), cfg, f)
	if !errors.Is(err, ttWinLocalBoom) || !strings.Contains(err.Error(), "routes") {
		t.Errorf("configureVia = %q, %v; want an error naming the routes step and wrapping %v", warnings, err, ttWinLocalBoom)
	}
}

func TestConfigureViaFailsOnIPv4AndStops(t *testing.T) {
	f := &ttWinLocalFake{fail: map[string]error{"setInterface v4 1500": ttWinLocalBoom}}
	_, err := configureVia(t.Context(), ttDefaultConfig(), f)
	if !errors.Is(err, ttWinLocalBoom) || !strings.Contains(err.Error(), "ipv4: set interface") {
		t.Errorf("configureVia = %v, want an error naming the ipv4 interface step and wrapping %v", err, ttWinLocalBoom)
	}
	if want := []string{"setInterface v4 1500"}; !slices.Equal(f.calls, want) {
		t.Errorf("calls = %q, want only %q", f.calls, want)
	}
}

func TestConfigureViaStopsBetweenStepsOnceCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &ttWinLocalFake{onCall: func(string) { cancel() }}
	_, err := configureVia(ctx, ttDefaultConfig(), f)
	if err != context.Canceled {
		t.Errorf("configureVia = %v, want exactly %v", err, context.Canceled)
	}
	if len(f.calls) != 1 {
		t.Errorf("calls = %q, want none after the cancel", f.calls)
	}
}

package bypass

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ttListenControl wires newListenConfig to the fakes at a clock frozen at ttT0.
func ttListenControl(t *testing.T, l *ttLookup, b *ttBinder) func(network, address string, c syscall.RawConn) error {
	t.Helper()
	lc := newListenConfig(l.lookup, b.bind, ttNow)
	if lc == nil || lc.Control == nil {
		t.Fatal("newListenConfig returned no Control hook")
	}
	return lc.Control
}

func TestNewListenConfigControlBindsByNetworkSuffix(t *testing.T) {
	tests := []struct {
		network  string
		address  string
		wantIPv6 bool
	}{
		{"udp4", ":0", false},
		{"udp6", ":0", true},
		{"tcp4", "0.0.0.0:0", false},
		{"tcp6", "[::]:0", true},
		{"ip4", "0.0.0.0", false},
		{"ip6", "::", true},
	}
	for _, tc := range tests {
		t.Run(tc.network, func(t *testing.T) {
			l, b, raw := &ttLookup{}, &ttBinder{}, &ttRawConn{}
			if err := ttListenControl(t, l, b)(tc.network, tc.address, raw); err != nil {
				t.Fatalf("Control(%s, %s) error = %v, want nil", tc.network, tc.address, err)
			}
			if want := []ttBindCall{{conn: raw, iface: ttIface(1), ipv6: tc.wantIPv6}}; !slices.Equal(b.calls, want) {
				t.Errorf("bind calls = %+v, want %+v", b.calls, want)
			}
			if want := []bool{tc.wantIPv6}; !slices.Equal(l.families, want) {
				t.Errorf("lookup families = %v, want %v", l.families, want)
			}
		})
	}
}

func TestNewListenConfigControlTakesBareNetworkFamilyFromLiteral(t *testing.T) {
	tests := []struct {
		network  string
		address  string
		wantIPv6 bool
	}{
		{"udp", "192.0.2.1:0", false},
		{"udp", "[2001:db8::1]:0", true},
		{"tcp", "192.0.2.1:0", false},
		{"udp", "[::ffff:192.0.2.1]:0", false},
		{"ip", "192.0.2.1", false},
	}
	for _, tc := range tests {
		t.Run(tc.network+" "+tc.address, func(t *testing.T) {
			l, b, raw := &ttLookup{}, &ttBinder{}, &ttRawConn{}
			if err := ttListenControl(t, l, b)(tc.network, tc.address, raw); err != nil {
				t.Fatalf("Control(%s, %s) error = %v, want nil", tc.network, tc.address, err)
			}
			if want := []ttBindCall{{conn: raw, iface: ttIface(1), ipv6: tc.wantIPv6}}; !slices.Equal(b.calls, want) {
				t.Errorf("bind calls = %+v, want %+v", b.calls, want)
			}
		})
	}
}

func TestNewListenConfigControlRefusesBareNetworkWithoutFamily(t *testing.T) {
	for _, address := range []string{":0", "0.0.0.0:0", "[::]:0", "localhost:0"} {
		t.Run(address, func(t *testing.T) {
			l, b := &ttLookup{}, &ttBinder{}
			err := ttListenControl(t, l, b)("udp", address, &ttRawConn{})
			if err == nil || !strings.Contains(err.Error(), "must name the family") {
				t.Errorf("Control(udp, %s) error = %v, want one saying the family must be given", address, err)
			}
			if len(l.families) != 0 || len(b.calls) != 0 {
				t.Errorf("lookup families %v, bind calls %+v, want neither", l.families, b.calls)
			}
		})
	}
}

func TestNewListenConfigWithoutCaptureHasNoControl(t *testing.T) {
	if lc := NewListenConfig(nil); lc == nil || lc.Control != nil {
		t.Errorf("NewListenConfig(nil) = %+v, want a zero-value ListenConfig", lc)
	}
}

func TestNewListenConfigListenPacketBareUDPReachesControlFamilySuffixed(t *testing.T) {
	l, b := &ttLookup{}, &ttBinder{}
	lc := newListenConfig(l.lookup, b.bind, ttNow)
	var networks []string
	control := lc.Control
	lc.Control = func(network, address string, c syscall.RawConn) error {
		networks = append(networks, network)
		return control(network, address, c)
	}
	conn, err := lc.ListenPacket(t.Context(), "udp", ":0")
	if err != nil {
		t.Fatalf("ListenPacket(udp, :0) error = %v, want nil", err)
	}
	conn.Close()
	if len(networks) != 1 || (networks[0] != "udp4" && networks[0] != "udp6") {
		t.Fatalf("Control networks = %q for ListenPacket(udp, :0), want one udp4 or udp6", networks)
	}
	if want := []bool{networks[0] == "udp6"}; !slices.Equal(l.families, want) {
		t.Errorf("lookup families = %v after Control saw %s, want %v", l.families, networks[0], want)
	}
}

func TestNewListenConfigListenUnixSucceeds(t *testing.T) {
	dir, err := os.MkdirTemp("", "bp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	ln, err := NewListenConfig(ttCaptureAll).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatalf("Listen(unix, %s) with a capture error = %v, want nil", path, err)
	}
	ln.Close()
}

func TestNewListenConfigControlBindsNoUnixSocket(t *testing.T) {
	for _, network := range []string{"unix", "unixgram", "unixpacket"} {
		t.Run(network, func(t *testing.T) {
			l, b := &ttLookup{}, &ttBinder{}
			if err := ttListenControl(t, l, b)(network, "/tmp/s", &ttRawConn{}); err != nil {
				t.Errorf("Control(%s, /tmp/s) error = %v, want nil", network, err)
			}
			if len(l.families) != 0 || len(b.calls) != 0 {
				t.Errorf("lookup families %v, bind calls %+v, want neither", l.families, b.calls)
			}
		})
	}
}

func TestNewListenConfigListenPacketFailsWithoutDefaultRoute(t *testing.T) {
	l, b := &ttLookup{err: fmt.Errorf("tt: %w", ErrNoDefaultRoute)}, &ttBinder{}
	conn, err := newListenConfig(l.lookup, b.bind, ttNow).ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if err == nil {
		conn.Close()
	}
	if !errors.Is(err, ErrNoDefaultRoute) {
		t.Errorf("ListenPacket error = %v, want ErrNoDefaultRoute", err)
	}
	if len(b.calls) != 0 {
		t.Errorf("bind calls = %d after a failed lookup, want 0", len(b.calls))
	}
}

func TestNewListenConfigControlInvalidatesCacheAfterBindError(t *testing.T) {
	l, b := &ttLookup{}, &ttBinder{err: ttErrBind}
	control := ttListenControl(t, l, b)
	if err := control("udp4", ":0", &ttRawConn{}); !errors.Is(err, ttErrBind) {
		t.Fatalf("Control error = %v, want %v", err, ttErrBind)
	}
	b.err = nil
	if err := control("udp4", ":0", &ttRawConn{}); err != nil {
		t.Fatalf("Control after the failed bind error = %v, want nil", err)
	}
	if want := []bool{false, false}; !slices.Equal(l.families, want) {
		t.Errorf("lookup families = %v, want %v: the failed bind must invalidate the cache", l.families, want)
	}
}

func TestNewListenConfigControlReusesLookupWithinTTL(t *testing.T) {
	l, b := &ttLookup{}, &ttBinder{}
	now := ttT0
	lc := newListenConfig(l.lookup, b.bind, func() time.Time { return now })
	for _, at := range []time.Duration{0, ttWithinTTL} {
		now = ttT0.Add(at)
		if err := lc.Control("udp4", ":0", &ttRawConn{}); err != nil {
			t.Fatalf("Control at +%v error = %v, want nil", at, err)
		}
	}
	if want := []bool{false}; !slices.Equal(l.families, want) {
		t.Errorf("lookup families = %v for two listens %v apart, want %v", l.families, ttWithinTTL, want)
	}
}

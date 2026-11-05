package tun

import (
	"bytes"
	"net/netip"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
)

func ttDefaultConfig() Config {
	return Config{
		Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64"),
		MTU:       1500,
		Bypass:    ttPrefixes("192.168.0.0/16", "10.0.0.0/8", "fe80::/64", "fd00::/8"),
	}
}

func ttPrefixes(s ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, len(s))
	for i, p := range s {
		prefixes[i] = netip.MustParsePrefix(p)
	}
	return prefixes
}

func TestHelperCommandIsTunHelper(t *testing.T) {
	if HelperCommand != "tun-helper" {
		t.Errorf("HelperCommand = %q, want tun-helper", HelperCommand)
	}
}

func TestNameDefaultsToTun(t *testing.T) {
	if got := (Config{}).name(); got != "tun" {
		t.Errorf("Config{}.name() = %q, want tun", got)
	}
	if got := (Config{Name: "wg"}).name(); got != "wg" {
		t.Errorf("Config{Name: wg}.name() = %q, want wg", got)
	}
}

func TestLinuxNameAppendsIndexVerb(t *testing.T) {
	for name, want := range map[string]string{"": "tun%d", "wg": "wg%d", "wg%d": "wg%d", "a%db": "a%db"} {
		if got := linuxName(Config{Name: name}); got != want {
			t.Errorf("linuxName(Name %q) = %q, want %q", name, got, want)
		}
	}
}

func TestRequestCarriesTheConfig(t *testing.T) {
	cfg := ttDefaultConfig()
	cfg.Name = "tt0"
	var buf bytes.Buffer
	if err := writeFrame(&buf, newRequest(cfg)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"name":"tt0"`) {
		t.Errorf("request frame %s carries no name tt0", buf.Bytes()[4:])
	}
	var req request
	if err := readFrame(&buf, &req); err != nil {
		t.Fatal(err)
	}
	if got := req.config(); !reflect.DeepEqual(got, cfg) {
		t.Errorf("request round trip = %+v, want %+v", got, cfg)
	}
}

func TestDefaultToolsLinuxIPIsAbsoluteOrEmpty(t *testing.T) {
	ip := defaultTools("linux").ip
	if ip == "" {
		return
	}
	if !path.IsAbs(ip) {
		t.Fatalf("defaultTools(linux).ip = %q, want an absolute path or empty, never a name looked up in PATH", ip)
	}
	if _, err := os.Stat(ip); err != nil {
		t.Errorf("defaultTools(linux).ip = %q, want an existing file: %v", ip, err)
	}
}

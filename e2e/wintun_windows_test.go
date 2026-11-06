package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/wzshiming/tun/wintun"
)

// ttWintunCache is the CacheDir of this whole binary, the helper it launches included, set before any wintun.Load.
var ttWintunCache = filepath.Join(os.TempDir(), "tun-e2e")

func init() {
	wintun.CacheDir = func() (string, error) { return ttWintunCache, nil }
}

// TestE2EWintunLoad holds whether or not an earlier test loaded wintun.dll, as Load runs once per process.
func TestE2EWintunLoad(t *testing.T) {
	ttGate(t)
	if !wintun.Embedded {
		t.Skip("this build embeds no wintun.dll")
	}
	if err := wintun.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	name, err := windows.UTF16PtrFromString("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	var module windows.Handle
	if err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, name, &module); err != nil {
		t.Fatalf("wintun.dll is not loaded after Load: %v", err)
	}
	if _, err := windows.GetProcAddress(module, "WintunCreateAdapter"); err != nil {
		t.Errorf("WintunCreateAdapter does not resolve in the loaded wintun.dll: %v", err)
	}

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetModuleFileName(module, &buf[0], uint32(len(buf)))
	if err != nil {
		t.Fatalf("GetModuleFileName: %v", err)
	}
	path := windows.UTF16ToString(buf[:n])
	t.Logf("wintun.dll loaded from %s", path)
	if base, dir := filepath.Base(path), filepath.Base(filepath.Dir(path)); !strings.EqualFold(base, "wintun.dll") || !strings.HasPrefix(dir, runtime.GOARCH+"-") {
		t.Errorf("loaded %s, want <CacheDir>\\wintun\\%s-<hash>\\wintun.dll", path, runtime.GOARCH)
	}
	// The loaded path is the final one, which may spell the cache directory differently, such as without 8.3 short names.
	got, err := os.Stat(filepath.Dir(filepath.Dir(path)))
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(filepath.Join(ttWintunCache, "wintun"))
	if err != nil {
		t.Fatalf("CacheDir holds no wintun directory: %v", err)
	}
	if !os.SameFile(got, want) {
		t.Errorf("loaded %s, want it under %s", path, filepath.Join(ttWintunCache, "wintun"))
	}
}

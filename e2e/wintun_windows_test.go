package e2e

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/wzshiming/tun/wintun"
)

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
	got, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := wintun.CacheDir()
	if err != nil {
		t.Fatalf("CacheDir: %v", err)
	}
	// The loaded path is the final one, which may spell the cache directory differently, such as without 8.3 short names.
	pattern := filepath.Join(cache, "wintun", runtime.GOARCH+"-*", "wintun.dll")
	candidates, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range candidates {
		if want, err := os.Stat(candidate); err == nil && os.SameFile(got, want) {
			return
		}
	}
	t.Errorf("loaded %s, want the file %s", path, pattern)
}

package tun

import (
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// ttWintunUse points CacheDir at a directory below cache, which stands for the user cache, and forgets any loaded wintun.dll for t, freeing what t loads when it ends; it returns where wintun.dll goes.
func ttWintunUse(t *testing.T, cache string) string {
	t.Helper()
	if !wintunEmbedded {
		t.Skipf("no wintun.dll embedded for %s", runtime.GOARCH)
	}
	wintunMu.Lock()
	prevCache, prevModule, prevHook := CacheDir, wintunModule, wintunBeforeOpen
	CacheDir = func() (string, error) { return filepath.Join(cache, "tun"), nil }
	wintunModule = 0
	wintunMu.Unlock()
	t.Cleanup(func() {
		wintunMu.Lock()
		defer wintunMu.Unlock()
		if wintunModule != 0 {
			windows.FreeLibrary(wintunModule)
		}
		CacheDir, wintunModule, wintunBeforeOpen = prevCache, prevModule, prevHook
	})
	return filepath.Join(append(append([]string{cache}, ttWintunSubdirs()...), "wintun.dll")...)
}

// ttWintunSubdirs are the directories loadWintun creates below the user cache.
func ttWintunSubdirs() []string {
	_, sub := wintunLocation(filepath.Join("cache", "tun"), runtime.GOARCH, wintunDLL)
	return sub
}

// ttWintunJunction makes link a directory junction to target, which needs no privilege.
func ttWintunJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command(os.Getenv("ComSpec"), "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v\n%s", link, target, err, out)
	}
	t.Cleanup(func() { os.Remove(link) })
}

func ttWintunWantRefused(t *testing.T, err error, target string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Errorf("loadWintun = %v, want an error naming a reparse point", err)
	}
	if wintunModule != 0 {
		t.Error("loadWintun loaded a module through a junction")
	}
	if names := ttWintunReadDir(t, target); len(names) != 0 {
		t.Errorf("junction target %s holds %q, want nothing written into it", target, names)
	}
}

func ttWintunWantEmbedded(t *testing.T, path string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if sha256.Sum256(got) != sha256.Sum256(wintunDLL) {
		t.Errorf("%s differs from the embedded wintun.dll", path)
	}
}

func TestLoadWintunWritesTheEmbeddedDLLAndLoadsIt(t *testing.T) {
	path := ttWintunUse(t, t.TempDir())
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	if _, err := windows.GetProcAddress(wintunModule, "WintunCreateAdapter"); err != nil {
		t.Errorf("the loaded module has no WintunCreateAdapter: %v", err)
	}
}

func TestLoadWintunReplacesAWrongDLL(t *testing.T) {
	path := ttWintunUse(t, t.TempDir())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not wintun"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	if wintunModule == 0 {
		t.Error("loadWintun loaded no module")
	}
}

func TestLoadWintunAgainKeepsTheFile(t *testing.T) {
	path := ttWintunUse(t, t.TempDir())
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := loadWintun(); err != nil {
		t.Fatalf("second loadWintun: %v", err)
	}
	// Forgetting the module provisions and loads again, now over the extracted file.
	wintunMu.Lock()
	first := wintunModule
	wintunModule = 0
	wintunMu.Unlock()
	defer windows.FreeLibrary(first)
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun after forgetting the module: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("mtime went from %v to %v, want wintun.dll left as extracted", before.ModTime(), after.ModTime())
	}
}

func TestLoadWintunRefusesAFileChangedBeforeVerification(t *testing.T) {
	path := ttWintunUse(t, t.TempDir())
	wintunBeforeOpen = func(path string) {
		if err := os.WriteFile(path, []byte("swapped"), 0o644); err != nil {
			t.Errorf("swap %s: %v", path, err)
		}
	}
	err := loadWintun()
	if err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("loadWintun = %v, want an error saying the file differs", err)
	}
	if wintunModule != 0 {
		t.Fatal("loadWintun loaded a module from a file that failed verification")
	}
	wintunBeforeOpen = func(string) {}
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun retried after a failure: %v", err)
	}
	ttWintunWantEmbedded(t, path)
}

func TestLoadWintunRefusesAJunctionAtAnOwnedDirectory(t *testing.T) {
	for i, name := range ttWintunSubdirs() {
		t.Run(name, func(t *testing.T) {
			cache, target := t.TempDir(), t.TempDir()
			ttWintunUse(t, cache)
			parent := filepath.Join(append([]string{cache}, ttWintunSubdirs()[:i]...)...)
			if err := os.MkdirAll(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			ttWintunJunction(t, filepath.Join(parent, name), target)
			ttWintunWantRefused(t, loadWintun(), target)
		})
	}
}

func TestLoadWintunRefusesAJunctionAtTheDLL(t *testing.T) {
	cache, target := t.TempDir(), t.TempDir()
	path := ttWintunUse(t, cache)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ttWintunJunction(t, path, target)
	ttWintunWantRefused(t, loadWintun(), target)
}

func TestLoadWintunAcceptsARedirectedUserCache(t *testing.T) {
	target := t.TempDir()
	cache := filepath.Join(t.TempDir(), "redirected-cache")
	ttWintunJunction(t, cache, target)
	path := ttWintunUse(t, cache)
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun under a redirected cache: %v", err)
	}
	ttWintunWantEmbedded(t, path)
}

func TestLoadWintunLoadsTheFinalPathOfTheVerifiedFile(t *testing.T) {
	target := t.TempDir()
	cache := filepath.Join(t.TempDir(), "redirected-cache")
	ttWintunJunction(t, cache, target)
	path := ttWintunUse(t, cache)
	prev := wintunLoadLibrary
	t.Cleanup(func() { wintunLoadLibrary = prev })
	var loaded []string
	wintunLoadLibrary = func(p string) (windows.Handle, error) {
		loaded = append(loaded, p)
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Errorf("%s opened for writing while being loaded, want the verifying handle still denying it", p)
		}
		return prev(p)
	}
	if err := loadWintun(); err != nil {
		t.Fatalf("loadWintun: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("loaded %q, want one path", loaded)
	}
	got := loaded[0]
	if !strings.HasPrefix(got, `\\?\`) || strings.Contains(got, "redirected-cache") {
		t.Errorf("loaded %q, want the \\\\?\\ final path with the junction resolved", got)
	}
	gotFi, err1 := os.Stat(got)
	wantFi, err2 := os.Stat(path)
	if err1 != nil || err2 != nil || !os.SameFile(gotFi, wantFi) {
		t.Errorf("loaded %q, want the file at %s (%v, %v)", got, path, err1, err2)
	}
}

func TestLoadWintunConcurrentCallsAllSucceed(t *testing.T) {
	ttWintunUse(t, t.TempDir())
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { errs[i] = loadWintun() })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Errorf("concurrent loadWintun: %v", err)
	}
}

func TestLoadWintunUnsupportedWithoutEmbeddedDLL(t *testing.T) {
	if wintunEmbedded {
		t.Skipf("wintun.dll is embedded for %s", runtime.GOARCH)
	}
	if err := loadWintun(); !errors.Is(err, ErrUnsupported) {
		t.Errorf("loadWintun = %v, want ErrUnsupported", err)
	}
}

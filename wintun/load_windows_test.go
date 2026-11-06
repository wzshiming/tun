package wintun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
)

// TestMain fails any test that reaches LoadLibrary without faking it, so no unit test maps wintun.dll into the process.
func TestMain(m *testing.M) {
	loadLibrary = func(path string) (windows.Handle, error) {
		return 0, fmt.Errorf("tt: LoadLibrary(%s) is not faked", path)
	}
	os.Exit(m.Run())
}

// ttWintunUse points CacheDir at a directory below cache, which stands for the user cache, forgets any loaded module and fakes LoadLibrary for t; it returns where wintun.dll goes and the paths t loads.
func ttWintunUse(t *testing.T, cache string) (string, *[]string) {
	t.Helper()
	if !Embedded {
		t.Skipf("no wintun.dll embedded for %s", runtime.GOARCH)
	}
	loaded := new([]string)
	mu.Lock()
	prevCache, prevModule, prevHook, prevLoad := CacheDir, module, beforeOpen, loadLibrary
	CacheDir = func() (string, error) { return filepath.Join(cache, "tun"), nil }
	module = 0
	// Load calls this under mu.
	loadLibrary = func(path string) (windows.Handle, error) {
		*loaded = append(*loaded, path)
		return windows.Handle(len(*loaded)), nil
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		CacheDir, module, beforeOpen, loadLibrary = prevCache, prevModule, prevHook, prevLoad
	})
	return filepath.Join(append(append([]string{cache}, ttWintunSubdirs()...), "wintun.dll")...), loaded
}

// ttWintunSubdirs are the directories Load creates below the user cache.
func ttWintunSubdirs() []string {
	_, sub := location(filepath.Join("cache", "tun"), runtime.GOARCH, dll)
	return sub
}

// ttWintunWantLoaded wants exactly one load, of the \\?\ final path of the file at path.
func ttWintunWantLoaded(t *testing.T, loaded []string, path string) {
	t.Helper()
	if len(loaded) != 1 {
		t.Fatalf("loaded %q, want one path", loaded)
	}
	got := loaded[0]
	if !strings.HasPrefix(got, `\\?\`) {
		t.Errorf("loaded %q, want a \\\\?\\ final path", got)
	}
	gotFi, err1 := os.Stat(got)
	wantFi, err2 := os.Stat(path)
	if err1 != nil || err2 != nil || !os.SameFile(gotFi, wantFi) {
		t.Errorf("loaded %q, want the file at %s (%v, %v)", got, path, err1, err2)
	}
}

// ttWintunJunction makes link a directory junction to target, which needs no privilege.
func ttWintunJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command(os.Getenv("ComSpec"), "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v\n%s", link, target, err, out)
	}
	t.Cleanup(func() { os.Remove(link) })
}

func ttWintunWantRefused(t *testing.T, err error, target string, loaded []string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Errorf("Load = %v, want an error naming a reparse point", err)
	}
	if module != 0 || len(loaded) != 0 {
		t.Errorf("Load loaded %q through a junction", loaded)
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
	if sha256.Sum256(got) != sha256.Sum256(dll) {
		t.Errorf("%s differs from the embedded wintun.dll", path)
	}
}

func TestLoadWritesTheEmbeddedDLLAndLoadsIt(t *testing.T) {
	path, loaded := ttWintunUse(t, t.TempDir())
	if err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
	if module == 0 {
		t.Error("Load kept no module")
	}
}

func TestLoadReplacesAWrongDLL(t *testing.T) {
	path, loaded := ttWintunUse(t, t.TempDir())
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not wintun"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadAgainKeepsTheFile(t *testing.T) {
	path, loaded := ttWintunUse(t, t.TempDir())
	if err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Load(); err != nil {
		t.Fatalf("second Load: %v", err)
	}
	if len(*loaded) != 1 {
		t.Errorf("loaded %q, want the second Load to reuse the module", *loaded)
	}
	// Forgetting the module provisions and loads again, now over the extracted file.
	mu.Lock()
	module = 0
	mu.Unlock()
	if err := Load(); err != nil {
		t.Fatalf("Load after forgetting the module: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("mtime went from %v to %v, want wintun.dll left as extracted", before.ModTime(), after.ModTime())
	}
}

func TestLoadRefusesAFileChangedBeforeVerification(t *testing.T) {
	path, loaded := ttWintunUse(t, t.TempDir())
	beforeOpen = func(path string) {
		if err := os.WriteFile(path, []byte("swapped"), 0o644); err != nil {
			t.Errorf("swap %s: %v", path, err)
		}
	}
	err := Load()
	if err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("Load = %v, want an error saying the file differs", err)
	}
	if module != 0 || len(*loaded) != 0 {
		t.Fatalf("Load loaded %q from a file that failed verification", *loaded)
	}
	beforeOpen = func(string) {}
	if err := Load(); err != nil {
		t.Fatalf("Load retried after a failure: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadRefusesAJunctionAtAnOwnedDirectory(t *testing.T) {
	for i, name := range ttWintunSubdirs() {
		t.Run(name, func(t *testing.T) {
			cache, target := t.TempDir(), t.TempDir()
			_, loaded := ttWintunUse(t, cache)
			parent := filepath.Join(append([]string{cache}, ttWintunSubdirs()[:i]...)...)
			if err := os.MkdirAll(parent, 0o755); err != nil {
				t.Fatal(err)
			}
			ttWintunJunction(t, filepath.Join(parent, name), target)
			err := Load()
			ttWintunWantRefused(t, err, target, *loaded)
		})
	}
}

func TestLoadRefusesAJunctionAtTheDLL(t *testing.T) {
	cache, target := t.TempDir(), t.TempDir()
	path, loaded := ttWintunUse(t, cache)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	ttWintunJunction(t, path, target)
	err := Load()
	ttWintunWantRefused(t, err, target, *loaded)
}

func TestLoadAcceptsARedirectedUserCache(t *testing.T) {
	target := t.TempDir()
	cache := filepath.Join(t.TempDir(), "redirected-cache")
	ttWintunJunction(t, cache, target)
	path, loaded := ttWintunUse(t, cache)
	if err := Load(); err != nil {
		t.Fatalf("Load under a redirected cache: %v", err)
	}
	ttWintunWantEmbedded(t, path)
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadLoadsTheFinalPathOfTheVerifiedFile(t *testing.T) {
	target := t.TempDir()
	cache := filepath.Join(t.TempDir(), "redirected-cache")
	ttWintunJunction(t, cache, target)
	path, loaded := ttWintunUse(t, cache)
	fake := loadLibrary
	loadLibrary = func(p string) (windows.Handle, error) {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Close()
			t.Errorf("%s opened for writing while being loaded, want the verifying handle still denying it", p)
		}
		return fake(p)
	}
	if err := Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	ttWintunWantLoaded(t, *loaded, path)
	if strings.Contains((*loaded)[0], "redirected-cache") {
		t.Errorf("loaded %q, want the junction resolved", (*loaded)[0])
	}
}

func TestLoadConcurrentCallsAllSucceed(t *testing.T) {
	path, loaded := ttWintunUse(t, t.TempDir())
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() { errs[i] = Load() })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		t.Errorf("concurrent Load: %v", err)
	}
	ttWintunWantLoaded(t, *loaded, path)
}

func TestLoadUnsupportedWithoutEmbeddedDLL(t *testing.T) {
	if Embedded {
		t.Skipf("wintun.dll is embedded for %s", runtime.GOARCH)
	}
	if err := Load(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("Load = %v, want errors.ErrUnsupported", err)
	}
}

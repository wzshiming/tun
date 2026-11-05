package tun

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func ttProvisionNoCheck(string) error { return nil }

// ttProvisionNoSymlink rejects a symlink the way the Windows check rejects a reparse point.
func ttProvisionNoSymlink(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("tt: %s is a link", path)
	}
	return nil
}

func ttProvisionWantEmpty(t *testing.T, dir string) {
	t.Helper()
	if names := ttWintunReadDir(t, dir); len(names) != 0 {
		t.Errorf("%s holds %q, want nothing written through the link", dir, names)
	}
}

func ttWintunReadDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestProvisionFileWritesAMissingFileIntoANewDirectory(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "a", "b")
	path, err := provisionFile(root, []string{"a", "b"}, "x.dll", []byte("payload"), ttProvisionNoCheck)
	if err != nil {
		t.Fatalf("provisionFile: %v", err)
	}
	if want := filepath.Join(dir, "x.dll"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "payload" {
		t.Errorf("read %s = %q, %v; want %q", path, got, err, "payload")
	}
	if names := ttWintunReadDir(t, dir); !slices.Equal(names, []string{"x.dll"}) {
		t.Errorf("%s holds %q, want only x.dll and no temporary file", dir, names)
	}
}

func TestProvisionFileReplacesDifferentContent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.dll"), []byte("stale content"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, err := provisionFile(dir, nil, "x.dll", []byte("payload"), ttProvisionNoCheck)
	if err != nil {
		t.Fatalf("provisionFile: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "payload" {
		t.Errorf("read %s = %q, %v; want %q", path, got, err, "payload")
	}
	if names := ttWintunReadDir(t, dir); !slices.Equal(names, []string{"x.dll"}) {
		t.Errorf("%s holds %q, want only x.dll and no temporary file", dir, names)
	}
}

func TestProvisionFileLeavesIdenticalContentUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.dll")
	if err := os.WriteFile(path, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionFile(dir, nil, "x.dll", []byte("payload"), ttProvisionNoCheck); err != nil {
		t.Fatalf("provisionFile: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(old) {
		t.Errorf("mtime = %v, want %v: an identical file must not be rewritten", fi.ModTime(), old)
	}
}

func TestCacheDirDefaultsToTunUnderTheUserCache(t *testing.T) {
	user, err := os.UserCacheDir()
	if err != nil {
		t.Skipf("no user cache directory: %v", err)
	}
	if got, err := CacheDir(); err != nil || got != filepath.Join(user, "tun") {
		t.Errorf("CacheDir = %q, %v; want %q", got, err, filepath.Join(user, "tun"))
	}
}

func TestWintunLocationKeysTheDLLByArchAndHashUnderCacheDir(t *testing.T) {
	dll := []byte("dll bytes")
	sum := sha256.Sum256(dll)
	cache := filepath.Join("user-cache", "app")
	root, sub := wintunLocation(cache, "arm64", dll)
	if want := []string{"app", "wintun", "arm64-" + hex.EncodeToString(sum[:])[:16]}; root != "user-cache" || !slices.Equal(sub, want) {
		t.Errorf("wintunLocation = %q, %q; want user-cache, %q", root, sub, want)
	}
}

func TestProvisionFileChecksEachOwnedDirectoryAndTheFileButNotTheRoot(t *testing.T) {
	root := t.TempDir()
	var checked []string
	check := func(path string) error {
		if _, err := os.Stat(path); path != filepath.Join(root, "a", "b", "x.dll") && err != nil {
			t.Errorf("checked %s before creating it: %v", path, err)
		}
		checked = append(checked, path)
		return nil
	}
	if _, err := provisionFile(root, []string{"a", "b"}, "x.dll", []byte("payload"), check); err != nil {
		t.Fatalf("provisionFile: %v", err)
	}
	for _, want := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b"), filepath.Join(root, "a", "b", "x.dll")} {
		if !slices.Contains(checked, want) {
			t.Errorf("checked %q, want %s among them", checked, want)
		}
	}
	if slices.Contains(checked, root) {
		t.Errorf("checked the root %s, which may legitimately be redirected", root)
	}
}

func TestProvisionFileRefusesALinkedOwnedDirectory(t *testing.T) {
	for _, link := range []string{"a", "b"} {
		t.Run(link, func(t *testing.T) {
			root, target := t.TempDir(), t.TempDir()
			parent := root
			if link == "b" {
				parent = filepath.Join(root, "a")
				if err := os.Mkdir(parent, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, filepath.Join(parent, link)); err != nil {
				t.Skipf("symlink: %v", err)
			}
			if _, err := provisionFile(root, []string{"a", "b"}, "x.dll", []byte("payload"), ttProvisionNoSymlink); err == nil {
				t.Error("provisionFile through a linked directory = nil error, want one")
			}
			ttProvisionWantEmpty(t, target)
		})
	}
}

func TestProvisionFileRefusesALinkedFileEvenWithTheRightContent(t *testing.T) {
	root, target := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "real.dll"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "real.dll"), filepath.Join(root, "x.dll")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, err := provisionFile(root, nil, "x.dll", []byte("payload"), ttProvisionNoSymlink); err == nil {
		t.Error("provisionFile over a linked file = nil error, want one")
	}
}

func TestProvisionFileChecksTheFileBeforeRenamingOverIt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "x.dll")
	// Refuse x.dll only once the temporary file is written, as if it became a link meanwhile.
	check := func(p string) error {
		if tmp, _ := filepath.Glob(filepath.Join(root, "x.dll.*.tmp")); p == path && len(tmp) > 0 {
			return errors.New("tt: refused")
		}
		return nil
	}
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := provisionFile(root, nil, "x.dll", []byte("payload"), check); err == nil {
		t.Fatal("provisionFile = nil error, want the check's")
	}
	if got, _ := os.ReadFile(path); string(got) != "stale" {
		t.Errorf("x.dll = %q, want it left alone after the check failed", got)
	}
	if names := ttWintunReadDir(t, root); !slices.Equal(names, []string{"x.dll"}) {
		t.Errorf("%s holds %q, want no temporary file left", root, names)
	}
}

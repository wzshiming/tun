package tun

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// CacheDir returns this package's cache directory, which on Windows holds the extracted wintun.dll; programs may replace it.
// Its parent is taken as given, while the directory itself and those below it are created and checked.
var CacheDir = func() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tun"), nil
}

// wintunLocation splits where the wintun.dll of goarch whose bytes are dll goes under cacheDir into the unchecked root and the directories below it.
func wintunLocation(cacheDir, goarch string, dll []byte) (root string, sub []string) {
	sum := sha256.Sum256(dll)
	return filepath.Dir(cacheDir), []string{filepath.Base(cacheDir), "wintun", goarch + "-" + hex.EncodeToString(sum[:])[:16]}
}

// provisionFile makes root/sub.../name hold data, writing a temporary file and renaming it over the target unless it already does.
// It creates each directory of sub and runs check on it before going further, and on the target before reading or replacing it; root is not checked.
func provisionFile(root string, sub []string, name string, data []byte, check func(path string) error) (path string, err error) {
	dir := root
	for _, s := range sub {
		dir = filepath.Join(dir, s)
		if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		if err := check(dir); err != nil {
			return "", err
		}
	}
	path = filepath.Join(dir, name)
	if err := check(path); err != nil {
		return "", err
	}
	if have, err := os.ReadFile(path); err == nil && bytes.Equal(have, data) {
		return path, nil
	}
	f, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			os.Remove(f.Name())
		}
	}()
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = check(path)
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return "", err
	}
	return path, nil
}

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

// wintunSubdirs are the directories, below the user cache, holding the wintun.dll of goarch whose bytes are dll.
func wintunSubdirs(goarch string, dll []byte) []string {
	sum := sha256.Sum256(dll)
	return []string{"tun", "wintun", goarch + "-" + hex.EncodeToString(sum[:])[:16]}
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

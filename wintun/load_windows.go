package wintun

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"

	"golang.org/x/sys/windows"
)

// beforeOpen runs between extracting wintun.dll and opening it for verification; tests swap the file there.
var beforeOpen = func(path string) {}

// loadLibrary loads the DLL at the absolute path, resolving its imports from System32 only.
var loadLibrary = func(path string) (windows.Handle, error) {
	return windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
}

var (
	mu sync.Mutex
	// module is the loaded wintun.dll, which golang.zx2c4.com/wintun then finds by its base name.
	module windows.Handle
)

// Load extracts the embedded wintun.dll and loads it once per process.
func Load() error {
	if !Embedded {
		return fmt.Errorf("tun: no wintun.dll for %s: %w", runtime.GOARCH, errors.ErrUnsupported)
	}
	mu.Lock()
	defer mu.Unlock()
	if module != 0 {
		return nil
	}
	cache, err := CacheDir()
	if err != nil {
		return fmt.Errorf("tun: wintun.dll directory: %w", err)
	}
	root, sub := location(cache, runtime.GOARCH, dll)
	path, err := provisionFile(root, sub, "wintun.dll", dll, rejectReparsePoint)
	if err != nil {
		return fmt.Errorf("tun: extract wintun.dll: %w", err)
	}
	beforeOpen(path)
	h, err := loadVerified(path, dll)
	if err != nil {
		return fmt.Errorf("tun: load %s: %w", path, err)
	}
	module = h
	return nil
}

// loadVerified loads the DLL at path if it holds want, keeping the file open without write or delete sharing from the check until it is loaded.
func loadVerified(path string, want []byte) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return 0, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	have, err := io.ReadAll(f)
	if err != nil {
		return 0, err
	}
	if sha256.Sum256(have) != sha256.Sum256(want) {
		return 0, errors.New("content differs from the embedded wintun.dll")
	}
	// Load what the handle verified: path itself can be re-pointed through a user-writable junction.
	final, err := finalPath(h)
	if err != nil {
		return 0, err
	}
	return loadLibrary(final)
}

// GetFinalPathNameByHandle flags golang.org/x/sys/windows does not define.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)

// finalPath returns the normalized \\?\ path of the file h is open on.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:min(n, uint32(len(buf)))]), nil
}

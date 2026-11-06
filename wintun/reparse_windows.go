package wintun

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// rejectReparsePoint fails if path is a junction, symlink or other reparse point, which a same-user process could aim anywhere.
func rejectReparsePoint(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if a, ok := fi.Sys().(*syscall.Win32FileAttributeData); !ok || a.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("tun: %s is a reparse point", path)
	}
	return nil
}

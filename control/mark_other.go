//go:build !linux

package control

import (
	"fmt"
	"syscall"
)

func ControlSocketMark(m int) ControlFunc {
	return func(_, _ string, c syscall.RawConn) (err error) {
		return fmt.Errorf("socket mark unsupported platform")
	}
}

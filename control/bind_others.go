//go:build !linux && !darwin

package control

import (
	"fmt"
	"net"
	"syscall"
)

func ControlBindToInterface(_ *net.Interface) ControlFunc {
	return func(string, string, syscall.RawConn) error {
		return fmt.Errorf("bind to interface unsupported platform")
	}
}

//go:build !linux && !darwin

package control

import (
	"errors"
	"net"
	"syscall"
)

func ControlBindToInterface(_ *net.Interface) ControlFunc {
	return func(string, string, syscall.RawConn) error {
		return errors.New("bind to interface unsupported platform")
	}
}

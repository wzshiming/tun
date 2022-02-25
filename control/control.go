package control

import (
	"syscall"
)

type ControlFunc func(string, string, syscall.RawConn) error

func Controls(controls ...ControlFunc) ControlFunc {
	if len(controls) == 0 {
		return nil
	}
	if len(controls) == 1 {
		return controls[0]
	}
	return func(address, network string, c syscall.RawConn) error {
		for _, f := range controls {
			if err := f(address, network, c); err != nil {
				return err
			}
		}
		return nil
	}
}

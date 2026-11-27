//go:build !darwin && !linux

package icmp

import (
	"errors"
	"net"
	"syscall"
)

// datagramSocket fails, as the platform has no unprivileged ICMP socket.
func datagramSocket(bool, func(syscall.RawConn) error) (net.PacketConn, error) {
	return nil, errors.ErrUnsupported
}

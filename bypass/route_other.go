//go:build !darwin && !linux && !windows

package bypass

import (
	"errors"
	"net"
)

var bindDefault bindFunc

// DefaultInterface returns errors.ErrUnsupported on this platform.
func DefaultInterface(ipv6 bool) (*net.Interface, error) {
	return nil, errors.ErrUnsupported
}

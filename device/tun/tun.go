// Package tun provides TUN which implemented device.Device interface.
package tun

import (
	"github.com/wzshiming/tun/device"
)

const Driver = "tun"

func (t *TUN) Type() string {
	return Driver
}

var _ device.Device = (*TUN)(nil)

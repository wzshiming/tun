package tun

import (
	"github.com/wzshiming/tun/device"
)

func init() {
	device.Registry("tun", Open)
}

package fd

import (
	"github.com/wzshiming/tun/device"
)

func init() {
	device.Registry("fd", Open)
}

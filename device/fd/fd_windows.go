package fd

import (
	"errors"
	"github.com/wzshiming/tun/device"
)

func Open(name string, mtu uint32) (device.Device, error) {
	return nil, errors.New("not supported")
}

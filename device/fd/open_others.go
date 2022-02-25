//go:build !linux && !windows

package fd

import (
	"fmt"
	"os"

	"github.com/wzshiming/tun/device"
)

func open(fd int, mtu uint32) (device.Device, error) {
	f := &FD{fd: fd, mtu: mtu}

	ep, err := device.New(os.NewFile(uintptr(fd), f.Name()), mtu, 0)
	if err != nil {
		return nil, fmt.Errorf("create endpoint %s: %w", f.Name(), err)
	}
	f.LinkEndpoint = ep

	return f, nil
}

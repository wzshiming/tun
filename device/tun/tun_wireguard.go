//go:build !linux

package tun

import (
	"fmt"
	"runtime"

	"github.com/wzshiming/tun/device"
	"golang.zx2c4.com/wireguard/tun"
)

type TUN struct {
	*device.Endpoint

	nt     *tun.NativeTun
	mtu    uint32
	name   string
	offset int
}

func Open(name string, mtu uint32) (_ device.Device, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("open tun: %v", r)
		}
	}()

	var (
		offset     = 4 /* 4 bytes TUN_PI */
		defaultMTU = 1500
	)
	if runtime.GOOS == "windows" {
		offset = 0
		defaultMTU = 0 /* auto */
	}

	t := &TUN{name: name, mtu: mtu, offset: offset}

	forcedMTU := defaultMTU
	if t.mtu > 0 {
		forcedMTU = int(t.mtu)
	}

	nt, err := tun.CreateTUN(t.name, forcedMTU)
	if err != nil {
		return nil, fmt.Errorf("create tun %q: %w", t.name, err)
	}
	t.nt = nt.(*tun.NativeTun)

	tunMTU, err := nt.MTU()
	if err != nil {
		return nil, fmt.Errorf("get mtu: %w", err)
	}
	t.mtu = uint32(tunMTU)

	ep, err := device.New(t, t.mtu, offset)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %w", err)
	}
	t.Endpoint = ep

	return t, nil
}

func (t *TUN) Read(packet []byte) (int, error) {
	return t.nt.Read(packet, t.offset)
}

func (t *TUN) Write(packet []byte) (int, error) {
	return t.nt.Write(packet, t.offset)
}

func (t *TUN) Name() string {
	name, _ := t.nt.Name()
	return name
}

func (t *TUN) Close() error {
	return t.nt.Close()
}

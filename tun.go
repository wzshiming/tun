package tun

import (
	"github.com/wzshiming/tun/device"
	"github.com/wzshiming/tun/netstack"
	"github.com/wzshiming/tun/route"
)

type Config struct {
	MTU          int
	Device       string
	Name         string
	BytesPool    BytesPool
	ListenPacket ListenPacket
	Dialer       Dialer
	Logger       Logger
}

func NewTun(c Config) *Tun {
	return &Tun{
		Config: &c,
	}
}

type Tun struct {
	*Config

	stack  *netstack.Stack
	device device.Device
}

func (t *Tun) Start() error {
	if t.Name == "" {
		t.Name = route.GetName()
	}
	if t.Device == "" {
		t.Device = "tun"
	}

	d, err := device.NewDevice(t.Device, t.Name, uint32(t.MTU))
	if err != nil {
		return err
	}
	t.device = d

	s, err := netstack.NewStack(t.device, t, netstack.WithDefault())
	if err != nil {
		return err
	}
	t.stack = s

	return nil
}

func (t *Tun) SetRoute(routes []string) error {
	return route.SetRoute(t.Name, routes)
}

func (t *Tun) Close() error {
	if t.device == nil {
		return nil
	}
	return t.device.Close()
}

package tun

import (
	"github.com/wzshiming/tun/device"
	"github.com/wzshiming/tun/route"
	"github.com/wzshiming/tun/stack"
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

	stack  *stack.Stack
	device device.Device
}

func (t *Tun) Start() error {
	if t.Name == "" {
		t.Name = route.GetName()
	}
	if t.Device == "" {
		t.Device = route.GetDevice()
	}

	d, err := device.NewDevice(t.Device, t.Name, uint32(t.MTU))
	if err != nil {
		return err
	}
	t.device = d

	s, err := stack.NewStack(t.device, t, stack.WithDefault())
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

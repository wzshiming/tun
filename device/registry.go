package device

import "fmt"

var registry = map[string]func(name string, mtu uint32) (Device, error){}

func Registry(name string, fun func(name string, mtu uint32) (Device, error)) {
	registry[name] = fun
}

func NewDevice(device, name string, mtu uint32) (Device, error) {
	if fun, ok := registry[device]; ok {
		return fun(name, mtu)
	}
	return nil, fmt.Errorf("device %s not found", device)
}

package tun

import (
	"context"
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// adapterGUID is the adapter's GUID, fixed per name so Windows keeps one network profile for it and adapters of different names never share one.
func adapterGUID(cfg Config) windows.GUID {
	b := nameGUID(cfg.name())
	return windows.GUID{
		Data1: binary.BigEndian.Uint32(b[0:4]),
		Data2: binary.BigEndian.Uint16(b[4:6]),
		Data3: binary.BigEndian.Uint16(b[6:8]),
		Data4: [8]byte(b[8:16]),
	}
}

// openLocal creates and configures the Wintun adapter in this process, which must be elevated.
func openLocal(ctx context.Context, cfg Config) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	guid := adapterGUID(cfg)
	dev, err := newWintunDevice(cfg.name(), &guid, cfg.MTU)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	var warnings []string
	if err == nil {
		warnings, err = configureVia(ctx, cfg, luidConfigurer(dev.LUID()))
	}
	if err != nil {
		dev.Close()
		return nil, err
	}
	return &Device{Device: dev, Interface: name, Warnings: warnings}, nil
}

// luidConfigurer configures the interface with this LUID through winipcfg.
type luidConfigurer winipcfg.LUID

func luidFamily(v6 bool) winipcfg.AddressFamily {
	if v6 {
		return windows.AF_INET6
	}
	return windows.AF_INET
}

// setInterface mirrors configureInterface in golang.zx2c4.com/wireguard/windows/tunnel/addressconfig.go.
func (c luidConfigurer) setInterface(v6 bool, mtu int) error {
	row, err := winipcfg.LUID(c).IPInterface(luidFamily(v6))
	if err != nil {
		return err
	}
	row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	row.DadTransmits = 0
	row.ManagedAddressConfigurationSupported = false
	row.OtherStatefulConfigurationSupported = false
	row.NLMTU = uint32(mtu)
	row.UseAutomaticMetric = false
	row.Metric = 0
	return row.Set()
}

func (c luidConfigurer) setAddress(addr netip.Prefix) error {
	return winipcfg.LUID(c).SetIPAddressesForFamily(luidFamily(addr.Addr().Is6()), []netip.Prefix{addr})
}

// addRoutes adds rather than sets the routes, as setting would flush the subnet route the address brought.
func (c luidConfigurer) addRoutes(v6 bool, routes []netip.Prefix) error {
	nextHop := netip.IPv4Unspecified()
	if v6 {
		nextHop = netip.IPv6Unspecified()
	}
	rows := make([]*winipcfg.RouteData, len(routes))
	for i, p := range routes {
		rows[i] = &winipcfg.RouteData{Destination: p, NextHop: nextHop, Metric: 0}
	}
	return winipcfg.LUID(c).AddRoutes(rows)
}

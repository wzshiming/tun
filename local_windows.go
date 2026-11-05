package tun

import (
	"context"
	"net/netip"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// wintunGUID is the adapter's fixed GUID, which keeps Windows from creating a new network profile on each open.
var wintunGUID = windows.GUID{Data1: 0x17cb5e1a, Data2: 0xf282, Data3: 0x43a6, Data4: [8]byte{0x97, 0xb6, 0x71, 0x0e, 0xb0, 0x5f, 0xa9, 0x0d}}

// openLocal creates and configures the Wintun adapter in this process, which must be elevated.
func openLocal(ctx context.Context, cfg Config) (*Device, error) {
	if err := loadWintun(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	wgtun.WintunTunnelType = "tun"
	guid := wintunGUID
	dev, err := wgtun.CreateTUNWithRequestedGUID("tun", &guid, cfg.MTU)
	if err != nil {
		return nil, err
	}
	name, err := dev.Name()
	var warnings []string
	if err == nil {
		luid := winipcfg.LUID(dev.(*wgtun.NativeTun).LUID())
		warnings, err = configureVia(ctx, cfg, luidConfigurer(luid))
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

//go:build windows

package bypass

import (
	"encoding/binary"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// IP_UNICAST_IF and IPV6_UNICAST_IF from ws2ipdef.h, which golang.org/x/sys/windows lacks.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// DefaultInterface returns the interface holding the family's default route, or ErrNoDefaultRoute when there is none.
func DefaultInterface(ipv6 bool) (*net.Interface, error) {
	family := winipcfg.AddressFamily(windows.AF_INET)
	if ipv6 {
		family = windows.AF_INET6
	}
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return nil, err
	}
	var candidates []routeCandidate
	for _, row := range rows {
		if row.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		candidates = append(candidates, defaultRouteCandidate(row, family))
	}
	index, err := pickDefaultRoute(candidates)
	if err != nil {
		return nil, err
	}
	return net.InterfaceByIndex(index)
}

// defaultRouteCandidate leaves the candidate down when its interface vanished between the table read and the lookups.
func defaultRouteCandidate(row winipcfg.MibIPforwardRow2, family winipcfg.AddressFamily) routeCandidate {
	c := routeCandidate{Index: int(row.InterfaceIndex), RouteMetric: row.Metric}
	ifRow, err := row.InterfaceLUID.Interface()
	if err != nil {
		return c
	}
	ipRow, err := row.InterfaceLUID.IPInterface(family)
	if err != nil {
		return c
	}
	c.IfaceMetric = ipRow.Metric
	c.Up = ifRow.OperStatus == winipcfg.IfOperStatusUp
	c.Loopback = ifRow.Type == winipcfg.IfTypeSoftwareLoopback
	return c
}

var bindDefault bindFunc = func(c syscall.RawConn, iface boundIface, ipv6 bool) error {
	level, opt, value := windows.IPPROTO_IP, ipUnicastIf, htonl(uint32(iface.Index))
	if ipv6 {
		level, opt, value = windows.IPPROTO_IPV6, ipv6UnicastIf, uint32(iface.Index)
	}
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = windows.SetsockoptInt(windows.Handle(fd), level, opt, int(value))
	}); cerr != nil {
		return cerr
	}
	return os.NewSyscallError("setsockopt", err)
}

func htonl(v uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return binary.NativeEndian.Uint32(b[:])
}

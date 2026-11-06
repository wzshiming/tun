package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/wzshiming/tun/bypass"
)

// IP_UNICAST_IF and IPV6_UNICAST_IF, which golang.org/x/sys/windows does not define.
const (
	ttIPUnicastIf   = 31
	ttIPv6UnicastIf = 31
)

// ttDefaultInterface returns the family's default-route interface, skipping the test when the runner has none.
func ttDefaultInterface(t *testing.T, ipv6 bool) *net.Interface {
	t.Helper()
	iface, err := bypass.DefaultInterface(ipv6)
	if errors.Is(err, bypass.ErrNoDefaultRoute) {
		t.Skipf("no default route for ipv6=%t on this host", ipv6)
	}
	if err != nil {
		t.Fatalf("DefaultInterface(%t) error = %v", ipv6, err)
	}
	return iface
}

// ttUnicastIf dials network/address through a dialer capturing prefix and reads the socket's level/opt back.
func ttUnicastIf(t *testing.T, network, address string, prefix netip.Prefix, level, opt int) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// Connecting a UDP socket only records the peer; no packet leaves the host.
	conn, err := bypass.NewDialer([]netip.Prefix{prefix}).DialContext(ctx, network, address)
	if err != nil {
		t.Fatalf("DialContext(%s, %s) error = %v", network, address, err)
	}
	defer conn.Close()
	sc, ok := conn.(syscall.Conn)
	if !ok {
		t.Fatalf("%T is not a syscall.Conn", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn error = %v", err)
	}
	var value int
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		value, optErr = windows.GetsockoptInt(windows.Handle(fd), level, opt)
	}); err != nil {
		t.Fatalf("RawConn.Control error = %v", err)
	}
	if optErr != nil {
		t.Fatalf("getsockopt(%d, %d) error = %v", level, opt, optErr)
	}
	return uint32(value)
}

func TestE2EBypassDefaultInterfaceIsUpAndNotLoopback(t *testing.T) {
	ttGate(t)
	iface := ttDefaultInterface(t, false)
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		t.Errorf("DefaultInterface(false) = %s (index %d, flags %v), want an up, non-loopback interface", iface.Name, iface.Index, iface.Flags)
	}
}

func TestE2EBypassBindsUDPToIPv4DefaultInterface(t *testing.T) {
	ttGate(t)
	iface := ttDefaultInterface(t, false)
	got := ttUnicastIf(t, "udp4", "1.1.1.1:53", netip.MustParsePrefix("1.1.1.1/32"), windows.IPPROTO_IP, ttIPUnicastIf)
	// Windows takes IP_UNICAST_IF in network byte order but reports it in host order.
	if got != uint32(iface.Index) {
		t.Errorf("IP_UNICAST_IF raw = %d, want index %d (%s holds the IPv4 default route)", got, iface.Index, iface.Name)
	}
}

func TestE2EBypassBindsUDPToIPv6DefaultInterface(t *testing.T) {
	ttGate(t)
	iface := ttDefaultInterface(t, true)
	got := ttUnicastIf(t, "udp6", "[2606:4700:4700::1111]:53", netip.MustParsePrefix("2606:4700:4700::1111/128"), windows.IPPROTO_IPV6, ttIPv6UnicastIf)
	if got != uint32(iface.Index) {
		t.Errorf("IPV6_UNICAST_IF = %d, want %d (%s holds the IPv6 default route)", got, iface.Index, iface.Name)
	}
}

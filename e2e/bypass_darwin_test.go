package e2e

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wzshiming/tun/bypass"
)

func TestE2EBypassBindsUDPToIPv4DefaultInterface(t *testing.T) {
	ttGate(t)
	iface, err := bypass.DefaultInterface(false)
	if errors.Is(err, bypass.ErrNoDefaultRoute) {
		t.Skip("no IPv4 default route on this host")
	}
	if err != nil {
		t.Fatalf("DefaultInterface(false) error = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// Connecting a UDP socket only records the peer; no packet leaves the host.
	conn, err := bypass.NewDialer(ttCaptureLab).DialContext(ctx, "udp4", "198.18.0.1:9")
	if err != nil {
		t.Fatalf("DialContext(udp4, 198.18.0.1:9) error = %v", err)
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
	var bound int
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		bound, optErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF)
	}); err != nil {
		t.Fatalf("RawConn.Control error = %v", err)
	}
	if optErr != nil {
		t.Fatalf("getsockopt(IP_BOUND_IF) error = %v", optErr)
	}
	if bound != iface.Index {
		t.Errorf("IP_BOUND_IF = %d, want %d (%s holds the IPv4 default route)", bound, iface.Index, iface.Name)
	}
}

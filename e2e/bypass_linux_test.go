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
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("SO_BINDTODEVICE needs privilege on this kernel: %v", err)
	}
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
	var device string
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		device, optErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("RawConn.Control error = %v", err)
	}
	if optErr != nil {
		t.Fatalf("getsockopt(SO_BINDTODEVICE) error = %v", optErr)
	}
	if device != iface.Name {
		t.Errorf("SO_BINDTODEVICE = %q, want %q (it holds the IPv4 default route)", device, iface.Name)
	}
}

func TestE2EBypassListenConfigBindsUDPToIPv4DefaultInterface(t *testing.T) {
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
	conn, err := bypass.NewListenConfig(ttCaptureLab).ListenPacket(ctx, "udp4", ":0")
	if errors.Is(err, syscall.EPERM) {
		t.Skipf("SO_BINDTODEVICE needs privilege on this kernel: %v", err)
	}
	if err != nil {
		t.Fatalf("ListenPacket(udp4, :0) error = %v", err)
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
	var device string
	var optErr error
	if err := raw.Control(func(fd uintptr) {
		device, optErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("RawConn.Control error = %v", err)
	}
	if optErr != nil {
		t.Fatalf("getsockopt(SO_BINDTODEVICE) error = %v", optErr)
	}
	if device != iface.Name {
		t.Errorf("SO_BINDTODEVICE = %q, want %q (it holds the IPv4 default route)", device, iface.Name)
	}
}

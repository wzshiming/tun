//go:build darwin || linux

package icmp

import (
	"net"
	"os"
	"runtime"
	"syscall"
)

// ipStripHdr is macOS's IP_STRIPHDR, which keeps the IPv4 header out of what a datagram ICMP socket reads.
const ipStripHdr = 0x17

// datagramSocket opens an unprivileged ICMP socket of the family, bound to no address, running control on it before the bind.
func datagramSocket(ipv6 bool, control func(syscall.RawConn) error) (net.PacketConn, error) {
	family, proto, local := syscall.AF_INET, syscall.IPPROTO_ICMP, syscall.Sockaddr(&syscall.SockaddrInet4{})
	if ipv6 {
		family, proto, local = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, &syscall.SockaddrInet6{}
	}
	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM, proto)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	// FilePacketConn duplicates the descriptor.
	f := os.NewFile(uintptr(fd), "icmp")
	defer f.Close()
	if runtime.GOOS == "darwin" && !ipv6 {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipStripHdr, 1); err != nil {
			return nil, os.NewSyscallError("setsockopt", err)
		}
	}
	c, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	if err := control(c); err != nil {
		return nil, err
	}
	if err := syscall.Bind(fd, local); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}
	return net.FilePacketConn(f)
}

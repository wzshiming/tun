// Package icmp relays the echo requests of an ICMP session to their target through an ICMP socket of the machine itself, and the echo replies back to the client; no proxy carries ICMP.
// Mount its Handler on a flow.Mux for the "icmp" network, e.g. m.Handle("icmp", "", &icmp.Handler{ListenConfig: lc}); the package registers nothing itself.
package icmp

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wzshiming/tun/flow"
)

var _ flow.Handler = (*Handler)(nil)

// Handler serves an ICMP echo session by sending its echo requests to their target from a socket of its own and the target's echo replies back to the client; it rejects other flows.
// The socket is a datagram ICMP one, which Linux grants to the groups of net.ipv4.ping_group_range and macOS to everyone, else a raw one, which needs root or, on Windows, an administrator; a session whose socket cannot be opened is rejected.
type Handler struct {
	// ListenConfig opens the raw socket, and its Control also runs on the datagram one, as for network "ip4" or "ip6": bypass.NewListenConfig keeps both off the TUN. Nil is the zero ListenConfig.
	ListenConfig *net.ListenConfig
	// Idle ends a session after this long without an echo request or reply; 0 means 30s.
	Idle time.Duration

	// idents numbers the sessions, each sending its echo requests under its number where the kernel does not pick one.
	idents atomic.Uint32
	// open replaces openSocket in tests.
	open func(ctx context.Context, ipv6 bool) (*socket, error)
}

// socket is the ICMP socket of one session.
type socket struct {
	net.PacketConn
	// datagram tells a datagram socket, addressed by *net.UDPAddr, from a raw one, addressed by *net.IPAddr.
	datagram bool
	// kernelIdent tells that the kernel sends the echo requests under an identifier it picked for the socket and delivers only their replies, as Linux does on a datagram socket.
	// Any other socket is delivered the ICMP messages of every session, and must tell its own replies by identifier.
	kernelIdent bool
}

func (s *socket) addr(ip netip.Addr) net.Addr {
	if s.datagram {
		return &net.UDPAddr{IP: ip.AsSlice()}
	}
	return &net.IPAddr{IP: ip.AsSlice()}
}

// addrOf returns the IP address of a socket's peer.
func addrOf(addr net.Addr) netip.Addr {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.UDPAddr:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
	}
	parsed, _ := netip.AddrFromSlice(ip)
	return parsed.Unmap()
}

// openSocket opens a datagram ICMP socket of the family, else a raw one.
func (h *Handler) openSocket(ctx context.Context, ipv6 bool) (*socket, error) {
	lc := h.ListenConfig
	if lc == nil {
		lc = &net.ListenConfig{}
	}
	network, raw, address := "ip4", "ip4:1", "0.0.0.0"
	if ipv6 {
		network, raw, address = "ip6", "ip6:58", "::"
	}
	conn, datagramErr := datagramSocket(ipv6, func(c syscall.RawConn) error {
		if lc.Control == nil {
			return nil
		}
		return lc.Control(network, address, c)
	})
	if datagramErr == nil {
		return &socket{PacketConn: conn, datagram: true, kernelIdent: runtime.GOOS == "linux"}, nil
	}
	conn, err := lc.ListenPacket(ctx, raw, address)
	if err != nil {
		return nil, fmt.Errorf("icmp: open socket: %w", errors.Join(datagramErr, err))
	}
	return &socket{PacketConn: conn}, nil
}

const (
	// headerSize is the size of an echo message's header: type, code, checksum, identifier and sequence number.
	headerSize = 8

	echoReply4 = 0
	echoReply6 = 129
)

// ServeFlow opens the session's socket before accepting, so a failed open rejects the flow, then relays until the session idles, its conn or socket fails or ctx ends, and closes both.
// An echo request the socket fails to send is lost alone. Only echo replies come back: an ICMP error about a request does not.
func (h *Handler) ServeFlow(ctx context.Context, f flow.Flow) {
	if f.Network() != "icmp" {
		f.Reject()
		return
	}
	target := f.Target().Addr().Unmap()
	open := h.openSocket
	if h.open != nil {
		open = h.open
	}
	sock, err := open(flow.WithClientAddr(ctx, &net.IPAddr{IP: f.Client().Addr().AsSlice()}), target.Is6())
	if err != nil {
		f.Reject()
		return
	}
	conn, err := f.Accept()
	if err != nil {
		sock.Close()
		return
	}
	end := sync.OnceFunc(func() {
		conn.Close()
		sock.Close()
	})
	defer end()
	stop := context.AfterFunc(ctx, end)
	defer stop()
	idle := cmp.Or(h.Idle, 30*time.Second)
	timer := time.AfterFunc(idle, end)
	defer timer.Stop()
	ident := uint16(h.idents.Add(1))

	var replies sync.WaitGroup
	defer replies.Wait()
	defer end()
	replies.Go(func() {
		defer end()
		reply := byte(echoReply4)
		if target.Is6() {
			reply = echoReply6
		}
		message := make([]byte, 65535)
		for {
			n, from, err := sock.ReadFrom(message)
			if err != nil {
				return
			}
			if n < headerSize || message[0] != reply || addrOf(from) != target {
				continue
			}
			if !sock.kernelIdent && binary.BigEndian.Uint16(message[4:]) != ident {
				continue
			}
			timer.Reset(idle)
			// The session puts the client's identifier back.
			if _, err := conn.Write(message[:n]); err != nil {
				return
			}
		}
	})

	to := sock.addr(target)
	message := make([]byte, 65535)
	for {
		n, err := conn.Read(message)
		if err != nil {
			return
		}
		if n < headerSize {
			continue
		}
		timer.Reset(idle)
		binary.BigEndian.PutUint16(message[4:], ident)
		// The kernel computes an ICMPv6 checksum on any socket, an ICMPv4 one only on some.
		if !target.Is6() {
			binary.BigEndian.PutUint16(message[2:], 0)
			binary.BigEndian.PutUint16(message[2:], checksum(message[:n]))
		}
		sock.WriteTo(message[:n], to)
	}
}

// checksum returns the Internet checksum of b.
func checksum(b []byte) uint16 {
	var sum uint32
	for ; len(b) >= 2; b = b[2:] {
		sum += uint32(binary.BigEndian.Uint16(b))
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

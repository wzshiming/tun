package tun

import (
	"context"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
)

type ListenPacket interface {
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func (t *Tun) HandleTCPConn(id stack.TransportEndpointID, conn *gonet.TCPConn) {
	go t.handleTCPConn(id, conn)
}

func (t *Tun) HandleUDPConn(id stack.TransportEndpointID, conn *gonet.UDPConn) {
	go t.handleUDPConn(id, conn)
}

func (t *Tun) handleTCPConn(id stack.TransportEndpointID, localConn *gonet.TCPConn) {
	defer localConn.Close()

	remote := &net.TCPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
	}

	targetConn, err := t.Dialer.DialContext(context.Background(), "tcp", remote.String())
	if err != nil {
		if t.Logger != nil {
			t.Logger.Println("dial error", err)
		}
		return
	}

	var buf1, buf2 []byte
	if t.BytesPool != nil {
		buf1 = t.BytesPool.Get()
		buf2 = t.BytesPool.Get()
		defer func() {
			t.BytesPool.Put(buf1)
			t.BytesPool.Put(buf2)
		}()
	} else {
		buf1 = make([]byte, 32*1024)
		buf2 = make([]byte, 32*1024)
	}
	tunnel(context.Background(), localConn, targetConn, buf1, buf2)
}

func (t *Tun) handleUDPConn(id stack.TransportEndpointID, uc *gonet.UDPConn) {
	defer uc.Close()

	remote := &net.UDPAddr{
		IP:   net.IP(id.LocalAddress),
		Port: int(id.LocalPort),
	}

	pc, err := t.ListenPacket.ListenPacket(context.Background(), "udp", ":0")
	if err != nil {
		if t.Logger != nil {
			t.Logger.Println("UDP listen error:", err)
		}
		return
	}

	go t.handleUDPToRemote(uc, pc, remote)
	t.handleUDPToLocal(uc, pc, remote)
}

func (t *Tun) handleUDPToRemote(uc *gonet.UDPConn, pc net.PacketConn, remote net.Addr) {
	var buf []byte
	if t.BytesPool != nil {
		buf = t.BytesPool.Get()
		defer func() {
			t.BytesPool.Put(buf)
		}()
	} else {
		buf = make([]byte, 32*1024)
	}

	for {
		n, err := uc.Read(buf)
		if err != nil {
			return
		}

		if _, err := pc.WriteTo(buf[:n], remote); err != nil {
			if t.Logger != nil {
				t.Logger.Println("UDP write to remote error:", err)
			}
		}
	}
}

func (t *Tun) handleUDPToLocal(uc *gonet.UDPConn, pc net.PacketConn, remote net.Addr) {
	var buf []byte
	if t.BytesPool != nil {
		buf = t.BytesPool.Get()
		defer func() {
			t.BytesPool.Put(buf)
		}()
	} else {
		buf = make([]byte, 32*1024)
	}

	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if t.Logger != nil {
				t.Logger.Println("UDP read from remote error:", err)
			}
			return
		}

		if from.Network() != remote.Network() || from.String() != remote.String() {
			if t.Logger != nil {
				t.Logger.Println("drop unknown packet from", from)
			}
			return
		}

		if _, err := uc.Write(buf[:n]); err != nil {
			if t.Logger != nil {
				t.Logger.Println("UDP write back from error:", err)
			}
			return
		}
	}
}

package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func TestServeNilHandlerAnswersUDPWithPortUnreachable(t *testing.T) {
	env := testServeWith(t, Options{Addresses: testAddresses}, func(*fakeDialer) Handler { return nil })
	conn := env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "not dns")
	err := testUDPError(t, env, conn, testWait)
	if want := (&tcpip.ErrConnectionRefused{}).String(); !strings.Contains(err.Error(), want) {
		t.Fatalf("client Read() error = %v, want %q from ICMP port unreachable", err, want)
	}
	if n := env.dev.unreachable.Load(); n == 0 {
		t.Fatal("Serve with a nil handler wrote no ICMP destination unreachable for UDP to port 1234")
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for UDP to port 1234: %+v, want no dial", dials)
	}
}

func TestUDPWithoutHandlerIsDropped(t *testing.T) {
	env := testServeWith(t, Options{Addresses: testAddresses}, func(d *fakeDialer) Handler {
		m := NewMux()
		m.Handle("tcp", 0, &Relay{Dialer: d})
		m.Handle("udp", 53, &DNS{Dialer: d})
		return m
	})
	conn := env.dialUDP(t, "10.0.0.9:1234")
	testSend(t, conn, "not dns")
	var netErr net.Error
	if err := testUDPError(t, env, conn, testSilence); !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("client Read() from 10.0.0.9:1234 = %v, want a timeout with no reply and no ICMP error", err)
	}
	if n := env.dev.unreachable.Load(); n != 0 {
		t.Fatalf("Serve wrote %d ICMP destination unreachable for UDP to port 1234, want the datagram dropped", n)
	}
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for UDP to port 1234: %+v, want no dial", dials)
	}
}

// testUDPError reads conn until an error other than a timeout, or the timeout once within has passed; a datagram read fails t.
func testUDPError(t *testing.T, env *testEnv, conn net.Conn, within time.Duration) error {
	t.Helper()
	// A blocked gonet Read does not wake for the ICMP error, so poll with short deadlines.
	reply := make([]byte, 512)
	for start := time.Now(); ; {
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		n, err := conn.Read(reply)
		if err == nil {
			t.Fatalf("client read %q from %v, want no reply", reply[:n], conn.RemoteAddr())
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() || time.Since(start) > within {
			return err
		}
		if returned := env.returned(); returned != "" {
			t.Fatalf("client read from %v ended early%s", conn.RemoteAddr(), returned)
		}
	}
}

func testSend(t *testing.T, conn net.Conn, datagram string) {
	t.Helper()
	if _, err := io.WriteString(conn, datagram); err != nil {
		t.Fatalf("client send %q: %v", datagram, err)
	}
}

// udpFamilies are, per IP family, the client's address, two targets and a source the client never sends to.
var udpFamilies = []struct {
	name                  string
	client                netip.Addr
	first, second, unseen netip.AddrPort
	maxDatagram           int
}{
	{"ipv4", testClient4, netip.MustParseAddrPort("10.0.0.9:5000"), netip.MustParseAddrPort("10.0.0.10:6000"), netip.MustParseAddrPort("10.0.0.77:7777"), 65507},
	{"ipv6", testClient6, netip.MustParseAddrPort("[fd00::9]:5000"), netip.MustParseAddrPort("[fd00::a]:6000"), netip.MustParseAddrPort("[fd00::77]:7777"), 65527},
}

// udpRead is one datagram a handler read, or the error reading it.
type udpRead struct {
	payload string
	from    netip.AddrPort
	err     error
}

// udpSessionServe serves handle as the udp fallback and counts its ServeFlow calls.
func udpSessionServe(t *testing.T, handle func(context.Context, Flow)) (*testEnv, *atomic.Int32) {
	t.Helper()
	served := new(atomic.Int32)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 0, HandlerFunc(func(ctx context.Context, f Flow) {
			served.Add(1)
			handle(ctx, f)
		}))
	})
	return env, served
}

// udpReadFrom reads one datagram from an accepted conn as a net.PacketConn.
func udpReadFrom(conn net.Conn) udpRead {
	pc, ok := conn.(net.PacketConn)
	if !ok {
		return udpRead{err: fmt.Errorf("accepted conn %T is not a net.PacketConn", conn)}
	}
	buf := make([]byte, 65535)
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		return udpRead{err: err}
	}
	return udpRead{payload: string(buf[:n]), from: udpAddrPort(addr)}
}

func udpAddrPort(addr net.Addr) netip.AddrPort {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}
	}
	ap := udpAddr.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

func testSendTo(t *testing.T, conn *gonet.UDPConn, datagram []byte, to netip.AddrPort) {
	t.Helper()
	if _, err := conn.WriteTo(datagram, net.UDPAddrFromAddrPort(to)); err != nil {
		t.Fatalf("client send a %d-byte datagram to %v: %v", len(datagram), to, err)
	}
}

// testRecvFrom reads one datagram on an unconnected client socket.
func testRecvFrom(t *testing.T, conn *gonet.UDPConn) udpRead {
	t.Helper()
	buf := make([]byte, 65535)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("client ReadFrom: %v", err)
	}
	return udpRead{payload: string(buf[:n]), from: udpAddrPort(addr)}
}

func testReceive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testWait):
		t.Fatalf("%s did not happen within %v", what, testWait)
		panic("unreachable")
	}
}

func TestUDPSessionCarriesEveryTargetOfOneClientSocket(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			type session struct {
				target, client netip.AddrPort
				reads          []udpRead
			}
			sessions := make(chan session, 4)
			env, served := udpSessionServe(t, func(_ context.Context, f Flow) {
				s := session{target: f.Target(), client: f.Client()}
				conn, err := f.Accept()
				if err != nil {
					return
				}
				conn.SetReadDeadline(time.Now().Add(testWait))
				for range 2 {
					s.reads = append(s.reads, udpReadFrom(conn))
				}
				sessions <- s
			})
			conn := env.listenUDP(t, fam.client)
			testSendTo(t, conn, []byte("first"), fam.first)
			testSendTo(t, conn, []byte("second"), fam.second)
			got := testReceive(t, sessions, "a session reading two datagrams")
			want := session{target: fam.first, client: udpAddrPort(conn.LocalAddr()), reads: []udpRead{{"first", fam.first, nil}, {"second", fam.second, nil}}}
			if fmt.Sprint(got) != fmt.Sprint(want) {
				t.Fatalf("session = %+v, want %+v", got, want)
			}
			if n := served.Load(); n != 1 {
				t.Fatalf("ServeFlow called %d times for one client socket sending to two targets, want once", n)
			}
		})
	}
}

func TestUDPSessionReadAndWriteAreTheConnectedView(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			reads := make(chan string, 2)
			env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
				conn, err := f.Accept()
				if err != nil {
					return
				}
				conn.SetReadDeadline(time.Now().Add(testWait))
				buf := make([]byte, 512)
				for range 2 {
					n, err := conn.Read(buf)
					if err != nil {
						reads <- err.Error()
						return
					}
					reads <- string(buf[:n])
				}
				conn.Write([]byte("reply"))
			})
			conn := env.listenUDP(t, fam.client)
			testSendTo(t, conn, []byte("first"), fam.first)
			testSendTo(t, conn, []byte("second"), fam.second)
			for _, want := range []string{"first", "second"} {
				if got := testReceive(t, reads, "handler Read"); got != want {
					t.Fatalf("handler Read() = %q, want %q", got, want)
				}
			}
			if got, want := testRecvFrom(t, conn), (udpRead{"reply", fam.first, nil}); got != want {
				t.Fatalf("client got %+v after the handler's Write, want %+v from Target()", got, want)
			}
		})
	}
}

func TestUDPSessionWriteToDeliversFromAnySource(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			errs := make(chan error, 1)
			env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
				conn, err := f.Accept()
				if err != nil {
					errs <- err
					return
				}
				conn.SetReadDeadline(time.Now().Add(testWait))
				udpReadFrom(conn)
				_, err = conn.(net.PacketConn).WriteTo([]byte("from unseen"), net.UDPAddrFromAddrPort(fam.unseen))
				errs <- err
			})
			conn := env.listenUDP(t, fam.client)
			testSendTo(t, conn, []byte("open"), fam.first)
			if err := testReceive(t, errs, "handler WriteTo"); err != nil {
				t.Fatalf("WriteTo(_, %v) = %v, want nil", fam.unseen, err)
			}
			if got, want := testRecvFrom(t, conn), (udpRead{"from unseen", fam.unseen, nil}); got != want {
				t.Fatalf("client got %+v, want %+v", got, want)
			}
		})
	}
}

// udpFixWriteFrom opens a session from client fam and returns the client socket and the error of the handler's WriteTo from src.
func udpFixWriteFrom(t *testing.T, fam netip.Addr, src netip.AddrPort) (*gonet.UDPConn, error) {
	t.Helper()
	errs := make(chan error, 1)
	env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			errs <- err
			return
		}
		conn.SetReadDeadline(time.Now().Add(testWait))
		udpReadFrom(conn)
		_, err = conn.(net.PacketConn).WriteTo([]byte("from "+src.String()), net.UDPAddrFromAddrPort(src))
		errs <- err
	})
	conn := env.listenUDP(t, fam)
	first := udpFamilies[0].first
	if fam.Is6() {
		first = udpFamilies[1].first
	}
	testSendTo(t, conn, []byte("open"), first)
	return conn, testReceive(t, errs, "handler WriteTo")
}

func TestUDPSessionWriteToFromIPv4MappedSourceDeliversPlainIPv4(t *testing.T) {
	src := netip.MustParseAddrPort("[::ffff:10.0.0.77]:7777")
	conn, err := udpFixWriteFrom(t, testClient4, src)
	if err != nil {
		t.Fatalf("WriteTo(_, %v) to an IPv4 client = %v, want nil", src, err)
	}
	if got, want := testRecvFrom(t, conn), (udpRead{"from " + src.String(), netip.MustParseAddrPort("10.0.0.77:7777"), nil}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
}

func TestUDPSessionWriteToFromIPv4MappedSourceToIPv6ClientFails(t *testing.T) {
	src := netip.MustParseAddrPort("[::ffff:10.0.0.77]:7777")
	if _, err := udpFixWriteFrom(t, testClient6, src); err == nil {
		t.Fatalf("WriteTo(_, %v) to an IPv6 client = nil error, want a wrong-family error", src)
	}
}

func TestUDPSessionWriteToFromUnspecifiedSourceFails(t *testing.T) {
	for _, tc := range []struct {
		client netip.Addr
		src    netip.AddrPort
	}{
		{testClient4, netip.MustParseAddrPort("0.0.0.0:7777")},
		{testClient6, netip.MustParseAddrPort("[::]:7777")},
	} {
		t.Run(tc.src.String(), func(t *testing.T) {
			if _, err := udpFixWriteFrom(t, tc.client, tc.src); err == nil {
				t.Fatalf("WriteTo(_, %v) = nil error, want an error for an unspecified source", tc.src)
			}
		})
	}
}

func TestUDPSessionWriteToCarriesLargestDatagramAndRejectsLarger(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			errs := make(chan error, 2)
			env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
				conn, err := f.Accept()
				if err != nil {
					errs <- err
					return
				}
				conn.SetReadDeadline(time.Now().Add(testWait))
				udpReadFrom(conn)
				pc, src := conn.(net.PacketConn), net.UDPAddrFromAddrPort(fam.unseen)
				_, err = pc.WriteTo(udpRelayDatagram(fam.maxDatagram+1, 3), src)
				errs <- err
				_, err = pc.WriteTo(udpRelayDatagram(fam.maxDatagram, 4), src)
				errs <- err
			})
			conn := env.listenUDP(t, fam.client)
			testSendTo(t, conn, []byte("open"), fam.first)
			if err := testReceive(t, errs, "handler WriteTo"); err == nil {
				t.Fatalf("WriteTo of a %d-byte datagram = nil error, want an error above the %d-byte maximum", fam.maxDatagram+1, fam.maxDatagram)
			}
			if err := testReceive(t, errs, "handler WriteTo"); err != nil {
				t.Fatalf("WriteTo of a %d-byte datagram = %v, want nil", fam.maxDatagram, err)
			}
			got := testRecvFrom(t, conn)
			if got.from != fam.unseen || got.payload != string(udpRelayDatagram(fam.maxDatagram, 4)) {
				t.Fatalf("client got %d bytes from %v, want the handler's %d bytes from %v", len(got.payload), got.from, fam.maxDatagram, fam.unseen)
			}
		})
	}
}

func TestUDPSessionReadDeadlineTimesOutAndCanBeExtended(t *testing.T) {
	reads := make(chan udpRead, 3)
	env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(testWait))
		reads <- udpReadFrom(conn)
		conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		reads <- udpReadFrom(conn)
		conn.SetReadDeadline(time.Now().Add(testWait))
		reads <- udpReadFrom(conn)
	})
	fam := udpFamilies[0]
	conn := env.listenUDP(t, fam.client)
	testSendTo(t, conn, []byte("first"), fam.first)
	testReceive(t, reads, "first ReadFrom")
	var netErr net.Error
	if got := testReceive(t, reads, "ReadFrom past its deadline"); !errors.As(got.err, &netErr) || !netErr.Timeout() {
		t.Fatalf("ReadFrom with a 50ms deadline and nothing queued = %+v, want a timeout", got)
	}
	testSendTo(t, conn, []byte("second"), fam.second)
	if got, want := testReceive(t, reads, "ReadFrom after extending the deadline"), (udpRead{"second", fam.second, nil}); got != want {
		t.Fatalf("ReadFrom after extending the deadline = %+v, want %+v", got, want)
	}
}

// udpFixQueued returns a session conn outside any stack with n datagrams queued, so a read racing them against another wake-up shows within n reads.
func udpFixQueued(n int) *udpConn {
	c := &udpConn{
		queue:        make(chan datagram, n),
		readDeadline: deadline{passed: make(chan struct{})},
		closed:       make(chan struct{}),
		onClose:      func() {},
	}
	for range n {
		c.queue <- datagram{payload: []byte("queued"), target: udpFamilies[0].first}
	}
	return c
}

func TestUDPSessionReadFromAfterCloseReturnsErrClosed(t *testing.T) {
	c := udpFixQueued(64)
	c.Close()
	for i := range 64 {
		if _, _, err := c.ReadFrom(make([]byte, 512)); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom %d after Close with datagrams queued = %v, want net.ErrClosed", i+1, err)
		}
	}
}

func TestUDPSessionReadFromPastDeadlineTimesOutWithDatagramQueued(t *testing.T) {
	c := udpFixQueued(64)
	c.SetReadDeadline(time.Now().Add(-time.Second))
	for i := range 64 {
		_, _, err := c.ReadFrom(make([]byte, 512))
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			t.Fatalf("ReadFrom %d past its deadline with datagrams queued = %v, want a timeout net.Error", i+1, err)
		}
	}
}

func TestUDPSessionClosedByHandlerFreesClientEndpoint(t *testing.T) {
	release := make(chan struct{})
	env, served := udpSessionServe(t, func(_ context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			return
		}
		conn.Close()
		<-release
	})
	// Cleanups run last first, so this one releases the handlers before Serve is stopped.
	t.Cleanup(func() { close(release) })
	conn := env.dialUDP(t, "10.0.0.9:5000")
	for deadline := time.Now().Add(testWait); served.Load() < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("ServeFlow called %d times within %v while the first handler, its conn closed, still runs; want the next datagram to start a session", served.Load(), testWait)
		}
		testSend(t, conn, "datagram")
	}
}

func TestUDPSessionRejectedByMuxIsRemoved(t *testing.T) {
	reads := make(chan udpRead, 4)
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 5353, HandlerFunc(func(_ context.Context, f Flow) {
			conn, err := f.Accept()
			if err != nil {
				return
			}
			conn.SetReadDeadline(time.Now().Add(testWait))
			reads <- udpReadFrom(conn)
		}))
	})
	fam := udpFamilies[0]
	conn := env.listenUDP(t, fam.client)
	testSendTo(t, conn, []byte("unhandled"), netip.MustParseAddrPort("10.0.0.9:1234"))
	handled := netip.MustParseAddrPort("10.0.0.9:5353")
	for deadline := time.Now().Add(testWait); ; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("no session served the client's datagrams to %v within %v of its rejected session", handled, testWait)
		}
		testSendTo(t, conn, []byte("handled"), handled)
		select {
		case got := <-reads:
			if want := (udpRead{"handled", handled, nil}); got != want {
				t.Fatalf("udp/5353 handler read %+v, want %+v", got, want)
			}
			if n := env.dev.unreachable.Load(); n != 0 {
				t.Fatalf("Serve wrote %d ICMP destination unreachable, want none", n)
			}
			return
		default:
		}
	}
}

func TestUDPSessionQueueDropsNewDatagramsBeyond128(t *testing.T) {
	const sent = 128 + 10
	accepted := make(chan net.Conn, 1)
	release := make(chan struct{})
	env := testServeMux(t, func(m *Mux) {
		m.Handle("udp", 0, HandlerFunc(func(_ context.Context, f Flow) {
			if conn, err := f.Accept(); err == nil {
				accepted <- conn
			}
			<-release
		}))
		m.Handle("tcp", 0, HandlerFunc(func(_ context.Context, f Flow) {
			if conn, err := f.Accept(); err == nil {
				io.Copy(conn, conn)
			}
		}))
	})
	t.Cleanup(func() { close(release) })
	fam := udpFamilies[0]
	conn := env.listenUDP(t, fam.client)
	for i := range sent {
		testSendTo(t, conn, []byte(fmt.Sprint(i)), fam.first)
	}
	// The stack handles packets in order, so an echo through it after the burst shows the burst handled without blocking.
	echo := env.dialTCP(t, "10.0.0.9:7")
	testRelay(t, echo, echo, "echo")
	session := testReceive(t, accepted, "the session's Accept")
	var got []string
	for {
		session.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		read := udpReadFrom(session)
		if read.err != nil {
			break
		}
		got = append(got, read.payload)
	}
	if len(got) == 0 || len(got) > 128 {
		t.Fatalf("session queued %d of %d datagrams sent while its handler did not read, want between 1 and 128", len(got), sent)
	}
	for i, payload := range got {
		if payload != fmt.Sprint(i) {
			t.Fatalf("queued datagram %d is %q, want %q: a full queue must drop the new datagrams", i, payload, fmt.Sprint(i))
		}
	}
}

func TestUDPDatagramWithBadChecksumIsDropped(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			reads := make(chan udpRead, 4)
			env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
				conn, err := f.Accept()
				if err != nil {
					return
				}
				conn.SetReadDeadline(time.Now().Add(testWait))
				reads <- udpReadFrom(conn)
			})
			client := netip.AddrPortFrom(fam.client, 4444)
			env.dev.inject(testUDPPacket(client, fam.first, "bad", true))
			select {
			case got := <-reads:
				t.Fatalf("a datagram with a bad UDP checksum reached a session as %+v, want it dropped", got)
			case <-time.After(testSilence):
			}
			env.dev.inject(testUDPPacket(client, fam.first, "good", false))
			if got, want := testReceive(t, reads, "the valid datagram's session read"), (udpRead{"good", fam.first, nil}); got != want {
				t.Fatalf("session read %+v, want %+v", got, want)
			}
		})
	}
}

// testUDPPacket builds an IP packet carrying payload from src to dst, its UDP checksum wrong when corrupt.
func testUDPPacket(src, dst netip.AddrPort, payload string, corrupt bool) []byte {
	srcAddr, dstAddr := tcpip.AddrFromSlice(src.Addr().AsSlice()), tcpip.AddrFromSlice(dst.Addr().AsSlice())
	udpLen := header.UDPMinimumSize + len(payload)
	var packet []byte
	var segment header.UDP
	if src.Addr().Is4() {
		packet = make([]byte, header.IPv4MinimumSize+udpLen)
		ip := header.IPv4(packet)
		ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(packet)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: srcAddr, DstAddr: dstAddr})
		ip.SetChecksum(^ip.CalculateChecksum())
		segment = header.UDP(packet[header.IPv4MinimumSize:])
	} else {
		packet = make([]byte, header.IPv6MinimumSize+udpLen)
		header.IPv6(packet).Encode(&header.IPv6Fields{PayloadLength: uint16(udpLen), TransportProtocol: header.UDPProtocolNumber, HopLimit: 64, SrcAddr: srcAddr, DstAddr: dstAddr})
		segment = header.UDP(packet[header.IPv6MinimumSize:])
	}
	copy(segment[header.UDPMinimumSize:], payload)
	segment.Encode(&header.UDPFields{SrcPort: src.Port(), DstPort: dst.Port(), Length: uint16(udpLen)})
	xsum := ^segment.CalculateChecksum(checksum.Combine(
		header.PseudoHeaderChecksum(header.UDPProtocolNumber, srcAddr, dstAddr, uint16(udpLen)),
		checksum.Checksum([]byte(payload), 0)))
	if corrupt {
		xsum ^= 0x5a5a
	}
	segment.SetChecksum(xsum)
	return packet
}

func TestServeCancelWakesUDPHandlerBlockedInReadFrom(t *testing.T) {
	blocked := make(chan struct{})
	env, _ := udpSessionServe(t, func(_ context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			return
		}
		udpReadFrom(conn)
		close(blocked)
		udpReadFrom(conn)
	})
	testSend(t, env.dialUDP(t, "10.0.0.9:5000"), "open")
	testReceive(t, blocked, "the handler's first ReadFrom")
	start := time.Now()
	env.cancel()
	env.wait(t)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Serve took %v to return with a handler blocked in ReadFrom, want under 1s", elapsed)
	}
}

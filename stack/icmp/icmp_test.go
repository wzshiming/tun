package icmp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
)

// testWait bounds every wait for something that must happen.
const testWait = 10 * time.Second

// testQuiet is how long a client waits before concluding no reply comes.
const testQuiet = 300 * time.Millisecond

// icmpFamilies are, per IP family, the client, the target pinged, another host, and the echo request and reply types.
var icmpFamilies = []struct {
	name                  string
	client, target, other netip.Addr
	request, reply        byte
}{
	{"ipv4", netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.10"), 8, 0},
	{"ipv6", netip.MustParseAddr("fd00::2"), netip.MustParseAddr("fd00::9"), netip.MustParseAddr("fd00::a"), 128, 129},
}

// packet is one message a fake socket sent or is to receive, and its peer.
type packet struct {
	message []byte
	peer    net.Addr
}

// fakeSocket is a socket's PacketConn whose sent messages the test takes and whose received ones it supplies.
type fakeSocket struct {
	net.PacketConn
	sent, received chan packet
	closed         chan struct{}
	closeOnce      sync.Once
}

func (s *fakeSocket) WriteTo(b []byte, addr net.Addr) (int, error) {
	select {
	case s.sent <- packet{bytes.Clone(b), addr}:
		return len(b), nil
	case <-s.closed:
		return 0, net.ErrClosed
	}
}

func (s *fakeSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case p := <-s.received:
		return copy(b, p.message), p.peer, nil
	case <-s.closed:
		return 0, nil, net.ErrClosed
	}
}

func (s *fakeSocket) Close() error {
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

// testEnv is one ServeFlow of a Handler on an "icmp" flow whose conn is one end of a pipe and whose socket is a fake.
type testEnv struct {
	flow   *stacktest.Flow
	client net.Conn
	socket *fakeSocket
	// opened receives the family of each socket the handler opened.
	opened chan bool
	cancel context.CancelFunc
	done   chan struct{}
}

// testServe serves h a flow of network from client to target, on a socket of the given kind.
func testServe(t *testing.T, h *Handler, network string, client, target netip.Addr, datagram, kernelIdent bool) *testEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served, ours := net.Pipe()
	env := &testEnv{
		client: ours,
		socket: &fakeSocket{sent: make(chan packet, 64), received: make(chan packet, 64), closed: make(chan struct{})},
		opened: make(chan bool, 1),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	env.flow = stacktest.NewFlow(network, netip.AddrPortFrom(client, 0x1234), netip.AddrPortFrom(target, 0), served)
	h.open = func(_ context.Context, ipv6 bool) (*socket, error) {
		env.opened <- ipv6
		return &socket{PacketConn: env.socket, datagram: datagram, kernelIdent: kernelIdent}, nil
	}
	go func() {
		defer close(env.done)
		h.ServeFlow(ctx, env.flow)
	}()
	t.Cleanup(func() {
		cancel()
		ours.Close()
		env.returned(t, testWait)
	})
	return env
}

// returned fails unless ServeFlow returns within wait.
func (env *testEnv) returned(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case <-env.done:
	case <-time.After(wait):
		t.Fatalf("ServeFlow did not return within %v", wait)
	}
}

// echo returns an echo message of the given type under the client's identifier 0x1234, with seq and payload and no checksum.
func echo(kind byte, seq uint16, payload string) []byte {
	message := append([]byte{kind, 0, 0, 0, 0x12, 0x34, 0, 0}, payload...)
	binary.BigEndian.PutUint16(message[6:], seq)
	return message
}

// request sends an echo request from the client and returns it as the socket sent it.
func (env *testEnv) request(t *testing.T, message []byte) packet {
	t.Helper()
	env.client.SetWriteDeadline(time.Now().Add(testWait))
	if _, err := env.client.Write(message); err != nil {
		t.Fatalf("client echo request: %v", err)
	}
	select {
	case p := <-env.socket.sent:
		return p
	case <-time.After(testWait):
		t.Fatalf("the socket sent nothing within %v of the client's echo request", testWait)
		panic("unreachable")
	}
}

// reply returns the next message delivered to the client within wait, or nil.
func (env *testEnv) reply(wait time.Duration) []byte {
	env.client.SetReadDeadline(time.Now().Add(wait))
	message := make([]byte, 65535)
	n, err := env.client.Read(message)
	if err != nil {
		return nil
	}
	return message[:n]
}

func TestHandlerRelaysEchoRequestsAndTheirReplies(t *testing.T) {
	for _, fam := range icmpFamilies {
		for _, kind := range []struct {
			name     string
			datagram bool
		}{{"raw", false}, {"datagram", true}} {
			t.Run(fam.name+"/"+kind.name, func(t *testing.T) {
				env := testServe(t, &Handler{}, "icmp", fam.client, fam.target, kind.datagram, false)
				sent := env.request(t, echo(fam.request, 7, "payload"))
				if ipv6 := <-env.opened; ipv6 != fam.target.Is6() {
					t.Fatalf("handler opened an IPv6 socket = %v for target %v", ipv6, fam.target)
				}
				if !env.flow.Accepted() {
					t.Fatal("flow not accepted once its socket was open")
				}
				if _, isUDP := sent.peer.(*net.UDPAddr); isUDP != kind.datagram || addrOf(sent.peer) != fam.target {
					t.Fatalf("echo request sent to %T %v, want the target %v addressed as the socket's kind", sent.peer, sent.peer, fam.target)
				}
				ident := binary.BigEndian.Uint16(sent.message[4:])
				if sent.message[0] != fam.request || ident == 0x1234 || binary.BigEndian.Uint16(sent.message[6:]) != 7 || string(sent.message[headerSize:]) != "payload" {
					t.Fatalf("socket sent % x, want the echo request with sequence 7 and its payload under the handler's identifier", sent.message)
				}
				if sum := checksum(sent.message); !fam.target.Is6() && sum != 0 {
					t.Fatalf("ICMPv4 echo request sent with a checksum off by %#x, want it valid", sum)
				}

				reply := echo(fam.reply, 7, "payload")
				binary.BigEndian.PutUint16(reply[4:], ident)
				foreign := bytes.Clone(reply)
				binary.BigEndian.PutUint16(foreign[4:], ident+1)
				request := bytes.Clone(reply)
				request[0] = fam.request
				env.socket.received <- packet{foreign, sent.peer}
				env.socket.received <- packet{reply, env.socket.addrOf(kind.datagram, fam.other)}
				env.socket.received <- packet{request, sent.peer}
				env.socket.received <- packet{reply[:4], sent.peer}
				if got := env.reply(testQuiet); got != nil {
					t.Fatalf("client got % x, want another session's reply, another host's, an echo request and a short message all dropped", got)
				}
				env.socket.received <- packet{reply, sent.peer}
				if got := env.reply(testWait); !bytes.Equal(got, reply) {
					t.Fatalf("client got % x, want the target's echo reply % x", got, reply)
				}
			})
		}
	}
}

func (s *fakeSocket) addrOf(datagram bool, ip netip.Addr) net.Addr {
	return (&socket{datagram: datagram}).addr(ip)
}

func TestHandlerTakesEveryReplyOfAKernelIdentSocket(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServe(t, &Handler{}, "icmp", fam.client, fam.target, true, true)
	sent := env.request(t, echo(fam.request, 1, "x"))
	// The kernel replaced the identifier the handler wrote and delivers only this socket's replies.
	reply := echo(fam.reply, 1, "x")
	binary.BigEndian.PutUint16(reply[4:], 0xbeef)
	env.socket.received <- packet{reply, sent.peer}
	if got := env.reply(testWait); !bytes.Equal(got, reply) {
		t.Fatalf("client got % x, want the reply % x whatever its identifier", got, reply)
	}
}

func TestHandlerGivesEachSessionItsOwnIdentifier(t *testing.T) {
	fam, h := icmpFamilies[0], &Handler{}
	seen := make(map[uint16]bool)
	for range 3 {
		// Each env replaces h.open, so the sessions are served one after another.
		env := testServe(t, h, "icmp", fam.client, fam.target, false, false)
		sent := env.request(t, echo(fam.request, 1, "x"))
		env.cancel()
		env.returned(t, testWait)
		ident := binary.BigEndian.Uint16(sent.message[4:])
		if seen[ident] {
			t.Fatalf("two sessions sent their echo requests under identifier %d, want each its own", ident)
		}
		seen[ident] = true
	}
}

func TestHandlerRejectsOtherNetworks(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServe(t, &Handler{}, "udp", fam.client, fam.target, false, false)
	env.returned(t, testWait)
	if !env.flow.Rejected() || len(env.opened) != 0 {
		t.Fatalf("udp flow rejected = %v with %d sockets opened, want it rejected with none", env.flow.Rejected(), len(env.opened))
	}
}

func TestHandlerRejectsTheFlowWhenNoSocketOpens(t *testing.T) {
	for _, fam := range icmpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			refused := errors.New("control refused")
			var mu sync.Mutex
			var networks []string
			h := &Handler{ListenConfig: &net.ListenConfig{Control: func(network, _ string, _ syscall.RawConn) error {
				mu.Lock()
				defer mu.Unlock()
				networks = append(networks, network)
				return refused
			}}}
			served, ours := net.Pipe()
			defer ours.Close()
			flow := stacktest.NewFlow("icmp", netip.AddrPortFrom(fam.client, 1), netip.AddrPortFrom(fam.target, 0), served)
			h.ServeFlow(context.Background(), flow)
			if !flow.Rejected() {
				t.Fatal("flow not rejected though its ListenConfig's Control refuses every socket")
			}
			want := "ip4"
			if fam.target.Is6() {
				want = "ip6"
			}
			for _, network := range networks {
				if network != want {
					t.Errorf("Control ran for network %q, want only %q", network, want)
				}
			}
		})
	}
}

func TestHandlerEndsAnIdleSession(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServe(t, &Handler{Idle: 200 * time.Millisecond}, "icmp", fam.client, fam.target, false, false)
	start := time.Now()
	env.request(t, echo(fam.request, 1, "x"))
	env.returned(t, testWait)
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("session ended %v after its last echo request, want it kept for the Idle of 200ms", elapsed)
	}
	select {
	case <-env.socket.closed:
	default:
		t.Fatal("ServeFlow returned without closing its socket")
	}
	if _, err := env.client.Write(echo(fam.request, 2, "x")); err == nil {
		t.Fatal("client wrote to the session's conn after ServeFlow returned, want it closed")
	}
}

func TestHandlerEndsWithItsContext(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServe(t, &Handler{}, "icmp", fam.client, fam.target, false, false)
	env.request(t, echo(fam.request, 1, "x"))
	env.cancel()
	env.returned(t, testWait)
	select {
	case <-env.socket.closed:
	default:
		t.Fatal("ServeFlow returned without closing its socket")
	}
}

func TestHandlerEndsWhenItsSocketFails(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServe(t, &Handler{}, "icmp", fam.client, fam.target, false, false)
	env.request(t, echo(fam.request, 1, "x"))
	env.socket.Close()
	env.returned(t, testWait)
}

// TestHandlerPingsLoopback relays an echo through the machine's own ICMP socket, where it may open one.
func TestHandlerPingsLoopback(t *testing.T) {
	for _, fam := range []struct {
		name           string
		target         netip.Addr
		request, reply byte
	}{{"ipv4", netip.MustParseAddr("127.0.0.1"), 8, 0}, {"ipv6", netip.MustParseAddr("::1"), 128, 129}} {
		t.Run(fam.name, func(t *testing.T) {
			h := &Handler{}
			sock, err := h.openSocket(context.Background(), fam.target.Is6())
			if err != nil {
				t.Skipf("no ICMP socket here: %v", err)
			}
			sock.Close()
			served, ours := net.Pipe()
			defer ours.Close()
			flow := stacktest.NewFlow("icmp", netip.AddrPortFrom(fam.target, 0x1234), netip.AddrPortFrom(fam.target, 0), served)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				h.ServeFlow(ctx, flow)
			}()
			defer func() {
				cancel()
				<-done
			}()
			ours.SetDeadline(time.Now().Add(testWait))
			if _, err := ours.Write(echo(fam.request, 42, "loopback")); err != nil {
				t.Fatalf("client echo request: %v", err)
			}
			reply := make([]byte, 65535)
			n, err := ours.Read(reply)
			if err != nil {
				t.Fatalf("no echo reply from %v within %v: %v", fam.target, testWait, err)
			}
			if reply[0] != fam.reply || binary.BigEndian.Uint16(reply[6:]) != 42 || string(reply[headerSize:n]) != "loopback" {
				t.Fatalf("client got % x, want the echo reply with sequence 42 carrying %q", reply[:n], "loopback")
			}
		})
	}
}

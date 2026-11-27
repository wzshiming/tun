package stack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// testSilence is how long an echo request must stay unanswered.
const testSilence = time.Second

// icmpFamilies are, per IP family, the client's address and two addresses it pings.
var icmpFamilies = []struct {
	name                   string
	client, other, another netip.Addr
}{
	{"ipv4", testClient4, netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr("10.0.0.10")},
	{"ipv6", testClient6, netip.MustParseAddr("fd00::9"), netip.MustParseAddr("fd00::a")},
}

// icmpEvent is what a testPong session saw: its flow, then each echo request it read or the error that ended it.
type icmpEvent struct {
	network        string
	target, client netip.AddrPort
	request        []byte
	err            error
}

// testPong returns a handler that accepts every flow and answers each echo request with its echo reply, written under a wrong identifier and checksum, reporting what it read on events.
func testPong(events chan<- icmpEvent) Handler {
	return HandlerFunc(func(_ context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			return
		}
		message := make([]byte, 65535)
		for {
			n, err := conn.Read(message)
			event := icmpEvent{network: f.Network(), target: f.Target(), client: f.Client(), request: append([]byte(nil), message[:n]...), err: err}
			select {
			case events <- event:
			default:
			}
			if err != nil {
				return
			}
			message[0] = byte(header.ICMPv4EchoReply)
			if f.Target().Addr().Is6() {
				message[0] = byte(header.ICMPv6EchoReply)
			}
			// The session must put its own checksum and identifier in place of these.
			copy(message[2:6], []byte{0xde, 0xad, 0xbe, 0xef})
			conn.Write(message[:n])
		}
	})
}

func TestICMPEchoWithoutHandlerStaysUnanswered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler Handler
	}{
		{"nil handler", nil},
		{"mux without icmp", func() Handler {
			m := NewMux()
			m.Handle("tcp", "", testEcho)
			m.Handle("udp", "", testEcho)
			return m
		}()},
		{"rejecting handler", HandlerFunc(func(_ context.Context, f Flow) { f.Reject() })},
	} {
		for _, fam := range icmpFamilies {
			t.Run(tc.name+"/"+fam.name, func(t *testing.T) {
				env := testServeWith(t, Options{}, tc.handler)
				if reply := testPing(t, env, fam.client, fam.other, testSilence); reply != nil {
					t.Fatalf("echo to %v was answered with % x, want it left without reply", fam.other, reply)
				}
			})
		}
	}
}

func TestICMPEchoFlowCarriesRequestsAndReplies(t *testing.T) {
	for _, fam := range icmpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			events := make(chan icmpEvent, 64)
			env := testServeWith(t, Options{}, testPong(events))
			reply := testPing(t, env, fam.client, fam.other, testWait)
			if reply == nil {
				t.Fatalf("echo to %v got no reply within %v, want the handler's", fam.other, testWait)
			}
			if got := string(reply[header.ICMPv4MinimumSize:]); got != "test" {
				t.Errorf("echo reply carries %q, want the request's payload %q", got, "test")
			}
			event := testReceive(t, events, "the handler reading an echo request")
			if event.err != nil || event.network != "icmp" || event.target != netip.AddrPortFrom(fam.other, 0) || event.client.Addr() != fam.client {
				t.Fatalf("handler was served %+v, want an icmp flow from %v to %v, port 0", event, fam.client, fam.other)
			}
			request := byte(header.ICMPv4Echo)
			if fam.other.Is6() {
				request = byte(header.ICMPv6EchoRequest)
			}
			if len(event.request) != header.ICMPv4MinimumSize+4 || event.request[0] != request || string(event.request[header.ICMPv4MinimumSize:]) != "test" {
				t.Fatalf("handler read % x, want the echo request message carrying %q", event.request, "test")
			}
			// The client's stack delivered the reply by its identifier, so the session wrote the client's.
			if ident := binary.BigEndian.Uint16(event.request[4:]); event.client.Port() != ident || binary.BigEndian.Uint16(reply[4:]) != ident {
				t.Errorf("flow client port = %d and reply identifier = %d, want both the request's identifier %d", event.client.Port(), binary.BigEndian.Uint16(reply[4:]), ident)
			}
		})
	}
}

func TestICMPSessionWriteTakesOnlyEchoReplies(t *testing.T) {
	for _, fam := range icmpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			type result struct {
				local, remote net.Addr
				errs          []error
			}
			results := make(chan result, 64)
			env := testServeWith(t, Options{}, HandlerFunc(func(_ context.Context, f Flow) {
				conn, err := f.Accept()
				if err != nil {
					return
				}
				message := make([]byte, 65535)
				n, err := conn.Read(message)
				if err != nil {
					return
				}
				r := result{local: conn.LocalAddr(), remote: conn.RemoteAddr()}
				// The echo request itself, a message cut short, and an echo reply of the other family.
				for _, b := range [][]byte{message[:n], message[:4], {byte(header.ICMPv4EchoReply) ^ byte(header.ICMPv6EchoReply) ^ replyType(fam.other), 0, 0, 0, 0, 0, 0, 1}} {
					_, err := conn.Write(b)
					r.errs = append(r.errs, err)
				}
				conn.Close()
				_, err = conn.Write([]byte{replyType(fam.other), 0, 0, 0, 0, 0, 0, 1})
				r.errs = append(r.errs, err)
				select {
				case results <- r:
				default:
				}
			}))
			if reply := testPing(t, env, fam.client, fam.other, testSilence); reply != nil {
				t.Fatalf("echo to %v was answered with % x, want none of the refused writes sent", fam.other, reply)
			}
			r := testReceive(t, results, "the handler writing to its session")
			for i, err := range r.errs[:3] {
				if err == nil || errors.Is(err, net.ErrClosed) {
					t.Errorf("Write %d of a message that is no echo reply = %v, want an error naming it", i+1, err)
				}
			}
			if !errors.Is(r.errs[3], net.ErrClosed) {
				t.Errorf("Write after Close = %v, want net.ErrClosed", r.errs[3])
			}
			if got, want := r.local.String()+" "+r.remote.String(), fam.other.String()+" "+fam.client.String(); got != want {
				t.Errorf("session LocalAddr and RemoteAddr = %s, want %s", got, want)
			}
		})
	}
}

func replyType(target netip.Addr) byte {
	if target.Is6() {
		return byte(header.ICMPv6EchoReply)
	}
	return byte(header.ICMPv4EchoReply)
}

func TestServeDispatchesICMPByAddress(t *testing.T) {
	for _, fam := range icmpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			events := make(chan icmpEvent, 64)
			env := testServeMux(t, func(m *Mux) { m.Handle("icmp", fam.other.String(), testPong(events)) })
			if testPing(t, env, fam.client, fam.other, testWait) == nil {
				t.Fatalf("echo to %v, registered on the Mux, got no reply within %v", fam.other, testWait)
			}
			if reply := testPing(t, env, fam.client, fam.another, testSilence); reply != nil {
				t.Fatalf("echo to %v, which no pattern matches, was answered with % x, want it rejected", fam.another, reply)
			}
		})
	}
}

func TestICMPSessionBeyondTheLimitEndsTheOneIdleLongest(t *testing.T) {
	events := make(chan icmpEvent, 1024)
	env := testServeWith(t, Options{MaxICMPSessions: 1}, testPong(events))
	fam := icmpFamilies[0]
	if testPing(t, env, fam.client, fam.other, testWait) == nil {
		t.Fatalf("echo to %v got no reply within %v", fam.other, testWait)
	}
	if testPing(t, env, fam.client, fam.another, testWait) == nil {
		t.Fatalf("echo to %v, a session beyond the limit of 1, got no reply within %v", fam.another, testWait)
	}
	for {
		event := testReceive(t, events, "the first session ending")
		if event.err == nil {
			continue
		}
		if event.target.Addr() != fam.other || !errors.Is(event.err, net.ErrClosed) {
			t.Fatalf("ended session = %+v, want the one to %v ended with net.ErrClosed", event, fam.other)
		}
		break
	}
	if got := (Options{}).maxICMPSessions(); got != 1024 {
		t.Errorf("default MaxICMPSessions = %d, want 1024", got)
	}
}

// testPing returns the first echo reply that echo requests from src to dst, carrying "test", get within wait, or nil.
func testPing(t *testing.T, env *testEnv, src, dst netip.Addr, wait time.Duration) []byte {
	t.Helper()
	conn, err := env.client.DialPingAddr(src, dst)
	if err != nil {
		t.Fatalf("client DialPingAddr(%v, %v): %v", src, dst, err)
	}
	request, reply := byte(header.ICMPv4Echo), byte(header.ICMPv4EchoReply)
	if dst.Is6() {
		request, reply = byte(header.ICMPv6EchoRequest), byte(header.ICMPv6EchoReply)
	}
	if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	replied := make(chan []byte, 1)
	reading := make(chan struct{})
	go func() {
		defer close(reading)
		message := make([]byte, testMTU)
		for {
			n, _, err := conn.ReadFrom(message)
			if err != nil {
				return
			}
			if n > 0 && message[0] == reply {
				replied <- message[:n]
				return
			}
		}
	}()
	defer func() {
		conn.Close()
		<-reading
	}()
	// PingConn.ReadFrom misses a reply that arrives before it waits, so keep sending until one is read.
	echo := []byte{request, 0, 0, 0, 0, 0, 0, 0, 't', 'e', 's', 't'}
	timeout := time.NewTimer(wait)
	defer timeout.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for seq := uint16(1); ; seq++ {
		binary.BigEndian.PutUint16(echo[6:], seq)
		if _, err := conn.Write(echo); err != nil {
			t.Fatalf("client echo request to %v: %v", dst, err)
		}
		select {
		case message := <-replied:
			return message
		case <-timeout.C:
			return nil
		case <-env.done:
			t.Fatalf("Serve returned %v while %v was being pinged", env.err, dst)
		case <-tick.C:
		}
	}
}

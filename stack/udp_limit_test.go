package stack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// udpLimitEvent is a datagram a session read, or the error that ended it.
type udpLimitEvent struct {
	client  netip.AddrPort
	payload string
	err     error
}

// udpLimitServe serves with at most limit UDP sessions; every session reports what it reads, and after reporting "hold" answers it from the datagram's target once release yields.
func udpLimitServe(t *testing.T, limit int) (env *testEnv, events <-chan udpLimitEvent, release chan<- struct{}) {
	t.Helper()
	reported, held := make(chan udpLimitEvent, 64), make(chan struct{})
	env = testServeWith(t, Options{MaxUDPSessions: limit}, HandlerFunc(func(ctx context.Context, f Flow) {
		conn, err := f.Accept()
		if err != nil {
			return
		}
		pc := conn.(net.PacketConn)
		buf := make([]byte, 2048)
		for {
			n, target, err := pc.ReadFrom(buf)
			if err != nil {
				reported <- udpLimitEvent{client: f.Client(), err: err}
				return
			}
			reported <- udpLimitEvent{client: f.Client(), payload: string(buf[:n])}
			if string(buf[:n]) == "hold" {
				select {
				case <-held:
					pc.WriteTo([]byte("reply"), target)
				case <-ctx.Done():
					return
				}
			}
		}
	}))
	return env, reported, held
}

var udpLimitTarget = netip.MustParseAddrPort("203.0.113.1:9000")

// udpLimitSend sends payload from conn and waits for its session to have read it.
func udpLimitSend(t *testing.T, events <-chan udpLimitEvent, conn *gonet.UDPConn, payload string) {
	t.Helper()
	testSendTo(t, conn, []byte(payload), udpLimitTarget)
	if got := testReceive(t, events, "the session reading "+payload); got.err != nil || got.payload != payload || got.client != udpAddrPort(conn.LocalAddr()) {
		t.Fatalf("session event = %+v, want %q read from %v", got, payload, conn.LocalAddr())
	}
}

func TestUDPSessionBeyondTheLimitEndsTheOneIdleLongest(t *testing.T) {
	env, events, _ := udpLimitServe(t, 2)
	a, b, c := env.listenUDP(t, testClient4), env.listenUDP(t, testClient4), env.listenUDP(t, testClient4)
	udpLimitSend(t, events, a, "a1")
	udpLimitSend(t, events, b, "b1")
	// a is now the session heard from last, so b is the idle one.
	udpLimitSend(t, events, a, "a2")
	testSendTo(t, c, []byte("c1"), udpLimitTarget)
	first, second := testReceive(t, events, "the third session's first event"), testReceive(t, events, "its second event")
	if first.err == nil {
		first, second = second, first
	}
	if first.client != udpAddrPort(b.LocalAddr()) || !errors.Is(first.err, net.ErrClosed) {
		t.Errorf("ended session = %+v, want the one of %v, idle longest, ended with net.ErrClosed", first, b.LocalAddr())
	}
	if second.client != udpAddrPort(c.LocalAddr()) || second.payload != "c1" {
		t.Errorf("new session read %+v, want c1 from %v", second, c.LocalAddr())
	}
	// The session that stayed still reads.
	udpLimitSend(t, events, a, "a3")
}

func TestUDPSessionAReplyWasSentToIsNotTheIdleOne(t *testing.T) {
	env, events, release := udpLimitServe(t, 2)
	a, b, c := env.listenUDP(t, testClient4), env.listenUDP(t, testClient4), env.listenUDP(t, testClient4)
	udpLimitSend(t, events, a, "hold")
	udpLimitSend(t, events, b, "b1")
	// By the datagrams it sent, a is the idle one; the reply it now gets makes that b.
	release <- struct{}{}
	if got := testRecvFrom(t, a); got.payload != "reply" || got.from != udpLimitTarget {
		t.Fatalf("client read %+v, want reply from %v", got, udpLimitTarget)
	}
	testSendTo(t, c, []byte("c1"), udpLimitTarget)
	first, second := testReceive(t, events, "the third session's first event"), testReceive(t, events, "its second event")
	if first.err == nil {
		first = second
	}
	if first.client != udpAddrPort(b.LocalAddr()) || !errors.Is(first.err, net.ErrClosed) {
		t.Errorf("ended session = %+v, want the one of %v, which had no datagram since a's reply", first, b.LocalAddr())
	}
}

func TestUDPSessionEndedForTheLimitStartsAgainOnItsNextDatagram(t *testing.T) {
	env, events, _ := udpLimitServe(t, 1)
	a, b := env.listenUDP(t, testClient4), env.listenUDP(t, testClient4)
	udpLimitSend(t, events, a, "a1")
	testSendTo(t, b, []byte("b1"), udpLimitTarget)
	for range 2 {
		if got := testReceive(t, events, "a ending or b reading"); got.err != nil {
			if got.client != udpAddrPort(a.LocalAddr()) {
				t.Fatalf("ended session = %+v, want the one of %v", got, a.LocalAddr())
			}
		} else if got.payload != "b1" {
			t.Fatalf("read %+v, want b1", got)
		}
	}
	testSendTo(t, a, []byte("a2"), udpLimitTarget)
	sawEnd, sawRead := false, false
	for range 2 {
		got := testReceive(t, events, "b ending or a reading again")
		switch {
		case got.err != nil && got.client == udpAddrPort(b.LocalAddr()):
			sawEnd = true
		case got.payload == "a2" && got.client == udpAddrPort(a.LocalAddr()):
			sawRead = true
		default:
			t.Fatalf("unexpected event %+v", got)
		}
	}
	if !sawEnd || !sawRead {
		t.Errorf("b ended = %v, a read again = %v; want both", sawEnd, sawRead)
	}
}

func TestUDPSessionsWithoutALimitAllStay(t *testing.T) {
	env, events, _ := udpLimitServe(t, -1)
	conns := make([]*gonet.UDPConn, 8)
	for i := range conns {
		conns[i] = env.listenUDP(t, testClient4)
		udpLimitSend(t, events, conns[i], "first")
	}
	for _, conn := range conns {
		udpLimitSend(t, events, conn, "second")
	}
	select {
	case got := <-events:
		t.Errorf("unexpected event %+v, want every session still live and silent", got)
	case <-time.After(testQuiet):
	}
}

func TestMaxUDPSessionsDefaultsTo4096(t *testing.T) {
	if got := (Options{}).maxUDPSessions(); got != 4096 {
		t.Errorf("default MaxUDPSessions = %d, want 4096", got)
	}
}

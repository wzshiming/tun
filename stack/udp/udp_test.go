package udp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestConeListensOnceAndRelaysEverySource(t *testing.T) {
	for _, fam := range udpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			h := &Handler{}
			listener, dialer := coneSetup(t, h)
			env := testServe(t, h, fam.client, fam.first)
			env.sendTo([]byte("to first"), fam.first)
			first := listener.nextCone(t, env)
			gotFirst, firstFrom := first.recvFrom(t)
			env.sendTo([]byte("to second"), fam.second)
			second := listener.nextCone(t, env)
			gotSecond, secondFrom := second.recvFrom(t)
			if first.addr != fam.first || string(gotFirst) != "to first" || second.addr != fam.second || string(gotSecond) != "to second" {
				t.Fatalf("targets got %v %q and %v %q, want %v %q and %v %q", first.addr, gotFirst, second.addr, gotSecond, fam.first, "to first", fam.second, "to second")
			}
			if firstFrom != secondFrom {
				t.Fatalf("targets received from %v and %v, want both from the session's one socket", firstFrom, secondFrom)
			}
			wantNetwork := map[string]string{"ipv4": "udp4", "ipv6": "udp6"}[fam.name]
			calls := listener.recorded()
			if len(calls) != 1 || calls[0].network != wantNetwork || calls[0].address != ":0" {
				t.Fatalf("ListenPacket calls %+v, want one (%q, %q)", calls, wantNetwork, ":0")
			}
			if got, want := calls[0].client, net.Addr(net.UDPAddrFromAddrPort(fam.client)); !sameAddr(got, want) {
				t.Fatalf("ClientAddr(ListenPacket ctx) = %T %v, want the client's %T %v", got, got, want, want)
			}
			if dials := dialer.recorded(); len(dials) != 0 {
				t.Fatalf("dialer.DialContext calls %+v, want none with ListenConfig set", dials)
			}
			second.send(t, []byte("from second"))
			if got, want := env.reply(t), (udpRead{"from second", fam.second}); got != want {
				t.Fatalf("client got %+v, want %+v", got, want)
			}
			first.send(t, []byte("from first"))
			if got, want := env.reply(t), (udpRead{"from first", fam.first}); got != want {
				t.Fatalf("client got %+v, want %+v", got, want)
			}
			unseen, _, err := first.socket.standIn(fam.unseen)
			if err != nil {
				t.Fatalf("stand in for %v: %v", fam.unseen, err)
			}
			unseen.send(t, []byte("from unseen"))
			if got, want := env.reply(t), (udpRead{"from unseen", fam.unseen}); got != want {
				t.Fatalf("client got %+v from a source it never sent to, want %+v", got, want)
			}
			if !env.flow.Accepted() {
				t.Fatal("flow not accepted, want the session accepted")
			}
		})
	}
}

func TestConeListenFailureEndsSessionAndNextSessionListensAgain(t *testing.T) {
	h := &Handler{}
	listener, _ := coneSetup(t, h)
	listener.fail(errors.New("cone test listen failure"))
	env := testServe(t, h, testClient, udpFamilies[0].first)
	env.send("first")
	env.expectNoReply(t, udpRelayQuiet, "after a failed ListenPacket")
	env.waitDone(t, testWait, "ListenPacket failed")
	if !env.flow.Accepted() || !env.session.Closed() {
		t.Fatalf("after a failed ListenPacket the flow is accepted %v and its session closed %v, want the session accepted and ended", env.flow.Accepted(), env.session.Closed())
	}
	testServe(t, h, testClient, udpFamilies[0].first).send("again")
	waitFor(t, func() bool { return listener.opens() >= 2 }, "ListenPacket not called again by the next session")
}

func TestConeIdleEndsSessionAndNextSessionListensAgain(t *testing.T) {
	h := &Handler{Idle: 200 * time.Millisecond}
	listener, _ := coneSetup(t, h)
	env := testServe(t, h, testClient, udpFamilies[0].first)
	env.send("open")
	target := listener.nextCone(t, env)
	target.recv(t)
	udpRelayExpectClosed(t, target, "session idle past Handler.Idle 200ms")
	env.waitDone(t, testWait, "the session idled")
	testServe(t, h, testClient, udpFamilies[0].first).send("again")
	waitFor(t, func() bool { return listener.opens() >= 2 }, "ListenPacket not called again by the session after the idle end")
}

func TestConeClosesEachSessionSocketOnce(t *testing.T) {
	const sessions = 5
	h := &Handler{}
	listener, _ := coneSetup(t, h)
	fam := udpFamilies[0]
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var envs []*testEnv
	for i := range sessions {
		client := netip.AddrPortFrom(fam.client.Addr(), fam.client.Port()+uint16(i))
		env := testServeCtx(t, ctx, h, "udp", client, fam.first)
		env.sendTo([]byte("open"), fam.first)
		listener.nextCone(t, env).recv(t)
		envs = append(envs, env)
	}
	cancel()
	for _, env := range envs {
		env.waitDone(t, testWait, "ctx ended")
	}
	if got := listener.closes(); got != sessions {
		t.Fatalf("Handler called Close %d times on the sockets of %d sessions, want once each", got, sessions)
	}
}

func TestConeWriteFailureDropsOnlyThatDatagram(t *testing.T) {
	fam := udpFamilies[0]
	h := &Handler{}
	listener, _ := coneSetup(t, h)
	listener.refuseWrites(fam.second)
	env := testServe(t, h, fam.client, fam.first)
	env.sendTo([]byte("open"), fam.first)
	target := listener.nextCone(t, env)
	target.recv(t)
	env.sendTo([]byte("refused"), fam.second)
	env.sendTo([]byte("after"), fam.first)
	if got := target.recv(t); string(got) != "after" {
		t.Fatalf("target got %q, want %q relayed after the refused datagram", got, "after")
	}
	if n := listener.opens(); n != 1 {
		t.Fatalf("ListenPacket called %d times, want the session kept on its one socket after a failed WriteTo", n)
	}
}

func TestConeReadErrorEndsSessionAndNextSessionListensAgain(t *testing.T) {
	h := &Handler{}
	listener, _ := coneSetup(t, h)
	env := testServe(t, h, testClient, udpFamilies[0].first)
	env.send("open")
	target := listener.nextCone(t, env)
	target.recv(t)
	// A past deadline fails the Handler's pending ReadFrom as a socket error would.
	target.socket.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case <-target.gone():
	case <-time.After(testWait):
		t.Fatalf("session socket still open %v after its ReadFrom failed, want the Handler to end the session", testWait)
	}
	env.waitDone(t, testWait, "the session socket's ReadFrom failed")
	testServe(t, h, testClient, udpFamilies[0].first).send("again")
	waitFor(t, func() bool { return listener.opens() >= 2 }, "ListenPacket not called again by the session after the ended one")
}

func TestConeCancelEndsStalledSession(t *testing.T) {
	h := &Handler{}
	listener, _ := coneSetup(t, h)
	listener.stall()
	env := testServe(t, h, testClient, udpFamilies[0].first)
	env.send("datagram")
	stalled := testReceive(t, listener.opened, "ListenPacket").(coneStalled)
	testReceive(t, stalled.writing, "the Handler's WriteTo on its stalled socket")
	env.cancel()
	testReceive(t, stalled.closed, "closing the stalled socket after ctx ended")
}

// udpRelayServe gives h a fresh udpRelayDialer and serves it a session to target from the client of target's family.
func udpRelayServe(t *testing.T, h *Handler, target string) (*testEnv, *udpRelayDialer) {
	t.Helper()
	dialer := newUDPRelayDialer(t)
	h.Dialer = dialer
	to := netip.MustParseAddrPort(target)
	client := udpFamilies[0].client
	if to.Addr().Is6() {
		client = udpFamilies[1].client
	}
	return testServe(t, h, client, to), dialer
}

func TestSymmetricDialsUDPWithClientAddr(t *testing.T) {
	env, dialer := udpRelayServe(t, &Handler{}, "10.0.0.9:5000")
	env.send("datagram")
	dialer.next(t, env)
	dialer.expectOnly(t, "10.0.0.9:5000", net.UDPAddrFromAddrPort(env.client))
}

func TestSymmetricDialsIPv6InBracketForm(t *testing.T) {
	env, dialer := udpRelayServe(t, &Handler{}, "[fd00::9]:5000")
	env.send("datagram")
	dialer.next(t, env)
	dialer.expectOnly(t, "[fd00::9]:5000", net.UDPAddrFromAddrPort(env.client))
}

func TestKeepsDatagramsWholeAndInOrderBothWays(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			env, opener := mode.serve(t, &Handler{})
			sizes := []int{1, 512, 1400}
			for i, size := range sizes {
				env.sendTo(udpRelayDatagram(size, byte(i)), env.target)
			}
			target := opener.next(t, env)
			for i, size := range sizes {
				if got, want := target.recv(t), udpRelayDatagram(size, byte(i)); !bytes.Equal(got, want) {
					t.Fatalf("target datagram %d is %d bytes %x..., want the client's %d-byte datagram %d", i, len(got), got[:min(len(got), 8)], size, i)
				}
			}
			for i, size := range sizes {
				target.send(t, udpRelayDatagram(size, byte(100+i)))
			}
			for i, size := range sizes {
				if got, want := env.replyFromTarget(t), udpRelayDatagram(size, byte(100+i)); !bytes.Equal(got, want) {
					t.Fatalf("client datagram %d is %d bytes %x..., want the target's %d-byte datagram %d", i, len(got), got[:min(len(got), 8)], size, i)
				}
			}
		})
	}
}

func TestKeepsDatagramsAbove32KiBWholeBothWays(t *testing.T) {
	for _, mode := range relayModes {
		for _, size := range []int{40000, 65507} {
			t.Run(fmt.Sprint(mode.name, " ", size, " from the client"), func(t *testing.T) {
				env, opener := mode.serve(t, &Handler{})
				env.sendTo(udpRelayDatagram(size, 1), env.target)
				if got := opener.next(t, env).recv(t); !bytes.Equal(got, udpRelayDatagram(size, 1)) {
					t.Fatalf("target got a %d-byte datagram, want the client's %d bytes unchanged", len(got), size)
				}
			})
			t.Run(fmt.Sprint(mode.name, " ", size, " from the target"), func(t *testing.T) {
				env, target := udpRelayOpen(t, mode, 0)
				target.send(t, udpRelayDatagram(size, 2))
				if got := env.replyFromTarget(t); !bytes.Equal(got, udpRelayDatagram(size, 2)) {
					t.Fatalf("client got a %d-byte datagram, want the target's %d bytes unchanged", len(got), size)
				}
			})
		}
	}
}

func TestTargetReusesItsSocket(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			env, opener := mode.serve(t, &Handler{})
			env.send("first")
			target := opener.next(t, env)
			target.recv(t)
			for _, datagram := range []string{"second", "third"} {
				env.send(datagram)
				if got := target.recv(t); string(got) != datagram {
					t.Fatalf("the target's socket got %q, want the later datagram %q", got, datagram)
				}
			}
			if n := opener.opens(); n != 1 {
				t.Fatalf("Handler opened %d sockets for one client port to one target, want 1", n)
			}
		})
	}
}

func TestSymmetricDialFailureDropsTargetAndRedials(t *testing.T) {
	h := &Handler{}
	dialer := newUDPRelayDialer(t)
	h.Dialer = dialer
	dialer.fail(errors.New("udpRelay test dial failure"))
	env := testServe(t, h, testClient, udpFamilies[0].first)
	env.send("first")
	env.expectNoReply(t, udpRelayQuiet, "after a failed dial")
	if !env.flow.Accepted() {
		t.Fatal("flow not accepted after a failed dial, want the session accepted")
	}
	// A datagram reaching the failed target before it is dropped is dropped with it, so send until one dials again.
	for deadline := time.Now().Add(testWait); len(dialer.recorded()) < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("dialer.DialContext called %d times within %v of resending, want the next datagram to dial again", len(dialer.recorded()), testWait)
		}
		env.send("again")
	}
	dialer.mu.Lock()
	opened := len(dialer.opened)
	dialer.mu.Unlock()
	if opened != 0 {
		t.Fatalf("%d dialled conns opened by failed dials, want none", opened)
	}
}

func TestSymmetricCancelEndsSessionWithStalledRemote(t *testing.T) {
	h := &Handler{}
	dialer := newUDPRelayDialer(t)
	h.Dialer = dialer
	dialer.stall()
	env := testServe(t, h, testClient, udpFamilies[0].first)
	env.send("datagram")
	target := dialer.next(t, env)
	select {
	case <-target.dialled.Conn.(*stalledConn).writing:
	case <-time.After(testWait):
		t.Fatalf("Handler did not write the datagram to its dialled conn within %v", testWait)
	}
	env.cancel()
	select {
	case <-target.dialled.closed:
	case <-time.After(testWait):
		t.Fatalf("Handler still held its stalled dialled conn open %v after ctx ended, want it closed", testWait)
	}
}

func TestSymmetricDialledReadErrorDropsTargetAndRedials(t *testing.T) {
	env, dialer := udpRelayServe(t, &Handler{}, "10.0.0.9:5000")
	env.send("open")
	target := dialer.next(t, env)
	target.recv(t)
	// A past deadline fails the Handler's pending Read as an ICMP port unreachable would.
	target.dialled.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case <-target.dialled.closed:
	case <-time.After(testWait):
		t.Fatalf("dialled conn still open %v after its Read failed, want the Handler to drop the target", testWait)
	}
	for deadline := time.Now().Add(testWait); len(dialer.recorded()) < 2; time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("dialer.DialContext called %d times within %v of resending, want the dropped target's next datagram to dial again", len(dialer.recorded()), testWait)
		}
		env.send("again")
	}
}

// udpRelayTwoTargets serves a Handler{Idle: idle} in mode a session from one client to two targets, each reached by one datagram.
func udpRelayTwoTargets(t *testing.T, mode relayMode, idle time.Duration) (env *testEnv, opener relayOpener, first, second relayEnd) {
	t.Helper()
	fam := udpFamilies[0]
	h := &Handler{Idle: idle}
	opener = mode.setup(t, h)
	env = testServe(t, h, fam.client, fam.first)
	env.sendTo([]byte("to first"), fam.first)
	first = opener.next(t, env)
	if got := first.recv(t); string(got) != "to first" {
		t.Fatalf("first target got %q, want %q", got, "to first")
	}
	env.sendTo([]byte("to second"), fam.second)
	second = opener.next(t, env)
	if got := second.recv(t); string(got) != "to second" {
		t.Fatalf("second target got %q, want %q", got, "to second")
	}
	return env, opener, first, second
}

func TestSymmetricDialsOnceEachTargetAndRepliesFromIt(t *testing.T) {
	fam := udpFamilies[0]
	env, opener, first, second := udpRelayTwoTargets(t, relayModes[0], 0)
	dialer := opener.(relayDialled)
	env.sendTo([]byte("again"), fam.first)
	if got := first.recv(t); string(got) != "again" {
		t.Fatalf("first target got %q, want the later datagram %q on the same socket", got, "again")
	}
	dials := dialer.recorded()
	client := env.client.String()
	if len(dials) != 2 || dials[0].address != fam.first.String() || dials[1].address != fam.second.String() {
		t.Fatalf("dialer.DialContext calls %+v, want one udp dial each to %v and %v", dials, fam.first, fam.second)
	}
	for _, dial := range dials {
		if dial.network != "udp" || dial.client == nil || dial.client.String() != client {
			t.Fatalf("dial %+v, want network udp tagged with the client %s", dial, client)
		}
	}
	second.send(t, []byte("from second"))
	if got, want := env.reply(t), (udpRead{"from second", fam.second}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	first.send(t, []byte("from first"))
	if got, want := env.reply(t), (udpRead{"from first", fam.first}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	if !env.flow.Accepted() {
		t.Fatal("flow not accepted, want the session accepted")
	}
}

func TestSymmetricReadErrorClosesOnlyThatTargetsSocket(t *testing.T) {
	fam := udpFamilies[0]
	env, opener, firstEnd, second := udpRelayTwoTargets(t, relayModes[0], 0)
	dialer, first := opener.(relayDialled), firstEnd.(*udpRelayTarget)
	// A past deadline fails the Handler's pending Read as an ICMP port unreachable would.
	first.dialled.SetReadDeadline(time.Now().Add(-time.Second))
	select {
	case <-first.dialled.closed:
	case <-time.After(testWait):
		t.Fatalf("first target's socket still open %v after its Read failed, want it closed", testWait)
	}
	env.sendTo([]byte("still"), fam.second)
	if got := second.recv(t); string(got) != "still" {
		t.Fatalf("second target got %q, want %q on its socket kept open", got, "still")
	}
	env.sendTo([]byte("redial"), fam.first)
	again := dialer.next(t, env)
	if got := again.recv(t); string(got) != "redial" {
		t.Fatalf("redialled first target got %q, want %q", got, "redial")
	}
	if dials := dialer.recorded(); len(dials) != 3 || dials[2].address != fam.first.String() {
		t.Fatalf("dialer.DialContext calls %+v, want a third dial to %v", dials, fam.first)
	}
	select {
	case <-second.gone():
		t.Fatal("second target's socket closed, want only the failed one closed")
	default:
	}
}

// relayStallBound is how long a datagram may take to reach its target while another target of its session dials.
const relayStallBound = 500 * time.Millisecond

func TestSymmetricSlowDialDoesNotDelayOtherTargets(t *testing.T) {
	fam := udpFamilies[0]
	env, dialer := udpRelayServe(t, &Handler{}, fam.second.String())
	dialer.slowDial(fam.second.String(), 2*time.Second)
	env.sendTo([]byte("to slow"), fam.second)
	start := time.Now()
	env.sendTo([]byte("to fast"), fam.first)
	fast := dialer.next(t, env).recv(t)
	if elapsed := time.Since(start); elapsed > relayStallBound {
		t.Fatalf("datagram to %v reached a target %v after sending while the dial to %v took 2s, want within %v", fam.first, elapsed.Round(time.Millisecond), fam.second, relayStallBound)
	}
	if string(fast) != "to fast" {
		t.Fatalf("first target reached got %q, want %q", fast, "to fast")
	}
	if got := dialer.next(t, env).recv(t); string(got) != "to slow" {
		t.Fatalf("slow target got %q once dialled, want %q", got, "to slow")
	}
}

func TestSymmetricFullQueueDropsInsteadOfDelayingOtherTargets(t *testing.T) {
	fam := udpFamilies[0]
	env, dialer := udpRelayServe(t, &Handler{}, fam.second.String())
	dialer.slowDial(fam.second.String(), 3*time.Second)
	for range 4 * relayQueueLen {
		env.sendTo([]byte("to slow"), fam.second)
	}
	start := time.Now()
	env.sendTo([]byte("to fast"), fam.first)
	fast := dialer.next(t, env).recv(t)
	if elapsed := time.Since(start); elapsed > relayStallBound {
		t.Fatalf("datagram to %v reached a target %v after sending while %d datagrams waited on a 3s dial to %v, want within %v", fam.first, elapsed.Round(time.Millisecond), 4*relayQueueLen, fam.second, relayStallBound)
	}
	if string(fast) != "to fast" {
		t.Fatalf("first target reached got %q, want %q", fast, "to fast")
	}
}

func TestSymmetricIdleCountsForTheWholeSession(t *testing.T) {
	const idle = 300 * time.Millisecond
	fam := udpFamilies[0]
	env, _, first, second := udpRelayTwoTargets(t, relayModes[0], idle)
	for end := time.Now().Add(3 * idle); time.Now().Before(end); time.Sleep(idle / 5) {
		env.sendTo([]byte("keep"), fam.first)
		first.recv(t)
		select {
		case <-second.gone():
			t.Fatalf("second target's socket closed while datagrams flowed to the first every %v, want Handler.Idle %v to count for the whole session", idle/5, idle)
		default:
		}
	}
	udpRelayExpectClosed(t, second, "second target once the session idled")
}

func TestSessionIdleClosesEverySocket(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			_, _, first, second := udpRelayTwoTargets(t, mode, 200*time.Millisecond)
			udpRelayExpectClosed(t, first, "first target of a session idle past Handler.Idle 200ms")
			udpRelayExpectClosed(t, second, "second target of a session idle past Handler.Idle 200ms")
		})
	}
}

func TestHandlerIdleDefaultsTo60Seconds(t *testing.T) {
	if got := (&Handler{}).idle(); got != 60*time.Second {
		t.Fatalf("Handler{}.idle() = %v, want the 60s default", got)
	}
	if got := (&Handler{Idle: 3 * time.Second}).idle(); got != 3*time.Second {
		t.Fatalf("Handler{Idle: 3s}.idle() = %v, want 3s", got)
	}
}

// udpRelayOpen serves a Handler{Idle: idle} in mode a session and returns it and its target once the first datagram arrived.
func udpRelayOpen(t *testing.T, mode relayMode, idle time.Duration) (*testEnv, relayEnd) {
	t.Helper()
	env, opener := mode.serve(t, &Handler{Idle: idle})
	env.send("open")
	target := opener.next(t, env)
	target.recv(t)
	return env, target
}

func udpRelayExpectClosed(t *testing.T, target relayEnd, what string) {
	t.Helper()
	select {
	case <-target.gone():
	case <-time.After(udpRelayIdleBound):
		t.Fatalf("%s: socket still open %v later, want Handler.Idle to close it", what, udpRelayIdleBound)
	}
}

func TestSessionEndsAfterIdle(t *testing.T) {
	for _, mode := range relayModes {
		t.Run(mode.name, func(t *testing.T) {
			_, target := udpRelayOpen(t, mode, 200*time.Millisecond)
			udpRelayExpectClosed(t, target, "session idle past Handler.Idle 200ms")
		})
	}
}

func TestTrafficEitherWayExtendsIdle(t *testing.T) {
	const idle = 500 * time.Millisecond
	for _, mode := range relayModes {
		for _, direction := range []string{"from the client", "from the target"} {
			t.Run(mode.name+" "+direction, func(t *testing.T) {
				env, target := udpRelayOpen(t, mode, idle)
				for end := time.Now().Add(3 * idle); time.Now().Before(end); time.Sleep(idle / 5) {
					if direction == "from the client" {
						env.send("keep")
						target.recv(t)
					} else {
						target.send(t, []byte("keep"))
						env.replyFromTarget(t)
					}
					select {
					case <-target.gone():
						t.Fatalf("Handler closed the session while datagrams flowed %s every %v, want each to push back Handler.Idle %v", direction, idle/5, idle)
					default:
					}
				}
				udpRelayExpectClosed(t, target, "session idle after datagrams "+direction)
			})
		}
	}
}

// pipeDialer answers each dial with one end of a net.Pipe and hands the test the other.
type pipeDialer struct{ remotes chan net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	conn, remote := net.Pipe()
	d.remotes <- remote
	return conn, nil
}

func TestCancelGivesDialledConnEOF(t *testing.T) {
	dialer := pipeDialer{make(chan net.Conn, 1)}
	env := testServe(t, &Handler{Dialer: dialer}, testClient, udpFamilies[0].first)
	env.send("datagram")
	remote := testReceive(t, dialer.remotes, "dialing the target")
	t.Cleanup(func() { remote.Close() })
	remote.SetDeadline(time.Now().Add(testWait))
	if _, err := io.ReadFull(remote, make([]byte, len("datagram"))); err != nil {
		t.Fatalf("target read the datagram: %v", err)
	}
	env.cancel()
	if n, err := remote.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("target Read() = %d, %v after ctx ended, want 0, EOF", n, err)
	}
	env.waitDone(t, testStopBound, "ctx ended")
	if !env.session.Closed() {
		t.Fatal("session conn still open after ServeFlow returned, want it closed")
	}
}

func TestCancelReturnsWithinBoundWithStalledRemote(t *testing.T) {
	t.Run("symmetric", func(t *testing.T) {
		h := &Handler{}
		dialer := newUDPRelayDialer(t)
		h.Dialer = dialer
		dialer.stall()
		env := testServe(t, h, testClient, udpFamilies[0].first)
		env.send("datagram")
		target := dialer.next(t, env)
		testReceive(t, target.dialled.Conn.(*stalledConn).writing, "the Handler's Write on its stalled dialled conn")
		env.cancel()
		env.waitDone(t, testStopBound, "ctx ended while a Write to a stalled dialled conn blocked")
		if !env.session.Closed() || !closed(target.dialled.closed) {
			t.Fatalf("after ServeFlow returned the session is closed %v and the dialled conn %v, want both closed", env.session.Closed(), closed(target.dialled.closed))
		}
	})
	t.Run("full cone", func(t *testing.T) {
		h := &Handler{}
		listener, _ := coneSetup(t, h)
		listener.stall()
		env := testServe(t, h, testClient, udpFamilies[0].first)
		env.send("datagram")
		stalled := testReceive(t, listener.opened, "ListenPacket").(coneStalled)
		testReceive(t, stalled.writing, "the Handler's WriteTo on its stalled socket")
		env.cancel()
		env.waitDone(t, testStopBound, "ctx ended while a WriteTo on a stalled socket blocked")
		if !env.session.Closed() || !closed(stalled.closed) {
			t.Fatalf("after ServeFlow returned the session is closed %v and the socket %v, want both closed", env.session.Closed(), closed(stalled.closed))
		}
	})
}

func TestRejectsOtherNetworks(t *testing.T) {
	for _, cone := range []bool{false, true} {
		t.Run(fmt.Sprint("ListenConfig set ", cone), func(t *testing.T) {
			h := &Handler{}
			listener, dialer := coneSetup(t, h)
			if !cone {
				h.ListenConfig = nil
			}
			env := testServeCtx(t, context.Background(), h, "tcp", testClient, udpFamilies[0].first)
			env.send("datagram")
			env.waitDone(t, testWait, "serving a tcp flow")
			if !env.flow.Rejected() || env.flow.Accepted() {
				t.Fatalf("tcp flow rejected %v and accepted %v, want rejected and never accepted", env.flow.Rejected(), env.flow.Accepted())
			}
			if dials, calls := dialer.recorded(), listener.recorded(); len(dials) != 0 || len(calls) != 0 {
				t.Fatalf("tcp flow dialled %+v and listened %+v, want neither", dials, calls)
			}
		})
	}
}

func closed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

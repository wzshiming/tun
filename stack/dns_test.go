package stack

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// testIdleBound is how long a 200ms DNS.Idle may take to end a flow; the 10s default exceeds it.
const testIdleBound = 5 * time.Second

// testDNSQuery is a well-formed DNS query for the A record of example.com.
const testDNSQuery = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"

// testServeDNS serves udp/53 with a DNS idle for idle over the env's dialer.
func testServeDNS(t *testing.T, idle time.Duration) *testEnv {
	t.Helper()
	return testServeWith(t, Options{Addresses: testAddresses}, func(d *fakeDialer) Handler {
		m := NewMux()
		m.Handle("udp", 53, &DNS{Dialer: d, Idle: idle})
		return m
	})
}

func TestUDPDNSDialsTCPWithClientAddr(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	conn := env.dialUDP(t, "10.0.0.53:53")
	testSend(t, conn, "query")
	env.nextTarget(t)
	env.dialer.expectOnly(t, "10.0.0.53:53", conn.LocalAddr())
}

func TestUDPDNSRelaysLengthFramedMessages(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	conn := env.dialUDP(t, "10.0.0.53:53")
	testSend(t, conn, "query")
	target := env.nextTarget(t)
	if got := testReadFrame(t, target); got != "query" {
		t.Fatalf("target read the framed message %q, want the datagram %q", got, "query")
	}
	testWriteFrame(t, target, "reply")
	reply := make([]byte, 512)
	n, err := conn.Read(reply)
	if err != nil || string(reply[:n]) != "reply" {
		t.Fatalf("client Read() = %q, %v, want the unframed reply %q", reply[:n], err, "reply")
	}
}

func TestUDPDNSFlowReusesTCPConn(t *testing.T) {
	env := testServe(t, Options{Addresses: testAddresses})
	conn := env.dialUDP(t, "10.0.0.53:53")
	testSend(t, conn, "first")
	target := env.nextTarget(t)
	testReadFrame(t, target)
	testSend(t, conn, "second")
	if got := testReadFrame(t, target); got != "second" {
		t.Fatalf("the flow's TCP conn read %q, want the second datagram %q", got, "second")
	}
	if dials := env.dialer.recorded(); len(dials) != 1 {
		t.Fatalf("dialer.DialContext called %d times for one UDP flow, want 1", len(dials))
	}
}

func TestUDPDNSFlowEndsAfterIdle(t *testing.T) {
	env := testServeDNS(t, 200*time.Millisecond)
	conn := env.dialUDP(t, "10.0.0.53:53")
	testSend(t, conn, "query")
	target := env.nextTarget(t)
	testReadFrame(t, target)
	if err := target.SetReadDeadline(time.Now().Add(testIdleBound)); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, target, "target of a flow idle past DNS.Idle 200ms")
}

func TestUDPDNSFlowWithStalledRemoteEndsAfterIdle(t *testing.T) {
	env := testServeDNS(t, 200*time.Millisecond)
	remote := testStalledDNS(t, env)
	select {
	case <-remote.closed:
	case <-time.After(testIdleBound):
		t.Fatalf("a DNS relay blocked writing to its stalled TCP/53 conn still held it open %v later, want the DNS.Idle 200ms idle timer to close it", testIdleBound)
	}
}

func TestUDPDNSRepliesPushBackIdle(t *testing.T) {
	const idle = 200 * time.Millisecond
	env := testServeDNS(t, idle)
	conn := env.dialUDP(t, "10.0.0.53:53")
	testSend(t, conn, "query")
	target := env.nextTarget(t)
	testReadFrame(t, target)
	start := time.Now()
	var last time.Time
	for i := 0; time.Since(start) < 3*idle; i++ {
		time.Sleep(80 * time.Millisecond)
		testWriteFrame(t, target, "reply")
		last = time.Now()
		conn.SetReadDeadline(time.Now().Add(time.Second))
		reply := make([]byte, 512)
		if n, err := conn.Read(reply); err != nil || string(reply[:n]) != "reply" {
			t.Fatalf("client Read() of reply %d, %v after the query = %q, %v, want %q: replies every 80ms must keep a flow with DNS.Idle %v alive", i+1, time.Since(start), reply[:n], err, "reply", idle)
		}
	}
	if err := target.SetReadDeadline(time.Now().Add(testIdleBound)); err != nil {
		t.Fatal(err)
	}
	testReadEOF(t, target, "target of a flow silent since its last reply")
	if ended := time.Since(last); ended < idle*3/4 || ended > 2*time.Second {
		t.Fatalf("flow ended %v after its last reply, want about DNS.Idle %v", ended, idle)
	}
}

func TestUDPDNSSessionDialsOnceEachServerAndRepliesFromIt(t *testing.T) {
	env := testServeDNS(t, 0)
	first, second := netip.MustParseAddrPort("10.0.0.53:53"), netip.MustParseAddrPort("10.0.0.54:53")
	conn := env.listenUDP(t, testClient4)
	testSendTo(t, conn, []byte("q1"), first)
	firstServer := env.nextTarget(t)
	if got := testReadFrame(t, firstServer); got != "q1" {
		t.Fatalf("first server read %q, want %q", got, "q1")
	}
	testSendTo(t, conn, []byte("q2"), second)
	secondServer := env.nextTarget(t)
	if got := testReadFrame(t, secondServer); got != "q2" {
		t.Fatalf("second server read %q, want %q", got, "q2")
	}
	testSendTo(t, conn, []byte("q3"), first)
	if got := testReadFrame(t, firstServer); got != "q3" {
		t.Fatalf("first server read %q, want the later query %q on the same conn", got, "q3")
	}
	dials := env.dialer.recorded()
	client := conn.LocalAddr().String()
	if len(dials) != 2 || dials[0].address != first.String() || dials[1].address != second.String() {
		t.Fatalf("dialer.DialContext calls %+v, want one tcp dial each to %v and %v", dials, first, second)
	}
	for _, dial := range dials {
		if dial.network != "tcp" || dial.client == nil || dial.client.String() != client {
			t.Fatalf("dial %+v, want network tcp tagged with the client %s", dial, client)
		}
	}
	testWriteFrame(t, secondServer, "r2")
	if got, want := testRecvFrom(t, conn), (udpRead{"r2", second, nil}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
	testWriteFrame(t, firstServer, "r1")
	if got, want := testRecvFrom(t, conn), (udpRead{"r1", first, nil}); got != want {
		t.Fatalf("client got %+v, want %+v", got, want)
	}
}

func TestDNSRejectsTCP(t *testing.T) {
	env := testServeWith(t, Options{Addresses: testAddresses}, func(d *fakeDialer) Handler {
		m := NewMux()
		m.Handle("tcp", 53, &DNS{Dialer: d})
		return m
	})
	env.dialTCPRefused(t, "10.0.0.53:53")
	if dials := env.dialer.recorded(); len(dials) != 0 {
		t.Fatalf("dialer.DialContext called for a TCP flow given to DNS: %+v, want no dial", dials)
	}
}

// testStalledDNS opens a DNS flow whose TCP/53 conn stalls and returns that conn once the relay is blocked writing a query to it.
func testStalledDNS(t *testing.T, env *testEnv) *stalledConn {
	t.Helper()
	env.dialer.stall()
	testSend(t, env.dialUDP(t, "10.0.0.53:53"), testDNSQuery)
	remote := env.nextTarget(t).(*stalledConn)
	select {
	case <-remote.writing:
	case <-time.After(testWait):
		t.Fatalf("the DNS relay did not write the query to its TCP/53 conn within %v%s", testWait, env.returned())
	}
	return remote
}

// testReadFrame reads one message prefixed with its 2-byte big-endian length.
func testReadFrame(t *testing.T, conn net.Conn) string {
	t.Helper()
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		t.Fatalf("read the 2-byte length of a relayed DNS message: %v", err)
	}
	message := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, message); err != nil {
		t.Fatalf("read a %d-byte relayed DNS message: %v", len(message), err)
	}
	return string(message)
}

func testWriteFrame(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(message)))
	if _, err := conn.Write(append(frame, message...)); err != nil {
		t.Fatalf("write the framed reply %q: %v", message, err)
	}
}

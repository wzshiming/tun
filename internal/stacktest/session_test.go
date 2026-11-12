package stacktest_test

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
)

var (
	_ net.Conn       = (*stacktest.Session)(nil)
	_ net.PacketConn = (*stacktest.Session)(nil)
)

// testWait bounds every wait for something expected to happen.
const testWait = 5 * time.Second

// testBlocked is how long a call must stay blocked to count as blocking.
const testBlocked = 50 * time.Millisecond

type readResult struct {
	data string
	addr net.Addr
	err  error
}

func testReadFrom(s *stacktest.Session) <-chan readResult {
	done := make(chan readResult, 1)
	go func() {
		b := make([]byte, 64)
		n, addr, err := s.ReadFrom(b)
		done <- readResult{string(b[:n]), addr, err}
	}()
	return done
}

func TestSessionReadFromReturnsSentDatagramsInOrderWithDestination(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	s.Send([]byte("first"), testTarget)
	s.Send([]byte("second"), testOther)
	for _, want := range []struct {
		data string
		to   netip.AddrPort
	}{{"first", testTarget}, {"second", testOther}} {
		b := make([]byte, 64)
		n, addr, err := s.ReadFrom(b)
		if err != nil {
			t.Fatalf("ReadFrom() error %v, want %q to %v", err, want.data, want.to)
		}
		udp, ok := addr.(*net.UDPAddr)
		if string(b[:n]) != want.data || !ok || udp.AddrPort() != want.to {
			t.Fatalf("ReadFrom() = %q, %#v; want %q, *net.UDPAddr %v", b[:n], addr, want.data, want.to)
		}
	}
}

func TestSessionWriteToDeliversReplyWithSource(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	if n, err := s.WriteTo([]byte("reply"), net.UDPAddrFromAddrPort(testOther)); n != 5 || err != nil {
		t.Fatalf("WriteTo() = %d, %v; want 5, nil", n, err)
	}
	data, from, ok := s.NextReply(testWait)
	if !ok || string(data) != "reply" || from != testOther {
		t.Fatalf("NextReply() = %q, %v, %v; want reply from %v", data, from, ok, testOther)
	}
}

func TestSessionNextReplyReportsAnIPv4MappedSourceAsIPv4(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	src := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 54), Port: 53}
	if _, err := s.WriteTo([]byte("reply"), src); err != nil {
		t.Fatalf("WriteTo() = %v", err)
	}
	if _, from, ok := s.NextReply(testWait); !ok || from != testOther {
		t.Fatalf("NextReply() from %v, %v after WriteTo from the 16-byte %v; want %v as the gateway sends it", from, ok, src, testOther)
	}
}

func TestSessionNextReplyGivesUpAfterItsWait(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	start := time.Now()
	if data, from, ok := s.NextReply(testBlocked); ok {
		t.Fatalf("NextReply() = %q, %v, true with no reply written; want false", data, from)
	}
	if waited := time.Since(start); waited < testBlocked || waited > testWait {
		t.Fatalf("NextReply(%v) returned after %v", testBlocked, waited)
	}
}

func TestSessionWriteToRejectsNonUDPAddr(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	if _, err := s.WriteTo([]byte("reply"), net.TCPAddrFromAddrPort(testOther)); err == nil {
		t.Fatal("WriteTo() with a *net.TCPAddr succeeded, want an error")
	}
	if data, from, ok := s.NextReply(testBlocked); ok {
		t.Fatalf("NextReply() = %q, %v after a refused WriteTo, want no reply", data, from)
	}
}

func TestSessionReadFromBlocksUntilADatagram(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	done := testReadFrom(s)
	select {
	case r := <-done:
		t.Fatalf("ReadFrom() = %+v with nothing sent, want it to block", r)
	case <-time.After(testBlocked):
	}
	s.Send([]byte("late"), testTarget)
	select {
	case r := <-done:
		if r.err != nil || r.data != "late" {
			t.Fatalf("ReadFrom() = %+v, want the late datagram", r)
		}
	case <-time.After(testWait):
		t.Fatalf("ReadFrom() still blocked %v after Send", testWait)
	}
}

func TestSessionReadFromBlocksUntilClose(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	done := testReadFrom(s)
	select {
	case r := <-done:
		t.Fatalf("ReadFrom() = %+v with nothing sent, want it to block", r)
	case <-time.After(testBlocked):
	}
	s.Close()
	select {
	case r := <-done:
		if !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("blocked ReadFrom() = %+v after Close, want net.ErrClosed", r)
		}
	case <-time.After(testWait):
		t.Fatalf("ReadFrom() still blocked %v after Close", testWait)
	}
}

func TestSessionReadFromAfterCloseFailsEvenWithDatagramsQueued(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	s.Send([]byte("queued"), testTarget)
	s.Close()
	if n, addr, err := s.ReadFrom(make([]byte, 64)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom() after Close = %d, %v, %v; want net.ErrClosed", n, addr, err)
	}
}

func TestSessionWriteToAfterCloseFails(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	s.Close()
	if _, err := s.WriteTo([]byte("reply"), net.UDPAddrFromAddrPort(testTarget)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo() after Close = %v, want net.ErrClosed", err)
	}
}

func TestSessionCloseIsRepeatableAndReported(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	if s.Closed() {
		t.Fatal("Closed() = true before Close")
	}
	for i := range 2 {
		if err := s.Close(); err != nil {
			t.Fatalf("Close() #%d = %v, want nil", i+1, err)
		}
	}
	if !s.Closed() {
		t.Fatal("Closed() = false after Close")
	}
}

func TestSessionAddrsAreTargetAndClient(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	local, lok := s.LocalAddr().(*net.UDPAddr)
	remote, rok := s.RemoteAddr().(*net.UDPAddr)
	if !lok || !rok || local.AddrPort() != testTarget || remote.AddrPort() != testClient {
		t.Fatalf("LocalAddr, RemoteAddr = %v, %v; want *net.UDPAddr %v, %v", s.LocalAddr(), s.RemoteAddr(), testTarget, testClient)
	}
}

func TestSessionUnsupportedMethodsFail(t *testing.T) {
	s := stacktest.NewSession(testClient, testTarget)
	s.Send([]byte("query"), testTarget)
	for name, call := range map[string]func() error{
		"Read":             func() error { _, err := s.Read(make([]byte, 64)); return err },
		"Write":            func() error { _, err := s.Write([]byte("reply")); return err },
		"SetDeadline":      func() error { return s.SetDeadline(time.Now()) },
		"SetReadDeadline":  func() error { return s.SetReadDeadline(time.Now()) },
		"SetWriteDeadline": func() error { return s.SetWriteDeadline(time.Now()) },
	} {
		if err := call(); !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s() = %v, want errors.ErrUnsupported", name, err)
		}
	}
}

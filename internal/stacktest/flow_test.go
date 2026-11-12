package stacktest_test

import (
	"net"
	"net/netip"
	"testing"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

var _ stack.Flow = (*stacktest.Flow)(nil)

var (
	testClient = netip.MustParseAddrPort("10.0.0.2:40000")
	testTarget = netip.MustParseAddrPort("10.0.0.53:53")
	testOther  = netip.MustParseAddrPort("10.0.0.54:53")
)

func testFlow(t *testing.T) (*stacktest.Flow, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	return stacktest.NewFlow("tcp", testClient, testTarget, a), a
}

func TestFlowReportsWhatItWasBuiltWith(t *testing.T) {
	f := stacktest.NewFlow("udp", testClient, testTarget, nil)
	if f.Network() != "udp" || f.Client() != testClient || f.Target() != testTarget {
		t.Fatalf("Network, Client, Target = %q, %v, %v; want udp, %v, %v", f.Network(), f.Client(), f.Target(), testClient, testTarget)
	}
}

func TestFlowAcceptReturnsItsConn(t *testing.T) {
	f, conn := testFlow(t)
	got, err := f.Accept()
	if err != nil || got != conn {
		t.Fatalf("Accept() = %v, %v; want the conn it was built with", got, err)
	}
	if !f.Accepted() || f.Rejected() {
		t.Fatalf("after Accept: Accepted %v, Rejected %v; want true, false", f.Accepted(), f.Rejected())
	}
}

func TestFlowSecondAcceptFails(t *testing.T) {
	f, _ := testFlow(t)
	f.Accept()
	if got, err := f.Accept(); err == nil {
		t.Fatalf("second Accept() = %v, nil; want an error", got)
	}
}

func TestFlowAcceptAfterRejectFails(t *testing.T) {
	f, _ := testFlow(t)
	f.Reject()
	if got, err := f.Accept(); err == nil {
		t.Fatalf("Accept() after Reject = %v, nil; want an error", got)
	}
	if f.Accepted() {
		t.Fatal("Accepted() = true after an Accept refused for Reject")
	}
}

func TestFlowRecordsReject(t *testing.T) {
	f, _ := testFlow(t)
	if f.Rejected() {
		t.Fatal("Rejected() = true before Reject")
	}
	f.Reject()
	if !f.Rejected() || f.Accepted() {
		t.Fatalf("after Reject: Rejected %v, Accepted %v; want true, false", f.Rejected(), f.Accepted())
	}
}

func TestFlowRejectAfterAcceptDoesNothing(t *testing.T) {
	f, _ := testFlow(t)
	f.Accept()
	f.Reject()
	if f.Rejected() {
		t.Fatal("Rejected() = true for a Reject after Accept, which the Flow contract makes a no-op")
	}
}

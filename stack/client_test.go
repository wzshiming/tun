package stack

import (
	"context"
	"net"
	"testing"
)

var _ ListenConfig = (*net.ListenConfig)(nil)

func TestClientAddrAbsentIsNil(t *testing.T) {
	if got := ClientAddr(context.Background()); got != nil {
		t.Errorf("ClientAddr(no client) = %v, want nil", got)
	}
}

func TestClientAddrReturnsTheAddrStored(t *testing.T) {
	want := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5353}
	if got := ClientAddr(WithClientAddr(context.Background(), want)); got != want {
		t.Errorf("ClientAddr(WithClientAddr(ctx, %v)) = %#v, want the same *net.UDPAddr", want, got)
	}
}

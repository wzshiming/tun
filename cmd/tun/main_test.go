package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"testing"

	"github.com/wzshiming/tun/stack"
)

// logDialer must listen too, so stack.DefaultMux relays UDP full cone.
var (
	_ stack.ListenConfig = (*logDialer)(nil)
	_ stack.Dialer       = (*logDialer)(nil)
)

func TestLogDialerListenPacketLogsEachNewTargetOnce(t *testing.T) {
	var logged bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&logged)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	var targets []net.PacketConn
	for range 2 {
		target, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for a target: %v", err)
		}
		defer target.Close()
		targets = append(targets, target)
	}
	d := &logDialer{listen: &net.ListenConfig{}}
	ctx := stack.WithClientAddr(context.Background(), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 4000})
	pc, err := d.ListenPacket(ctx, "udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	for _, target := range []net.PacketConn{targets[0], targets[1], targets[0], targets[1]} {
		if _, err := pc.WriteTo([]byte("datagram"), target.LocalAddr()); err != nil {
			t.Fatalf("WriteTo %v: %v", target.LocalAddr(), err)
		}
	}
	want := "198.18.0.1:4000 -> udp " + targets[0].LocalAddr().String() + "\n198.18.0.1:4000 -> udp " + targets[1].LocalAddr().String() + "\n"
	if got := logged.String(); got != want {
		t.Errorf("logged %q, want one line per new target:\n%s", got, strings.TrimSpace(want))
	}
}

type failingListener struct{ err error }

func (l failingListener) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, l.err
}

func (l failingListener) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, l.err
}

func TestLogDialerListenUsesItsListenConfig(t *testing.T) {
	listenErr := errors.New("listen refused")
	d := &logDialer{listen: failingListener{listenErr}}
	if l, err := d.Listen(context.Background(), "tcp4", ":0"); !errors.Is(err, listenErr) {
		t.Fatalf("Listen = %v, %v; want the listen config's error", l, err)
	}
}

func TestLogDialerListenPacketLogsItsFailure(t *testing.T) {
	var logged bytes.Buffer
	flags, out := log.Flags(), log.Writer()
	log.SetFlags(0)
	log.SetOutput(&logged)
	t.Cleanup(func() {
		log.SetFlags(flags)
		log.SetOutput(out)
	})
	listenErr := errors.New("listen refused")
	d := &logDialer{listen: failingListener{listenErr}}
	ctx := stack.WithClientAddr(context.Background(), &net.UDPAddr{IP: net.IPv4(198, 18, 0, 1), Port: 4000})
	if pc, err := d.ListenPacket(ctx, "udp4", ":0"); !errors.Is(err, listenErr) {
		t.Fatalf("ListenPacket = %v, %v; want the listener's error", pc, err)
	}
	if got, want := logged.String(), "198.18.0.1:4000 -> udp4 :0: listen refused\n"; got != want {
		t.Errorf("logged %q, want the one line %q", got, want)
	}
}

type closeWriteConn struct {
	net.Conn
	closedWrite bool
}

func (c *closeWriteConn) CloseWrite() error {
	c.closedWrite = true
	return nil
}

func TestLogConnPassesCloseWriteToTheInnerConn(t *testing.T) {
	inner := &closeWriteConn{}
	cw, ok := any(&logConn{Conn: inner}).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("*logConn does not expose CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil || !inner.closedWrite {
		t.Errorf("CloseWrite = %v, inner closed write %t; want nil, true", err, inner.closedWrite)
	}
}

func TestLogConnCloseWriteIsUnsupportedWithoutTheInnerOne(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	cw, ok := any(&logConn{Conn: a}).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("*logConn does not expose CloseWrite")
	}
	if err := cw.CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("CloseWrite = %v, want errors.ErrUnsupported", err)
	}
}

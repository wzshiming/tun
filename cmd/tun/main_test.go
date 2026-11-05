package main

import (
	"errors"
	"net"
	"testing"
)

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

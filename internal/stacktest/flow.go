// Package stacktest provides doubles of what a stack.Handler is served: a Flow and the conn of a UDP session.
package stacktest

import (
	"errors"
	"net"
	"net/netip"
	"sync"
)

// Flow is a double of stack.Flow whose Accept returns the conn it was built with.
type Flow struct {
	network        string
	client, target netip.AddrPort
	conn           net.Conn

	mu       sync.Mutex
	accepted bool
	rejected bool
}

// NewFlow returns a flow of network, "tcp" or "udp", from client to target, whose Accept returns conn: for udp a *Session.
func NewFlow(network string, client, target netip.AddrPort, conn net.Conn) *Flow {
	return &Flow{network: network, client: client, target: target, conn: conn}
}

func (f *Flow) Network() string        { return f.network }
func (f *Flow) Target() netip.AddrPort { return f.target }
func (f *Flow) Client() netip.AddrPort { return f.client }

// Accept returns the flow's conn the first time; a second call, or one after Reject, returns an error.
func (f *Flow) Accept() (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.accepted {
		return nil, errors.New("stacktest: flow accepted twice")
	}
	if f.rejected {
		return nil, errors.New("stacktest: flow accepted after Reject")
	}
	f.accepted = true
	return f.conn, nil
}

// Reject records that the flow was refused; after Accept it does nothing.
func (f *Flow) Reject() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.accepted {
		f.rejected = true
	}
}

// Accepted reports whether Accept returned the conn.
func (f *Flow) Accepted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accepted
}

// Rejected reports whether Reject was called before any Accept.
func (f *Flow) Rejected() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rejected
}

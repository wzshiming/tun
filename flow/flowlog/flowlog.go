// Package flowlog logs the flows a flow.Handler serves, and the dials and listens that fail for them.
// Wrap a handler, usually the flow.Mux, with Handler, and give the handlers a Dialer to dial and listen through.
package flowlog

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wzshiming/tun/flow"
)

// Logger is what the package logs each line with; a *log.Logger is one.
type Logger interface {
	Printf(format string, v ...any)
}

// printer returns logger, or log.Default() for nil.
func printer(logger Logger) Logger {
	if logger == nil {
		return log.Default()
	}
	return logger
}

// Dialer dials and listens for the handlers, logging each dial and listen that fails with the client it was for, the flow.ClientAddr of its ctx.
type Dialer struct {
	// Dialer dials.
	Dialer flow.Dialer
	// ListenConfig listens.
	ListenConfig flow.ListenConfig
	// Logger is logged with; nil is log.Default().
	Logger Logger
}

var (
	_ flow.Dialer       = (*Dialer)(nil)
	_ flow.ListenConfig = (*Dialer)(nil)
)

// logFailure logs err as the failure of a dial or listen of network and address for the client ctx carries.
func logFailure(ctx context.Context, logger Logger, network, address string, err error) {
	client := "unknown"
	if addr := flow.ClientAddr(ctx); addr != nil {
		client = addr.String()
	}
	printer(logger).Printf("%s -> %s %s: %v", client, network, address, err)
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, address)
	if err != nil {
		logFailure(ctx, d.Logger, network, address, err)
	}
	return conn, err
}

// Listen is unlogged, as no handler of a flow calls it.
func (d *Dialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.ListenConfig.Listen(ctx, network, address)
}

func (d *Dialer) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := d.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		logFailure(ctx, d.Logger, network, address, err)
	}
	return pc, err
}

// Handler returns a handler that serves each flow with next and logs it with logger, nil being log.Default(): as it starts, each further target a UDP session sends to, and as it ends, either rejected or with the bytes it carried each way and how long it lasted.
func Handler(next flow.Handler, logger Logger) flow.Handler {
	logger = printer(logger)
	return flow.HandlerFunc(func(ctx context.Context, f flow.Flow) {
		lf := &logFlow{Flow: f, logger: logger, start: time.Now()}
		if f.Network() == "icmp" {
			// Neither end of an echo session has a port.
			lf.name = fmt.Sprintf("%s -> icmp %s", f.Client().Addr(), f.Target().Addr())
		} else {
			lf.name = fmt.Sprintf("%s -> %s %s", f.Client(), f.Network(), f.Target())
		}
		logger.Printf("%s", lf.name)
		next.ServeFlow(ctx, lf)
		lf.end()
	})
}

// logFlow is a flow that counts the bytes of its accepted conn.
type logFlow struct {
	flow.Flow
	// name is the flow as its log lines begin: its client, network and target.
	name   string
	logger Logger
	start  time.Time

	mu   sync.Mutex
	conn *logConn
}

// Accept returns the flow's conn counting its bytes, as a net.PacketConn if the flow's is one, which then logs each further target the client sends to.
func (f *logFlow) Accept() (net.Conn, error) {
	conn, err := f.Flow.Accept()
	if err != nil {
		return nil, err
	}
	lc := &logConn{Conn: conn}
	f.mu.Lock()
	f.conn = lc
	f.mu.Unlock()
	if pc, ok := conn.(net.PacketConn); ok {
		return &logPacketConn{logConn: lc, pc: pc, logger: f.logger, client: f.Client(), seen: map[string]bool{f.Target().String(): true}}, nil
	}
	return lc, nil
}

// end logs how the flow ended, once its handler returned: one never accepted was rejected, by the handler or by what serves the flows.
func (f *logFlow) end() {
	f.mu.Lock()
	conn := f.conn
	f.mu.Unlock()
	if conn == nil {
		f.logger.Printf("%s rejected", f.name)
		return
	}
	f.logger.Printf("%s closed: read %d, written %d bytes in %s",
		f.name, conn.read.Load(), conn.written.Load(), time.Since(f.start).Round(time.Millisecond))
}

// logConn is a flow's conn counting the bytes it carries, named as a conn to the target sees them: read is what the client was sent, written what it sent.
type logConn struct {
	net.Conn
	read, written atomic.Int64
}

func (c *logConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.written.Add(int64(n))
	return n, err
}

func (c *logConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.read.Add(int64(n))
	return n, err
}

// CloseWrite lets a handler half-close a TCP flow instead of closing both ends at the first EOF.
func (c *logConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

// logPacketConn is the conn of a UDP session, which also logs each target its client first sends to after the flow's own.
type logPacketConn struct {
	*logConn
	pc     net.PacketConn
	logger Logger
	client netip.AddrPort
	mu     sync.Mutex
	seen   map[string]bool
}

func (c *logPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.pc.ReadFrom(b)
	c.written.Add(int64(n))
	if err == nil && addr != nil {
		target := addr.String()
		c.mu.Lock()
		seen := c.seen[target]
		c.seen[target] = true
		c.mu.Unlock()
		if !seen {
			c.logger.Printf("%s -> udp %s", c.client, target)
		}
	}
	return n, addr, err
}

func (c *logPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.pc.WriteTo(b, addr)
	c.read.Add(int64(n))
	return n, err
}

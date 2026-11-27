// Command tun captures the system's traffic into a TUN device, forwards every
// flow directly through the physical interface and logs it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/stack"
	"github.com/wzshiming/tun/stack/dns"
	"github.com/wzshiming/tun/stack/icmp"
	"github.com/wzshiming/tun/stack/tcp"
	"github.com/wzshiming/tun/stack/udp"
)

type prefixes []netip.Prefix

func (p *prefixes) String() string {
	s := make([]string, len(*p))
	for i, v := range *p {
		s[i] = v.String()
	}
	return strings.Join(s, ",")
}

func (p *prefixes) Set(v string) error {
	prefix, err := netip.ParsePrefix(v)
	if err != nil {
		return err
	}
	*p = append(*p, prefix)
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == tun.HelperCommand {
		os.Exit(tun.Helper(os.Args[2:]))
	}

	var cfg tun.Config
	var addrs, bypassed prefixes
	flag.Var(&addrs, "addr", "TUN address in CIDR form, repeatable (default 198.18.0.1/30 and fd00:6a77:7761::1/64)")
	flag.IntVar(&cfg.MTU, "mtu", 1500, "TUN MTU")
	flag.Var(&bypassed, "bypass", "destination CIDR never captured, repeatable")
	flag.StringVar(&cfg.Name, "name", "tun", "interface name (ignored on macOS)")
	var dnsTargets []string
	flag.Func("dns", "host:port of a DNS server mirrored, over TCP, for every DNS query to port 53, repeatable: a later one is asked when the earlier ones fail (default the server the query is addressed to)", func(v string) error {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			return err
		}
		if host == "" {
			return errors.New("missing host")
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("port %q is not a number from 1 to 65535", port)
		}
		dnsTargets = append(dnsTargets, v)
		return nil
	})
	flag.Parse()
	if len(addrs) == 0 {
		addrs = prefixes{netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")}
	}
	cfg.Addresses = addrs
	cfg.Bypass = bypassed

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, dnsTargets); err != nil {
		if errors.Is(err, tun.ErrDenied) {
			fmt.Fprintln(os.Stderr, "tun: the privilege prompt was refused; accept it or run as root/administrator")
		} else {
			fmt.Fprintln(os.Stderr, "tun:", err)
		}
		stop()
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg tun.Config, dnsTargets []string) error {
	dev, err := tun.Open(ctx, cfg)
	if err != nil {
		return err
	}
	capture := tun.CaptureRoutes(cfg)
	log.Printf("interface %s up, %d routes captured", dev.Interface, len(capture))
	for _, w := range dev.Warnings {
		log.Printf("warning: %s", w)
	}

	listen := bypass.NewListenConfig(capture)
	dialer := &logDialer{dialer: bypass.NewDialer(capture), listen: listen, icmp: listen}
	err = stack.Serve(ctx, dev.Device, newHandler(dialer, dnsTargets, cfg.Addresses), stack.Options{MTU: cfg.MTU})
	if ctx.Err() != nil {
		log.Printf("interface %s down", dev.Interface)
		return nil
	}
	return err
}

// newHandler relays every flow through dialer, UDP full cone through its ListenPacket, and ICMP echo through sockets of its icmp config, and answers the DNS queries to port 53, of UDP and of TCP, as a mirror of the server they are addressed to, or of dnsTargets if any, which it asks over TCP.
// It logs every flow, whichever handler serves it, and through dialer each dial and listen that fails.
// It answers itself the ICMP echo to addresses, those of the TUN device, which an OS that routes them into the device expects to be there.
func newHandler(dialer *logDialer, dnsTargets []string, addresses []netip.Prefix) stack.Handler {
	m := stack.NewMux()
	m.Handle("icmp", "", &icmp.Handler{ListenConfig: dialer.icmp})
	for _, address := range addresses {
		m.Handle("icmp", address.Addr().String(), icmp.Echo{})
	}
	m.Handle("tcp", "", &tcp.Handler{Dialer: dialer})
	m.Handle("udp", "", &udp.Handler{Dialer: dialer, ListenConfig: dialer})
	mirror := &dns.Handler{Dialer: dialer, Upstreams: dnsTargets}
	m.Handle("udp", ":53", mirror)
	m.Handle("tcp", ":53", mirror)
	return logged(m)
}

// logDialer dials and listens for the handlers, logging each dial and listen that fails with the client it was for.
type logDialer struct {
	dialer *net.Dialer
	listen stack.ListenConfig
	// icmp opens the sockets of the ICMP echo sessions.
	icmp *net.ListenConfig
}

// logFailure logs err as the failure of a dial or listen of network and address for the client ctx carries.
func logFailure(ctx context.Context, network, address string, err error) {
	client := "unknown"
	if addr := stack.ClientAddr(ctx); addr != nil {
		client = addr.String()
	}
	log.Printf("%s -> %s %s: %v", client, network, address, err)
}

func (d *logDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		logFailure(ctx, network, address, err)
	}
	return conn, err
}

// Listen is unlogged, as the stack never calls it.
func (d *logDialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.listen.Listen(ctx, network, address)
}

func (d *logDialer) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	pc, err := d.listen.ListenPacket(ctx, network, address)
	if err != nil {
		logFailure(ctx, network, address, err)
	}
	return pc, err
}

// logged returns a handler that serves each flow with next and logs it: as it starts, each further target a UDP session sends to, and as it ends, either rejected or with the bytes it carried each way and how long it lasted.
func logged(next stack.Handler) stack.Handler {
	return stack.HandlerFunc(func(ctx context.Context, f stack.Flow) {
		lf := &logFlow{Flow: f, start: time.Now()}
		if f.Network() == "icmp" {
			// Neither end of an echo session has a port.
			lf.name = fmt.Sprintf("%s -> icmp %s", f.Client().Addr(), f.Target().Addr())
		} else {
			lf.name = fmt.Sprintf("%s -> %s %s", f.Client(), f.Network(), f.Target())
		}
		log.Print(lf.name)
		next.ServeFlow(ctx, lf)
		lf.end()
	})
}

// logFlow is a flow that counts the bytes of its accepted conn.
type logFlow struct {
	stack.Flow
	// name is the flow as its log lines begin: its client, network and target.
	name  string
	start time.Time

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
		return &logPacketConn{logConn: lc, pc: pc, client: f.Client(), seen: map[string]bool{f.Target().String(): true}}, nil
	}
	return lc, nil
}

// end logs how the flow ended, once its handler returned: one never accepted was rejected, by the handler or by Serve.
func (f *logFlow) end() {
	f.mu.Lock()
	conn := f.conn
	f.mu.Unlock()
	if conn == nil {
		log.Printf("%s rejected", f.name)
		return
	}
	log.Printf("%s closed: read %d, written %d bytes in %s",
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
			log.Printf("%s -> udp %s", c.client, target)
		}
	}
	return n, addr, err
}

func (c *logPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	n, err := c.pc.WriteTo(b, addr)
	c.read.Add(int64(n))
	return n, err
}

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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/stack"
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
	flag.Parse()
	if len(addrs) == 0 {
		addrs = prefixes{netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")}
	}
	cfg.Addresses = addrs
	cfg.Bypass = bypassed

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		if errors.Is(err, tun.ErrDenied) {
			fmt.Fprintln(os.Stderr, "tun: the privilege prompt was refused; accept it or run as root/administrator")
		} else {
			fmt.Fprintln(os.Stderr, "tun:", err)
		}
		stop()
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg tun.Config) error {
	dev, err := tun.Open(ctx, cfg)
	if err != nil {
		return err
	}
	capture := tun.CaptureRoutes(cfg)
	log.Printf("interface %s up, %d routes captured", dev.Interface, len(capture))
	for _, w := range dev.Warnings {
		log.Printf("warning: %s", w)
	}

	dialer := &logDialer{dialer: bypass.NewDialer(capture)}
	err = stack.Serve(ctx, dev.Device, stack.DefaultMux(dialer), stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	if ctx.Err() != nil {
		log.Printf("interface %s down", dev.Interface)
		return nil
	}
	return err
}

type logDialer struct {
	dialer *net.Dialer
}

func (d *logDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	client := "unknown"
	if addr := stack.ClientAddr(ctx); addr != nil {
		client = addr.String()
	}
	flow := fmt.Sprintf("%s -> %s %s", client, network, address)
	log.Print(flow)
	conn, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		log.Printf("%s: %v", flow, err)
		return nil, err
	}
	return &logConn{Conn: conn, flow: flow, start: time.Now()}, nil
}

type logConn struct {
	read, written int64 // first for 64-bit atomic alignment on 32-bit platforms
	net.Conn
	flow  string
	start time.Time
	once  sync.Once
}

func (c *logConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(&c.read, int64(n))
	return n, err
}

func (c *logConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(&c.written, int64(n))
	return n, err
}

// CloseWrite lets the stack half-close the flow instead of closing both ends at the first EOF.
func (c *logConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *logConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() {
		log.Printf("%s closed: read %d, written %d bytes in %s",
			c.flow, atomic.LoadInt64(&c.read), atomic.LoadInt64(&c.written), time.Since(c.start).Round(time.Millisecond))
	})
	return err
}

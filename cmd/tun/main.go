// Command tun captures the system's traffic into a TUN device, forwards every
// flow directly through the physical interface and logs it.
// It serves a page saying ready over HTTP at port 80, or that of -ready-port, of the address next to each of the device's, by default http://198.18.0.2/ and http://[fd00:6a77:7761::2]/, which answers once the device captures and the flows are served.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	nethttp "net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/flow"
	"github.com/wzshiming/tun/flow/flowlog"
	"github.com/wzshiming/tun/routes"
	"github.com/wzshiming/tun/stack"
	"github.com/wzshiming/tun/stack/dns"
	"github.com/wzshiming/tun/stack/icmp"
	"github.com/wzshiming/tun/stack/tcp"
	"github.com/wzshiming/tun/stack/udp"
	"go4.org/netipx"
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

// settings are what the flags set.
type settings struct {
	tun   tun.Config
	stack stack.Options
	// dnsTargets are the DNS servers mirrored, the server each query is addressed to when empty.
	dnsTargets []string
	// The idles of the handlers, their size and their lifetime, each with the handler's default when 0.
	tcpHalfCloseIdle, udpIdle, icmpIdle, dnsIdle, dnsStale, dnsFailedFor time.Duration
	dnsCacheSize                                                         int
	// readyPort is the port of the ready page, which 0 leaves unserved.
	readyPort uint
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == tun.HelperCommand {
		os.Exit(tun.Helper(os.Args[2:]))
	}

	var s settings
	cfg := &s.tun
	var addrs, bypassed prefixes
	flag.Var(&addrs, "addr", "TUN address in CIDR form, repeatable (default 198.18.0.1/30 and fd00:6a77:7761::1/64)")
	flag.IntVar(&cfg.MTU, "mtu", 1500, "TUN MTU")
	flag.Var(&bypassed, "bypass", "destination CIDR never captured, repeatable; any given replace the defaults (default 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/3, fe80::/10, ff00::/8 and ::/8 but for the NAT64 prefixes 64:ff9b::/96 and 64:ff9b:1::/48)")
	flag.StringVar(&cfg.Name, "name", "tun", "interface name (ignored on macOS)")
	dnsTargets := &s.dnsTargets
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
		*dnsTargets = append(*dnsTargets, v)
		return nil
	})
	flag.DurationVar(&s.dnsIdle, "dns-idle", 0, "how long a DNS flow may idle, and a DNS query wait for its answer (0 means 10s)")
	flag.IntVar(&s.dnsCacheSize, "dns-cache-size", 0, "most DNS replies kept to answer later queries (0 means 4096, negative disables the cache)")
	flag.DurationVar(&s.dnsStale, "dns-stale", 0, "how long past its lifetime a kept DNS reply still answers while the server gives no new one (0 means 24h, negative not at all)")
	flag.DurationVar(&s.dnsFailedFor, "dns-failed-for", 0, "how long a -dns server that failed to answer is asked after the others (0 means 30s, negative not at all)")
	flag.DurationVar(&s.stack.AnswerTimeout, "answer-timeout", 0, "how long a TCP connection may wait for its target to be dialled (0 means 30s)")
	flag.DurationVar(&s.stack.KeepAliveIdle, "tcp-keepalive-idle", 0, "how long a TCP client may stay silent before it is sent keepalive probes (0 means 60s)")
	flag.DurationVar(&s.stack.KeepAliveInterval, "tcp-keepalive-interval", 0, "time between TCP keepalive probes (0 means 15s)")
	flag.DurationVar(&s.tcpHalfCloseIdle, "tcp-half-close-idle", 0, "how long a half-closed TCP connection may idle (0 means 60s)")
	flag.DurationVar(&s.udpIdle, "udp-idle", 0, "how long a UDP session may idle (0 means 60s)")
	flag.DurationVar(&s.icmpIdle, "icmp-idle", 0, "how long an ICMP echo session may idle (0 means 30s)")
	flag.IntVar(&s.stack.MaxUDPSessions, "max-udp-sessions", 0, "most UDP sessions live at once, the idlest ending for one more (0 means 4096, negative no limit)")
	flag.IntVar(&s.stack.MaxICMPSessions, "max-icmp-sessions", 0, "most ICMP echo sessions live at once, the idlest ending for one more (0 means 1024, negative no limit)")
	flag.UintVar(&s.readyPort, "ready-port", 80, "port of the ready page, 0 to serve none")
	flag.Parse()
	if s.readyPort > 65535 {
		fmt.Fprintf(os.Stderr, "tun: -ready-port %d is not a number from 0 to 65535\n", s.readyPort)
		os.Exit(2)
	}
	if len(addrs) == 0 {
		addrs = prefixes{netip.MustParsePrefix("198.18.0.1/30"), netip.MustParsePrefix("fd00:6a77:7761::1/64")}
	}
	if len(bypassed) == 0 {
		bypassed = routes.Reserved()
	}
	cfg.Addresses = addrs
	cfg.Bypass = bypassed
	s.stack.MTU = cfg.MTU

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, s); err != nil {
		if errors.Is(err, tun.ErrDenied) {
			fmt.Fprintln(os.Stderr, "tun: the privilege prompt was refused; accept it or run as root/administrator")
		} else {
			fmt.Fprintln(os.Stderr, "tun:", err)
		}
		stop()
		os.Exit(1)
	}
}

func run(ctx context.Context, s settings) error {
	cfg := s.tun
	dev, err := tun.Open(ctx, cfg)
	if err != nil {
		return err
	}
	capture := tun.CaptureRoutes(cfg)
	log.Printf("interface %s up, %d routes captured", dev.Interface, len(capture))
	for _, w := range dev.Warnings {
		log.Printf("warning: %s", w)
	}

	if s.readyPort != 0 {
		for _, addr := range readyAddrs(cfg.Addresses) {
			host := addr.String()
			if s.readyPort != 80 {
				host = netip.AddrPortFrom(addr, uint16(s.readyPort)).String()
			} else if addr.Is6() {
				host = "[" + host + "]"
			}
			log.Printf("ready page at http://%s/", host)
		}
	}

	listen := bypass.NewListenConfig(capture)
	dialer := &flowlog.Dialer{Dialer: bypass.NewDialer(capture), ListenConfig: listen}
	err = stack.Serve(ctx, dev.Device, newHandler(dialer, listen, s), s.stack)
	if ctx.Err() != nil {
		log.Printf("interface %s down", dev.Interface)
		return nil
	}
	return err
}

// newHandler relays every flow through dialer, UDP full cone through its ListenPacket, and ICMP echo through sockets of icmpListen, and answers the DNS queries to port 53, of UDP and of TCP, as a mirror of the server they are addressed to, or of s.dnsTargets if any, which it asks over TCP.
// It logs every flow, whichever handler serves it, and through dialer each dial and listen that fails.
// It answers itself the ICMP echo to the addresses of the TUN device, which an OS that routes them into the device expects to be there.
// It serves the ready page at s.readyPort, unless 0, of readyAddrs of those addresses.
func newHandler(dialer *flowlog.Dialer, icmpListen *net.ListenConfig, s settings) flow.Handler {
	addresses := s.tun.Addresses
	m := flow.NewMux()
	m.Handle("icmp", "", &icmp.Handler{ListenConfig: icmpListen, Idle: s.icmpIdle})
	for _, address := range addresses {
		m.Handle("icmp", address.Addr().String(), icmp.Echo{Idle: s.icmpIdle})
	}
	m.Handle("tcp", "", &tcp.Handler{Dialer: dialer, HalfCloseIdle: s.tcpHalfCloseIdle})
	m.Handle("udp", "", &udp.Handler{Dialer: dialer, ListenConfig: dialer, Idle: s.udpIdle})
	// The two servers below serve their listeners for as long as the process runs.
	mirror := &dns.Handler{Dialer: dialer, Upstreams: s.dnsTargets, FailedFor: s.dnsFailedFor, Idle: s.dnsIdle, CacheSize: s.dnsCacheSize, Stale: s.dnsStale}
	queries := flow.NewListener()
	m.Handle("udp", ":53", queries)
	m.Handle("tcp", ":53", queries)
	go mirror.Serve(queries)
	if addrs := readyAddrs(addresses); len(addrs) > 0 && s.readyPort != 0 {
		ready := flow.NewListener()
		for _, addr := range addrs {
			m.Handle("tcp", netip.AddrPortFrom(addr, uint16(s.readyPort)).String(), ready)
		}
		go (&nethttp.Server{Handler: nethttp.HandlerFunc(serveReady), ReadHeaderTimeout: 10 * time.Second}).Serve(ready)
	}
	return flowlog.Handler(m, nil)
}

// serveReady answers a request for / with the page that says the TUN serves its flows, which a client reaches only through the device.
func serveReady(w nethttp.ResponseWriter, r *nethttp.Request) {
	if r.URL.Path != "/" {
		nethttp.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "ready\n")
}

// readyAddrs returns, for each of the device's addresses, the address that serves the ready page: the next one of its subnet, else the one before.
// The device's own would not do, as an OS like Linux answers its own addresses itself, without routing them into the device.
// It is never an IPv4 subnet's network or broadcast address, and an address whose subnet has no other gets none.
func readyAddrs(addresses []netip.Prefix) []netip.Addr {
	var addrs []netip.Addr
	for _, address := range addresses {
		subnet := address.Masked()
		usable := func(addr netip.Addr) bool {
			if !addr.IsValid() || !subnet.Contains(addr) {
				return false
			}
			// A /31 has neither a network nor a broadcast address.
			if addr.Is4() && subnet.Bits() < 31 {
				return addr != subnet.Addr() && addr != netipx.PrefixLastIP(subnet)
			}
			return true
		}
		if next := address.Addr().Next(); usable(next) {
			addrs = append(addrs, next)
		} else if prev := address.Addr().Prev(); usable(prev) {
			addrs = append(addrs, prev)
		}
	}
	return addrs
}

// Package bypass keeps a TUN consumer's own sockets off the TUN by binding them to the physical default-route interface.
package bypass

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

// ErrNoDefaultRoute reports that no interface holds the family's default route.
var ErrNoDefaultRoute = errors.New("bypass: no default route")

type boundIface struct {
	Index int
	Name  string
}

type lookupFunc func(ipv6 bool) (boundIface, error)

type bindFunc func(c syscall.RawConn, iface boundIface, ipv6 bool) error

// NewDialer returns a dialer that binds sockets for destinations in capture to the default-route interface current at dial time.
func NewDialer(capture []netip.Prefix) *net.Dialer {
	// Platforms without interface binding leave bindDefault nil.
	if bindDefault == nil {
		return &net.Dialer{}
	}
	return newDialer(capture, lookupDefault, bindDefault, time.Now)
}

func newDialer(capture []netip.Prefix, lookup lookupFunc, bind bindFunc, now func() time.Time) *net.Dialer {
	b := &defaultBinder{lookup: lookup, bind: bind, now: now}
	d := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			ipv6, ok := shouldBind(network, address, capture)
			if !ok {
				return nil
			}
			return b.bindSocket(c, ipv6)
		},
	}
	// DNS server addresses are IP literals, so resolving through d never recurses.
	d.Resolver = &net.Resolver{PreferGo: true, Dial: d.DialContext}
	return d
}

// NewListenConfig returns a listen config that binds every IP socket to the default-route interface of its family;
// Unix sockets are left unbound. Listen on "udp4"/"udp6" (or "tcp4"/"tcp6") or on a literal IP address to pick the family.
// A bare "udp" or "tcp" with a wildcard or host-name address takes the family net chooses, usually IPv6 on a dual-stack
// host, so it binds to the IPv6 default interface and fails with ErrNoDefaultRoute on a host routing only IPv4.
// Any family without a default route fails the same way.
// The interface is fixed when the socket is created: a later default-route change does not move the socket.
// An empty capture, or a platform that cannot bind, yields a zero-value ListenConfig.
func NewListenConfig(capture []netip.Prefix) *net.ListenConfig {
	if len(capture) == 0 || bindDefault == nil {
		return &net.ListenConfig{}
	}
	return newListenConfig(lookupDefault, bindDefault, time.Now)
}

func newListenConfig(lookup lookupFunc, bind bindFunc, now func() time.Time) *net.ListenConfig {
	b := &defaultBinder{lookup: lookup, bind: bind, now: now}
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			switch network {
			case "unix", "unixgram", "unixpacket":
				return nil
			}
			ipv6, err := listenFamily(network, address)
			if err != nil {
				return err
			}
			return b.bindSocket(c, ipv6)
		},
	}
}

// listenFamily takes the family from the network's 4 or 6 suffix, which net always adds before calling Control for IP
// listens, else from address's literal IP; it fails for anything else, reachable only by calling Control directly.
func listenFamily(network, address string) (ipv6 bool, err error) {
	switch network {
	case "tcp4", "udp4", "ip4":
		return false, nil
	case "tcp6", "udp6", "ip6":
		return true, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Control receives ip networks' addresses without a port.
		host = address
	}
	if ip, err := netip.ParseAddr(host); err == nil && !ip.IsUnspecified() {
		return ip.Unmap().Is6(), nil
	}
	return false, fmt.Errorf("bypass: %s listen address %q must name the family (use udp4/udp6 or a literal address)", network, address)
}

// defaultBinder binds sockets to the family's default-route interface, looked up through a per-family cache.
type defaultBinder struct {
	cache  routeCache
	lookup lookupFunc
	bind   bindFunc
	now    func() time.Time
}

func (b *defaultBinder) bindSocket(c syscall.RawConn, ipv6 bool) error {
	iface, err := b.cache.get(ipv6, b.now(), b.lookup)
	if err != nil {
		return err
	}
	if err := b.bind(c, iface, ipv6); err != nil {
		// The interface may be gone, so the next socket looks it up again.
		b.cache.invalidate(ipv6)
		return err
	}
	return nil
}

func lookupDefault(ipv6 bool) (boundIface, error) {
	iface, err := DefaultInterface(ipv6)
	if err != nil {
		return boundIface{}, err
	}
	return boundIface{Index: iface.Index, Name: iface.Name}, nil
}

func shouldBind(network, address string, capture []netip.Prefix) (ipv6 bool, ok bool) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		// Control receives ip networks' addresses without a port.
		host = address
	}
	literal, err := netip.ParseAddr(host)
	if err != nil {
		return false, false
	}
	ip := literal.Unmap()
	switch network {
	case "tcp", "udp", "ip":
		ipv6 = ip.Is6()
	case "tcp4", "udp4", "ip4":
		if !ip.Is4() {
			return false, false
		}
	case "tcp6", "udp6", "ip6":
		// The socket is IPv6 even when the literal is IPv4-mapped.
		if !literal.Is6() {
			return false, false
		}
		ipv6 = true
	default:
		return false, false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false, false
	}
	for _, prefix := range capture {
		if prefix.Contains(ip) {
			return ipv6, true
		}
	}
	return false, false
}

const routeTTL = time.Second

type routeEntry struct {
	iface   boundIface
	err     error
	expires time.Time
}

// routeCache caches failed lookups too, so a missing route costs one lookup per TTL rather than one per dial.
type routeCache struct {
	mu      sync.Mutex
	entries map[bool]routeEntry
}

func (c *routeCache) get(ipv6 bool, now time.Time, lookup lookupFunc) (boundIface, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[ipv6]; ok && now.Before(e.expires) {
		return e.iface, e.err
	}
	iface, err := lookup(ipv6)
	if c.entries == nil {
		c.entries = make(map[bool]routeEntry, 2)
	}
	c.entries[ipv6] = routeEntry{iface: iface, err: err, expires: now.Add(routeTTL)}
	return iface, err
}

func (c *routeCache) invalidate(ipv6 bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ipv6)
}

# tun

`github.com/wzshiming/tun` captures a machine's IP traffic into a TUN device and hands every flow to a Go handler of your choice. It opens the TUN device with the privileges it needs (prompting the user when the process is not root/administrator), installs routes that capture everything except what must escape, runs a gVisor userspace network stack that turns packets back into TCP connections and UDP sessions and dispatches them by network and destination port, ships handlers that relay TCP through a `Dialer` and UDP full cone through a `ListenConfig` (symmetric through the `Dialer` without one), DNS on UDP port 53 over TCP, and provides a dialer and a listen config bound to the physical interface so forwarded traffic does not loop back into the TUN. It runs on macOS, Linux and Windows 10+.

## Install

```sh
go get github.com/wzshiming/tun
```

## Packages

### `tun` — the device

- `type Config struct { Addresses []netip.Prefix; MTU int; Bypass []netip.Prefix; Name string }` — the TUN's own addresses, its MTU, destinations never captured, and the interface name (default `tun`; ignored on macOS; Linux appends `%d` when absent; the adapter name on Windows).
- `type Device struct { tun.Device; Interface string; Warnings []string }` — embeds a `golang.zx2c4.com/wireguard/tun` device, plus the real interface name and non-fatal setup warnings.
- `func Open(ctx context.Context, cfg Config) (*Device, error)` — validates `cfg`, creates the device, assigns the addresses and installs the capture routes. Without root/administrator rights it re-executes the current binary as `<exe> tun-helper …` with elevated rights, so your `main` must dispatch that subcommand.
- `const HelperCommand = "tun-helper"` and `func Helper(args []string) int` — the helper subcommand and its entry point; the return value is the exit code.
- `func CaptureRoutes(cfg Config) []netip.Prefix` — the routes `Open` captures.
- `var ErrDenied error` — the privilege prompt was refused. `var ErrUnsupported error` — the platform is not supported.

### `stack` — the userspace network stack

- `type Dialer interface { DialContext(ctx context.Context, network, address string) (net.Conn, error) }`
- `type ListenConfig interface { Listen(ctx context.Context, network, address string) (net.Listener, error); ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) }` — opens listening sockets, shaped like the standard library's; `*net.ListenConfig` is one.
- `type Flow interface { Network() string; Target() netip.AddrPort; Client() netip.AddrPort; Accept() (net.Conn, error); Reject() }` — a captured TCP connection or UDP session: `Accept` completes the TCP handshake or returns the UDP session's conn (see [UDP](#udp)), once; `Reject` resets the TCP client or drops the session's datagrams.
- `type Handler interface { ServeFlow(ctx context.Context, f Flow) }` and `type HandlerFunc func(context.Context, Flow)` — called once per flow on its own goroutine; when it returns, an unanswered flow is rejected and an accepted conn is closed.
- `type Mux struct { Fallback Handler }` with `func NewMux() *Mux`, `func (m *Mux) Handle(network, pattern string, h Handler)` and `func (m *Mux) ServeFlow(ctx context.Context, f Flow)` — dispatches by `"tcp"`/`"udp"` and a destination pattern in the standard library's host:port syntax: `""` any address and port, `host` any port, `host:port`, `:port` any address; `host` is an IP (`1.1.1.1`, `2001:db8::1`) or a CIDR prefix (`10.0.0.0/8`, host bits masked off), bracketed when IPv6 with a port (`[fd00::/8]:53`); port 0 means any port; an IPv4-mapped IPv6 address counts as IPv4. A flow goes to the longest prefix containing its destination, of its family, that has a handler for its port or for any port, falling through to shorter prefixes and then the any-address patterns; with none it goes to `Fallback`, set before serving, or is rejected when `Fallback` is nil. `Handle` panics on another network, a nil handler, an invalid or duplicate pattern. A `Mux` is a `Handler`, so it can serve a pattern of another `Mux`, dispatching with its own patterns and `Fallback` and never back to the outer one. A UDP session goes by its first datagram's address and port.
- `type Relay struct { Dialer Dialer; ListenConfig ListenConfig; Idle time.Duration }` — dials a TCP flow's target first, resetting the client when that fails, then pipes both ways. Accepts a UDP session and relays it full cone when `ListenConfig` is set, symmetric otherwise (see [UDP](#udp)), ending it after `Idle` (default 60s) without datagrams either way.
- `type DNS struct { Dialer Dialer; Idle time.Duration }` — relays each datagram of a UDP session as a length-framed message over one TCP connection per server it sends to, dialled through `Dialer`, and the replies back from that server; the session ends after `Idle` (default 10s) without datagrams; rejects TCP.
- `func DefaultMux(dialer Dialer) *Mux` — `Handle("tcp", "", Relay)`, `Handle("udp", ":53", DNS)` and `Handle("udp", "", Relay)`, no `Fallback`: `Relay` for every TCP and UDP destination, except `DNS` for UDP port 53. When `dialer` also implements `ListenConfig`, the UDP `Relay` gets it as `ListenConfig` and relays full cone; a wrapper around a dialer must forward `Listen` and `ListenPacket` to keep that.
- `type Options struct { MTU int; Addresses []netip.Prefix }`
- `func Serve(ctx context.Context, dev wgtun.Device, handler Handler, opts Options) error` — hands every captured flow of `dev`, a `golang.zx2c4.com/wireguard/tun` device such as `(*tun.Device).Device`, to `handler` (nil refuses them all, UDP with ICMP port unreachable); returns when `ctx` ends or the device fails, once every `ServeFlow` has returned, and closes the device.
- `func ClientAddr(ctx context.Context) net.Addr` — inside `DialContext` or `ListenPacket`, the captured flow's source (`*net.TCPAddr` or `*net.UDPAddr`), nil when absent; `WithClientAddr` sets it.

### `bypass` — escaping the TUN

- `func NewDialer(capture []netip.Prefix) *net.Dialer` — a dialer that binds connections to captured destinations onto the default-route interface.
- `func NewListenConfig(capture []netip.Prefix) *net.ListenConfig` — a listen config that binds every socket onto its family's default-route interface, fixed at creation; pass it as `Relay.ListenConfig` for direct egress.
- `func DefaultInterface(ipv6 bool) (*net.Interface, error)` and `var ErrNoDefaultRoute error`.

## UDP

- **Sessions.** `Serve` gives each client socket, keyed by its address and port, one UDP session carrying every datagram it sends, to any target. `Flow.Target` is the first datagram's destination. The `Mux` picks the component by that first datagram's address and port and the whole session goes to it, so a socket that later sends to another address or port stays with the first component.
- **The session conn** is a `net.Conn` and a `net.PacketConn`: `ReadFrom` returns each datagram with the `*net.UDPAddr` the client sent it to; `WriteTo(b, src)` delivers `b` to the client as if from `src`; `Read` and `Write` are the view connected to `Flow.Target`; read deadlines apply; `Close` ends the session, and the client's next datagram starts a new one.
- **`Relay` full cone**, when `ListenConfig` is set: one unconnected `"udp4"` or `"udp6"` socket per session, by the client's family, sends every target's datagrams, and every datagram it receives, from any source, reaches the client with that source's real address. A failed `ListenPacket` ends the session silently.
- **`Relay` symmetric**, when `ListenConfig` is nil: one connected socket dialled per target, replies coming only from that target; the only mode for dialers that cannot provide unconnected sockets, such as proxy chains. A slow dial delays only its own target.
- **`DefaultMux`** relays full cone when its dialer is also a `ListenConfig`, symmetric otherwise. For direct egress, `bypass.NewListenConfig` is the `ListenConfig`.
- **`DNS`** carries UDP port 53 over TCP: one TCP connection per server within a session.
- **Unhandled UDP**, whose first datagram's address and port match no pattern of the `Mux` and which has no `Fallback`, is dropped; ICMP port unreachable is sent only when `Serve`'s handler is nil.
- **Interface.** A relay socket stays on the interface it was bound to at creation: after a default-route change, new sessions use the new interface while running ones keep the old one until they idle out (60s by default).

## Example

```go
func main() {
	if len(os.Args) > 1 && os.Args[1] == tun.HelperCommand {
		os.Exit(tun.Helper(os.Args[2:]))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	cfg := tun.Config{
		Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		MTU:       1500,
	}
	dev, err := tun.Open(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	capture := tun.CaptureRoutes(cfg)
	dialer := &logDialer{dialer: bypass.NewDialer(capture), listen: bypass.NewListenConfig(capture)}
	err = stack.Serve(ctx, dev.Device, stack.DefaultMux(dialer), stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

type logDialer struct {
	dialer *net.Dialer
	listen stack.ListenConfig
}

func (d *logDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	log.Println(stack.ClientAddr(ctx), "->", network, address)
	return d.dialer.DialContext(ctx, network, address)
}

// Listen and ListenPacket make logDialer a stack.ListenConfig, keeping DefaultMux's UDP relay full cone.
func (d *logDialer) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return d.listen.Listen(ctx, network, address)
}

func (d *logDialer) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return d.listen.ListenPacket(ctx, network, address)
}
```

## Privileges

A process running as root/administrator opens the device directly. Otherwise `Open` starts the current executable as `<exe> tun-helper …` with elevated rights; the helper creates the device and the routes. On macOS and Linux it hands the device's descriptor to the parent and exits once the parent closes the connection; on Windows it serves the session and exits when the parent closes the connection. A refused prompt makes `Open` return `ErrDenied`.

- **macOS**: an `osascript` administrator prompt.
- **Linux**: `pkexec` (polkit). The helper configures the device with iproute2, so the `ip` command must be installed.
- **Windows**: a UAC prompt on each `Open`. The elevated helper creates a Wintun adapter and relays packets to the parent over a token-checked loopback connection. Requires Windows 10 or later.

### Wintun

Windows builds embed the unmodified Wintun 0.14.1 DLL, made by WireGuard LLC, through [github.com/wzshiming/wintun](https://github.com/wzshiming/wintun), which loads it in memory, so no file is written. The DLL is distributed under the license in that module's [embedded/LICENSE.txt](https://github.com/wzshiming/wintun/blob/master/embedded/LICENSE.txt). Windows installs the Wintun driver on the first `Open`.

## What is captured

`CaptureRoutes` returns `0.0.0.0/0` and `::/0` for each address family the TUN has an address in, minus `Config.Bypass`, the TUN's own addresses and a few fixed holes. `Open` routes exactly those prefixes into the TUN.

Traffic forwarded to the real network must not be captured again. The `bypass` dialer binds connections to captured destinations, and its listen config every socket, onto the default-route interface: `IP_BOUND_IF` on macOS, `SO_BINDTODEVICE` on Linux, `IP_UNICAST_IF` on Windows.

## Limits

- UDP: see [UDP](#udp) — a session is dispatched by its first datagram's address and port, and a relay socket keeps the interface it was created on.
- Linux: binding to an interface with `SO_BINDTODEVICE` without privileges requires kernel 5.7 or later.

## Command `cmd/tun`

`cmd/tun` captures the traffic, forwards every flow directly through the physical interface, UDP full cone, and logs it: the flow (`<client> -> <network> <address>`), dial and listen errors, and on close the bytes read and written and the duration; a UDP session logs `<client> -> udp <address>` once for each target it sends to.

```sh
go run ./cmd/tun [flags]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-addr` | `198.18.0.1/30` and `fd00:6a77:7761::1/64` | TUN address in CIDR form, repeatable |
| `-mtu` | `1500` | TUN MTU |
| `-bypass` | none | destination CIDR never captured, repeatable |
| `-name` | `tun` | interface name (ignored on macOS) |

It exits 0 on SIGINT/SIGTERM once the device is open and 1 on any error; a SIGINT/SIGTERM while the device is still opening, such as during the privilege prompt, exits 1.

## End-to-end tests

The end-to-end tests in `./e2e` open real TUN devices, a Wintun adapter on Windows, change the machine's routes and bind sockets to its default interface. Every test skips unless `TUN_E2E=1`; with it set, each runs when the process has the privileges it needs and skips otherwise. The test binary is its own helper.

```sh
TUN_E2E=1 go test ./e2e -v                          # TestE2EHelper: starts its helper with sudo -n
go test -c -o tun-e2e.test ./e2e
sudo -n env TUN_E2E=1 ./tun-e2e.test -test.v        # TestE2ERoot: needs root and an IPv4 default route
```

- **macOS and Linux**: `TestE2EHelper` runs as a normal user and starts its helper with `sudo -n`, so it skips unless passwordless `sudo` is available; `TestE2ERoot` runs as root. The bypass test needs a default route, and on Linux before 5.7 root.
- **Windows**: 386, amd64 or arm64. `TestE2EWindowsLocal` and `TestE2EWindowsHelper` need an elevated process; `TestE2EWindowsHelperRunas` additionally needs `TUN_E2E_RUNAS=1`, as it goes through UAC. The bypass tests need no elevation.

## License

MIT, see [LICENSE](LICENSE). The embedded Wintun DLL is covered by its own license, see [Wintun](#wintun).
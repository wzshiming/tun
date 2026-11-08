# tun

`github.com/wzshiming/tun` captures a machine's IP traffic into a TUN device and hands every flow to a Go handler of your choice. It opens the TUN device with the privileges it needs (prompting the user when the process is not root/administrator), installs routes that capture everything except what must escape, runs a gVisor userspace network stack that turns packets back into TCP connections and UDP flows and dispatches them by network and destination port, ships handlers that relay TCP and UDP through a dialer, DNS on UDP port 53 over TCP, and provides a dialer bound to the physical interface so forwarded traffic does not loop back into the TUN. It runs on macOS, Linux and Windows 10+.

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
- `type Flow interface { Network() string; Target() netip.AddrPort; Client() netip.AddrPort; Accept() (net.Conn, error); Reject() }` — a captured TCP connection or UDP flow: `Accept` completes the TCP handshake or returns the UDP flow's datagram conn (one datagram per `Read`), once; `Reject` resets the TCP client or drops the UDP datagrams.
- `type Handler interface { ServeFlow(ctx context.Context, f Flow) }` and `type HandlerFunc func(context.Context, Flow)` — called once per flow on its own goroutine; when it returns, an unanswered flow is rejected and an accepted conn is closed.
- `type Mux struct` with `func NewMux() *Mux`, `func (m *Mux) Handle(network string, port uint16, h Handler)` and `func (m *Mux) ServeFlow(ctx context.Context, f Flow)` — dispatches by `"tcp"`/`"udp"` and destination port, port 0 being the network's fallback; a flow without a handler is rejected.
- `type Relay struct { Dialer Dialer; Idle time.Duration }` — dials a TCP flow's target first, resetting the client when that fails, then pipes both ways; accepts a UDP flow, dials its target as `"udp"` and relays its datagrams one for one both ways, ending the flow after `Idle` (default 60s) without datagrams or when the dial fails.
- `type DNS struct { Dialer Dialer; Idle time.Duration }` — relays a UDP flow's datagrams as length-framed messages over one TCP connection to its target; the flow ends after `Idle` (default 10s) without datagrams; rejects TCP.
- `func DefaultMux(dialer Dialer) *Mux` — `Relay` for every TCP and UDP port, except `DNS` for UDP port 53.
- `type Options struct { MTU int; Addresses []netip.Prefix }`
- `func Serve(ctx context.Context, dev wgtun.Device, handler Handler, opts Options) error` — hands every captured flow of `dev`, a `golang.zx2c4.com/wireguard/tun` device such as `(*tun.Device).Device`, to `handler` (nil refuses them all, UDP with ICMP port unreachable); returns when `ctx` ends or the device fails, once every `ServeFlow` has returned, and closes the device.
- `func ClientAddr(ctx context.Context) net.Addr` — inside `DialContext`, the captured flow's source (`*net.TCPAddr` or `*net.UDPAddr`), nil when absent; `WithClientAddr` sets it.

### `bypass` — escaping the TUN

- `func NewDialer(capture []netip.Prefix) *net.Dialer` — a dialer that binds connections to captured destinations onto the default-route interface.
- `func NewListenConfig(capture []netip.Prefix) *net.ListenConfig` — a listen config that binds every socket onto its family's default-route interface, fixed at creation.
- `func DefaultInterface(ipv6 bool) (*net.Interface, error)` and `var ErrNoDefaultRoute error`.

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
	direct := bypass.NewDialer(tun.CaptureRoutes(cfg))
	dialer := dialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		log.Println(stack.ClientAddr(ctx), "->", network, address)
		return direct.DialContext(ctx, network, address)
	})
	err = stack.Serve(ctx, dev.Device, stack.DefaultMux(dialer), stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
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

Traffic forwarded to the real network must not be captured again. The `bypass` dialer binds connections to captured destinations onto the default-route interface: `IP_BOUND_IF` on macOS, `SO_BINDTODEVICE` on Linux, `IP_UNICAST_IF` on Windows.

## Limits

- UDP: `DefaultMux` relays UDP through the dialer as `"udp"` by default; port 53 is handled by the `DNS` component over TCP. UDP to a port the `Mux` has no component for is dropped; ICMP port unreachable is only sent when `Serve`'s handler is nil.
- Linux: binding to an interface with `SO_BINDTODEVICE` without privileges requires kernel 5.7 or later.

## Command `cmd/tun`

`cmd/tun` captures the traffic, forwards every flow directly through the physical interface and logs it: the flow (`<client> -> <network> <address>`), dial errors, and on close the bytes read and written and the duration.

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
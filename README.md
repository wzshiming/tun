# tun

`github.com/wzshiming/tun` captures a machine's IP traffic into a TUN device and hands every flow to a Go dialer of your choice. It opens the TUN device with the privileges it needs (prompting the user when the process is not root/administrator), installs routes that capture everything except what must escape, runs a gVisor userspace network stack that turns packets back into TCP connections and DNS queries, and provides a dialer bound to the physical interface so forwarded traffic does not loop back into the TUN. It runs on macOS, Linux and Windows 10+.

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
- `type Options struct { MTU int; Addresses []netip.Prefix; DNSIdle time.Duration }`
- `func Serve(ctx context.Context, dev tun.Device, dialer Dialer, opts Options) error` — relays every captured flow through `dialer`; returns when `ctx` ends or the device fails, and closes the device.
- `func ClientAddr(ctx context.Context) net.Addr` — inside `DialContext`, the captured flow's source (`*net.TCPAddr` or `*net.UDPAddr`), nil when absent.

### `bypass` — escaping the TUN

- `func NewDialer(capture []netip.Prefix) *net.Dialer` — a dialer that binds connections to captured destinations onto the default-route interface.
- `func DefaultInterface(ipv6 bool) (*net.Interface, error)` and `var ErrNoDefaultRoute error`.

### `wintun` — the embedded Wintun DLL

- `const Embedded bool` — Windows only: whether this build carries a `wintun.dll` (amd64 and arm64).
- `var CacheDir func() (string, error)` — where the embedded `wintun.dll` is extracted on Windows (default `os.UserCacheDir()/tun`).
- `func Load() error` — Windows only: extracts the embedded `wintun.dll` under `CacheDir()`, verifies it and loads it once per process; wraps `errors.ErrUnsupported` when none is embedded. The process that creates the adapter, `Open`'s or its elevated helper, calls it.

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
	err = stack.Serve(ctx, dev.Device, dialer, stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
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

The module embeds the unmodified Wintun 0.14.1 DLLs for amd64 and arm64, made by WireGuard LLC and distributed under the license in [wintun/bin/LICENSE.txt](wintun/bin/LICENSE.txt). The DLL is extracted under `wintun.CacheDir()` and verified before it is loaded. Windows installs the Wintun driver on the first `Open`.

## What is captured

`CaptureRoutes` returns `0.0.0.0/0` and `::/0` for each address family the TUN has an address in, minus `Config.Bypass`, the TUN's own addresses and a few fixed holes. `Open` routes exactly those prefixes into the TUN.

Traffic forwarded to the real network must not be captured again. The `bypass` dialer binds connections to captured destinations onto the default-route interface: `IP_BOUND_IF` on macOS, `SO_BINDTODEVICE` on Linux, `IP_UNICAST_IF` on Windows.

## Limits

- UDP: only DNS (port 53) is relayed, over TCP through the dialer; all other UDP is answered with ICMP port unreachable.
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

The end-to-end tests in `./e2e` open real TUN devices, change the machine's routes, bind sockets to its default interface and load the real `wintun.dll`. Every test skips unless `TUN_E2E=1`; with it set, each runs when the process has the privileges it needs and skips otherwise. The test binary is its own helper.

```sh
TUN_E2E=1 go test ./e2e -v                          # TestE2EHelper: starts its helper with sudo -n
go test -c -o tun-e2e.test ./e2e
sudo -n env TUN_E2E=1 ./tun-e2e.test -test.v        # TestE2ERoot: needs root and an IPv4 default route
```

- **macOS and Linux**: `TestE2EHelper` runs as a normal user and starts its helper with `sudo -n`, so it skips unless passwordless `sudo` is available; `TestE2ERoot` runs as root. The bypass test needs a default route, and on Linux before 5.7 root.
- **Windows**: amd64 or arm64. `TestE2EWindowsLocal` and `TestE2EWindowsHelper` need an elevated prompt; `TestE2EWindowsHelperRunas` additionally needs `TUN_E2E_RUNAS=1`, as it goes through UAC. `TestE2EWintunLoad` and the bypass tests need no elevation.

## License

MIT, see [LICENSE](LICENSE). The embedded Wintun DLLs are covered by [wintun/bin/LICENSE.txt](wintun/bin/LICENSE.txt).
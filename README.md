# tun

Captures a machine's IP traffic into a TUN device for your program to serve flow by flow. `tun` opens the device, prompting for privileges when the process is not root/administrator, and installs the capture routes; `stack` runs a gVisor userspace stack that turns the packets back into TCP connections and UDP sessions and hands them to your `Handler`; `bypass` provides a dialer and a listen config bound to the physical interface so forwarded traffic is not captured again. Runs on macOS, Linux and Windows 10+.

```sh
go get github.com/wzshiming/tun
```

## Usage

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
	direct := egress{bypass.NewDialer(capture), bypass.NewListenConfig(capture)}
	err = stack.Serve(ctx, dev.Device, stack.DefaultMux(direct), stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

// egress is a stack.Dialer and, through the embedded ListenConfig, a stack.ListenConfig, so UDP is relayed full cone.
type egress struct {
	*net.Dialer
	*net.ListenConfig
}

func (e egress) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	log.Println(stack.ClientAddr(ctx), "->", network, address)
	return e.Dialer.DialContext(ctx, network, address)
}
```

## API

### `tun`

- `Config`: `Addresses`, one or two prefixes with at most one per family; `MTU`, 1280 to 65535; `Bypass`, destinations never captured; `Name`, the interface name, `tun` when empty. macOS ignores `Name` and picks a `utunN`; Linux appends `%d` unless present, the pattern at most 15 bytes; Windows names the Wintun adapter with it, at most 127 bytes, and derives the adapter GUID from it.
- `Open(ctx, cfg) (*Device, error)` validates `cfg`, creates the device, assigns the addresses and routes `CaptureRoutes(cfg)` into it. Without root/administrator rights it re-executes the current binary as `<exe> tun-helper …` with elevated rights, so `main` must dispatch `HelperCommand` to `Helper(args) int`, whose result is the exit code.
- `Device` embeds a `golang.zx2c4.com/wireguard/tun` device; `Interface` is the real interface name and `Warnings` the configuration that failed without failing `Open`.
- `CaptureRoutes(cfg) []netip.Prefix`: `0.0.0.0/0` and `::/0` for each address family the TUN has an address in, minus `Bypass`, the TUN's own addresses and a few fixed holes (loopback, link-local, multicast, broadcast).
- `ErrDenied`: the privilege prompt was refused. `ErrUnsupported`: the platform has no TUN support.

### `stack`

- `Serve(ctx, dev, handler, opts) error` hands every TCP connection and UDP session of `dev` to `handler` until `ctx` ends or reading the device fails, waits for every `ServeFlow` to return, and closes the device.
- `Options`: `MTU`, 0 takes the device's; `Addresses`, the gateway's own, the only ones answering ICMP echo.
- `Handler` has one method, `ServeFlow(ctx, f)`, called once per flow on its own goroutine; when it returns, a flow neither accepted nor rejected is rejected and an accepted conn still open is closed. `HandlerFunc` makes a function a `Handler`.
- `Flow`: `Network()` is `"tcp"` or `"udp"`, `Target()` the destination, `Client()` the source; `Accept()` completes the TCP handshake or returns the UDP session's conn, also a `net.PacketConn` whose `ReadFrom` gives each datagram's target and whose `WriteTo` answers from any specified address of the client's family; `Reject()` resets TCP or drops UDP. A UDP session groups the datagrams one client address and port sends, to any target, and is dispatched by its first datagram's destination address and port.
- `Mux`, from `NewMux()`: `Handle(network, pattern, h)` registers `h` for `"tcp"` or `"udp"` and a destination pattern, `""` for any, `host`, `host:port` or `:port`, where `host` is an IP or a CIDR prefix, IPv6 bracketed before a port, and port 0 means any port; it panics on an invalid or duplicate pattern. A flow tries the prefixes containing its destination, longest first, each for its port then for any port, then the any-address patterns, then `Fallback`. A `Mux` is itself a `Handler`.
- `Relay{Dialer, ListenConfig, Idle}` dials a TCP flow's target before accepting it, so a failed dial resets the client, then pipes both ways. It relays a UDP session full cone through one socket from `ListenConfig` when that is set, else symmetric through one dialled conn per target, and ends it after `Idle` without datagrams, 60s by default.
- `DNS{Dialer, Idle}` relays a UDP session's datagrams as length-framed messages over one TCP connection per target, dialled through `Dialer`, and ends it after `Idle` without datagrams, 10s by default; it rejects TCP.
- `DefaultMux(dialer)` is the default wiring, three patterns: `""` for `"tcp"` and for `"udp"` to `Relay` through `dialer`, and `":53"` for `"udp"` to `DNS` through `dialer`, so every TCP connection and UDP session is relayed, except a UDP session whose first datagram goes to port 53, which `DNS` carries over TCP. The UDP relay is full cone when `dialer` is also a `ListenConfig`, symmetric otherwise; a wrapper around a dialer must forward `Listen` and `ListenPacket` to keep full cone. To serve flows your own way, `Handle` your own `Handler` on a `Mux`, `DefaultMux`'s included for any other pattern, set `Fallback` for what no pattern matches, or pass any `Handler` straight to `Serve`. A flow nobody handles is rejected: TCP is reset, UDP is dropped; UDP is answered with ICMP port unreachable only when `Serve`'s handler is nil.
- `Dialer` is `DialContext(ctx, network, address)`; `ListenConfig` is `Listen` plus `ListenPacket`, as `*net.ListenConfig` has them. In the dials of `Relay` and `DNS` and in `Relay`'s `ListenPacket`, `ClientAddr(ctx)` is the flow's source, a `*net.TCPAddr` or `*net.UDPAddr`.

### `bypass`

- `NewDialer(capture) *net.Dialer` binds connections to destinations in `capture` onto the default-route interface at dial time (`IP_BOUND_IF` on macOS, `SO_BINDTODEVICE` on Linux, `IP_UNICAST_IF` on Windows) and resolves names through itself.
- `NewListenConfig(capture) *net.ListenConfig` binds every IP socket onto its family's default-route interface, which `udp4`/`udp6` or a literal address picks, or none when `capture` is empty; the interface is fixed when the socket is created, so a full-cone UDP session keeps it after a route change.
- `DefaultInterface(ipv6) (*net.Interface, error)` returns the interface holding the family's default route, or `ErrNoDefaultRoute`.

## Platforms

| | Prompt | Notes |
| --- | --- | --- |
| macOS | `osascript` | the helper hands the device descriptor to the parent and exits |
| Linux | `pkexec` | as macOS; needs the `ip` command; unprivileged `SO_BINDTODEVICE` needs kernel 5.7+ |
| Windows 10+ | UAC on each `Open` | 386, amd64 and arm64; the elevated helper runs a Wintun adapter and relays packets to the parent over a token-checked loopback connection; the first `Open` installs the Wintun driver |

## `cmd/tun`

Captures the traffic, forwards every flow directly and logs it.

```sh
go run ./cmd/tun [-addr CIDR]... [-mtu 1500] [-bypass CIDR]... [-name tun]
```

`-addr` defaults to `198.18.0.1/30` and `fd00:6a77:7761::1/64`. Exits 0 on SIGINT/SIGTERM once the device is open, 1 otherwise.

## License

MIT, see [LICENSE](LICENSE).

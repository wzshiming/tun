//go:build darwin || linux

package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/elevate"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/internal/hook"
)

// TestE2EHelper swaps hook.Launch, so it must not run in parallel.
func TestE2EHelper(t *testing.T) {
	ttGate(t)
	if hook.IsElevated() {
		t.Skip("runs unprivileged")
	}
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		t.Skipf("starts its helper with sudo -n: %v", err)
	}
	probe, cancelProbe := context.WithTimeout(context.Background(), 10*time.Second)
	err = exec.CommandContext(probe, sudo, "-n", "true").Run()
	cancelProbe()
	if err != nil {
		t.Skipf("starts its helper with sudo -n, which needs passwordless sudo: %v", err)
	}
	prev := hook.Launch
	t.Cleanup(func() { hook.Launch = prev })
	hook.Launch = func(ctx context.Context, exe string, args []string) (elevate.Proc, error) {
		cmd := exec.CommandContext(ctx, sudo, append([]string{"-n", exe}, args...)...)
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return ttExecProc{cmd}, nil
	}

	// Bypassing everything else keeps the runner's own traffic off the TUN.
	captured := ttPrefixes("1.1.1.1/32", "2606:4700:4700::1111/128", netip.PrefixFrom(ttUDPEchoTarget.Addr(), 32).String(), netip.PrefixFrom(ttConeSecondTarget.Addr(), 32).String())
	cfg := ttConfig(ttSet(t, ttPrefixes("0.0.0.0/0", "::/0"), captured).Prefixes())
	want := captured
	if got := tun.CaptureRoutes(cfg); len(got) != len(want) || slices.ContainsFunc(want, func(p netip.Prefix) bool { return !slices.Contains(got, p) }) {
		t.Fatalf("CaptureRoutes = %v, want exactly %v", got, want)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dev := ttOpen(t, ctx, cfg)
	if len(dev.Warnings) != 0 {
		t.Fatalf("Open warned: %q", dev.Warnings)
	}
	echo := ttServeLocal(t, ttEchoServer)
	rec := &ttDialRecorder{
		redirect: map[string]string{
			"1.1.1.1:8080":                echo,
			"[2606:4700:4700::1111]:8080": echo,
			ttUDPEchoTarget.String():      ttServeUDPEcho(t),
			ttConeSecondTarget.String():   ttServeUDPEcho(t),
		},
		dns: ttServeLocal(t, ttDNSServer),
	}
	rec.logDialErrorsOnFailure(t)
	errCh := ttServeDev(ctx, dev, cfg, rec)

	ttWaitFor(t, 10*time.Second, func() bool {
		return ttIfaceHas(dev.Interface, "198.18.0.1") && ttIfaceHas(dev.Interface, "fd00:6a77:7761::1")
	}, dev.Interface+" to hold 198.18.0.1 and fd00:6a77:7761::1")
	for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111", ttUDPEchoTarget.Addr().String(), ttConeSecondTarget.Addr().String()} {
		if got := ttRouteDev(t, ip); got != dev.Interface {
			t.Fatalf("route to %s leaves through %q, want %s", ip, got, dev.Interface)
		}
	}
	if got := ttRouteDev(t, "8.8.8.8"); got == dev.Interface {
		t.Errorf("route to 8.8.8.8 leaves through %s, want it left off the TUN", got)
	}

	t.Run("tcp4 echo", func(t *testing.T) { ttEchoVia(t, rec, "1.1.1.1:8080", "198.18.0.1") })
	t.Run("tcp6 echo", func(t *testing.T) { ttEchoVia(t, rec, "[2606:4700:4700::1111]:8080", "fd00:6a77:7761::1") })
	t.Run("dns over udp", func(t *testing.T) {
		ttDNSVia(t, "1.1.1.1:53")
		rec.wantDial(t, "tcp", "1.1.1.1:53", "")
	})
	t.Run("udp relayed", func(t *testing.T) {
		conn, err := net.ListenUDP("udp4", nil)
		if err != nil {
			t.Fatalf("listen udp4: %v", err)
		}
		defer conn.Close()
		ttConeEchoFrom(t, conn, ttUDPEchoTarget)
		ttConeEchoFrom(t, conn, ttConeSecondTarget)
		injected := []byte("from a source never sent to")
		ttConeAwait(t, conn, ttConeInjectedSource, injected, func() { rec.inject(t, ttConeInjectedSource, injected) })
		rec.wantDial(t, "udp", ttUDPEchoTarget.String(), "198.18.0.1")
		rec.wantDial(t, "udp", ttConeSecondTarget.String(), "198.18.0.1")
	})
	t.Run("udp without a handler is dropped", func(t *testing.T) {
		conn, err := net.Dial("udp", "1.1.1.1:9999")
		if err != nil {
			t.Fatalf("dial udp 1.1.1.1:9999: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write(make([]byte, 8)); err != nil {
			t.Fatalf("send to udp 1.1.1.1:9999: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("read from udp 1.1.1.1:9999 = %v, want a timeout with no reply and no ICMP port unreachable", err)
		}
		if dials := rec.dialsTo("1.1.1.1:9999"); len(dials) != 0 {
			t.Errorf("Serve dialed %+v, want UDP to port 9999 never dialed", dials)
		}
		// A Serve that died would also leave the datagram unanswered.
		select {
		case err := <-errCh:
			t.Fatalf("Serve returned %v while UDP to port 9999 went unanswered, want it still serving", err)
		default:
		}
	})
	t.Run("ping", func(t *testing.T) {
		for _, ip := range []string{"198.18.0.1", "fd00:6a77:7761::1"} {
			if !ttPingOK(t, ip) {
				t.Errorf("ping %s got no reply", ip)
			}
		}
	})

	ttTeardown(t, cancel, errCh, dev)
	conn, err := net.DialTimeout("tcp", echo, 5*time.Second)
	if err != nil {
		t.Fatalf("dial the echo server at %s after teardown: %v", echo, err)
	}
	defer conn.Close()
	ttEcho(t, conn, 1<<10)
}

func TestE2ERoot(t *testing.T) {
	ttGate(t)
	if !hook.IsElevated() {
		t.Skip("needs root")
	}
	phys, err := bypass.DefaultInterface(false)
	if err != nil {
		t.Skipf("no IPv4 default route for the bypass dialer: %v", err)
	}
	// Loopback, the private ranges, IPv6 link-local and ULA stay off the TUN.
	cfg := ttConfig(ttPrefixes("127.0.0.1/32", "::1/128", "192.168.0.0/16", "10.0.0.0/8", "fe80::/64", "fd00::/8"))
	capture := tun.CaptureRoutes(cfg)
	if len(capture) <= 50 {
		t.Fatalf("CaptureRoutes = %v, want more than 50 routes", capture)
	}
	for _, kept := range ttPrefixes("10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4") {
		if i := slices.IndexFunc(capture, kept.Overlaps); i >= 0 {
			t.Fatalf("capture route %v overlaps %v, which must stay off the TUN", capture[i], kept)
		}
	}
	rec := &ttDialRecorder{base: bypass.NewDialer(capture)}
	rec.logDialErrorsOnFailure(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ttLogRoutes(t, "before Open", phys.Name)
	dev := ttOpen(t, ctx, cfg)
	if len(dev.Warnings) != 0 {
		t.Fatalf("Open warned: %q", dev.Warnings)
	}
	// Sockets bound to phys need a default route scoped to it; the "\n" keeps en1 from matching en10.
	if scoped := ttLogRoutes(t, "after Open", phys.Name); runtime.GOOS == "darwin" && !strings.Contains(scoped, "interface: "+phys.Name+"\n") {
		t.Errorf("route -n get -inet -ifscope %s 1.1.1.1 found no route through %s, want the default route Open scopes to it", phys.Name, phys.Name)
	}
	errCh := ttServeDev(ctx, dev, cfg, rec)

	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "140.82.112.3"} {
		if got := ttRouteDev(t, ip); got != dev.Interface {
			t.Fatalf("route to %s leaves through %q, want %s", ip, got, dev.Interface)
		}
	}
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "169.254.169.254"} {
		if got := ttRouteDev(t, ip); got == dev.Interface {
			t.Errorf("route to %s leaves through %s, want it left off the TUN", ip, got)
		}
	}

	if err := ttGet(t, "https://1.1.1.1/", 20*time.Second); err != nil {
		t.Errorf("GET https://1.1.1.1/ through %s: %v", dev.Interface, err)
	}
	rec.wantDial(t, "tcp", "1.1.1.1:443", "198.18.0.1")
	// Its name resolves through whatever resolver the runner has, so a failure is only logged.
	if err := ttGet(t, "https://api.github.com/", 15*time.Second); err != nil {
		t.Logf("GET https://api.github.com/ through %s: %v", dev.Interface, err)
	}
	if !ttPingOK(t, "198.18.0.1") {
		t.Error("ping 198.18.0.1 got no reply")
	}

	ttTeardown(t, cancel, errCh, dev)
	if err := ttGet(t, "https://1.1.1.1/", 20*time.Second); err != nil {
		t.Errorf("GET https://1.1.1.1/ after teardown: %v", err)
	}
}

// ttTeardown stops Serve and closes dev, then waits for its interface and its route to 1.1.1.1 to go.
func ttTeardown(t *testing.T, cancel context.CancelFunc, errCh <-chan error, dev *tun.Device) {
	t.Helper()
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Serve = %v, want %v", err, context.Canceled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve still running 10s after cancel")
	}
	dev.Close()
	ttWaitFor(t, 10*time.Second, func() bool {
		_, err := net.InterfaceByName(dev.Interface)
		return err != nil && ttRouteDev(t, "1.1.1.1") != dev.Interface
	}, dev.Interface+" and its route to 1.1.1.1 to go away")
}

// ttPingOK reports whether ip answers one ICMP echo within a few seconds.
func ttPingOK(t *testing.T, ip string) bool {
	t.Helper()
	name, args := "ping", []string{"-c", "1", "-W", "3", ip}
	switch v6 := netip.MustParseAddr(ip).Is6(); {
	case runtime.GOOS == "darwin" && v6:
		// ping6 has no timeout flag; the context bounds it.
		name, args = "ping6", []string{"-c", "1", ip}
	case runtime.GOOS == "darwin":
		args = []string{"-c", "1", "-t", "3", ip}
	case v6:
		args = []string{"-6", "-c", "1", "-W", "3", ip}
	}
	path, err := exec.LookPath(name)
	if err != nil {
		t.Logf("look up %s: %v", name, err)
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		t.Logf("%s %q: %v\n%s", path, args, err, out)
	}
	return err == nil
}

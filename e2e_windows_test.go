//go:build e2e && windows

package tun

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/stack"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// ttWinLocalGate skips unless TUN_E2E=1, -test.run names the TestE2E tests and the process is elevated.
func ttWinLocalGate(t *testing.T) {
	t.Helper()
	if os.Getenv("TUN_E2E") != "1" {
		t.Skip("changes the host's interfaces and routes; set TUN_E2E=1 to run")
	}
	if run := flag.Lookup("test.run"); run == nil || !strings.Contains(run.Value.String(), "TestE2E") {
		t.Skip("runs only when -test.run names the TestE2E tests")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated process")
	}
}

// ttWinLocalRecorder records the addresses Serve dials through base.
type ttWinLocalRecorder struct {
	base stack.Dialer

	mu    sync.Mutex
	dials []string
}

func (r *ttWinLocalRecorder) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.dials = append(r.dials, network+" "+address)
	r.mu.Unlock()
	return r.base.DialContext(ctx, network, address)
}

func (r *ttWinLocalRecorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.dials)
}

// ttWinLocalWaitFor polls cond every 200ms and fails t unless it holds within timeout.
func ttWinLocalWaitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", timeout, msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// ttWinLocalHas reports whether the interface name holds ip.
func ttWinLocalHas(name string, ip netip.Addr) bool {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(addrs, func(a net.Addr) bool {
		n, ok := a.(*net.IPNet)
		if !ok {
			return false
		}
		got, _ := netip.AddrFromSlice(n.IP)
		return got.Unmap() == ip
	})
}

// ttWinLocalBestIndex returns the index of the interface Windows routes ip through.
func ttWinLocalBestIndex(t *testing.T, ip string) uint32 {
	t.Helper()
	var index uint32
	sa := &windows.SockaddrInet4{Addr: netip.MustParseAddr(ip).As4()}
	if err := windows.GetBestInterfaceEx(sa, &index); err != nil {
		t.Fatalf("GetBestInterfaceEx(%s): %v", ip, err)
	}
	return index
}

func TestE2EWindowsLocal(t *testing.T) {
	ttWinLocalGate(t)
	cfg := Config{
		Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64"),
		MTU:       1500,
		Bypass:    ttPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dev, err := openLocal(ctx, cfg)
	if err != nil {
		t.Fatalf("openLocal: %v", err)
	}
	// Should the test hang, closing the device still removes the adapter with its addresses and routes.
	watchdog := time.AfterFunc(3*time.Minute, func() { dev.Close() })
	t.Cleanup(func() {
		watchdog.Stop()
		dev.Close()
	})
	t.Logf("opened %s, warnings %q", dev.Interface, dev.Warnings)

	ttWinLocalWaitFor(t, 10*time.Second, func() bool {
		return ttWinLocalHas(dev.Interface, netip.MustParseAddr("198.18.0.1"))
	}, dev.Interface+" to hold 198.18.0.1")
	iface, err := net.InterfaceByName(dev.Interface)
	if err != nil {
		t.Fatalf("InterfaceByName(%s): %v", dev.Interface, err)
	}
	native, ok := dev.Device.(*wgtun.NativeTun)
	if !ok {
		t.Fatalf("device is %T, want *wgtun.NativeTun", dev.Device)
	}
	luid := winipcfg.LUID(native.LUID())
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		t.Fatalf("GetIPForwardTable2: %v", err)
	}
	if n := len(slices.DeleteFunc(rows, func(r winipcfg.MibIPforwardRow2) bool { return r.InterfaceLUID != luid })); n <= 50 {
		t.Errorf("%s has %d IPv4 routes, want more than 50", dev.Interface, n)
	}
	if got := ttWinLocalBestIndex(t, "1.1.1.1"); got != uint32(iface.Index) {
		t.Errorf("best interface for 1.1.1.1 = %d, want %s's %d", got, dev.Interface, iface.Index)
	}
	if got := ttWinLocalBestIndex(t, "10.0.0.1"); got == uint32(iface.Index) {
		t.Errorf("best interface for 10.0.0.1 = %s's %d, want it left off the TUN", dev.Interface, got)
	}

	rec := &ttWinLocalRecorder{base: bypass.NewDialer(CaptureRoutes(cfg))}
	errCh := make(chan error, 1)
	go func() {
		errCh <- stack.Serve(ctx, dev, rec, stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
	}()

	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       20 * time.Second,
	}
	resp, err := client.Get("https://1.1.1.1/")
	if err != nil {
		t.Errorf("GET https://1.1.1.1/ through %s: %v", dev.Interface, err)
	} else {
		resp.Body.Close()
		t.Logf("GET https://1.1.1.1/: %s", resp.Status)
	}
	if dials := rec.recorded(); !slices.Contains(dials, "tcp 1.1.1.1:443") {
		t.Errorf("Serve dialed %q, want tcp 1.1.1.1:443", dials)
	}

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
	ttWinLocalWaitFor(t, 10*time.Second, func() bool {
		_, err := net.InterfaceByName(dev.Interface)
		return err != nil
	}, dev.Interface+" to go away")
}

//go:build windows

package e2e

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/wzshiming/elevate"
	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/wzshiming/tun"
	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/internal/hook"
	"github.com/wzshiming/tun/wintun"
)

// ttWinBypass keeps the runner's private networks off the TUN.
var ttWinBypass = ttPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")

// ttWinGate skips unless TUN_E2E=1, the build embeds wintun.dll and the process is elevated.
func ttWinGate(t *testing.T) {
	t.Helper()
	ttGate(t)
	if !wintun.Embedded {
		t.Skip("this build embeds no wintun.dll")
	}
	if !hook.IsElevated() {
		t.Skip("needs an elevated process")
	}
}

// ttWinBestIndex returns the index of the interface Windows routes ip through.
func ttWinBestIndex(t *testing.T, ip string) uint32 {
	t.Helper()
	var index uint32
	sa := &windows.SockaddrInet4{Addr: netip.MustParseAddr(ip).As4()}
	if err := windows.GetBestInterfaceEx(sa, &index); err != nil {
		t.Fatalf("GetBestInterfaceEx(%s): %v", ip, err)
	}
	return index
}

// ttWinStop cancels Serve through cancel and waits for it to return.
func ttWinStop(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
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
}

func TestE2EWindowsLocal(t *testing.T) {
	ttWinGate(t)
	cfg := ttConfig(ttWinBypass)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// Open in an elevated process creates the adapter itself.
	dev := ttOpen(t, ctx, cfg)

	ttWaitFor(t, 10*time.Second, func() bool { return ttIfaceHas(dev.Interface, "198.18.0.1") }, dev.Interface+" to hold 198.18.0.1")
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
	if got := ttWinBestIndex(t, "1.1.1.1"); got != uint32(iface.Index) {
		t.Errorf("best interface for 1.1.1.1 = %d, want %s's %d", got, dev.Interface, iface.Index)
	}
	if got := ttWinBestIndex(t, "10.0.0.1"); got == uint32(iface.Index) {
		t.Errorf("best interface for 10.0.0.1 = %s's %d, want it left off the TUN", dev.Interface, got)
	}

	rec := &ttDialRecorder{base: bypass.NewDialer(tun.CaptureRoutes(cfg))}
	rec.logDialErrorsOnFailure(t)
	errCh := ttServeDev(ctx, dev, cfg, rec)
	if err := ttGet(t, "https://1.1.1.1/", 20*time.Second); err != nil {
		t.Errorf("GET https://1.1.1.1/ through %s: %v", dev.Interface, err)
	}
	rec.wantDial(t, "tcp", "1.1.1.1:443", "")

	ttWinStop(t, cancel, errCh)
	dev.Close()
	ttWaitFor(t, 10*time.Second, func() bool {
		_, err := net.InterfaceByName(dev.Interface)
		return err != nil
	}, dev.Interface+" to go away")
}

// ttWinHelperProc is an elevate.Proc that closes exited once the helper has exited.
type ttWinHelperProc struct {
	proc   elevate.Proc
	exited chan struct{}
}

func (p *ttWinHelperProc) Wait() error {
	defer close(p.exited)
	return p.proc.Wait()
}

// ttWinHelperCmd is an elevate.Proc for a helper started with exec.
type ttWinHelperCmd struct{ cmd *exec.Cmd }

func (c ttWinHelperCmd) Wait() error {
	err := c.cmd.Wait()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return &elevate.ExitError{Code: ee.ExitCode()}
	}
	return err
}

// ttWinHelperRecord makes Open take the helper path, launched through launch, so the test sees the helper exit.
func ttWinHelperRecord(t *testing.T, launch func(context.Context, string, []string) (elevate.Proc, error)) <-chan struct{} {
	t.Helper()
	prevLaunch, prevElevated := hook.Launch, hook.IsElevated
	t.Cleanup(func() { hook.Launch, hook.IsElevated = prevLaunch, prevElevated })
	exited := make(chan struct{})
	hook.IsElevated = func() bool { return false }
	hook.Launch = func(ctx context.Context, exe string, args []string) (elevate.Proc, error) {
		proc, err := launch(ctx, exe, args)
		if err != nil {
			return nil, err
		}
		return &ttWinHelperProc{proc: proc, exited: exited}, nil
	}
	return exited
}

// TestE2EWindowsHelper swaps hook.Launch and hook.IsElevated, so it must not run in parallel.
func TestE2EWindowsHelper(t *testing.T) {
	ttWinGate(t)
	exited := ttWinHelperRecord(t, func(_ context.Context, exe string, args []string) (elevate.Proc, error) {
		cmd := exec.Command(exe, args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return ttWinHelperCmd{cmd}, nil
	})
	ttWinHelperRun(t, exited)
}

// TestE2EWindowsHelperRunas swaps hook.Launch and hook.IsElevated, so it must not run in parallel.
func TestE2EWindowsHelperRunas(t *testing.T) {
	ttWinGate(t)
	if os.Getenv("TUN_E2E_RUNAS") != "1" {
		t.Skip("set TUN_E2E_RUNAS=1 to launch the helper through ShellExecuteEx runas")
	}
	exited := ttWinHelperRecord(t, hook.Launch)
	// A UAC prompt nobody answers must fail the test instead of hanging it.
	guard := time.AfterFunc(2*time.Minute, func() { panic("TestE2EWindowsHelperRunas still running after 2 minutes; is a UAC prompt waiting?") })
	defer guard.Stop()
	ttWinHelperRun(t, exited)
}

// ttWinHelperRun opens the TUN through the helper, fetches https://1.1.1.1/ through it and checks the helper and its adapter go away on Close.
func ttWinHelperRun(t *testing.T, exited <-chan struct{}) {
	t.Helper()
	cfg := ttConfig(ttWinBypass)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dev := ttOpen(t, ctx, cfg)

	var iface *net.Interface
	ttWaitFor(t, 10*time.Second, func() bool {
		var err error
		iface, err = net.InterfaceByName(dev.Interface)
		return err == nil
	}, "adapter "+dev.Interface)
	ttWaitFor(t, 10*time.Second, func() bool {
		var idx uint32
		err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &idx)
		return err == nil && int(idx) == iface.Index
	}, "the best interface to 1.1.1.1 to be "+dev.Interface)

	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	rec := &ttDialRecorder{base: bypass.NewDialer(tun.CaptureRoutes(cfg))}
	rec.logDialErrorsOnFailure(t)
	errCh := ttServeDev(serveCtx, dev, cfg, rec)
	if err := ttGet(t, "https://1.1.1.1/", 20*time.Second); err != nil {
		t.Errorf("GET https://1.1.1.1/ through %s: %v", dev.Interface, err)
	}

	ttWinStop(t, stop, errCh)
	dev.Close()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("helper still running 10s after Close")
	}
	ttWaitFor(t, 10*time.Second, func() bool {
		_, err := net.InterfaceByName(dev.Interface)
		return err != nil
	}, "adapter "+dev.Interface+" to go away")
}

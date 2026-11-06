//go:build e2e && windows

package tun

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/wzshiming/tun/bypass"
	"github.com/wzshiming/tun/internal/elevate"
	"github.com/wzshiming/tun/stack"
	"golang.org/x/sys/windows"
)

// TestMain runs the helper when a test launches this binary as one.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == HelperCommand {
		os.Exit(Helper(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// ttWinHelperGate skips the e2e tests, which change the host's adapters and routes, unless TUN_E2E=1, -test.run names them and the process is elevated.
func ttWinHelperGate(t *testing.T) {
	t.Helper()
	if os.Getenv("TUN_E2E") != "1" {
		t.Skip("changes the host's adapters and routes; set TUN_E2E=1 to run")
	}
	if run := flag.Lookup("test.run"); run == nil || !strings.Contains(run.Value.String(), "TestE2E") {
		t.Skip("runs only when -test.run names the TestE2E tests")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token")
	}
}

// ttWinHelperProc is an elevate.Proc that closes exited once the helper has exited.
type ttWinHelperProc struct {
	proc   elevate.Proc
	exited chan struct{}
}

func (p *ttWinHelperProc) Wait() (int, error) {
	defer close(p.exited)
	return p.proc.Wait()
}

// ttWinHelperCmd is an elevate.Proc for a helper started with exec.
type ttWinHelperCmd struct{ cmd *exec.Cmd }

func (c ttWinHelperCmd) Wait() (int, error) {
	err := c.cmd.Wait()
	if _, ok := errors.AsType[*exec.ExitError](err); err != nil && !ok {
		return -1, err
	}
	return c.cmd.ProcessState.ExitCode(), nil
}

// ttWinHelperRecord swaps elevate.Launch for launch so the test sees the helper exit.
func ttWinHelperRecord(t *testing.T, launch func(context.Context, string, []string) (elevate.Proc, error)) <-chan struct{} {
	t.Helper()
	prev := elevate.Launch
	t.Cleanup(func() { elevate.Launch = prev })
	exited := make(chan struct{})
	elevate.Launch = func(ctx context.Context, exe string, args []string) (elevate.Proc, error) {
		proc, err := launch(ctx, exe, args)
		if err != nil {
			return nil, err
		}
		return &ttWinHelperProc{proc: proc, exited: exited}, nil
	}
	return exited
}

func TestE2EWindowsHelper(t *testing.T) {
	ttWinHelperGate(t)
	exited := ttWinHelperRecord(t, func(_ context.Context, _ string, args []string) (elevate.Proc, error) {
		cmd := exec.Command(os.Args[0], args...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return ttWinHelperCmd{cmd}, nil
	})
	ttWinHelperRun(t, exited)
}

func TestE2EWindowsHelperRunas(t *testing.T) {
	ttWinHelperGate(t)
	if os.Getenv("TUN_E2E_RUNAS") != "1" {
		t.Skip("set TUN_E2E_RUNAS=1 to launch the helper through ShellExecuteEx runas")
	}
	exited := ttWinHelperRecord(t, elevate.Launch)
	// A UAC prompt nobody answers must fail the test instead of hanging it.
	guard := time.AfterFunc(2*time.Minute, func() { panic("TestE2EWindowsHelperRunas still running after 2 minutes; is a UAC prompt waiting?") })
	defer guard.Stop()
	ttWinHelperRun(t, exited)
}

// ttWinHelperRun opens the TUN through the helper, fetches https://1.1.1.1/ through it and checks the helper and its adapter go away on Close.
func ttWinHelperRun(t *testing.T, exited <-chan struct{}) {
	t.Helper()
	cfg := Config{
		Addresses: ttPrefixes("198.18.0.1/30", "fd00:6a77:7761::1/64"),
		MTU:       1500,
		Bypass:    ttPrefixes("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dev, err := openViaHelper(ctx, cfg)
	if err != nil {
		t.Fatalf("openViaHelper: %v", err)
	}
	t.Cleanup(func() { dev.Close() })
	t.Logf("opened %s, warnings %q", dev.Interface, dev.Warnings)

	var iface *net.Interface
	ttWinHelperWaitFor(t, 10*time.Second, func() bool {
		iface, err = net.InterfaceByName(dev.Interface)
		return err == nil
	}, "adapter "+dev.Interface)
	ttWinHelperWaitFor(t, 10*time.Second, func() bool {
		var idx uint32
		err := windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &idx)
		return err == nil && int(idx) == iface.Index
	}, "the best interface to 1.1.1.1 to be "+dev.Interface)

	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	served := make(chan error, 1)
	go func() {
		served <- stack.Serve(serveCtx, dev, bypass.NewDialer(CaptureRoutes(cfg)), stack.Options{MTU: cfg.MTU, Addresses: cfg.Addresses})
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

	stop()
	select {
	case err := <-served:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Serve = %v, want %v", err, context.Canceled)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve still running 10s after cancel")
	}
	dev.Close()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("helper still running 10s after Close")
	}
	ttWinHelperWaitFor(t, 10*time.Second, func() bool {
		_, err := net.InterfaceByName(dev.Interface)
		return err != nil
	}, "adapter "+dev.Interface+" to go away")
}

// ttWinHelperWaitFor polls cond every 200ms and fails t unless it holds within timeout.
func ttWinHelperWaitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", timeout, msg)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

//go:build windows

package tun

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/wzshiming/tun/wintun"
)

// ttWinHelperSwap makes the process look unelevated and routes elevate to fake; it returns the recorded launches.
func ttWinHelperSwap(t *testing.T, fake func(ctx context.Context, exe string, args []string) (helperProc, error)) *[][]string {
	t.Helper()
	prevElevate, prevIsElevated := elevate, isElevated
	t.Cleanup(func() { elevate, isElevated = prevElevate, prevIsElevated })
	var calls [][]string
	isElevated = func() bool { return false }
	elevate = func(ctx context.Context, exe string, args []string) (helperProc, error) {
		calls = append(calls, append([]string{exe}, args...))
		return fake(ctx, exe, args)
	}
	return &calls
}

func ttWinHelperNeedWintun(t *testing.T) {
	t.Helper()
	if !wintun.Embedded {
		t.Skip("no Wintun DLL embedded for this architecture")
	}
}

func TestHelperRejectsWrongArgCounts(t *testing.T) {
	for _, args := range [][]string{nil, {"127.0.0.1:1"}, {"127.0.0.1:1", "tok", "x"}} {
		if got := Helper(args); got != 2 {
			t.Errorf("Helper(%q) = %d, want 2", args, got)
		}
	}
}

func TestHelperRejectsAddressesOtherThanLoopbackAddrPorts(t *testing.T) {
	for _, addr := range []string{"10.0.0.1:1", "localhost:1", "127.0.0.1"} {
		if got := Helper([]string{addr, "tok"}); got != 2 {
			t.Errorf("Helper(%q) = %d, want 2", addr, got)
		}
	}
}

func TestHelperRefusesToRunUnelevated(t *testing.T) {
	prev := isElevated
	t.Cleanup(func() { isElevated = prev })
	isElevated = func() bool { return false }
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if got := Helper([]string{ln.Addr().String(), "tok"}); got != 2 {
		t.Errorf("Helper unelevated = %d, want 2", got)
	}
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
	if c, err := ln.Accept(); err == nil {
		c.Close()
		t.Error("an unelevated Helper connected to the parent, want it to stop first")
	}
}

func TestOpenReturnsValidationErrorWithoutElevating(t *testing.T) {
	calls := ttWinHelperSwap(t, func(context.Context, string, []string) (helperProc, error) { return nil, ErrDenied })
	cfg := ttDefaultConfig()
	cfg.MTU = 0
	if _, err := Open(t.Context(), cfg); err == nil || !strings.Contains(err.Error(), "MTU") {
		t.Errorf("Open = %v, want the MTU validation error", err)
	}
	if len(*calls) != 0 {
		t.Errorf("elevate called %q, want no call", *calls)
	}
}

func TestOpenElevatesTestBinaryAndReturnsDenied(t *testing.T) {
	ttWinHelperNeedWintun(t)
	calls := ttWinHelperSwap(t, func(context.Context, string, []string) (helperProc, error) { return nil, ErrDenied })
	if _, err := Open(t.Context(), ttDefaultConfig()); !errors.Is(err, ErrDenied) {
		t.Errorf("Open = %v, want ErrDenied", err)
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("elevate called %d times, want once", len(*calls))
	}
	got := (*calls)[0]
	if len(got) != 4 || got[0] != exe || got[1] != HelperCommand ||
		!regexp.MustCompile(`^127\.0\.0\.1:\d+$`).MatchString(got[2]) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(got[3]) {
		t.Errorf("elevate got %q, want [%s tun-helper 127.0.0.1:<port> <64 hex>]", got, exe)
	}
}

func TestOpenRelaysThroughHelper(t *testing.T) {
	ttWinHelperNeedWintun(t)
	fake := ttRelayNewFakeDev()
	open := func(context.Context, Config) (*Device, error) {
		return &Device{Device: fake, Interface: "tun", Warnings: []string{"w1"}}, nil
	}
	var launched []string
	ttWinHelperSwap(t, ttRelayLaunch(open, &launched))
	dev, err := Open(t.Context(), ttDefaultConfig())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()
	if dev.Interface != "tun" || len(dev.Warnings) != 1 || dev.Warnings[0] != "w1" {
		t.Errorf("Device Interface, Warnings = %q, %q, want tun, [w1]", dev.Interface, dev.Warnings)
	}
	go func() { fake.in <- []byte("ping") }()
	if got, err := ttRelayRead(t, dev); err != nil || string(got) != "ping" {
		t.Errorf("Read = %q, %v, want ping", got, err)
	}
	if _, err := dev.Write([][]byte{[]byte("pong")}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case got := <-fake.out:
		if string(got) != "pong" {
			t.Errorf("device got %q, want pong", got)
		}
	case <-time.After(5 * time.Second):
		t.Error("device got no packet within 5s")
	}
}

func TestOpenReportsHelperExitCode(t *testing.T) {
	ttWinHelperNeedWintun(t)
	ttWinHelperSwap(t, func(context.Context, string, []string) (helperProc, error) {
		proc := &ttRelayProc{done: make(chan struct{}), code: 3}
		close(proc.done)
		return proc, nil
	})
	if _, err := Open(t.Context(), ttDefaultConfig()); err == nil || !strings.Contains(err.Error(), "3") {
		t.Errorf("Open = %v, want an error naming exit code 3", err)
	}
}

func TestOpenReturnsCtxErrWhileWaiting(t *testing.T) {
	ttWinHelperNeedWintun(t)
	prompt := make(chan struct{})
	t.Cleanup(func() { close(prompt) })
	ttWinHelperSwap(t, func(context.Context, string, []string) (helperProc, error) {
		<-prompt
		return nil, ErrDenied
	})
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	if _, err := Open(ctx, ttDefaultConfig()); !errors.Is(err, context.Canceled) {
		t.Errorf("Open = %v, want context.Canceled", err)
	}
}

func TestElevateErrorMapsCancelledToDenied(t *testing.T) {
	if err := elevateError(windows.ERROR_CANCELLED); !errors.Is(err, ErrDenied) {
		t.Errorf("elevateError(ERROR_CANCELLED) = %v, want ErrDenied", err)
	}
	if err := elevateError(windows.ERROR_FILE_NOT_FOUND); errors.Is(err, ErrDenied) || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Errorf("elevateError(ERROR_FILE_NOT_FOUND) = %v, want it wrapped and not ErrDenied", err)
	}
}

func TestWinProcWaitReturnsExitCode(t *testing.T) {
	cmd := exec.Command(os.Getenv("ComSpec"), "/c", "exit 3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if code, err := winProc(h).Wait(); code != 3 || err != nil {
		t.Errorf("Wait = %d, %v, want 3, nil", code, err)
	}
}

//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/wzshiming/tun/internal/elevate"
)

// ttUnixLaunchSwap makes the process look unprivileged and routes elevate.Launch to fake; it returns the recorded launches.
func ttUnixLaunchSwap(t *testing.T, fake func(ctx context.Context, exe string, args []string) *exec.Cmd) *[][]string {
	t.Helper()
	prevLaunch, prevIsElevated := elevate.Launch, elevate.IsElevated
	t.Cleanup(func() { elevate.Launch, elevate.IsElevated = prevLaunch, prevIsElevated })
	var calls [][]string
	elevate.IsElevated = func() bool { return false }
	elevate.Launch = func(ctx context.Context, exe string, args []string) *exec.Cmd {
		calls = append(calls, append([]string{exe}, args...))
		return fake(ctx, exe, args)
	}
	return &calls
}

func TestOpenLaunchesHelperCommandOnTheSocket(t *testing.T) {
	calls := ttUnixLaunchSwap(t, func(ctx context.Context, _ string, _ []string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "exit 1")
	})
	Open(t.Context(), ttDefaultConfig())
	if len(*calls) != 1 {
		t.Fatalf("Launch called %d times, want once", len(*calls))
	}
	got := (*calls)[0]
	if len(got) != 3 || got[1] != HelperCommand || !filepath.IsAbs(got[2]) {
		t.Errorf("Launch got %q, want [<exe> %s <absolute socket>]", got, HelperCommand)
	}
}

func TestOpenReturnsErrDeniedWhenThePromptIsDeclined(t *testing.T) {
	// The launcher exits as osascript does on a canceled prompt and as pkexec does on a dismissed one.
	ttUnixLaunchSwap(t, func(ctx context.Context, _ string, _ []string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", "echo 'execution error: User canceled. (-128)' >&2; exit 126")
	})
	if _, err := Open(t.Context(), ttDefaultConfig()); !errors.Is(err, ErrDenied) {
		t.Errorf("Open = %v, want ErrDenied", err)
	}
}

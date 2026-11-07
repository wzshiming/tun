//go:build darwin || linux

package tun

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wzshiming/elevate"

	"github.com/wzshiming/tun/internal/hook"
)

// ttUnixLaunchSwap makes the process look unprivileged and routes hook.Launch to a helper that exits at once with waitErr; it returns the recorded launches.
func ttUnixLaunchSwap(t *testing.T, waitErr error) *[][]string {
	t.Helper()
	prevLaunch, prevIsElevated := hook.Launch, hook.IsElevated
	t.Cleanup(func() { hook.Launch, hook.IsElevated = prevLaunch, prevIsElevated })
	var calls [][]string
	hook.IsElevated = func() bool { return false }
	hook.Launch = func(_ context.Context, exe string, args []string) (elevate.Proc, error) {
		calls = append(calls, append([]string{exe}, args...))
		proc := &ttRelayProc{done: make(chan struct{}), err: waitErr}
		close(proc.done)
		return proc, nil
	}
	return &calls
}

func TestOpenLaunchesHelperCommandOnTheSocket(t *testing.T) {
	calls := ttUnixLaunchSwap(t, &elevate.ExitError{Code: 1})
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
	ttUnixLaunchSwap(t, elevate.ErrDenied)
	if _, err := Open(t.Context(), ttDefaultConfig()); err != ErrDenied {
		t.Errorf("Open = %v, want ErrDenied itself", err)
	}
}

func TestOpenReportsHelperExitCodeAndStderr(t *testing.T) {
	ttUnixLaunchSwap(t, &elevate.ExitError{Code: 7, Stderr: "boom"})
	_, err := Open(t.Context(), ttDefaultConfig())
	if _, ok := errors.AsType[*elevate.ExitError](err); !ok || !strings.Contains(err.Error(), "7") || !strings.Contains(err.Error(), "boom") {
		t.Errorf("Open = %v, want an *elevate.ExitError naming exit code 7 and stderr boom", err)
	}
	if err != nil && strings.Contains(err.Error(), "tun helper: elevate:") {
		t.Errorf("Open = %q, want a single prefix before elevate's", err)
	}
}

func TestOpenReturnsTheLaunchError(t *testing.T) {
	ttUnixLaunchSwap(t, nil)
	launchErr := errors.New("no launcher")
	hook.Launch = func(context.Context, string, []string) (elevate.Proc, error) { return nil, launchErr }
	if _, err := Open(t.Context(), ttDefaultConfig()); !errors.Is(err, launchErr) {
		t.Errorf("Open = %v, want the launch error", err)
	}
}

func TestOpenFailsWhenTheHelperExitsCleanlyWithoutConnecting(t *testing.T) {
	ttUnixLaunchSwap(t, nil)
	dev, err := Open(t.Context(), ttDefaultConfig())
	if err == nil {
		dev.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "exited before connecting") {
		t.Errorf("Open = %v after the helper exited 0 without connecting, want an error saying it exited before connecting", err)
	}
}

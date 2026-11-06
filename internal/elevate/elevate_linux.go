package elevate

import (
	"context"
	"os/exec"
)

// Launch returns the command that asks for administrator privileges through pkexec and runs exe with args as root.
var Launch = func(ctx context.Context, exe string, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, "/usr/bin/pkexec", append([]string{exe}, args...)...)
}

// ClassifyExit explains why the launcher of the helper exited without the helper connecting.
func ClassifyExit(code int, stderr string) error {
	// pkexec exits 126 when the user dismisses the prompt and 127 when authorization fails.
	if code == 126 || code == 127 {
		return ErrDenied
	}
	return exitError(code, stderr)
}

package elevate

import (
	"context"
	"os/exec"
	"strings"
)

var appleQuote = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// appleScript runs exe with args as root once the user approves the administrator prompt.
func appleScript(exe string, args []string) string {
	var b strings.Builder
	b.WriteString(`do shell script quoted form of "` + appleQuote.Replace(exe) + `"`)
	for _, a := range args {
		b.WriteString(` & " " & quoted form of "` + appleQuote.Replace(a) + `"`)
	}
	b.WriteString(` with administrator privileges`)
	return b.String()
}

// Launch returns the command that asks for administrator privileges through osascript and runs exe with args as root.
var Launch = func(ctx context.Context, exe string, args []string) *exec.Cmd {
	return exec.CommandContext(ctx, "/usr/bin/osascript", "-e", appleScript(exe, args))
}

// ClassifyExit explains why the launcher of the helper exited without the helper connecting.
func ClassifyExit(code int, stderr string) error {
	if strings.Contains(stderr, "(-128)") {
		return ErrDenied
	}
	return exitError(code, stderr)
}

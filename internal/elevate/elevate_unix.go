//go:build darwin || linux

package elevate

import (
	"fmt"
	"os"
	"strings"
)

// IsElevated reports whether the process runs as root.
var IsElevated = func() bool { return os.Geteuid() == 0 }

// exitError reports a launcher exit that does not mean the user declined.
func exitError(code int, stderr string) error {
	return fmt.Errorf("tun helper exited %d: %s", code, strings.TrimSpace(stderr))
}

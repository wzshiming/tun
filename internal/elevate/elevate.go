// Package elevate checks whether the process may open a TUN itself and otherwise launches a privileged helper.
package elevate

import "errors"

// ErrDenied reports that the user declined the administrator prompt.
var ErrDenied = errors.New("tun: administrator privileges denied")

// Proc is a launched helper.
type Proc interface {
	// Wait blocks until the helper exits, returns its exit code and releases the process.
	Wait() (int, error)
}

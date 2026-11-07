// Package hook holds the process-level seams that tests replace.
package hook

import (
	"context"

	"github.com/wzshiming/elevate"
)

// Launch starts a helper behind the system's administrator prompt.
var Launch func(ctx context.Context, exe string, args []string) (elevate.Proc, error) = elevate.Launch

// IsElevated reports whether the process already has administrator privileges.
var IsElevated func() bool = elevate.IsElevated

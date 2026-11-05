//go:build !darwin && !linux && !windows

package tun

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

// Open returns ErrUnsupported: TUN devices need macOS, Linux or Windows.
func Open(ctx context.Context, cfg Config) (*Device, error) {
	return nil, ErrUnsupported
}

// Helper reports that tun-helper is unsupported here and returns 2.
func Helper(args []string) int {
	fmt.Fprintf(os.Stderr, "tun-helper: unsupported on %s\n", runtime.GOOS)
	return 2
}

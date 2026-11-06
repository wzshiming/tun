//go:build windows

package tun

import (
	"context"
	"os"
	"path/filepath"

	"github.com/wzshiming/tun/internal/elevate"
	"github.com/wzshiming/tun/wintun"
)

// Open prompts for administrator privileges through UAC unless the process is elevated.
func Open(ctx context.Context, cfg Config) (*Device, error) {
	if err := validate(cfg); err != nil {
		return nil, err
	}
	if !wintun.Embedded {
		return nil, ErrUnsupported
	}
	if elevate.IsElevated() {
		return openLocal(ctx, cfg)
	}
	return openViaHelper(ctx, cfg)
}

// openViaHelper opens the TUN in an elevated tun-helper and relays its packets.
func openViaHelper(ctx context.Context, cfg Config) (*Device, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return nil, err
	}
	return openViaRelay(ctx, cfg, exe, elevate.Launch)
}

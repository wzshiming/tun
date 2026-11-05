package tun

import (
	"fmt"
	"strings"
)

// linuxName returns the name pattern a Linux TUN is created with, in which the kernel replaces "%d" with a free index.
func linuxName(cfg Config) string {
	name := cfg.name()
	if !strings.Contains(name, "%d") {
		name += "%d"
	}
	return name
}

// validateName rejects a name with a path separator or control character, or one whose name pattern exceeds IFNAMSIZ-1 bytes.
func validateName(name string) error {
	if err := validateNameChars(name); err != nil {
		return err
	}
	// The pattern itself, "%d" included, must fit the ifreq name field.
	if pattern := linuxName(Config{Name: name}); len(pattern) > 15 {
		return fmt.Errorf("tun: interface name pattern %q is %d bytes, longer than 15", pattern, len(pattern))
	}
	return nil
}

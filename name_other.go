//go:build !darwin && !linux && !windows

package tun

// validateName rejects a name with a path separator or control character.
func validateName(name string) error { return validateNameChars(name) }

package tun

import "fmt"

// validateName rejects a name with a path separator or control character, or one longer than 127 bytes.
func validateName(name string) error {
	if err := validateNameChars(name); err != nil {
		return err
	}
	// Wintun limits adapter names and tunnel types to MAX_ADAPTER_NAME-1.
	if len(name) > 127 {
		return fmt.Errorf("tun: interface name %q is %d bytes, longer than 127", name, len(name))
	}
	return nil
}

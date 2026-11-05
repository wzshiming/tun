package tun

// validateName rejects a name with a path separator or control character; macOS ignores the name otherwise.
func validateName(name string) error { return validateNameChars(name) }

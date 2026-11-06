//go:build windows && !amd64 && !arm64

package wintun

// Embedded reports whether this build carries a wintun.dll.
const Embedded = false

var dll []byte

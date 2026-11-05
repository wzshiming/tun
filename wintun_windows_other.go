//go:build windows && !amd64 && !arm64

package tun

// wintunEmbedded reports whether this build carries a wintun.dll.
const wintunEmbedded = false

var wintunDLL []byte

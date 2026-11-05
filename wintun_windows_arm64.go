package tun

import _ "embed"

// wintunEmbedded reports whether this build carries a wintun.dll.
const wintunEmbedded = true

//go:embed wintun/bin/arm64/wintun.dll
var wintunDLL []byte

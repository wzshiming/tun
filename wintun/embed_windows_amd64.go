package wintun

import _ "embed"

// Embedded reports whether this build carries a wintun.dll.
const Embedded = true

//go:embed bin/amd64/wintun.dll
var dll []byte

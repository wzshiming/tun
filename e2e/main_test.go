package e2e

import (
	"os"
	"testing"

	"github.com/wzshiming/tun"
)

// TestMain runs the helper when Open launches this binary as one.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == tun.HelperCommand {
		os.Exit(tun.Helper(os.Args[2:]))
	}
	os.Exit(m.Run())
}

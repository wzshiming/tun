package tun

import (
	"strings"
	"testing"
)

func TestValidateNameWindows(t *testing.T) {
	ttCheckValidateName(t, []ttNameCase{
		{"abcdefghijklmnopqrstuvwxyz", false},
		{strings.Repeat("a", 127), false},
		{strings.Repeat("a", 128), true},
	})
}

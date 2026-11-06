package tun

import "testing"

func TestValidateNameDarwin(t *testing.T) {
	ttCheckValidateName(t, []ttNameCase{
		{"abcdefghijklmnopqrstuvwxyz", false},
	})
}

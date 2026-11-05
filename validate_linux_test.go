package tun

import "testing"

func TestValidateNameLinux(t *testing.T) {
	ttCheckValidateName(t, []ttNameCase{
		{"", false},
		{"wg", false},
		{"wg%d", false},
		{"abcdefghijklm", false},
		{"abcdefghijklmn", true},
		{"abcdefghijklm%d", false},
		{"abcdefghijklmno", true},
		{"abcdefghijklmn%d", true},
	})
}

func TestLinuxNameAppendsIndexVerb(t *testing.T) {
	for name, want := range map[string]string{"": "tun%d", "wg": "wg%d", "wg%d": "wg%d", "a%db": "a%db"} {
		if got := linuxName(Config{Name: name}); got != want {
			t.Errorf("linuxName(Name %q) = %q, want %q", name, got, want)
		}
	}
}

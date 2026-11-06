package elevate

import (
	"slices"
	"testing"
)

func TestLaunchRunsPkexec(t *testing.T) {
	cmd := Launch(t.Context(), "/x/app", []string{"tun-helper", "/tmp/s"})
	want := []string{"/usr/bin/pkexec", "/x/app", "tun-helper", "/tmp/s"}
	if !slices.Equal(cmd.Args, want) {
		t.Errorf("Launch args = %q, want %q", cmd.Args, want)
	}
}

func TestClassifyExit(t *testing.T) {
	ttClassifyExit(t, []ttClassifyExitRow{
		{"126", 126, "Error executing command as another user: Request dismissed\n", true},
		{"127", 127, "Error executing command as another user: Not authorized\n", true},
		{"1", 1, "tun-helper: create tun: operation not permitted\n", false},
	})
}

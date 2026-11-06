package elevate

import (
	"slices"
	"testing"
)

func TestAppleScriptQuotesEveryPath(t *testing.T) {
	got := appleScript("/Applications/My App.app/x", []string{"tun-helper", `/tmp/a'b"c\d/s`})
	const want = `do shell script quoted form of "/Applications/My App.app/x" & " " & quoted form of "tun-helper" & " " & quoted form of "/tmp/a'b\"c\\d/s" with administrator privileges`
	if got != want {
		t.Errorf("appleScript =\n%s\nwant\n%s", got, want)
	}
}

func TestLaunchRunsOsascriptWithAdministratorPrivileges(t *testing.T) {
	args := []string{"tun-helper", "/tmp/s"}
	cmd := Launch(t.Context(), "/x/app", args)
	want := []string{"/usr/bin/osascript", "-e", appleScript("/x/app", args)}
	if !slices.Equal(cmd.Args, want) {
		t.Errorf("Launch args = %q, want %q", cmd.Args, want)
	}
}

func TestClassifyExit(t *testing.T) {
	ttClassifyExit(t, []ttClassifyExitRow{
		{"user canceled", 1, "0:156: execution error: User canceled. (-128)\n", true},
		{"other failure", 1, "tun-helper: create tun: operation not permitted\n", false},
	})
}

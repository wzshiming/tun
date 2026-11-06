package elevate

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestShellExecuteInfoRunsExeAsAdministrator(t *testing.T) {
	args := []string{"tun-helper", "127.0.0.1:1", "a b"}
	info, err := shellExecuteInfoFor(`C:\x y\app.exe`, args)
	if err != nil {
		t.Fatal(err)
	}
	if got := windows.UTF16PtrToString(info.verb); got != "runas" {
		t.Errorf("verb = %q, want runas", got)
	}
	if got := windows.UTF16PtrToString(info.file); got != `C:\x y\app.exe` {
		t.Errorf("file = %q, want the exe", got)
	}
	if got, want := windows.UTF16PtrToString(info.parameters), windows.ComposeCommandLine(args); got != want {
		t.Errorf("parameters = %q, want %q", got, want)
	}
	if info.fMask != seeMaskNoCloseProcess|seeMaskNoAsync|seeMaskFlagNoUI || info.show != windows.SW_HIDE {
		t.Errorf("fMask, show = %#x, %d, want a hidden process handle without UI", info.fMask, info.show)
	}
}

func TestElevateErrorMapsCancelledToDenied(t *testing.T) {
	if err := elevateError(windows.ERROR_CANCELLED); !errors.Is(err, ErrDenied) {
		t.Errorf("elevateError(ERROR_CANCELLED) = %v, want ErrDenied", err)
	}
	if err := elevateError(windows.ERROR_FILE_NOT_FOUND); errors.Is(err, ErrDenied) || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Errorf("elevateError(ERROR_FILE_NOT_FOUND) = %v, want it wrapped and not ErrDenied", err)
	}
}

func TestWinProcWaitReturnsExitCode(t *testing.T) {
	cmd := exec.Command(os.Getenv("ComSpec"), "/c", "exit 3")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	if code, err := winProc(h).Wait(); code != 3 || err != nil {
		t.Errorf("Wait = %d, %v, want 3, nil", code, err)
	}
}

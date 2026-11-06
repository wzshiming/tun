package elevate

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
	seeMaskFlagNoUI       = 0x00000400
)

// shellExecuteInfo is SHELLEXECUTEINFOW, which x/sys/windows lacks.
type shellExecuteInfo struct {
	cbSize        uint32
	fMask         uint32
	hwnd          windows.HWND
	verb          *uint16
	file          *uint16
	parameters    *uint16
	directory     *uint16
	show          int32
	instApp       windows.Handle
	idList        uintptr
	class         *uint16
	keyClass      windows.Handle
	hotKey        uint32
	iconOrMonitor windows.Handle
	process       windows.Handle
}

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

// IsElevated reports whether the process token is elevated.
var IsElevated = func() bool { return windows.GetCurrentProcessToken().IsElevated() }

// winProc is the handle of a process launched by Launch.
type winProc windows.Handle

func (p winProc) Wait() (int, error) {
	h := windows.Handle(p)
	defer windows.CloseHandle(h)
	if _, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil {
		return -1, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return -1, err
	}
	return int(code), nil
}

// shellExecuteInfoFor describes running exe with args through the runas verb, hidden and returning the process handle.
func shellExecuteInfoFor(exe string, args []string) (shellExecuteInfo, error) {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return shellExecuteInfo{}, err
	}
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return shellExecuteInfo{}, err
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return shellExecuteInfo{}, err
	}
	info := shellExecuteInfo{
		fMask:      seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		verb:       verb,
		file:       file,
		parameters: params,
		show:       windows.SW_HIDE,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	return info, nil
}

// Launch runs exe with args elevated after the user approves the UAC prompt, which it waits for and which ctx cannot cancel.
var Launch = func(ctx context.Context, exe string, args []string) (Proc, error) {
	info, err := shellExecuteInfoFor(exe, args)
	if err != nil {
		return nil, err
	}

	// ShellExecuteEx may use COM, which wants an initialized apartment on the calling thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED|windows.COINIT_DISABLE_OLE1DDE); err == nil || err == windows.Errno(windows.S_FALSE) {
		defer windows.CoUninitialize()
	}
	ok, _, callErr := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return nil, elevateError(callErr)
	}
	if info.process == 0 {
		return nil, errors.New("tun: ShellExecuteEx started no process")
	}
	return winProc(info.process), nil
}

// elevateError reports a failed ShellExecuteEx, ErrDenied when the user declined the prompt.
func elevateError(err error) error {
	if errors.Is(err, windows.ERROR_CANCELLED) {
		return ErrDenied
	}
	return fmt.Errorf("tun: ShellExecuteEx runas: %w", err)
}

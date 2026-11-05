package tun

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// createTUNName lets the kernel pick a free utun unit; cfg.Name has no say on macOS.
func createTUNName(Config) string { return "utun" }

func peerUID(conn *net.UnixConn) (uint32, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Xucred
	if cerr := rc.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); cerr != nil {
		return 0, cerr
	}
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}

func deviceFromFile(f *os.File) (wgtun.Device, error) {
	// MTU 0 keeps the one the helper set; only root may change it.
	return wgtun.CreateTUNFromFile(f, 0)
}

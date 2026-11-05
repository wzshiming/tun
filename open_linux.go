package tun

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

// createTUNName lets the kernel pick a free index for the name.
func createTUNName(cfg Config) string { return linuxName(cfg) }

func peerUID(conn *net.UnixConn) (uint32, error) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	if cerr := rc.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil {
		return 0, cerr
	}
	if err != nil {
		return 0, err
	}
	return cred.Uid, nil
}

func deviceFromFile(f *os.File) (wgtun.Device, error) {
	// The device wraps the descriptor number in an *os.File of its own, so it gets a duplicate that closing f leaves open.
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	f.Close()
	if err != nil {
		return nil, err
	}
	dev, _, err := wgtun.CreateUnmonitoredTUNFromFD(fd)
	return dev, err
}

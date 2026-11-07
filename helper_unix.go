//go:build darwin || linux

package tun

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/wzshiming/tun/internal/hook"
)

// Helper runs the HelperCommand subcommand that Open launches as root.
func Helper(args []string) int {
	if len(args) != 1 || !filepath.IsAbs(args[0]) {
		fmt.Fprintln(os.Stderr, "usage: "+HelperCommand+" <absolute unix socket path>")
		return 2
	}
	if !hook.IsElevated() {
		fmt.Fprintln(os.Stderr, "tun-helper: must run as root")
		return 2
	}
	// CreateTUN would write the interface name to the file this names.
	os.Unsetenv("WG_TUN_NAME_FILE")
	c, err := net.DialTimeout("unix", args[0], 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper:", err)
		return 1
	}
	conn := c.(*net.UnixConn)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(helperDeadline))
	dev := openRequested(conn, openLocal)
	if dev == nil {
		return 1
	}
	if err := sendReply(conn, reply{Name: dev.Interface, Warnings: dev.Warnings}, dev.File()); err != nil {
		dev.Close()
		fmt.Fprintln(os.Stderr, "tun-helper: send reply:", err)
		return 1
	}
	// Open closes the connection once it holds the descriptor.
	io.Copy(io.Discard, conn)
	return 0
}

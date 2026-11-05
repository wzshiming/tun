//go:build windows

package tun

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Helper runs the tun-helper subcommand that Open launches elevated.
func Helper(args []string) int {
	const usage = "usage: tun-helper <127.0.0.1:port> <token>"
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	addr, err := helperAddr(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper:", err)
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	if !isElevated() {
		fmt.Fprintln(os.Stderr, "tun-helper: must run elevated")
		return 2
	}
	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper:", err)
		return 1
	}
	return serveHelper(conn, args[1], openLocal)
}

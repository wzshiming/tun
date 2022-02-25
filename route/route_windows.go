package route

import (
	"fmt"
	"strings"

	wintun "golang.zx2c4.com/wintun"
)

// Check everything needed for tun setup
func CheckContext() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("failed to found tun driver: %v", r)
		}
	}()
	wintun.RunningVersion()
	return
}

// SetRoute let specified ip range route to tun device
func SetRoute(name string, ipRange []string) error {
	var lastErr error
	for i, r := range ipRange {
		ip, mask, err := toIpAndMask(r)
		tunIp := strings.Split(r, "/")[0]
		if err != nil {
			return err
		}
		if i == 0 {
			// run command: netsh interface ip set address KtConnectTunnel static 172.20.0.1 255.255.0.0
			err = cmd("netsh",
				"interface",
				"ip",
				"set",
				"address",
				name,
				"static",
				tunIp,
				mask,
			)
		} else {
			// run command: netsh interface ip add address KtConnectTunnel 172.21.0.1 255.255.0.0
			err = cmd("netsh",
				"interface",
				"ip",
				"add",
				"address",
				name,
				tunIp,
				mask,
			)
		}
		if err != nil {
			lastErr = err
			continue
		}
		// run command: route add 172.20.0.0 mask 255.255.0.0 172.20.0.1
		err = cmd("route",
			"add",
			ip,
			"mask",
			mask,
			tunIp,
		)
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

func GetName() string {
	return "tun0"
}

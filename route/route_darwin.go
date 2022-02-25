package route

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Check everything needed for tun setup
func Check() error {
	// TODO: check whether ifconfig and route command exists
	return nil
}

// SetRoute set specified ip range route to tun device
func SetRoute(name string, ipRange []string) error {
	var err, lastErr error
	for i, r := range ipRange {
		tunIp := strings.Split(r, "/")[0]
		if i == 0 {
			// run command: ifconfig utun6 inet 172.20.0.0/16 172.20.0.0
			err = cmd("ifconfig",
				name,
				"inet",
				r,
				tunIp,
			)
		} else {
			// run command: ifconfig utun6 add 172.20.0.0/16 172.20.0.1
			err = cmd("ifconfig",
				name,
				"add",
				r,
				tunIp,
			)
		}
		if err != nil {
			lastErr = err
			continue
		}
		// run command: route add -net 172.20.0.0/16 -interface utun6
		err = cmd("route",
			"add",
			"-net",
			r,
			"-interface",
			name,
		)
		if err != nil {
			lastErr = err
		}
	}
	return lastErr
}

var tunName = ""

func GetName() string {
	if tunName != "" {
		return tunName
	}
	const prefix = "utun"
	tunN := 0
	if ifaces, err := net.Interfaces(); err == nil {
		for _, i := range ifaces {
			if strings.HasPrefix(i.Name, prefix) {
				if num, err2 := strconv.Atoi(strings.TrimPrefix(i.Name, prefix)); err2 == nil && num > tunN {
					tunN = num
				}
			}
		}
		tunN++
	} else {
		tunN = 9
	}
	tunName = fmt.Sprintf("%s%d", prefix, tunN)
	return tunName
}

package control

import (
	"net"
	"strings"
)

func DefaultInterfaceName() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagBroadcast == 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "en") || strings.HasPrefix(iface.Name, "eth") {
			return iface.Name, nil
		}
	}
	return "", nil
}

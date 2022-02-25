package route

import (
	"net"
)

func toIpAndMask(cidr string) (string, string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}
	return ipNet.IP.String(), net.IP(ipNet.Mask).String(), nil
}

func GetDevice() string {
	return "tun"
}

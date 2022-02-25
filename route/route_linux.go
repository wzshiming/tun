package route

// Check everything needed for tun setup
func Check() error {
	// TODO: check whether ip command exists
	return nil
}

// SetRoute let specified ip range route to tun device
func SetRoute(name string, ipRange []string) error {
	// run command: ip link set dev kt0 up
	err := cmd("ip",
		"link",
		"set",
		"dev",
		name,
		"up",
	)
	if err != nil {
		// log.Error().Msgf("Failed to set tun device up")
		return err
	}
	var lastErr error
	for _, r := range ipRange {
		// run command: ip route add 10.96.0.0/16 dev kt0
		err = cmd("ip",
			"route",
			"add",
			r,
			"dev",
			name,
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

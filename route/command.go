//go:build !windows
// +build !windows

package route

import (
	"fmt"
	"os/exec"
	"strings"
)

func cmd(name string, arg ...string) error {
	c := exec.Command(name, arg...)
	out, err := c.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%q: %w: %q", strings.Join(append([]string{name}, arg...), " "), err, out)
	}
	return nil
}

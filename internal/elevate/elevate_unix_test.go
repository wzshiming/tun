//go:build darwin || linux

package elevate

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestIsElevatedMeansRoot(t *testing.T) {
	if got, want := IsElevated(), os.Geteuid() == 0; got != want {
		t.Errorf("IsElevated = %v, want %v", got, want)
	}
}

// ttClassifyExitRow is an exit of the launcher and whether it means the user declined.
type ttClassifyExitRow struct {
	name   string
	code   int
	stderr string
	denied bool
}

// ttClassifyExit checks ClassifyExit returns ErrDenied for the denied rows and a generic error naming the code otherwise.
func ttClassifyExit(t *testing.T, rows []ttClassifyExitRow) {
	t.Helper()
	// The generic rows' stderr holds no digits, so finding the code proves it is reported.
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			err := ClassifyExit(tc.code, tc.stderr)
			if tc.denied {
				if !errors.Is(err, ErrDenied) {
					t.Errorf("ClassifyExit = %v, want ErrDenied", err)
				}
				return
			}
			if err == nil || errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), strconv.Itoa(tc.code)) {
				t.Errorf("ClassifyExit = %v, want a generic error containing exit code %d", err, tc.code)
			}
		})
	}
}

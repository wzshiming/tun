package bypass

import (
	"errors"
	"testing"
)

// ttCandidate is an up, non-loopback default route on index.
func ttCandidate(index int, routeMetric, ifaceMetric uint32) routeCandidate {
	return routeCandidate{Index: index, RouteMetric: routeMetric, IfaceMetric: ifaceMetric, Up: true}
}

func ttWantPick(t *testing.T, candidates []routeCandidate, want int) {
	t.Helper()
	if got, err := pickDefaultRoute(candidates); err != nil || got != want {
		t.Errorf("pickDefaultRoute(%+v) = (%d, %v), want (%d, nil)", candidates, got, err, want)
	}
}

func TestPickDefaultRouteLowerRouteMetricLosesToLowerEffectiveMetric(t *testing.T) {
	ttWantPick(t, []routeCandidate{ttCandidate(7, 0, 5000), ttCandidate(4, 256, 25)}, 4)
}

func TestPickDefaultRouteSkipsDownInterface(t *testing.T) {
	down := ttCandidate(3, 0, 1)
	down.Up = false
	ttWantPick(t, []routeCandidate{down, ttCandidate(4, 256, 25)}, 4)
}

func TestPickDefaultRouteSkipsLoopbackInterface(t *testing.T) {
	loopback := ttCandidate(1, 0, 1)
	loopback.Loopback = true
	ttWantPick(t, []routeCandidate{loopback, ttCandidate(4, 256, 25)}, 4)
}

func TestPickDefaultRouteBreaksTiesByLowestIndex(t *testing.T) {
	ttWantPick(t, []routeCandidate{ttCandidate(9, 100, 25), ttCandidate(4, 25, 100), ttCandidate(6, 125, 0)}, 4)
}

func TestPickDefaultRouteDoesNotOverflowMetricSum(t *testing.T) {
	ttWantPick(t, []routeCandidate{ttCandidate(2, ^uint32(0), 1), ttCandidate(5, 10, 10)}, 5)
}

func TestPickDefaultRouteWithoutUsableCandidateReturnsErrNoDefaultRoute(t *testing.T) {
	down := ttCandidate(3, 0, 1)
	down.Up = false
	loopback := ttCandidate(1, 0, 1)
	loopback.Loopback = true
	tests := []struct {
		name       string
		candidates []routeCandidate
	}{
		{"no candidates", nil},
		{"down and loopback only", []routeCandidate{down, loopback}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := pickDefaultRoute(tc.candidates); !errors.Is(err, ErrNoDefaultRoute) {
				t.Errorf("pickDefaultRoute(%+v) = (%d, %v), want ErrNoDefaultRoute", tc.candidates, got, err)
			}
		})
	}
}

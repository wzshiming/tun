package dns

import (
	"slices"
	"testing"
	"time"
)

func TestFailedForSetsHowLongAFailedServerIsAskedLast(t *testing.T) {
	servers := []string{"a:53", "b:53"}
	for _, tt := range []struct {
		failedFor time.Duration
		ago       time.Duration
		want      []string
	}{
		{0, 10 * time.Second, []string{"b:53", "a:53"}},
		{0, 40 * time.Second, servers},
		{5 * time.Second, 10 * time.Second, servers},
		{time.Minute, 40 * time.Second, []string{"b:53", "a:53"}},
		{-1, 0, servers},
	} {
		h := &Handler{FailedFor: tt.failedFor, failed: map[string]time.Time{"a:53": time.Now().Add(-tt.ago)}}
		if got := h.order(servers); !slices.Equal(got, tt.want) {
			t.Errorf("FailedFor %v, a:53 failed %v ago: order = %v, want %v", tt.failedFor, tt.ago, got, tt.want)
		}
	}
}

func TestMaxInFlightDefaultsUnlessPositive(t *testing.T) {
	for n, want := range map[int]int{0: 64, -1: 64, 3: 3} {
		if got := (&Handler{MaxInFlight: n}).maxInFlight(); got != want {
			t.Errorf("MaxInFlight %d = %d, want %d", n, got, want)
		}
	}
}

package stack

import "testing"

func TestOptionsQueueAndHandshakeLimitsDefaultUnlessPositive(t *testing.T) {
	for _, tt := range []struct {
		name      string
		get       func(Options) int
		set       func(*Options, int)
		byDefault int
	}{
		{"SessionQueueLen", Options.sessionQueueLen, func(o *Options, n int) { o.SessionQueueLen = n }, 128},
		{"MaxTCPHandshakes", Options.maxTCPHandshakes, func(o *Options, n int) { o.MaxTCPHandshakes = n }, 2048},
		{"LinkQueueLen", Options.linkQueueLen, func(o *Options, n int) { o.LinkQueueLen = n }, 1024},
	} {
		for _, n := range []int{0, -1} {
			var o Options
			tt.set(&o, n)
			if got := tt.get(o); got != tt.byDefault {
				t.Errorf("%s of %d = %d, want the default %d", tt.name, n, got, tt.byDefault)
			}
		}
		var o Options
		tt.set(&o, 7)
		if got := tt.get(o); got != 7 {
			t.Errorf("%s of 7 = %d, want 7", tt.name, got)
		}
	}
}

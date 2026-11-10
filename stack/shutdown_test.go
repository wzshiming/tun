package stack

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// shutdownReabortEvery sets Serve's re-abort interval and per-round hook until the test ends; call it before starting Serve.
func shutdownReabortEvery(t *testing.T, interval time.Duration, round func()) {
	t.Helper()
	oldInterval, oldRound := reabortInterval, reaborted
	reabortInterval, reaborted = interval, round
	t.Cleanup(func() { reabortInterval, reaborted = oldInterval, oldRound })
}

func TestServeKeepsAbortingEndpointsWhileServeFlowIsOutstanding(t *testing.T) {
	var rounds atomic.Int32
	shutdownReabortEvery(t, 5*time.Millisecond, func() { rounds.Add(1) })
	accepted := make(chan struct{}, 1)
	// The handler ignores ctx and outlives the cancel until two re-abort rounds ran, or 2s passed.
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", "", HandlerFunc(func(_ context.Context, f Flow) {
			if _, err := f.Accept(); err != nil {
				return
			}
			accepted <- struct{}{}
			for limit := time.Now().Add(2 * time.Second); rounds.Load() < 2 && time.Now().Before(limit); {
				time.Sleep(time.Millisecond)
			}
		}))
	})
	env.dialTCP(t, "10.0.0.9:443")
	select {
	case <-accepted:
	case <-time.After(testWait):
		t.Fatal("the handler did not accept the flow")
	}
	env.cancel()
	env.wait(t)
	if n := rounds.Load(); n < 2 {
		t.Fatalf("Serve ran %d re-abort rounds while a ServeFlow was outstanding, want at least 2", n)
	}
}

func TestServeCancelWithoutFlowsReturnsWithin100ms(t *testing.T) {
	env := testServeMux(t, func(m *Mux) {
		m.Handle("tcp", "", HandlerFunc(func(context.Context, Flow) {}))
	})
	start := time.Now()
	env.cancel()
	env.wait(t)
	if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
		t.Fatalf("Serve took %v to return after a cancel with no outstanding flows, want under 100ms", elapsed)
	}
}

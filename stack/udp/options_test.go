package udp

import "testing"

func TestQueueLenDefaultsUnlessPositive(t *testing.T) {
	for n, want := range map[int]int{0: relayQueueLen, -1: relayQueueLen, 3: 3} {
		if got := (&Handler{QueueLen: n}).queueLen(); got != want {
			t.Errorf("QueueLen %d = %d, want %d", n, got, want)
		}
	}
}

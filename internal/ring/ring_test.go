package ring

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// ttRingFake is a Ring whose receive ring holds rx and whose send ring records sent.
type ttRingFake struct {
	mu        sync.Mutex
	rx        [][]byte
	sent      [][]byte
	allocErrs []error // returned by successive allocate calls; nil means success
	ended     bool    // receive and allocate return ErrEnded
	endCalls  int
	released  int           // release zeroes the packet, as the ring may reuse it
	waiting   chan struct{} // receives a value each time wait blocks
	woken     chan struct{}
	wakeOnce  sync.Once
}

func ttNewRingFake() *ttRingFake {
	return &ttRingFake{waiting: make(chan struct{}, 16), woken: make(chan struct{})}
}

func (r *ttRingFake) Receive() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return nil, ErrEnded
	}
	if len(r.rx) == 0 {
		return nil, ErrEmpty
	}
	p := r.rx[0]
	r.rx = r.rx[1:]
	return p, nil
}

func (r *ttRingFake) Release(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.released++
	clear(p)
}

func (r *ttRingFake) Allocate(n int) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return nil, ErrEnded
	}
	if len(r.allocErrs) > 0 {
		err := r.allocErrs[0]
		r.allocErrs = r.allocErrs[1:]
		if err != nil {
			return nil, err
		}
	}
	return make([]byte, n), nil
}

func (r *ttRingFake) Send(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, p)
}

func (r *ttRingFake) Wait() {
	r.waiting <- struct{}{}
	<-r.woken
}

func (r *ttRingFake) Wake() { r.wakeOnce.Do(func() { close(r.woken) }) }

func (r *ttRingFake) End() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endCalls++
	r.ended = true
}

func TestRingDeviceReadReturnsPacketAndSize(t *testing.T) {
	ring := ttNewRingFake()
	ring.rx = [][]byte{[]byte("ping")}
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	bufs, sizes := [][]byte{make([]byte, 64)}, []int{0}
	n, err := dev.Read(bufs, sizes, 16)
	if err != nil || n != 1 {
		t.Fatalf("Read = %d, %v, want 1, nil", n, err)
	}
	if got := string(bufs[0][16 : 16+sizes[0]]); got != "ping" {
		t.Errorf("Read packet = %q, want ping", got)
	}
	if ring.released != 1 {
		t.Errorf("released %d packets, want 1", ring.released)
	}
}

func TestRingDeviceReadBlockedOnEmptyRingReturnsErrClosedOnClose(t *testing.T) {
	ring := ttNewRingFake()
	dev := New(ring, "tun0", 1500)
	errc := make(chan error, 1)
	go func() {
		_, err := dev.Read([][]byte{make([]byte, 64)}, []int{0}, 0)
		errc <- err
	}()
	select {
	case <-ring.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not wait on the empty ring within 5s")
	}
	dev.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("Read = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked 5s after Close")
	}
}

func TestRingDeviceWriteDropsOnOverflowAndContinues(t *testing.T) {
	ring := ttNewRingFake()
	ring.allocErrs = []error{ErrFull, nil}
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	n, err := dev.Write([][]byte{[]byte("xxdropped"), []byte("xxkept")}, 2)
	if err != nil || n != 2 {
		t.Fatalf("Write = %d, %v, want 2, nil", n, err)
	}
	if len(ring.sent) != 1 || string(ring.sent[0]) != "kept" {
		t.Errorf("sent %q, want [kept]", ring.sent)
	}
}

func TestRingDeviceWriteSkipsOversizedPacket(t *testing.T) {
	ring := ttNewRingFake()
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	n, err := dev.Write([][]byte{make([]byte, packetMax+1), []byte("kept")}, 0)
	if err != nil || n != 2 {
		t.Fatalf("Write = %d, %v, want 2, nil", n, err)
	}
	if len(ring.sent) != 1 || string(ring.sent[0]) != "kept" {
		t.Errorf("sent %d packets, want only kept", len(ring.sent))
	}
}

func TestRingDeviceReadReturnsErrClosedOnEndedRing(t *testing.T) {
	ring := ttNewRingFake()
	ring.ended = true
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	if _, err := dev.Read([][]byte{make([]byte, 64)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Read = %v, want os.ErrClosed", err)
	}
}

func TestRingDeviceWriteReturnsErrClosedOnEndedRing(t *testing.T) {
	ring := ttNewRingFake()
	ring.ended = true
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	if _, err := dev.Write([][]byte{[]byte("ping")}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write = %v, want os.ErrClosed", err)
	}
}

func TestRingDeviceCloseIsIdempotentAndClosesEventsAfterUp(t *testing.T) {
	ring := ttNewRingFake()
	dev := New(ring, "tun0", 1500)
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := dev.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if ring.endCalls != 1 {
		t.Errorf("ring ended %d times, want once", ring.endCalls)
	}
	if ev, ok := <-dev.Events(); !ok || ev != wgtun.EventUp {
		t.Errorf("first event = %v, %v, want EventUp", ev, ok)
	}
	if _, ok := <-dev.Events(); ok {
		t.Error("Events still open after Close")
	}
	if _, err := dev.Read([][]byte{make([]byte, 64)}, []int{0}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Read after Close = %v, want os.ErrClosed", err)
	}
	if _, err := dev.Write([][]byte{[]byte("ping")}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close = %v, want os.ErrClosed", err)
	}
}

func TestRingDeviceReportsNameMTUAndBatchSize(t *testing.T) {
	dev := New(ttNewRingFake(), "tun0", 1400)
	defer dev.Close()
	if name, err := dev.Name(); err != nil || name != "tun0" {
		t.Errorf("Name = %q, %v, want tun0", name, err)
	}
	if mtu, err := dev.MTU(); err != nil || mtu != 1400 {
		t.Errorf("MTU = %d, %v, want 1400", mtu, err)
	}
	if dev.BatchSize() != batchSize || dev.File() != nil {
		t.Errorf("BatchSize, File = %d, %v, want %d, nil", dev.BatchSize(), dev.File(), batchSize)
	}
}

func TestRingDeviceReadDrainsTheRingIntoItsBuffers(t *testing.T) {
	ring := ttNewRingFake()
	ring.rx = [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	bufs, sizes := [][]byte{make([]byte, 64), make([]byte, 64)}, make([]int, 2)
	n, err := dev.Read(bufs, sizes, 16)
	if err != nil || n != 2 {
		t.Fatalf("Read = %d, %v, want 2, nil", n, err)
	}
	if one, two := string(bufs[0][16:16+sizes[0]]), string(bufs[1][16:16+sizes[1]]); one != "one" || two != "two" {
		t.Errorf("Read packets = %q, %q, want one, two", one, two)
	}
	if n, err = dev.Read(bufs, sizes, 16); err != nil || n != 1 || string(bufs[0][16:16+sizes[0]]) != "three" {
		t.Fatalf("second Read = %d, %v, %q, want 1, nil, three", n, err, bufs[0][16:16+sizes[0]])
	}
	if ring.released != 3 {
		t.Errorf("released %d packets, want 3", ring.released)
	}
	select {
	case <-ring.waiting:
		t.Error("Read waited on a ring that held packets")
	default:
	}
}

// The ring ending behind a packet is the next Read's to report.
func TestRingDeviceReadReturnsThePacketsBeforeTheRingEnded(t *testing.T) {
	ring := &ttEndingRing{ttRingFake: ttNewRingFake()}
	ring.rx = [][]byte{[]byte("last")}
	dev := New(ring, "tun0", 1500)
	defer dev.Close()
	bufs, sizes := [][]byte{make([]byte, 64), make([]byte, 64)}, make([]int, 2)
	if n, err := dev.Read(bufs, sizes, 0); err != nil || n != 1 || string(bufs[0][:sizes[0]]) != "last" {
		t.Fatalf("Read = %d, %v, want 1, nil with the last packet", n, err)
	}
	if n, err := dev.Read(bufs, sizes, 0); n != 0 || !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Read of the ended ring = %d, %v, want 0, os.ErrClosed", n, err)
	}
}

// ttEndingRing ends once its last packet is received.
type ttEndingRing struct{ *ttRingFake }

func (r *ttEndingRing) Receive() ([]byte, error) {
	p, err := r.ttRingFake.Receive()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil && len(r.rx) == 0 {
		r.ended = true
	}
	return p, err
}

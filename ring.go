package tun

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// Errors a packetRing returns in place of its platform's codes.
var (
	errRingEmpty = errors.New("tun: ring empty")
	errRingFull  = errors.New("tun: ring full")
	errRingEnded = errors.New("tun: ring ended")
)

// packetRing is a session's pair of packet rings, such as Wintun's.
type packetRing interface {
	// receive returns the next received packet, errRingEmpty when there is none or errRingEnded.
	receive() ([]byte, error)
	release(p []byte)
	// allocate returns n bytes of the send ring, errRingFull or errRingEnded.
	allocate(n int) ([]byte, error)
	send(p []byte)
	// wait blocks until a packet may be received or wake has been called.
	wait()
	wake()
	end()
}

// ringDevice is a wgtun.Device over a packetRing.
type ringDevice struct {
	ring   packetRing
	name   string
	mtu    int
	events chan wgtun.Event
	closed atomic.Bool
	// running is held for reading by Read and Write, so Close can wait for them.
	running sync.RWMutex
	once    sync.Once
}

func newRingDevice(ring packetRing, name string, mtu int) *ringDevice {
	events := make(chan wgtun.Event, 1)
	events <- wgtun.EventUp
	return &ringDevice{ring: ring, name: name, mtu: mtu, events: events}
}

func (d *ringDevice) File() *os.File { return nil }

func (d *ringDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.running.RLock()
	defer d.running.RUnlock()
	for !d.closed.Load() {
		p, err := d.ring.receive()
		switch {
		case err == nil:
			sizes[0] = copy(bufs[0][offset:], p)
			d.ring.release(p)
			return 1, nil
		case errors.Is(err, errRingEmpty):
			// One reader at a time: Wintun's read event is auto-reset, so one SetEvent wakes one waiter.
			d.ring.wait()
		case errors.Is(err, errRingEnded):
			return 0, os.ErrClosed
		default:
			return 0, fmt.Errorf("tun: read: %w", err)
		}
	}
	return 0, os.ErrClosed
}

func (d *ringDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.running.RLock()
	defer d.running.RUnlock()
	if d.closed.Load() {
		return 0, os.ErrClosed
	}
	for i, b := range bufs {
		b = b[offset:]
		if len(b) > packetMax {
			continue
		}
		p, err := d.ring.allocate(len(b))
		switch {
		case err == nil:
			copy(p, b)
			d.ring.send(p)
		case errors.Is(err, errRingFull):
			// The ring is full, so the packet is dropped.
		case errors.Is(err, errRingEnded):
			return i, os.ErrClosed
		default:
			return i, fmt.Errorf("tun: write: %w", err)
		}
	}
	return len(bufs), nil
}

func (d *ringDevice) MTU() (int, error)          { return d.mtu, nil }
func (d *ringDevice) Name() (string, error)      { return d.name, nil }
func (d *ringDevice) Events() <-chan wgtun.Event { return d.events }
func (d *ringDevice) BatchSize() int             { return 1 }

// Close wakes blocked readers, waits for every Read and Write to return, then ends the ring.
func (d *ringDevice) Close() error {
	d.once.Do(func() {
		d.closed.Store(true)
		d.ring.wake()
		d.running.Lock()
		d.ring.end()
		d.running.Unlock()
		close(d.events)
	})
	return nil
}

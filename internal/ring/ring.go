// Package ring makes a wgtun.Device of a session's pair of packet rings, such as Wintun's.
package ring

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// packetMax bounds a packet written to the ring.
const packetMax = 65535

// batchSize is how many packets a Device takes per Read.
const batchSize = 32

// Errors a Ring returns in place of its platform's codes.
var (
	ErrEmpty = errors.New("tun: ring empty")
	ErrFull  = errors.New("tun: ring full")
	ErrEnded = errors.New("tun: ring ended")
)

// Ring is a session's pair of packet rings, such as Wintun's.
type Ring interface {
	// Receive returns the next received packet, ErrEmpty when there is none or ErrEnded.
	Receive() ([]byte, error)
	Release(p []byte)
	// Allocate returns n bytes of the send ring, ErrFull or ErrEnded.
	Allocate(n int) ([]byte, error)
	Send(p []byte)
	// Wait blocks until a packet may be received or Wake has been called.
	Wait()
	Wake()
	End()
}

var _ wgtun.Device = (*Device)(nil)

// Device is a wgtun.Device over a Ring.
type Device struct {
	ring   Ring
	name   string
	mtu    int
	events chan wgtun.Event
	closed atomic.Bool
	// running is held for reading by Read and Write, so Close can wait for them.
	running sync.RWMutex
	once    sync.Once
}

// New returns a Device of that name and MTU over ring, already up.
func New(ring Ring, name string, mtu int) *Device {
	events := make(chan wgtun.Event, 1)
	events <- wgtun.EventUp
	return &Device{ring: ring, name: name, mtu: mtu, events: events}
}

func (d *Device) File() *os.File { return nil }

func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.running.RLock()
	defer d.running.RUnlock()
	for !d.closed.Load() {
		p, err := d.ring.Receive()
		switch {
		case err == nil:
			sizes[0] = copy(bufs[0][offset:], p)
			d.ring.Release(p)
			// The packets already in the ring come along, so the caller handles a burst in one go; an error here is the next Read's to report.
			n := 1
			for ; n < len(bufs); n++ {
				if p, err = d.ring.Receive(); err != nil {
					break
				}
				sizes[n] = copy(bufs[n][offset:], p)
				d.ring.Release(p)
			}
			return n, nil
		case errors.Is(err, ErrEmpty):
			// One reader at a time: Wintun's read event is auto-reset, so one SetEvent wakes one waiter.
			d.ring.Wait()
		case errors.Is(err, ErrEnded):
			return 0, os.ErrClosed
		default:
			return 0, fmt.Errorf("tun: read: %w", err)
		}
	}
	return 0, os.ErrClosed
}

func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
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
		p, err := d.ring.Allocate(len(b))
		switch {
		case err == nil:
			copy(p, b)
			d.ring.Send(p)
		case errors.Is(err, ErrFull):
			// The ring is full, so the packet is dropped.
		case errors.Is(err, ErrEnded):
			return i, os.ErrClosed
		default:
			return i, fmt.Errorf("tun: write: %w", err)
		}
	}
	return len(bufs), nil
}

func (d *Device) MTU() (int, error)          { return d.mtu, nil }
func (d *Device) Name() (string, error)      { return d.name, nil }
func (d *Device) Events() <-chan wgtun.Event { return d.events }
func (d *Device) BatchSize() int             { return batchSize }

// WhileOpen calls f and returns true unless the Device is closed; the ring is not ended while f runs.
func (d *Device) WhileOpen(f func()) bool {
	d.running.RLock()
	defer d.running.RUnlock()
	if d.closed.Load() {
		return false
	}
	f()
	return true
}

// Close wakes blocked readers, waits for every Read and Write to return, then ends the ring.
func (d *Device) Close() error {
	d.once.Do(func() {
		d.closed.Store(true)
		d.ring.Wake()
		d.running.Lock()
		d.ring.End()
		d.running.Unlock()
		close(d.events)
	})
	return nil
}

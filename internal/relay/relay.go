// Package relay carries the packets of a TUN device over a connection: Pump relays them between a wgtun.Device and the conn, and a Device at the other end of the conn is the wgtun.Device they come out of.
package relay

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// packetMax bounds the payload of a packet frame.
const packetMax = 65535

// batchSize is how many packets a Device takes per Read; a batch written to it, or pumped from a device, costs one write of the conn.
const batchSize = 32

// pumpOffset is the headroom Pump keeps in front of each packet, enough for a Linux TUN's virtio-net header.
const pumpOffset = 16

var _ wgtun.Device = (*Device)(nil)

// Device is a wgtun.Device whose packets travel as frames over a connection, to a Pump at its other end.
type Device struct {
	conn   net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	w      *bufio.Writer
	name   string
	mtu    int
	events chan wgtun.Event
	once   sync.Once
	// closed tells Read and Write that their failure is the device's own Close.
	closed atomic.Bool
	// Exited, when set, yields once the process at the other end of the conn has exited; Close waits for it, for ExitTimeout at most.
	Exited <-chan error
	// ExitTimeout bounds that wait.
	ExitTimeout time.Duration
}

// New returns a Device of that name and MTU whose packets travel over conn, already up.
func New(conn net.Conn, name string, mtu int) *Device {
	events := make(chan wgtun.Event, 1)
	events <- wgtun.EventUp
	return &Device{
		conn:   conn,
		r:      bufio.NewReaderSize(conn, 4+packetMax),
		w:      bufio.NewWriterSize(conn, 4+packetMax),
		name:   name,
		mtu:    mtu,
		events: events,
	}
}

func (d *Device) File() *os.File { return nil }

func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := readPacket(d.r, bufs[0][offset:])
	if err != nil {
		return 0, d.closedErr(err)
	}
	sizes[0] = n
	// The packets already buffered whole come along without another read of the conn.
	count := 1
	for ; count < len(bufs) && buffered(d.r); count++ {
		if n, err = readPacket(d.r, bufs[count][offset:]); err != nil {
			return count, d.closedErr(err)
		}
		sizes[count] = n
	}
	return count, nil
}

// buffered reports whether r holds a whole packet frame, so that reading it cannot block; a frame too large to be one is left for readPacket to refuse.
func buffered(r *bufio.Reader) bool {
	if r.Buffered() < 4 {
		return false
	}
	size, _ := r.Peek(4)
	n := binary.BigEndian.Uint32(size)
	return n <= packetMax && r.Buffered()-4 >= int(n)
}

func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	for _, b := range bufs {
		if err := writePacket(d.w, b[offset:]); err != nil {
			return 0, d.closedErr(err)
		}
	}
	if err := d.w.Flush(); err != nil {
		return 0, d.closedErr(err)
	}
	return len(bufs), nil
}

// closedErr returns os.ErrClosed, as a native device does, in place of the err of a Read or Write that failed once the device was closed.
func (d *Device) closedErr(err error) error {
	if d.closed.Load() {
		return os.ErrClosed
	}
	return err
}

func (d *Device) MTU() (int, error)          { return d.mtu, nil }
func (d *Device) Name() (string, error)      { return d.name, nil }
func (d *Device) Events() <-chan wgtun.Event { return d.events }
func (d *Device) BatchSize() int             { return batchSize }

func (d *Device) Close() error {
	var err error
	d.once.Do(func() {
		d.closed.Store(true)
		close(d.events)
		err = d.conn.Close()
		if d.Exited == nil {
			return
		}
		timer := time.NewTimer(d.ExitTimeout)
		defer timer.Stop()
		select {
		case <-d.Exited:
		case <-timer.C:
		}
	})
	return err
}

func writePacket(w io.Writer, p []byte) error {
	if len(p) > packetMax {
		return fmt.Errorf("tun: packet of %d bytes exceeds %d", len(p), packetMax)
	}
	if _, err := w.Write(binary.BigEndian.AppendUint32(nil, uint32(len(p)))); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

func readPacket(r io.Reader, buf []byte) (int, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > packetMax {
		return 0, fmt.Errorf("tun: packet frame of %d bytes exceeds %d", n, packetMax)
	}
	if int(n) > len(buf) {
		return 0, fmt.Errorf("tun: packet of %d bytes exceeds the %d-byte buffer", n, len(buf))
	}
	return io.ReadFull(r, buf[:n])
}

// Pump relays packets between dev and conn until either fails, then closes conn and returns the first error; the caller closes dev.
func Pump(dev wgtun.Device, conn net.Conn) error {
	errc := make(chan error, 2)
	go func() {
		bufs := make([][]byte, dev.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, pumpOffset+packetMax)
		}
		sizes := make([]int, len(bufs))
		w := bufio.NewWriterSize(conn, 4+packetMax)
		for {
			n, err := dev.Read(bufs, sizes, pumpOffset)
			for i := range n {
				if err := writePacket(w, bufs[i][pumpOffset:pumpOffset+sizes[i]]); err != nil {
					errc <- err
					return
				}
			}
			if ferr := w.Flush(); ferr != nil {
				err = ferr
			}
			// ErrTooManySegments comes with the segments that fit; only the rest of the GSO packet is lost.
			if err != nil && !errors.Is(err, wgtun.ErrTooManySegments) {
				errc <- err
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, pumpOffset+packetMax)
		r := bufio.NewReaderSize(conn, 4+packetMax)
		for {
			n, err := readPacket(r, buf[pumpOffset:])
			if err == nil {
				_, err = dev.Write([][]byte{buf[:pumpOffset+n]}, pumpOffset)
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	err := <-errc
	conn.Close()
	return err
}

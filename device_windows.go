package tun

import (
	"errors"

	"github.com/wzshiming/wintun"
	"golang.org/x/sys/windows"
)

// wintunRingCapacity is the size of each of the session's rings, 8 MiB.
const wintunRingCapacity = 0x800000

// wintunDevice is a wgtun.Device over a Wintun adapter's session.
type wintunDevice struct {
	*ringDevice
	adapter *wintun.Adapter
}

// newWintunDevice creates the adapter, or reuses the one of that name, and starts a session on it.
func newWintunDevice(name string, guid *windows.GUID, mtu int) (*wintunDevice, error) {
	adapter, err := wintun.CreateAdapter(name, name, guid)
	if err != nil {
		return nil, err
	}
	session, err := adapter.StartSession(wintunRingCapacity)
	if err != nil {
		adapter.Close()
		return nil, err
	}
	ring := &wintunRing{adapter: adapter, session: session, readWait: session.ReadWaitEvent()}
	return &wintunDevice{ringDevice: newRingDevice(ring, name, mtu), adapter: adapter}, nil
}

// LUID returns the adapter's LUID, or 0 once closed.
func (d *wintunDevice) LUID() uint64 { return d.adapter.LUID() }

// wintunRing is a packetRing over a Wintun session; end also closes the adapter.
type wintunRing struct {
	adapter  *wintun.Adapter
	session  *wintun.Session
	readWait windows.Handle
}

// ringErr maps the Wintun error codes to the packetRing errors.
func ringErr(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
		return errRingEmpty
	case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
		return errRingFull
	case errors.Is(err, windows.ERROR_HANDLE_EOF):
		return errRingEnded
	}
	return err
}

func (r *wintunRing) receive() ([]byte, error) {
	p, err := r.session.ReceivePacket()
	if err != nil {
		return nil, ringErr(err)
	}
	return p, nil
}

func (r *wintunRing) release(p []byte) { r.session.ReleaseReceivePacket(p) }

func (r *wintunRing) allocate(n int) ([]byte, error) {
	p, err := r.session.AllocateSendPacket(n)
	if err != nil {
		return nil, ringErr(err)
	}
	return p, nil
}

func (r *wintunRing) send(p []byte) { r.session.SendPacket(p) }
func (r *wintunRing) wait()         { windows.WaitForSingleObject(r.readWait, windows.INFINITE) }
func (r *wintunRing) wake()         { windows.SetEvent(r.readWait) }

func (r *wintunRing) end() {
	r.session.End()
	r.adapter.Close()
}

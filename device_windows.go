package tun

import (
	"errors"

	"github.com/wzshiming/wintun"
	"golang.org/x/sys/windows"

	"github.com/wzshiming/tun/internal/ring"
)

// wintunRingCapacity is the size of each of the session's rings, 8 MiB.
const wintunRingCapacity = 0x800000

// wintunDevice is a wgtun.Device over a Wintun adapter's session.
type wintunDevice struct {
	*ring.Device
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
	r := &wintunRing{adapter: adapter, session: session, readWait: session.ReadWaitEvent()}
	return &wintunDevice{Device: ring.New(r, name, mtu), adapter: adapter}, nil
}

// LUID returns the adapter's LUID, or 0 once closed.
func (d *wintunDevice) LUID() uint64 {
	var luid uint64
	d.WhileOpen(func() { luid = d.adapter.LUID() })
	return luid
}

// wintunRing is a ring.Ring over a Wintun session; End also closes the adapter.
type wintunRing struct {
	adapter  *wintun.Adapter
	session  *wintun.Session
	readWait windows.Handle
}

// ringErr maps the Wintun error codes to the ring.Ring errors.
func ringErr(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_NO_MORE_ITEMS):
		return ring.ErrEmpty
	case errors.Is(err, windows.ERROR_BUFFER_OVERFLOW):
		return ring.ErrFull
	case errors.Is(err, windows.ERROR_HANDLE_EOF):
		return ring.ErrEnded
	}
	return err
}

func (r *wintunRing) Receive() ([]byte, error) {
	p, err := r.session.ReceivePacket()
	if err != nil {
		return nil, ringErr(err)
	}
	return p, nil
}

func (r *wintunRing) Release(p []byte) { r.session.ReleaseReceivePacket(p) }

func (r *wintunRing) Allocate(n int) ([]byte, error) {
	p, err := r.session.AllocateSendPacket(n)
	if err != nil {
		return nil, ringErr(err)
	}
	return p, nil
}

func (r *wintunRing) Send(p []byte) { r.session.SendPacket(p) }
func (r *wintunRing) Wait()         { windows.WaitForSingleObject(r.readWait, windows.INFINITE) }
func (r *wintunRing) Wake()         { windows.SetEvent(r.readWait) }

func (r *wintunRing) End() {
	r.session.End()
	r.adapter.Close()
}

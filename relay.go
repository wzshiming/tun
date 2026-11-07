package tun

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/wzshiming/elevate"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/wzshiming/tun/internal/hook"
)

// packetMax bounds the payload of a packet frame.
const packetMax = 65535

// pumpOffset is the headroom pump keeps in front of each packet, enough for a Linux TUN's virtio-net header.
const pumpOffset = 16

// relayConnectTimeout bounds the wait for the helper to connect once it is launched, and then for its reply.
var relayConnectTimeout = 60 * time.Second

// helperExitTimeout bounds how long closing a relayed device waits for the helper to remove its adapter and exit.
var helperExitTimeout = 5 * time.Second

// helperTokenTimeout bounds how long a connection to the relay listener may take to present the token.
const helperTokenTimeout = 10 * time.Second

// helperDeadline bounds each exchange between the tun-helper and its parent.
const helperDeadline = 10 * time.Second

// relayDevice is a wgtun.Device whose packets travel as frames over a connection to a tun-helper.
type relayDevice struct {
	conn   net.Conn
	r      *bufio.Reader
	wmu    sync.Mutex
	w      *bufio.Writer
	name   string
	mtu    int
	events chan wgtun.Event
	once   sync.Once
	// exited, when set, yields once the helper process has exited.
	exited <-chan error
}

func newRelay(conn net.Conn, name string, mtu int) *relayDevice {
	events := make(chan wgtun.Event, 1)
	events <- wgtun.EventUp
	return &relayDevice{
		conn:   conn,
		r:      bufio.NewReaderSize(conn, 4+packetMax),
		w:      bufio.NewWriterSize(conn, 4+packetMax),
		name:   name,
		mtu:    mtu,
		events: events,
	}
}

func (d *relayDevice) File() *os.File { return nil }

func (d *relayDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := readPacket(d.r, bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (d *relayDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	for _, b := range bufs {
		if err := writePacket(d.w, b[offset:]); err != nil {
			return 0, err
		}
	}
	if err := d.w.Flush(); err != nil {
		return 0, err
	}
	return len(bufs), nil
}

func (d *relayDevice) MTU() (int, error)          { return d.mtu, nil }
func (d *relayDevice) Name() (string, error)      { return d.name, nil }
func (d *relayDevice) Events() <-chan wgtun.Event { return d.events }
func (d *relayDevice) BatchSize() int             { return 1 }

func (d *relayDevice) Close() error {
	var err error
	d.once.Do(func() {
		close(d.events)
		err = d.conn.Close()
		if d.exited == nil {
			return
		}
		timer := time.NewTimer(helperExitTimeout)
		defer timer.Stop()
		select {
		case <-d.exited:
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

// pump relays packets between dev and conn until either fails, then closes conn and returns the first error; the caller closes dev.
func pump(dev wgtun.Device, conn net.Conn) error {
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

// newToken returns 32 random bytes in hex, which the helper sends first to prove this process launched it.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// helperAddr parses the address a tun-helper dials, which must be a loopback address and port.
func helperAddr(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !ap.Addr().IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("%s is not a loopback address", s)
	}
	return ap, nil
}

// acceptHelper sends to found each connection to ln that presents token within tokenTimeout, until ln closes; once done closes, late ones are closed instead.
func acceptHelper(ln net.Listener, token string, tokenTimeout time.Duration, found chan<- net.Conn, done <-chan struct{}) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			got := make([]byte, len(token))
			conn.SetReadDeadline(time.Now().Add(tokenTimeout))
			if _, err := io.ReadFull(conn, got); err != nil || subtle.ConstantTimeCompare(got, []byte(token)) != 1 {
				conn.Close()
				return
			}
			conn.SetReadDeadline(time.Time{})
			select {
			case found <- conn:
			case <-done:
				conn.Close()
			}
		}()
	}
}

// openViaRelay launches exe's tun-helper and returns a Device relaying the packets of the TUN the helper opens.
// hook.Launch may block on a prompt that cannot be cancelled, so ctx ends the wait without it.
func openViaRelay(ctx context.Context, cfg Config, exe string) (*Device, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	token, err := newToken()
	if err != nil {
		return nil, err
	}

	launch := hook.Launch
	done := make(chan struct{})
	defer close(done)
	found := make(chan net.Conn)
	go acceptHelper(ln, token, helperTokenTimeout, found, done)

	launched := make(chan error, 1)
	exited := make(chan error, 1)
	go func() {
		proc, err := launch(ctx, exe, []string{HelperCommand, ln.Addr().String(), token})
		launched <- err
		if err != nil {
			return
		}
		err = proc.Wait()
		code := 0
		if ee, ok := errors.AsType[*elevate.ExitError](err); ok {
			code, err = ee.Code, nil
		}
		if err == nil {
			err = fmt.Errorf("tun: tun helper exited with code %d before connecting", code)
		}
		exited <- err
	}()

	var conn net.Conn
	var timeout <-chan time.Time
	for conn == nil {
		select {
		case conn = <-found:
		case err := <-launched:
			if err != nil {
				return nil, err
			}
			timeout = time.After(relayConnectTimeout)
		case err := <-exited:
			return nil, err
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, fmt.Errorf("tun: tun helper did not connect within %v", relayConnectTimeout)
		}
	}
	ln.Close()

	var rep reply
	conn.SetDeadline(time.Now().Add(relayConnectTimeout))
	err = writeFrame(conn, newRequest(cfg))
	if err == nil {
		err = readFrame(conn, &rep)
	}
	if err == nil && rep.Error != "" {
		err = errors.New(rep.Error)
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tun: tun helper: %w", err)
	}
	conn.SetDeadline(time.Time{})
	relay := newRelay(conn, rep.Name, cfg.MTU)
	relay.exited = exited
	return &Device{Device: relay, Interface: rep.Name, Warnings: rep.Warnings}, nil
}

// serveHelper is the tun-helper side of openViaRelay: it opens the requested TUN with open and relays its packets over conn until either ends.
func serveHelper(conn net.Conn, token string, open func(context.Context, Config) (*Device, error)) int {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(helperDeadline))
	if _, err := io.WriteString(conn, token); err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper: send token:", err)
		return 1
	}
	dev := openRequested(conn, open)
	if dev == nil {
		return 1
	}
	defer dev.Close()
	if err := writeFrame(conn, reply{Name: dev.Interface, Warnings: dev.Warnings}); err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper: send reply:", err)
		return 1
	}
	conn.SetDeadline(time.Time{})
	pump(dev, conn)
	return 0
}

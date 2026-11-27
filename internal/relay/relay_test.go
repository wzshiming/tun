package relay

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// ttRelayFakeDev is a wgtun.Device whose Read yields the packets sent to in and whose Write sends the packets to out.
type ttRelayFakeDev struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

func ttRelayNewFakeDev() *ttRelayFakeDev {
	return &ttRelayFakeDev{in: make(chan []byte), out: make(chan []byte, 16), closed: make(chan struct{})}
}

func (d *ttRelayFakeDev) File() *os.File { return nil }

func (d *ttRelayFakeDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case p, ok := <-d.in:
		if !ok {
			return 0, errors.New("tt: fake device failed")
		}
		sizes[0] = copy(bufs[0][offset:], p)
		return 1, nil
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *ttRelayFakeDev) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		select {
		case d.out <- bytes.Clone(b[offset:]):
		case <-d.closed:
			return 0, os.ErrClosed
		}
	}
	return len(bufs), nil
}

func (d *ttRelayFakeDev) MTU() (int, error)          { return 1500, nil }
func (d *ttRelayFakeDev) Name() (string, error)      { return "fake0", nil }
func (d *ttRelayFakeDev) Events() <-chan wgtun.Event { return nil }
func (d *ttRelayFakeDev) BatchSize() int             { return 1 }

func (d *ttRelayFakeDev) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// ttRelayPair connects a relay device to a fake device pumped over net.Pipe; the channel receives pump's result.
func ttRelayPair(t *testing.T) (*Device, *ttRelayFakeDev, <-chan error) {
	t.Helper()
	a, b := net.Pipe()
	fake := ttRelayNewFakeDev()
	relay := New(a, "relay0", 1500)
	pumped := make(chan error, 1)
	go func() { pumped <- Pump(fake, b) }()
	t.Cleanup(func() {
		relay.Close()
		fake.Close()
	})
	return relay, fake, pumped
}

// ttRelayRead reads one packet from dev within 5s.
func ttRelayRead(t *testing.T, dev wgtun.Device) ([]byte, error) {
	t.Helper()
	type result struct {
		p   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		bufs, sizes := [][]byte{make([]byte, 16+packetMax)}, make([]int, 1)
		n, err := dev.Read(bufs, sizes, 16)
		if err == nil && n != 1 {
			err = errors.New("tt: Read returned no packet")
		}
		done <- result{bufs[0][16 : 16+sizes[0]], err}
	}()
	select {
	case r := <-done:
		return r.p, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked after 5s")
		return nil, nil
	}
}

func ttRelayRandom(n int) []byte {
	p := make([]byte, n)
	rand.Read(p)
	return p
}

func TestRelayReadDeliversDevicePacketsInOrder(t *testing.T) {
	relay, fake, _ := ttRelayPair(t)
	want := [][]byte{ttRelayRandom(1), ttRelayRandom(1500), ttRelayRandom(65535)}
	go func() {
		for _, p := range want {
			fake.in <- p
		}
	}()
	for i, w := range want {
		got, err := ttRelayRead(t, relay)
		if err != nil {
			t.Fatalf("Read packet %d: %v", i, err)
		}
		if !bytes.Equal(got, w) {
			t.Fatalf("Read packet %d = %d bytes, want the %d bytes the device read", i, len(got), len(w))
		}
	}
}

func TestRelayWriteDeliversPacketsToDevice(t *testing.T) {
	relay, fake, _ := ttRelayPair(t)
	want := [][]byte{ttRelayRandom(1), ttRelayRandom(1500), ttRelayRandom(65535)}
	bufs := make([][]byte, len(want))
	for i, p := range want {
		bufs[i] = append(make([]byte, 16), p...)
	}
	if n, err := relay.Write(bufs, 16); err != nil || n != len(bufs) {
		t.Fatalf("Write = %d, %v, want %d, nil", n, err, len(bufs))
	}
	for i, w := range want {
		select {
		case got := <-fake.out:
			if !bytes.Equal(got, w) {
				t.Fatalf("device got packet %d = %d bytes, want the %d bytes written", i, len(got), len(w))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("device got no packet %d within 5s", i)
		}
	}
}

func TestRelayWriteRejectsOversizedPacket(t *testing.T) {
	relay, _, _ := ttRelayPair(t)
	if _, err := relay.Write([][]byte{make([]byte, 65536)}, 0); err == nil {
		t.Fatal("Write of a 65536-byte packet = nil error, want one")
	}
}

func TestRelayReadRejectsOversizedFrame(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	relay := New(a, "relay0", 1500)
	defer relay.Close()
	go b.Write(binary.BigEndian.AppendUint32(nil, 65536))
	if _, err := ttRelayRead(t, relay); err == nil {
		t.Fatal("Read of a 65536-byte frame = nil error, want one")
	}
}

func TestRelayCloseEndsPumpAndUnblocksRead(t *testing.T) {
	relay, _, pumped := ttRelayPair(t)
	read := make(chan error, 1)
	go func() {
		_, err := relay.Read([][]byte{make([]byte, packetMax)}, []int{0}, 0)
		read <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := relay.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := relay.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	select {
	case err := <-read:
		if err == nil {
			t.Error("pending Read = nil error after Close, want one")
		}
	case <-time.After(5 * time.Second):
		t.Error("pending Read still blocked 5s after Close")
	}
	select {
	case <-pumped:
	case <-time.After(5 * time.Second):
		t.Error("pump still running 5s after the relay closed")
	}
}

func TestPumpDeviceErrorSurfacesOnRelay(t *testing.T) {
	relay, fake, pumped := ttRelayPair(t)
	close(fake.in)
	select {
	case err := <-pumped:
		if err == nil || !strings.Contains(err.Error(), "fake device failed") {
			t.Errorf("pump = %v, want the device's error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pump still running 5s after the device failed")
	}
	if _, err := ttRelayRead(t, relay); err == nil {
		t.Error("relay Read = nil error after the pump side failed, want one")
	}
}

func TestRelayEventsYieldsUpThenClosesAfterClose(t *testing.T) {
	relay, _, _ := ttRelayPair(t)
	select {
	case ev := <-relay.Events():
		if ev != wgtun.EventUp {
			t.Fatalf("first event = %v, want EventUp", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no first event")
	}
	relay.Close()
	select {
	case ev, ok := <-relay.Events():
		if ok {
			t.Fatalf("event after Close = %v, want a closed channel", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("Events still open after Close")
	}
}

func TestRelayReportsNameMTUAndBatchSize(t *testing.T) {
	relay, _, _ := ttRelayPair(t)
	name, _ := relay.Name()
	mtu, _ := relay.MTU()
	if name != "relay0" || mtu != 1500 || relay.BatchSize() != batchSize || relay.File() != nil {
		t.Errorf("Name, MTU, BatchSize, File = %q, %d, %d, %v, want relay0, 1500, %d, nil", name, mtu, relay.BatchSize(), relay.File(), batchSize)
	}
}

// ttRelayFrames returns packets as the frames a pump writes them in.
func ttRelayFrames(packets ...[]byte) []byte {
	var frames bytes.Buffer
	for _, p := range packets {
		writePacket(&frames, p)
	}
	return frames.Bytes()
}

// ttRelayReadBatch reads up to batch packets from dev in one Read within 5s.
func ttRelayReadBatch(t *testing.T, dev wgtun.Device, batch int) ([][]byte, error) {
	t.Helper()
	type result struct {
		packets [][]byte
		err     error
	}
	done := make(chan result, 1)
	go func() {
		bufs, sizes := make([][]byte, batch), make([]int, batch)
		for i := range bufs {
			bufs[i] = make([]byte, 16+packetMax)
		}
		n, err := dev.Read(bufs, sizes, 16)
		var r result
		for i := range n {
			r.packets = append(r.packets, bufs[i][16:16+sizes[i]])
		}
		r.err = err
		done <- r
	}()
	select {
	case r := <-done:
		return r.packets, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked after 5s")
		return nil, nil
	}
}

func TestRelayReadReturnsEveryPacketAlreadyBuffered(t *testing.T) {
	a, b := net.Pipe()
	relay := New(a, "relay0", 1500)
	defer relay.Close()
	defer b.Close()
	want := [][]byte{ttRelayRandom(40), ttRelayRandom(1500), ttRelayRandom(1)}
	// One write of the pipe reaches the relay's buffer in one read.
	go b.Write(ttRelayFrames(want...))
	got, err := ttRelayReadBatch(t, relay, 8)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("Read returned %d packets, want the %d buffered", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("packet %d = %d bytes, want the %d sent", i, len(got[i]), len(want[i]))
		}
	}
}

func TestRelayReadLeavesPacketsBeyondItsBuffersToTheNextRead(t *testing.T) {
	a, b := net.Pipe()
	relay := New(a, "relay0", 1500)
	defer relay.Close()
	defer b.Close()
	want := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	go b.Write(ttRelayFrames(want...))
	first, err := ttRelayReadBatch(t, relay, 2)
	if err != nil || len(first) != 2 {
		t.Fatalf("first Read = %d packets, %v, want 2, nil", len(first), err)
	}
	rest, err := ttRelayReadBatch(t, relay, 2)
	if err != nil || len(rest) != 1 || string(rest[0]) != "three" {
		t.Fatalf("second Read = %q, %v, want [three], nil", rest, err)
	}
}

// A frame whose payload has not all arrived must not hold back the packets before it.
func TestRelayReadDoesNotWaitForAPartlyBufferedPacket(t *testing.T) {
	a, b := net.Pipe()
	relay := New(a, "relay0", 1500)
	defer relay.Close()
	defer b.Close()
	frames := ttRelayFrames([]byte("whole"), []byte("partial"))
	go b.Write(frames[:len(frames)-3])
	got, err := ttRelayReadBatch(t, relay, 8)
	if err != nil || len(got) != 1 || string(got[0]) != "whole" {
		t.Fatalf("Read = %q, %v, want [whole], nil", got, err)
	}
	go b.Write(frames[len(frames)-3:])
	got, err = ttRelayReadBatch(t, relay, 8)
	if err != nil || len(got) != 1 || string(got[0]) != "partial" {
		t.Fatalf("Read after the rest arrived = %q, %v, want [partial], nil", got, err)
	}
}

func TestRelayReadReturnsThePacketsBeforeAnOversizedFrame(t *testing.T) {
	a, b := net.Pipe()
	relay := New(a, "relay0", 1500)
	defer relay.Close()
	defer b.Close()
	frames := append(ttRelayFrames([]byte("good")), 0xff, 0xff, 0xff, 0xff)
	go b.Write(frames)
	got, err := ttRelayReadBatch(t, relay, 8)
	if err != nil || len(got) != 1 || string(got[0]) != "good" {
		t.Fatalf("Read = %q, %v, want [good], nil", got, err)
	}
	if _, err = ttRelayReadBatch(t, relay, 8); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Read of the oversized frame = %v, want an error that it exceeds the limit", err)
	}
}

// ttRelayDiscardDev is a wgtun.Device that drops what it is written and never has a packet to read.
type ttRelayDiscardDev struct{ *ttRelayFakeDev }

func (d ttRelayDiscardDev) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }

// BenchmarkRelayWrite sends 1400-byte packets through a relay device over loopback TCP, as Open's parent does to its helper, in the batches a caller gets from a BatchSize of 1 and of batchSize.
func BenchmarkRelayWrite(b *testing.B) {
	for _, batch := range []int{1, batchSize} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer ln.Close()
			pumped := make(chan error, 1)
			fake := ttRelayDiscardDev{ttRelayNewFakeDev()}
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					pumped <- err
					return
				}
				pumped <- Pump(fake, conn)
			}()
			conn, err := net.Dial("tcp4", ln.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			relay := New(conn, "relay0", 1500)
			bufs := make([][]byte, batch)
			for i := range bufs {
				bufs[i] = make([]byte, pumpOffset+1400)
			}
			b.SetBytes(1400)
			b.ResetTimer()
			for sent := 0; sent < b.N; sent += batch {
				if _, err := relay.Write(bufs, pumpOffset); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			relay.Close()
			fake.Close()
			<-pumped
		})
	}
}

func TestRelayReadBlockedWhenTheDeviceClosesReturnsErrClosed(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	relay := New(a, "relay0", 1500)
	errc := make(chan error, 1)
	go func() {
		_, err := relay.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0)
		errc <- err
	}()
	// The Read is not known to block yet, but one that starts after the Close must report it the same.
	time.Sleep(50 * time.Millisecond)
	relay.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("Read = %v, want os.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked 5s after Close")
	}
}

func TestRelayReadAndWriteAfterCloseReturnErrClosed(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	relay := New(a, "relay0", 1500)
	relay.Close()
	if _, err := relay.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Read after Close = %v, want os.ErrClosed", err)
	}
	if _, err := relay.Write([][]byte{[]byte("packet")}, 0); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Write after Close = %v, want os.ErrClosed", err)
	}
}

// A conn the helper ended is a failure of its own, not the device's Close.
func TestRelayReadOfAConnThePeerClosedKeepsItsError(t *testing.T) {
	a, b := net.Pipe()
	relay := New(a, "relay0", 1500)
	defer relay.Close()
	b.Close()
	if _, err := relay.Read([][]byte{make([]byte, 64)}, make([]int, 1), 0); !errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
		t.Errorf("Read = %v, want io.EOF and not os.ErrClosed", err)
	}
}

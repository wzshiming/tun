package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wzshiming/elevate"
	wgtun "golang.zx2c4.com/wireguard/tun"

	"github.com/wzshiming/tun/internal/hook"
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
func ttRelayPair(t *testing.T) (*relayDevice, *ttRelayFakeDev, <-chan error) {
	t.Helper()
	a, b := net.Pipe()
	fake := ttRelayNewFakeDev()
	relay := newRelay(a, "relay0", 1500)
	pumped := make(chan error, 1)
	go func() { pumped <- pump(fake, b) }()
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
	relay := newRelay(a, "relay0", 1500)
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
	if name != "relay0" || mtu != 1500 || relay.BatchSize() != 1 || relay.File() != nil {
		t.Errorf("Name, MTU, BatchSize, File = %q, %d, %d, %v, want relay0, 1500, 1, nil", name, mtu, relay.BatchSize(), relay.File())
	}
}

// ttRelayListen returns a loopback listener whose connections presenting token within tokenTimeout acceptHelper sends to the returned channel.
func ttRelayListen(t *testing.T, token string, tokenTimeout time.Duration) (net.Listener, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		ln.Close()
	})
	found := make(chan net.Conn)
	go acceptHelper(ln, token, tokenTimeout, found, done)
	return ln, found
}

func TestAcceptHelperRejectsWrongToken(t *testing.T) {
	token, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	ln, found := ttRelayListen(t, token, helperTokenTimeout)
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(strings.Repeat("0", len(token))))
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read after a wrong token = %v, want EOF from the closed connection", err)
	}
	select {
	case <-found:
		t.Error("acceptHelper accepted a connection with a wrong token")
	default:
	}
}

func TestAcceptHelperAcceptsRightToken(t *testing.T) {
	token, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	ln, found := ttRelayListen(t, token, helperTokenTimeout)
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(token))
	select {
	case conn := <-found:
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("acceptHelper did not accept the right token within 5s")
	}
}

func TestHelperAddrAcceptsOnlyLoopbackAddrPorts(t *testing.T) {
	for _, s := range []string{"127.0.0.1:5000", "127.1.2.3:1", "[::1]:5000"} {
		if _, err := helperAddr(s); err != nil {
			t.Errorf("helperAddr(%q) = %v, want it accepted", s, err)
		}
	}
	for _, s := range []string{"10.0.0.1:5000", "0.0.0.0:5000", "[::]:5000", "localhost:5000", "evil.example:5000", "127.0.0.1", ""} {
		if _, err := helperAddr(s); err == nil {
			t.Errorf("helperAddr(%q) = nil error, want it refused", s)
		}
	}
}

func TestAcceptHelperDropsASilentConnectionAndKeepsWaiting(t *testing.T) {
	token, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	ln, found := ttRelayListen(t, token, 100*time.Millisecond)
	silent, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	silent.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := silent.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read on a connection that never sent the token = %v, want EOF once the deadline dropped it", err)
	}
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(token))
	select {
	case conn := <-found:
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("acceptHelper stopped waiting after dropping the silent connection")
	}
}

func TestNewTokenIs64HexChars(t *testing.T) {
	a, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newToken()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(a) || a == b {
		t.Errorf("newToken = %q, %q, want two different 64-char hex strings", a, b)
	}
}

// ttRelayProc is a fake elevate.Proc whose Wait returns err once done is closed.
type ttRelayProc struct {
	done chan struct{}
	err  error
}

func (p *ttRelayProc) Wait() error {
	<-p.done
	return p.err
}

// ttRelayExit is what elevate's Wait returns for a helper exiting with code.
func ttRelayExit(code int) error {
	if code == 0 {
		return nil
	}
	return &elevate.ExitError{Code: code}
}

// ttRelaySwapLaunch routes hook.Launch to launch until t ends, so its callers must not run in parallel.
func ttRelaySwapLaunch(t *testing.T, launch func(context.Context, string, []string) (elevate.Proc, error)) {
	t.Helper()
	prev := hook.Launch
	t.Cleanup(func() { hook.Launch = prev })
	hook.Launch = launch
}

// ttRelayLaunch returns a launch that records its arguments and runs serveHelper in a goroutine after a connection with a wrong token.
func ttRelayLaunch(open func(context.Context, Config) (*Device, error), gotArgs *[]string) func(context.Context, string, []string) (elevate.Proc, error) {
	return func(_ context.Context, exe string, args []string) (elevate.Proc, error) {
		*gotArgs = append([]string{exe}, args...)
		proc := &ttRelayProc{done: make(chan struct{})}
		go func() {
			defer close(proc.done)
			if len(args) != 3 {
				proc.err = ttRelayExit(2)
				return
			}
			if bad, err := net.Dial("tcp4", args[1]); err == nil {
				bad.Write([]byte(strings.Repeat("0", len(args[2]))))
				io.Copy(io.Discard, bad)
				bad.Close()
			}
			conn, err := net.Dial("tcp4", args[1])
			if err != nil {
				proc.err = ttRelayExit(1)
				return
			}
			proc.err = ttRelayExit(serveHelper(conn, args[2], open))
		}()
		return proc, nil
	}
}

func TestOpenViaRelayReturnsRelayedDevice(t *testing.T) {
	fake := ttRelayNewFakeDev()
	var gotCfg Config
	open := func(_ context.Context, cfg Config) (*Device, error) {
		gotCfg = cfg
		return &Device{Device: fake, Interface: "tun", Warnings: []string{"w1"}}, nil
	}
	var args []string
	cfg := ttDefaultConfig()
	cfg.Name = "tt0"
	ttRelaySwapLaunch(t, ttRelayLaunch(open, &args))
	dev, err := openViaRelay(t.Context(), cfg, "/x/app.exe")
	if err != nil {
		t.Fatalf("openViaRelay: %v", err)
	}
	defer dev.Close()
	if len(args) != 4 || args[0] != "/x/app.exe" || args[1] != HelperCommand ||
		!regexp.MustCompile(`^127\.0\.0\.1:\d+$`).MatchString(args[2]) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(args[3]) {
		t.Fatalf("launch got %q, want [/x/app.exe tun-helper 127.0.0.1:<port> <64 hex>]", args)
	}
	if dev.Interface != "tun" || len(dev.Warnings) != 1 || dev.Warnings[0] != "w1" {
		t.Errorf("Device Interface, Warnings = %q, %q, want tun, [w1]", dev.Interface, dev.Warnings)
	}
	if gotCfg.Name != cfg.Name || gotCfg.MTU != cfg.MTU || len(gotCfg.Addresses) != 2 || len(gotCfg.Bypass) != len(cfg.Bypass) {
		t.Errorf("helper opened %+v, want %+v", gotCfg, cfg)
	}
	if mtu, _ := dev.MTU(); mtu != cfg.MTU {
		t.Errorf("MTU = %d, want %d", mtu, cfg.MTU)
	}

	go func() { fake.in <- []byte("ping") }()
	if got, err := ttRelayRead(t, dev); err != nil || string(got) != "ping" {
		t.Errorf("Read = %q, %v, want ping", got, err)
	}
	if _, err := dev.Write([][]byte{[]byte("pong")}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case got := <-fake.out:
		if string(got) != "pong" {
			t.Errorf("device got %q, want pong", got)
		}
	case <-time.After(5 * time.Second):
		t.Error("device got no packet within 5s")
	}

	dev.Close()
	select {
	case <-fake.closed:
	case <-time.After(5 * time.Second):
		t.Error("helper did not close its device 5s after the relay closed")
	}
}

// ttRelayHeldProc is an elevate.Proc that exits only once its helper has returned and release is closed.
type ttRelayHeldProc struct {
	elevate.Proc
	release chan struct{}
}

func (p *ttRelayHeldProc) Wait() error {
	err := p.Proc.Wait()
	<-p.release
	return err
}

// ttRelayOpenHeld opens a relayed device whose helper process lingers until release is closed.
func ttRelayOpenHeld(t *testing.T, release chan struct{}) *Device {
	t.Helper()
	open := func(context.Context, Config) (*Device, error) {
		return &Device{Device: ttRelayNewFakeDev(), Interface: "tun"}, nil
	}
	var args []string
	inner := ttRelayLaunch(open, &args)
	launch := func(ctx context.Context, exe string, args []string) (elevate.Proc, error) {
		proc, err := inner(ctx, exe, args)
		if err != nil {
			return nil, err
		}
		return &ttRelayHeldProc{proc, release}, nil
	}
	ttRelaySwapLaunch(t, launch)
	dev, err := openViaRelay(t.Context(), ttDefaultConfig(), "x")
	if err != nil {
		t.Fatalf("openViaRelay: %v", err)
	}
	return dev
}

func TestRelayCloseWaitsForTheHelperToExit(t *testing.T) {
	release := make(chan struct{})
	dev := ttRelayOpenHeld(t, release)
	closed := make(chan error, 1)
	go func() { closed <- dev.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned while the helper process still ran")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close still blocked 5s after the helper exited")
	}
}

// ttRelayCtxProc is an elevate.Proc whose Wait, like elevate's on Windows, returns the launch ctx's error once it is done, and otherwise exits once release is closed.
type ttRelayCtxProc struct {
	elevate.Proc
	ctx     context.Context
	release chan struct{}
}

func (p *ttRelayCtxProc) Wait() error {
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	case <-p.release:
		return p.Proc.Wait()
	}
}

func TestRelayCloseWaitsForTheHelperAfterOpensCtxIsCancelled(t *testing.T) {
	open := func(context.Context, Config) (*Device, error) {
		return &Device{Device: ttRelayNewFakeDev(), Interface: "tun"}, nil
	}
	var args []string
	inner := ttRelayLaunch(open, &args)
	release := make(chan struct{})
	ttRelaySwapLaunch(t, func(ctx context.Context, exe string, args []string) (elevate.Proc, error) {
		proc, err := inner(ctx, exe, args)
		if err != nil {
			return nil, err
		}
		return &ttRelayCtxProc{proc, ctx, release}, nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	dev, err := openViaRelay(ctx, ttDefaultConfig(), "x")
	cancel()
	if err != nil {
		t.Fatalf("openViaRelay: %v", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- dev.Close() }()
	select {
	case <-closed:
		close(release)
		t.Fatal("Close returned while the helper process still ran, taking the cancelled Open ctx for its exit")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-closed:
		if err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close still blocked 5s after the helper exited")
	}
}

func TestRelayCloseGivesUpOnAHelperThatDoesNotExit(t *testing.T) {
	prev := helperExitTimeout
	helperExitTimeout = 100 * time.Millisecond
	t.Cleanup(func() { helperExitTimeout = prev })
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	dev := ttRelayOpenHeld(t, release)
	start := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- dev.Close() }()
	select {
	case <-closed:
		if d := time.Since(start); d < helperExitTimeout {
			t.Errorf("Close returned after %v, want it to wait %v for the helper", d, helperExitTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close still blocked 5s on a helper that does not exit")
	}
}

func TestOpenViaRelaySurfacesReplyError(t *testing.T) {
	open := func(context.Context, Config) (*Device, error) { return nil, errors.New("no adapter today") }
	var args []string
	ttRelaySwapLaunch(t, ttRelayLaunch(open, &args))
	_, err := openViaRelay(t.Context(), ttDefaultConfig(), "x")
	if err == nil || !strings.Contains(err.Error(), "no adapter today") {
		t.Errorf("openViaRelay = %v, want the helper's error", err)
	}
}

func TestOpenViaRelayPassesLaunchError(t *testing.T) {
	ttRelaySwapLaunch(t, func(context.Context, string, []string) (elevate.Proc, error) { return nil, ErrDenied })
	if _, err := openViaRelay(t.Context(), ttDefaultConfig(), "x"); !errors.Is(err, ErrDenied) {
		t.Errorf("openViaRelay = %v, want ErrDenied", err)
	}
}

func TestErrDeniedIsElevateErrDenied(t *testing.T) {
	if ErrDenied != elevate.ErrDenied {
		t.Errorf("ErrDenied = %p, want elevate.ErrDenied %p", ErrDenied, elevate.ErrDenied)
	}
}

// ttRelayExitedLaunch returns a launch whose helper has already exited with Wait returning err.
func ttRelayExitedLaunch(err error) func(context.Context, string, []string) (elevate.Proc, error) {
	return func(context.Context, string, []string) (elevate.Proc, error) {
		proc := &ttRelayProc{done: make(chan struct{}), err: err}
		close(proc.done)
		return proc, nil
	}
}

func TestOpenViaRelayReportsHelperExitCode(t *testing.T) {
	ttRelaySwapLaunch(t, ttRelayExitedLaunch(&elevate.ExitError{Code: 7, Stderr: "boom"}))
	_, err := openViaRelay(t.Context(), ttDefaultConfig(), "x")
	if err == nil || !strings.Contains(err.Error(), "exited with code 7 before connecting") {
		t.Errorf("openViaRelay = %v, want an error saying the helper exited with code 7 before connecting", err)
	}
}

func TestOpenViaRelayReportsCleanHelperExitAsCode0(t *testing.T) {
	ttRelaySwapLaunch(t, ttRelayExitedLaunch(nil))
	_, err := openViaRelay(t.Context(), ttDefaultConfig(), "x")
	if err == nil || !strings.Contains(err.Error(), "exited with code 0 before connecting") {
		t.Errorf("openViaRelay = %v, want an error saying the helper exited with code 0 before connecting", err)
	}
}

func TestOpenViaRelayReturnsErrDeniedFromWait(t *testing.T) {
	ttRelaySwapLaunch(t, ttRelayExitedLaunch(elevate.ErrDenied))
	if _, err := openViaRelay(t.Context(), ttDefaultConfig(), "x"); !errors.Is(err, ErrDenied) {
		t.Errorf("openViaRelay = %v, want ErrDenied", err)
	}
}

func TestOpenViaRelayReturnsOnCancelDuringPrompt(t *testing.T) {
	prompt := make(chan struct{})
	t.Cleanup(func() { close(prompt) })
	prompting := make(chan struct{})
	ttRelaySwapLaunch(t, func(context.Context, string, []string) (elevate.Proc, error) {
		close(prompting)
		<-prompt
		return nil, ErrDenied
	})
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	done := make(chan error, 1)
	go func() {
		_, err := openViaRelay(ctx, ttDefaultConfig(), "x")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("openViaRelay = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("openViaRelay still blocked 5s after cancel")
	}
	// Orders openViaRelay's read of hook.Launch before the cleanup restores it.
	<-prompting
}

func TestOpenViaRelayUsesTheLauncherInstalledAtCallTime(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	calls := make(chan string, 2)
	launcher := func(name string) func(context.Context, string, []string) (elevate.Proc, error) {
		return func(context.Context, string, []string) (elevate.Proc, error) {
			calls <- name
			<-release
			return nil, ErrDenied
		}
	}
	ttRelaySwapLaunch(t, launcher("A"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := openViaRelay(ctx, ttDefaultConfig(), "x"); !errors.Is(err, context.Canceled) {
		t.Errorf("openViaRelay = %v, want context.Canceled", err)
	}
	ttRelaySwapLaunch(t, launcher("B"))
	select {
	case got := <-calls:
		if got != "A" {
			t.Errorf("openViaRelay launched through %s, installed after it returned; want A", got)
		}
	case <-time.After(5 * time.Second):
		t.Error("openViaRelay did not launch the helper within 5s")
	}
}

func TestOpenViaRelayTimesOutWithoutConnection(t *testing.T) {
	prev := relayConnectTimeout
	relayConnectTimeout = 50 * time.Millisecond
	t.Cleanup(func() { relayConnectTimeout = prev })
	proc := &ttRelayProc{done: make(chan struct{})}
	t.Cleanup(func() { close(proc.done) })
	ttRelaySwapLaunch(t, func(context.Context, string, []string) (elevate.Proc, error) { return proc, nil })
	_, err := openViaRelay(t.Context(), ttDefaultConfig(), "x")
	if err == nil || !strings.Contains(err.Error(), "did not connect") {
		t.Errorf("openViaRelay = %v, want an error saying the helper did not connect", err)
	}
}

func TestServeHelperRejectsInvalidRequest(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	a.SetDeadline(time.Now().Add(5 * time.Second))
	opened := false
	open := func(context.Context, Config) (*Device, error) { opened = true; return nil, errors.New("tt") }
	code := make(chan int, 1)
	go func() { code <- serveHelper(b, "tok", open) }()
	io.ReadFull(a, make([]byte, 3))
	writeFrame(a, request{MTU: 1500})
	var rep reply
	if err := readFrame(a, &rep); err != nil || rep.Error == "" {
		t.Errorf("reply = %+v, %v, want an error reply", rep, err)
	}
	if c := <-code; c != 1 || opened {
		t.Errorf("serveHelper = %d (opened %v), want 1 without opening", c, opened)
	}
}

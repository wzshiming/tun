package tun

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/wzshiming/elevate"

	"github.com/wzshiming/tun/internal/hook"
	"github.com/wzshiming/tun/internal/relay"
)

// relayConnectTimeout bounds the wait for the helper to connect once it is launched, and then for its reply.
var relayConnectTimeout = 60 * time.Second

// helperExitTimeout bounds how long closing a relayed device waits for the helper to remove its adapter and exit.
var helperExitTimeout = 5 * time.Second

// helperTokenTimeout bounds how long a connection to the relay listener may take to present the token.
const helperTokenTimeout = 10 * time.Second

// helperDeadline bounds each exchange between the tun-helper and its parent.
const helperDeadline = 10 * time.Second

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
		// Wait must report the helper's real exit, which Close waits for, so the launch outlives ctx.
		proc, err := launch(context.WithoutCancel(ctx), exe, []string{HelperCommand, ln.Addr().String(), token})
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
	dev := relay.New(conn, rep.Name, cfg.MTU)
	dev.Exited, dev.ExitTimeout = exited, helperExitTimeout
	return &Device{Device: dev, Interface: rep.Name, Warnings: rep.Warnings}, nil
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
	relay.Pump(dev, conn)
	return 0
}

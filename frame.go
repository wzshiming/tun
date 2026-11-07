package tun

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"
)

// frameMax bounds the JSON payload of a frame.
const frameMax = 65536

// request asks the helper for a TUN; the helper validates it and computes the routes itself.
type request struct {
	Name      string         `json:"name"`
	Addresses []netip.Prefix `json:"addresses"`
	MTU       int            `json:"mtu"`
	Bypass    []netip.Prefix `json:"bypass,omitempty"`
}

func newRequest(cfg Config) request {
	return request{Name: cfg.Name, Addresses: cfg.Addresses, MTU: cfg.MTU, Bypass: cfg.Bypass}
}

func (r request) config() Config {
	return Config{Name: r.Name, Addresses: r.Addresses, MTU: r.MTU, Bypass: r.Bypass}
}

// reply answers a request; the TUN's descriptor travels with it unless Error is set.
type reply struct {
	Name     string   `json:"name"`
	Warnings []string `json:"warnings,omitempty"`
	Error    string   `json:"error,omitempty"`
}

func writeFrame(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(payload) > frameMax {
		return fmt.Errorf("tun: frame payload of %d bytes exceeds %d", len(payload), frameMax)
	}
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(payload)), uint32(len(payload)))
	_, err = w.Write(append(frame, payload...))
	return err
}

func readFrame(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > frameMax {
		return fmt.Errorf("tun: frame payload of %d bytes exceeds %d", n, frameMax)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}

// openRequested opens the TUN conn requests, or replies with the error and returns nil.
func openRequested(conn net.Conn, open func(context.Context, Config) (*Device, error)) *Device {
	var req request
	if err := readFrame(conn, &req); err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper: read request:", err)
		return nil
	}
	cfg := req.config()
	var dev *Device
	err := validate(cfg)
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		dev, err = open(ctx, cfg)
		cancel()
	}
	// A client that stops reading must not stall the elevated helper.
	conn.SetDeadline(time.Now().Add(helperDeadline))
	if err != nil {
		fmt.Fprintln(os.Stderr, "tun-helper:", err)
		writeFrame(conn, reply{Error: err.Error()})
		return nil
	}
	return dev
}

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/quic"

	"github.com/wzshiming/tun/flow"
)

// ttServed is a TEST-NET-2 address nothing is dialled for: ttServeDev answers its HTTP, HTTPS and QUIC itself.
var ttServed = netip.MustParseAddr("198.51.100.80")

// ttQUICTarget is a TEST-NET-2 destination ttServeDev relays, which tests redirect to a loopback QUIC echo server.
var ttQUICTarget = netip.MustParseAddrPort("198.51.100.1:443")

// ttQUICProto is the ALPN protocol of the QUIC echo servers.
const ttQUICProto = "tt-echo"

// ttTLS returns the config of the tests' TLS servers, whose one certificate names every address a test reaches one at, and the pool that trusts it.
var ttTLS = sync.OnceValues(func() (*tls.Config, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tun e2e"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{ttServed.AsSlice(), ttQUICTarget.Addr().AsSlice(), net.IPv4(1, 1, 1, 1), net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
})

// ttQUICConfig returns the config of a QUIC echo server.
func ttQUICConfig() *quic.Config {
	server, _ := ttTLS()
	server = server.Clone()
	server.NextProtos = []string{ttQUICProto}
	server.MinVersion = tls.VersionTLS13
	return &quic.Config{TLSConfig: server}
}

// ttWebHandler answers a request with its protocol, path and whether it came over TLS.
func ttWebHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s %s tls=%t", r.Proto, r.URL.Path, r.TLS != nil)
}

// ttHandleServed mounts on mux what answers at ttServed without any dial, until ctx ends: HTTP at port 80 and HTTPS at port 443 from one net/http Server on two flow.Listener, and at UDP port 443 a QUIC echo server on the conn of each session a third one accepts.
func ttHandleServed(ctx context.Context, mux *flow.Mux) {
	server, _ := ttTLS()
	server = server.Clone()
	// Served with and without TLS, the server sets HTTP/2 up whichever comes first only with "h2" named here.
	server.NextProtos = []string{"h2", "http/1.1"}
	web := &http.Server{Handler: http.HandlerFunc(ttWebHandler), TLSConfig: server, ReadHeaderTimeout: 10 * time.Second}
	plain, secure, sessions := flow.NewListener(), flow.NewListener(), flow.NewListener()
	mux.Handle("tcp", netip.AddrPortFrom(ttServed, 80).String(), plain)
	mux.Handle("tcp", netip.AddrPortFrom(ttServed, 443).String(), secure)
	mux.Handle("udp", netip.AddrPortFrom(ttServed, 443).String(), sessions)
	go web.Serve(plain)
	go web.ServeTLS(secure, "", "")
	go func() {
		for {
			conn, err := sessions.Accept()
			if err != nil {
				return
			}
			go ttServeQUICSession(ctx, conn)
		}
	}()
	context.AfterFunc(ctx, func() {
		web.Close()
		sessions.Close()
	})
}

// ttServeQUICSession runs a QUIC endpoint on conn, a UDP session's, and echoes the streams of the one connection its client makes; it then closes conn.
// The endpoint takes each datagram's target for its peer, and what it sends there the conn sends to the client from that target.
func ttServeQUICSession(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	endpoint, err := quic.NewEndpoint(conn.(net.PacketConn), ttQUICConfig())
	if err != nil {
		return
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		endpoint.Close(closing)
	}()
	if c, err := endpoint.Accept(ctx); err == nil {
		ttQUICEchoStreams(ctx, c)
	}
}

// ttQUICEchoStreams answers each stream of c with the bytes its client sent before closing its side, until c ends.
func ttQUICEchoStreams(ctx context.Context, c *quic.Conn) {
	defer c.Close()
	for {
		s, err := c.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			defer s.Close()
			if b, err := io.ReadAll(s); err == nil {
				s.Write(b)
			}
		}()
	}
}

// ttServeQUICEcho runs a QUIC echo server on a new 127.0.0.1 socket and returns the socket's address.
func ttServeQUICEcho(t *testing.T) string {
	t.Helper()
	endpoint, err := quic.Listen("udp4", "127.0.0.1:0", ttQUICConfig())
	if err != nil {
		t.Fatalf("listen for quic on 127.0.0.1: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		endpoint.Close(ctx)
	})
	go func() {
		for {
			c, err := endpoint.Accept(ctx)
			if err != nil {
				return
			}
			go ttQUICEchoStreams(ctx, c)
		}
	}()
	return endpoint.LocalAddr().String()
}

// ttServeTLSWeb serves ttWebHandler over HTTPS on a new 127.0.0.1 listener and returns the listener's address.
func ttServeTLSWeb(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on 127.0.0.1: %v", err)
	}
	server, _ := ttTLS()
	srv := &http.Server{Handler: http.HandlerFunc(ttWebHandler), TLSConfig: server.Clone()}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// ttGetBody fetches url on a new connection, trusting ttTLS's certificate, and fails t unless it answers 200 with want.
func ttGetBody(t *testing.T, url, want string) {
	t.Helper()
	_, pool := ttTLS()
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true, DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read the body: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != want {
		t.Fatalf("GET %s = %s %q, want 200 OK %q", url, resp.Status, body, want)
	}
}

// ttQUICEcho connects to the QUIC echo server at address and fails t unless 64 KiB sent on a stream come back unchanged within 10s.
func ttQUICEcho(t *testing.T, address netip.AddrPort) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, err := quic.Listen("udp4", ":0", nil)
	if err != nil {
		t.Fatalf("listen udp4 for quic: %v", err)
	}
	defer endpoint.Close(ctx)
	_, pool := ttTLS()
	config := &quic.Config{TLSConfig: &tls.Config{RootCAs: pool, ServerName: address.Addr().String(), NextProtos: []string{ttQUICProto}, MinVersion: tls.VersionTLS13}}
	c, err := endpoint.Dial(ctx, "udp4", address.String(), config)
	if err != nil {
		t.Fatalf("quic handshake with %v: %v", address, err)
	}
	defer c.Close()
	s, err := c.NewStream(ctx)
	if err != nil {
		t.Fatalf("open a quic stream to %v: %v", address, err)
	}
	s.SetReadContext(ctx)
	s.SetWriteContext(ctx)
	want := make([]byte, 64<<10)
	rand.Read(want)
	if _, err := s.Write(want); err != nil {
		t.Fatalf("write to the quic stream to %v: %v", address, err)
	}
	if err := s.CloseWrite(); err != nil {
		t.Fatalf("end the quic stream to %v: %v", address, err)
	}
	got, err := io.ReadAll(s)
	if err != nil {
		t.Fatalf("read the quic stream from %v: %v", address, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("quic echo via %v: %d bytes came back, changed or short of the %d sent", address, len(got), len(want))
	}
}

// ttServedVia checks through the TUN what ttHandleServed answers at ttServed, and that Serve dialled nothing for it.
func ttServedVia(t *testing.T, rec *ttDialRecorder) {
	t.Run("http served by the stack", func(t *testing.T) {
		ttGetBody(t, "http://"+ttServed.String()+"/plain", "HTTP/1.1 /plain tls=false")
	})
	t.Run("https served by the stack", func(t *testing.T) {
		ttGetBody(t, "https://"+ttServed.String()+"/secure", "HTTP/2.0 /secure tls=true")
	})
	t.Run("quic served by the stack", func(t *testing.T) {
		ttQUICEcho(t, netip.AddrPortFrom(ttServed, 443))
	})
	for _, port := range []uint16{80, 443} {
		if dials := rec.dialsTo(netip.AddrPortFrom(ttServed, port).String()); len(dials) != 0 {
			t.Errorf("Serve dialed %+v, want %v answered without a dial", dials, ttServed)
		}
	}
}

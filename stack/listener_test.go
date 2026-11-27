package stack_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// listenerWait bounds every wait.
const listenerWait = 10 * time.Second

var (
	listenerClient = netip.MustParseAddrPort("10.0.0.2:40000")
	listenerTarget = netip.MustParseAddrPort("10.0.0.9:80")
)

// listenerPair returns both ends of a real loopback TCP connection, closed when t ends, with deadlines listenerWait away.
func listenerPair(t *testing.T) (conn, peer *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	for _, end := range []net.Conn{c, p} {
		end.SetDeadline(time.Now().Add(listenerWait))
		t.Cleanup(func() { end.Close() })
	}
	return c.(*net.TCPConn), p.(*net.TCPConn)
}

// listenerEnv is one tcp flow served by a Listener.
type listenerEnv struct {
	flow *stacktest.Flow
	// accepted is the flow's conn; client is the client's end of it.
	accepted, client *net.TCPConn
	cancel           context.CancelFunc
	done             chan struct{}
}

// listenerServe runs l on a tcp flow over a loopback conn until the test ends.
func listenerServe(t *testing.T, l *stack.Listener) *listenerEnv {
	t.Helper()
	accepted, peer := listenerPair(t)
	env := &listenerEnv{flow: stacktest.NewFlow("tcp", listenerClient, listenerTarget, accepted), accepted: accepted, client: peer, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	env.cancel = cancel
	go func() {
		defer close(env.done)
		l.ServeFlow(ctx, env.flow)
	}()
	t.Cleanup(func() {
		cancel()
		env.wait(t, "its ctx ending")
	})
	return env
}

func (e *listenerEnv) wait(t *testing.T, after string) {
	t.Helper()
	select {
	case <-e.done:
	case <-time.After(listenerWait):
		t.Fatalf("ServeFlow did not return within %v of %s", listenerWait, after)
	}
}

// running fails the test if ServeFlow returned.
func (e *listenerEnv) running(t *testing.T, during string) {
	t.Helper()
	select {
	case <-e.done:
		t.Fatalf("ServeFlow returned during %s", during)
	case <-time.After(50 * time.Millisecond):
	}
}

// listenerHTTP serves a new Listener with srv, plain or over TLS, until the test ends.
func listenerHTTP(t *testing.T, srv *http.Server, overTLS bool) *stack.Listener {
	t.Helper()
	l := stack.NewListener()
	go func() {
		if overTLS {
			srv.ServeTLS(l, "", "")
		} else {
			srv.Serve(l)
		}
	}()
	t.Cleanup(func() { srv.Close() })
	return l
}

// listenerGet sends a GET of path on conn and returns the response's body.
func listenerGet(t *testing.T, conn net.Conn, r *bufio.Reader, path string) string {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: example.test\r\n\r\n", path); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %s, body %q", path, resp.Status, body)
	}
	return string(body)
}

func listenerEchoPath() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "path "+r.URL.Path) })
}

func TestListenerServesHTTPRequestsOfAKeptAliveConnection(t *testing.T) {
	env := listenerServe(t, listenerHTTP(t, &http.Server{Handler: listenerEchoPath()}, false))
	r := bufio.NewReader(env.client)
	for _, path := range []string{"/first", "/second"} {
		if got := listenerGet(t, env.client, r, path); got != "path "+path {
			t.Fatalf("GET %s = %q, want %q", path, got, "path "+path)
		}
	}
	if !env.flow.Accepted() {
		t.Fatal("the flow was not accepted")
	}
	env.running(t, "a kept-alive connection")
}

func TestListenerConnCarriesTheFlowsAddresses(t *testing.T) {
	type addrs struct{ remote, local string }
	got := make(chan addrs, 1)
	h := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		got <- addrs{r.RemoteAddr, fmt.Sprint(local)}
	})
	env := listenerServe(t, listenerHTTP(t, &http.Server{Handler: h}, false))
	listenerGet(t, env.client, bufio.NewReader(env.client), "/")
	want := addrs{env.accepted.RemoteAddr().String(), env.accepted.LocalAddr().String()}
	if a := <-got; a != want {
		t.Fatalf("RemoteAddr, LocalAddrContextKey = %+v, want the conn's %+v", a, want)
	}
}

func TestListenerFlowEndsOnceTheClientCloses(t *testing.T) {
	env := listenerServe(t, listenerHTTP(t, &http.Server{Handler: listenerEchoPath()}, false))
	listenerGet(t, env.client, bufio.NewReader(env.client), "/")
	env.client.Close()
	env.wait(t, "the client closing")
}

func TestListenerFlowEndsOnceTheServerClosesTheConn(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Connection", "close") })
	env := listenerServe(t, listenerHTTP(t, &http.Server{Handler: h}, false))
	r := bufio.NewReader(env.client)
	listenerGet(t, env.client, r, "/")
	if _, err := r.ReadByte(); err != io.EOF {
		t.Fatalf("read after a Connection: close response = %v, want EOF", err)
	}
	env.wait(t, "the server closing the connection")
}

func TestListenerClosesTheConnWhenContextEnds(t *testing.T) {
	env := listenerServe(t, listenerHTTP(t, &http.Server{Handler: listenerEchoPath()}, false))
	listenerGet(t, env.client, bufio.NewReader(env.client), "/")
	env.cancel()
	env.wait(t, "its ctx ending")
	if n, err := env.client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("the client after ctx ended: Read() = %d, %v; want 0, EOF", n, err)
	}
}

func TestListenerHijackedConnLastsUntilItsHijackerClosesIt(t *testing.T) {
	hijacked := make(chan net.Conn, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		io.WriteString(conn, "raw")
		hijacked <- conn
	})
	env := listenerServe(t, listenerHTTP(t, &http.Server{Handler: h}, false))
	fmt.Fprint(env.client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	raw := make([]byte, 3)
	if _, err := io.ReadFull(env.client, raw); err != nil || string(raw) != "raw" {
		t.Fatalf("read from the hijacked conn = %q, %v; want raw", raw, err)
	}
	conn := <-hijacked
	env.running(t, "a hijacked connection")
	conn.Close()
	env.wait(t, "the hijacker closing the connection")
}

func TestListenerShutdownWaitsForTheRequestInFlightAndRejectsLaterFlows(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "late")
	})}
	l := listenerHTTP(t, srv, false)
	env := listenerServe(t, l)
	fmt.Fprint(env.client, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	<-started
	shutdown := make(chan error, 1)
	go func() { shutdown <- srv.Shutdown(context.Background()) }()
	env.running(t, "a Shutdown with its request in flight")

	late := listenerServe(t, l)
	late.wait(t, "a flow arriving after the Shutdown")
	if !late.flow.Rejected() {
		t.Fatal("a flow arriving after the server's Shutdown was not rejected")
	}

	close(release)
	resp, err := http.ReadResponse(bufio.NewReader(env.client), nil)
	if err != nil {
		t.Fatalf("response of the request in flight at Shutdown: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "late" {
		t.Fatalf("body = %q, want late", body)
	}
	if err := <-shutdown; err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	env.wait(t, "Shutdown")
}

func TestListenerServesHTTPSWithHTTP2(t *testing.T) {
	// The test server only lends its certificate and a client trusting it.
	ts := httptest.NewUnstartedServer(nil)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s %s tls=%t", r.Proto, r.URL.Path, r.TLS != nil && r.TLS.HandshakeComplete)
		}),
		TLSConfig: &tls.Config{Certificates: ts.TLS.Certificates},
	}
	env := listenerServe(t, listenerHTTP(t, srv, true))
	transport := ts.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) { return env.client, nil }
	resp, err := (&http.Client{Transport: transport, Timeout: listenerWait}).Get("https://example.com/secure")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := "HTTP/2.0 /secure tls=true"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	transport.CloseIdleConnections()
	env.wait(t, "the client closing its TLS connection")
}

func TestListenerAcceptsAUDPSessionAsAPacketConn(t *testing.T) {
	l := stack.NewListener()
	defer l.Close()
	session := stacktest.NewSession(listenerClient, listenerTarget)
	flow := stacktest.NewFlow("udp", listenerClient, listenerTarget, session)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.ServeFlow(t.Context(), flow)
	}()
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	pc, ok := conn.(net.PacketConn)
	if !ok {
		t.Fatalf("Accept() of a udp flow returned a %T, want a net.PacketConn", conn)
	}
	if conn.RemoteAddr().String() != listenerClient.String() || conn.LocalAddr().String() != listenerTarget.String() {
		t.Fatalf("RemoteAddr, LocalAddr = %v, %v; want %v, %v", conn.RemoteAddr(), conn.LocalAddr(), listenerClient, listenerTarget)
	}
	other := netip.MustParseAddrPort("10.0.0.10:80")
	session.Send([]byte("ping"), other)
	b := make([]byte, 16)
	n, addr, err := pc.ReadFrom(b)
	if err != nil || string(b[:n]) != "ping" || addr.String() != other.String() {
		t.Fatalf("ReadFrom() = %q, %v, %v; want ping sent to %v", b[:n], addr, err, other)
	}
	if _, err := pc.WriteTo([]byte("pong"), addr); err != nil {
		t.Fatal(err)
	}
	if reply, from, ok := session.NextReply(listenerWait); !ok || string(reply) != "pong" || from != other {
		t.Fatalf("reply = %q from %v, %v; want pong from %v", reply, from, ok, other)
	}
	conn.Close()
	select {
	case <-done:
	case <-time.After(listenerWait):
		t.Fatalf("ServeFlow did not return within %v of its conn closing", listenerWait)
	}
	if !session.Closed() {
		t.Fatal("closing the accepted conn left the session open")
	}
}

func TestListenerLeavesAFlowNobodyAcceptsUnanswered(t *testing.T) {
	l := stack.NewListener()
	flow := stacktest.NewFlow("tcp", listenerClient, listenerTarget, nil)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.ServeFlow(ctx, flow)
	}()
	select {
	case <-done:
		t.Fatal("ServeFlow returned with nobody accepting and its ctx live")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(listenerWait):
		t.Fatalf("ServeFlow did not return within %v of its ctx ending", listenerWait)
	}
	if flow.Accepted() {
		t.Fatal("a flow nobody accepted was accepted")
	}
}

func TestListenerCloseFailsAcceptAndRejectsFlows(t *testing.T) {
	l := stack.NewListener()
	waiting := stacktest.NewFlow("tcp", listenerClient, listenerTarget, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.ServeFlow(t.Context(), waiting)
	}()
	time.Sleep(50 * time.Millisecond)
	l.Close()
	l.Close()
	select {
	case <-done:
	case <-time.After(listenerWait):
		t.Fatalf("ServeFlow of a waiting flow did not return within %v of Close", listenerWait)
	}
	later := stacktest.NewFlow("tcp", listenerClient, listenerTarget, nil)
	l.ServeFlow(t.Context(), later)
	if !waiting.Rejected() || !later.Rejected() {
		t.Fatalf("after Close: waiting flow rejected %v, later flow rejected %v; want both", waiting.Rejected(), later.Rejected())
	}
	if conn, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() after Close = %v, %v; want net.ErrClosed", conn, err)
	}
}

func TestListenerSkipsAFlowThatCannotBeAccepted(t *testing.T) {
	l := stack.NewListener()
	defer l.Close()
	gone := stacktest.NewFlow("tcp", listenerClient, listenerTarget, nil)
	gone.Reject()
	go l.ServeFlow(t.Context(), gone)
	env := listenerServe(t, l)
	conn, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if conn.RemoteAddr().String() != env.accepted.RemoteAddr().String() {
		t.Fatalf("Accept() returned the conn of %v, want that of the flow still acceptable", conn.RemoteAddr())
	}
	if _, ok := conn.(interface{ CloseWrite() error }); !ok {
		t.Fatalf("Accept() of a tcp flow returned a %T without CloseWrite", conn)
	}
	conn.Close()
	env.wait(t, "its conn closing")
}

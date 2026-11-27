package stack

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// testAnswerTimeout is the Options.AnswerTimeout the answer tests serve with.
	testAnswerTimeout = 300 * time.Millisecond
	// testAnswerWindow is how long a client may wait for the reset testAnswerTimeout brings.
	testAnswerWindow = 2*testAnswerTimeout + 2*time.Second
	// testAnswerSpared is how long a flow testAnswerTimeout must leave alone is watched, well past it.
	testAnswerSpared = testAnswerTimeout + time.Second
)

// answerCall is one ServeFlow call and what answering its flow at once returned.
type answerCall struct {
	ctx  context.Context
	flow Flow
	conn net.Conn
	err  error
}

// answerNever leaves a flow unanswered.
func answerNever(Flow) (net.Conn, error) { return nil, nil }

// answerServe serves with testAnswerTimeout a handler that passes each flow to answer, hands the call to the test and returns only when the test ends.
func answerServe(t *testing.T, answer func(Flow) (net.Conn, error)) (*testEnv, <-chan answerCall) {
	t.Helper()
	calls, release := make(chan answerCall, 4), make(chan struct{})
	env := testServeWith(t, Options{AnswerTimeout: testAnswerTimeout}, HandlerFunc(func(ctx context.Context, f Flow) {
		conn, err := answer(f)
		calls <- answerCall{ctx, f, conn, err}
		<-release
	}))
	// Cleanups run last first, so this one releases the handlers before Serve is stopped.
	t.Cleanup(func() { close(release) })
	return env, calls
}

// answerDialRefused dials a TCP flow and returns how long its client waited for the reset, failing t unless one came within testAnswerWindow.
func answerDialRefused(t *testing.T, env *testEnv) time.Duration {
	t.Helper()
	ctx, cancel := context.WithTimeout(env.alive, testAnswerWindow)
	defer cancel()
	start := time.Now()
	conn, err := env.client.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("10.0.0.9:443"))
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
	}
	if want := (&tcpip.ErrConnectionRefused{}).String(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("client dial of a TCP flow left unanswered = %v after %v%s, want %q within %v under AnswerTimeout %v", err, elapsed, env.returned(), want, testAnswerWindow, testAnswerTimeout)
	}
	return elapsed
}

// answerSpared watches ctx, the ServeFlow ctx of what, for testAnswerSpared and fails t if it ends.
func answerSpared(t *testing.T, ctx context.Context, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(testAnswerSpared):
	}
	if ctx.Err() != nil {
		t.Fatalf("ServeFlow's ctx of %s ended within %v, want AnswerTimeout %v to leave it alone", what, testAnswerSpared, testAnswerTimeout)
	}
}

func TestTCPFlowUnansweredPastAnswerTimeoutIsRefused(t *testing.T) {
	env, _ := answerServe(t, answerNever)
	if elapsed := answerDialRefused(t, env); elapsed < testAnswerTimeout {
		t.Fatalf("Serve refused a TCP flow its handler left unanswered after %v, want it to wait out AnswerTimeout %v", elapsed, testAnswerTimeout)
	}
}

func TestAnswerTimeoutEndsServeFlowContext(t *testing.T) {
	env, calls := answerServe(t, answerNever)
	answerDialRefused(t, env)
	if call := testReceive(t, calls, "the unanswered flow's ServeFlow call"); call.ctx.Err() == nil {
		t.Fatal("ServeFlow's ctx is still live once Serve refused its TCP flow for want of an answer, want it ended by then")
	}
}

func TestFlowAcceptAfterAnswerTimeoutErrors(t *testing.T) {
	env, calls := answerServe(t, answerNever)
	answerDialRefused(t, env)
	conn, err := testReceive(t, calls, "the unanswered flow's ServeFlow call").flow.Accept()
	if err == nil {
		conn.Close()
		t.Fatal("Accept() on a TCP flow Serve refused for want of an answer = nil error, want an error")
	}
}

func TestTCPFlowAcceptedWithinAnswerTimeoutOutlivesIt(t *testing.T) {
	env, calls := answerServe(t, Flow.Accept)
	client := env.dialTCP(t, "10.0.0.9:443")
	call := testReceive(t, calls, "the handler's Accept")
	if call.err != nil {
		t.Fatalf("Accept() as soon as the TCP flow arrived = %v, want its conn", call.err)
	}
	answerSpared(t, call.ctx, "a TCP flow accepted at once")
	call.conn.SetDeadline(time.Now().Add(testWait))
	testDeliver(t, client, call.conn, "client to handler")
	testDeliver(t, call.conn, client, "handler to client")
}

func TestOptionsAnswerTimeoutDefaultsTo30Seconds(t *testing.T) {
	if got := (Options{}).answerTimeout(); got != 30*time.Second {
		t.Fatalf("Options{}.answerTimeout() = %v, want the 30s default", got)
	}
	if got := (Options{AnswerTimeout: 3 * time.Second}).answerTimeout(); got != 3*time.Second {
		t.Fatalf("Options{AnswerTimeout: 3s}.answerTimeout() = %v, want 3s", got)
	}
}

func TestUDPFlowUnansweredPastAnswerTimeoutIsStillAccepted(t *testing.T) {
	env, calls := answerServe(t, answerNever)
	target := netip.MustParseAddrPort("10.0.0.9:5353")
	testSend(t, env.dialUDP(t, target.String()), "query")
	call := testReceive(t, calls, "the UDP flow's ServeFlow call")
	answerSpared(t, call.ctx, "an unanswered UDP flow")
	conn, err := call.flow.Accept()
	if err != nil {
		t.Fatalf("Accept() on a UDP flow left unanswered past AnswerTimeout %v = %v, want its session", testAnswerTimeout, err)
	}
	conn.SetReadDeadline(time.Now().Add(testWait))
	if got, want := udpReadFrom(conn), (udpRead{"query", target, nil}); got != want {
		t.Fatalf("the session accepted past AnswerTimeout read %+v, want %+v", got, want)
	}
}

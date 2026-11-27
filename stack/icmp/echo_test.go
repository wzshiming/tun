package icmp

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/wzshiming/tun/flow"
	"github.com/wzshiming/tun/internal/stacktest"
	"github.com/wzshiming/tun/stack"
)

// echoEnv is one ServeFlow of an Echo on a flow whose conn is one end of a pipe.
type echoEnv struct {
	flow   *stacktest.Flow
	client net.Conn
	cancel context.CancelFunc
	done   chan struct{}
}

// testServeEcho serves h a flow of network from client to target.
func testServeEcho(t *testing.T, h Echo, network string, client, target netip.Addr) *echoEnv {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	served, ours := net.Pipe()
	env := &echoEnv{
		flow:   stacktest.NewFlow(network, netip.AddrPortFrom(client, 0x1234), netip.AddrPortFrom(target, 0), served),
		client: ours,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		defer close(env.done)
		h.ServeFlow(ctx, env.flow)
	}()
	t.Cleanup(func() {
		cancel()
		ours.Close()
		env.returned(t)
	})
	return env
}

// returned fails unless ServeFlow returns within testWait.
func (env *echoEnv) returned(t *testing.T) {
	t.Helper()
	select {
	case <-env.done:
	case <-time.After(testWait):
		t.Fatalf("ServeFlow did not return within %v", testWait)
	}
}

// exchange sends message from the client and returns what the session answers within wait, or nil.
func (env *echoEnv) exchange(t *testing.T, message []byte, wait time.Duration) []byte {
	t.Helper()
	env.client.SetWriteDeadline(time.Now().Add(testWait))
	if _, err := env.client.Write(message); err != nil {
		t.Fatalf("client echo request: %v", err)
	}
	env.client.SetReadDeadline(time.Now().Add(wait))
	reply := make([]byte, 65535)
	n, err := env.client.Read(reply)
	if err != nil {
		return nil
	}
	return reply[:n]
}

func TestEchoAnswersEachEchoRequestItself(t *testing.T) {
	for _, fam := range icmpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			env := testServeEcho(t, Echo{}, "icmp", fam.client, fam.target)
			for seq := uint16(1); seq <= 3; seq++ {
				request := echo(fam.request, seq, "payload")
				want := echo(fam.reply, seq, "payload")
				if got := env.exchange(t, request, testWait); !bytes.Equal(got, want) {
					t.Fatalf("echo request % x was answered with % x, want the echo reply % x", request, got, want)
				}
			}
			if !env.flow.Accepted() {
				t.Error("flow not accepted")
			}
		})
	}
}

func TestEchoLeavesAMessageShorterThanItsHeaderUnanswered(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServeEcho(t, Echo{}, "icmp", fam.client, fam.target)
	if got := env.exchange(t, []byte{fam.request, 0, 0, 0}, testQuiet); got != nil {
		t.Fatalf("a 4-byte message was answered with % x, want it dropped", got)
	}
	if got, want := env.exchange(t, echo(fam.request, 1, "x"), testWait), echo(fam.reply, 1, "x"); !bytes.Equal(got, want) {
		t.Fatalf("the echo request after it was answered with % x, want % x", got, want)
	}
}

func TestEchoRejectsOtherNetworks(t *testing.T) {
	fam := icmpFamilies[0]
	for _, network := range []string{"tcp", "udp"} {
		env := testServeEcho(t, Echo{}, network, fam.client, fam.target)
		env.returned(t)
		if !env.flow.Rejected() {
			t.Errorf("%s flow not rejected", network)
		}
	}
}

func TestEchoEndsAnIdleSession(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServeEcho(t, Echo{Idle: 200 * time.Millisecond}, "icmp", fam.client, fam.target)
	start := time.Now()
	if env.exchange(t, echo(fam.request, 1, "x"), testWait) == nil {
		t.Fatal("echo request got no reply")
	}
	env.returned(t)
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond {
		t.Fatalf("session ended %v after its last echo request, want it kept for the Idle of 200ms", elapsed)
	}
	if _, err := env.client.Write(echo(fam.request, 2, "x")); err == nil {
		t.Fatal("client wrote to the session's conn after ServeFlow returned, want it closed")
	}
}

func TestEchoEndsWithItsContext(t *testing.T) {
	fam := icmpFamilies[0]
	env := testServeEcho(t, Echo{}, "icmp", fam.client, fam.target)
	if env.exchange(t, echo(fam.request, 1, "x"), testWait) == nil {
		t.Fatal("echo request got no reply")
	}
	env.cancel()
	env.returned(t)
}

// A ping through Serve reaches Echo by the address it is mounted on, and no other address answers.
func TestEchoAnswersAPingThroughServe(t *testing.T) {
	for _, fam := range icmpFamilies {
		t.Run(fam.name, func(t *testing.T) {
			dev, client, err := netstack.CreateNetTUN([]netip.Addr{fam.client}, nil, 1500)
			if err != nil {
				t.Fatalf("netstack.CreateNetTUN: %v", err)
			}
			m := flow.NewMux()
			m.Handle("icmp", fam.target.String(), Echo{})
			ctx, cancel := context.WithCancel(context.Background())
			served := make(chan error, 1)
			go func() { served <- stack.Serve(ctx, dev, m, stack.Options{}) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-served:
				case <-time.After(testWait):
					t.Errorf("Serve did not return within %v", testWait)
				}
			})
			ping := func(target netip.Addr, wait time.Duration) []byte {
				conn, err := client.DialPingAddr(fam.client, target)
				if err != nil {
					t.Fatalf("client DialPingAddr(%v, %v): %v", fam.client, target, err)
				}
				defer conn.Close()
				// PingConn.Read misses a reply that arrives before it waits, so keep sending until one is read.
				stop := make(chan struct{})
				defer close(stop)
				go func() {
					for {
						conn.Write(echo(fam.request, 1, "test"))
						select {
						case <-stop:
							return
						case <-time.After(50 * time.Millisecond):
						}
					}
				}()
				conn.SetReadDeadline(time.Now().Add(wait))
				message := make([]byte, 1500)
				n, err := conn.Read(message)
				if err != nil {
					return nil
				}
				return message[:n]
			}
			reply := ping(fam.target, testWait)
			if len(reply) < headerSize || reply[0] != fam.reply || string(reply[headerSize:]) != "test" {
				t.Fatalf("ping of %v, where Echo is mounted, got % x, want an echo reply carrying \"test\"", fam.target, reply)
			}
			if reply := ping(fam.other, testQuiet); reply != nil {
				t.Fatalf("ping of %v, where nothing is mounted, was answered with % x", fam.other, reply)
			}
		})
	}
}

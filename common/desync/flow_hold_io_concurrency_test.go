package desync

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type heldIOCase struct {
	lease            *Lease
	flow             *flowState
	head, tail, next *Packet
}

func newHeldIOCase(t *testing.T, transport string) heldIOCase {
	t.Helper()
	if transport == "tcp" {
		h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`, `{"hold_timeout":"10s"}`)
		hello := buildClientHello("io-order.example")
		return heldIOCase{h.lease, h.lease.tcpFlow,
			buildIPv4TCP(t, hello[:12], 1000, tcpFlagACK|tcpFlagPSH),
			buildIPv4TCP(t, hello[12:], 1012, tcpFlagACK|tcpFlagPSH),
			buildIPv4TCP(t, []byte("later"), 1000+uint32(len(hello)), tcpFlagACK|tcpFlagPSH)}
	}
	fixture := newUDPPeerEngine(t, 4, `,"limits":{"hold_timeout":"10s"}`, "["+qa519UDPRules("010203", 2, "")+"]")
	lease := fixture.connected("192.0.2.10:12345", "198.51.100.20:443")
	head, tail := qa519SplitInitials(t, "io-order.example", 40, qa519DCID(0x19), 1, 1)
	next, _ := qa519SplitInitials(t, "next-cycle.example", 40, qa519DCID(0x29), 1, 1)
	// Construct the real peer before admission, without adding a captured
	// original or a second budget owner.
	packet := udpPeerPacket(t, lease.intent.Source, lease.intent.Destination, head)
	flow, ok := lease.acquireUDPFlow(packet)
	if !ok {
		t.Fatal("peer admission refused")
	}
	lease.releaseUDPUser()
	return heldIOCase{lease, flow, packet,
		udpPeerPacket(t, lease.intent.Source, lease.intent.Destination, tail),
		udpPeerPacket(t, lease.intent.Source, lease.intent.Destination, next)}
}

type heldIOSnapshot struct {
	bytes, queued int
	global        int64
	packets       uint64
}

// Read state using the real flow mutex while a synchronous callback is blocked.
// A timeout is a failing lock boundary, not a successful no-op observation.
func snapshotHeldIO(t *testing.T, c heldIOCase) heldIOSnapshot {
	t.Helper()
	out := make(chan heldIOSnapshot, 1)
	go func() {
		c.flow.mu.Lock()
		out <- heldIOSnapshot{c.flow.heldBytes, len(c.flow.holds), c.lease.engine.heldBytes.Load(), c.flow.countersSnapshot().packets}
		c.flow.mu.Unlock()
	}()
	select {
	case result := <-out:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("flow mutex unavailable while held I/O blocked")
		return heldIOSnapshot{}
	}
}

func assertHeldIOPending(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
		t.Fatal("detached release was overtaken before synchronous callback returned")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestHeldIOJoinsDetachedRelease(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, phase := range []string{"inject", "complete"} {
			for _, contender := range []string{"packet", "flush", "timer"} {
				t.Run(transport+"/"+phase+"/"+contender, func(t *testing.T) {
					c := newHeldIOCase(t, transport)
					entered, release, replayDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
					var blockOnce, releaseOnce sync.Once
					unblock := func() { releaseOnce.Do(func() { close(release) }) }
					t.Cleanup(unblock)
					block := func() { blockOnce.Do(func() { close(entered); <-release }) }
					var sends, completes atomic.Int32
					inject := func([]byte) error {
						sends.Add(1)
						if phase == "inject" {
							block()
						}
						return nil
					}
					complete := func(Verdict, string, []byte) {
						completes.Add(1)
						if phase == "complete" {
							block()
						}
					}
					if v := c.lease.HandlePacket(c.head.Raw, DirectionOutbound, inject, complete); v != VerdictHold {
						t.Fatalf("head=%v", v)
					}
					c.flow.mu.Lock()
					gen := c.flow.holdGen
					c.flow.mu.Unlock()
					go func() { defer close(replayDone); c.lease.HandlePacket(c.tail.Raw, DirectionOutbound, inject, complete) }()
					waitTCPBudgetSignal(t, entered)
					before := snapshotHeldIO(t, c)
					want := len(c.head.Raw)
					if transport == "udp" {
						want += len(c.tail.Raw)
					}
					if before.bytes != want || before.global != int64(want) || before.queued != 0 {
						t.Fatalf("active snapshot=%+v, want charged=%d detached", before, want)
					}
					started, done := make(chan struct{}), make(chan struct{})
					go func() {
						defer close(done)
						close(started)
						switch contender {
						case "packet":
							c.lease.HandlePacket(c.next.Raw, DirectionOutbound, nil, func(Verdict, string, []byte) {})
						case "flush":
							c.flow.flushHeld("competing flush")
						case "timer":
							c.flow.expireGen(gen)
						}
					}()
					waitTCPBudgetSignal(t, started)
					assertHeldIOPending(t, done)
					if during := snapshotHeldIO(t, c); during != before {
						t.Fatalf("contender mutated active release: before=%+v during=%+v", before, during)
					}
					unblock()
					waitTCPBudgetSignal(t, replayDone)
					waitTCPBudgetSignal(t, done)
					wantCompletes := int32(1)
					if transport == "udp" {
						wantCompletes = 2
					}
					if sends.Load() == 0 || completes.Load() != wantCompletes {
						t.Fatalf("vacuous sends=%d originals=%d", sends.Load(), completes.Load())
					}
					if transport == "udp" && contender == "packet" {
						// The new cycle was admitted only after the old release. A
						// stopped old timer must not disposition this new original.
						c.flow.expireGen(gen)
						if got := snapshotHeldIO(t, c); got.queued != 1 || got.bytes != len(c.next.Raw) {
							t.Fatalf("old timer reached new cycle: %+v", got)
						}
					}
					c.flow.flushHeld("cleanup")
					if got := snapshotHeldIO(t, c); got.bytes != 0 || got.global != 0 || got.queued != 0 {
						t.Fatalf("final reservations=%+v", got)
					}
				})
			}
		}
	}
}

func TestHeldIOCloseJoinsDetachedRelease(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, phase := range []string{"inject", "complete"} {
			t.Run(transport+"/"+phase, func(t *testing.T) {
				c := newHeldIOCase(t, transport)
				entered, release, replayDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once, releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				block := func() { once.Do(func() { close(entered); <-release }) }
				var sends, completes atomic.Int32
				inject := func([]byte) error {
					sends.Add(1)
					if phase == "inject" {
						block()
					}
					return nil
				}
				complete := func(Verdict, string, []byte) {
					completes.Add(1)
					if phase == "complete" {
						block()
					}
				}
				if v := c.lease.HandlePacket(c.head.Raw, DirectionOutbound, inject, complete); v != VerdictHold {
					t.Fatalf("head=%v", v)
				}
				go func() { defer close(replayDone); c.lease.HandlePacket(c.tail.Raw, DirectionOutbound, inject, complete) }()
				waitTCPBudgetSignal(t, entered)
				before := snapshotHeldIO(t, c)
				closed := make(chan struct{})
				closeErr := make(chan error, 1)
				go func() { defer close(closed); closeErr <- c.lease.Close(nil) }()
				deadline := time.Now().Add(5 * time.Second)
				for !c.lease.closedFlag.Load() {
					if time.Now().After(deadline) {
						t.Fatal("Close did not publish admission fence")
					}
					runtime.Gosched()
				}
				assertHeldIOPending(t, closed)
				select {
				case <-c.lease.captureRetired:
					t.Fatal("capture retired before held I/O returned")
				default:
				}
				if c.lease.engine.ActiveLeases() != 1 {
					t.Fatal("charged lease retired before held I/O returned")
				}
				if transport == "udp" && udpPeerCharge(c.lease.engine) != 1 {
					t.Fatal("peer state charge retired before replay returned")
				}
				if during := snapshotHeldIO(t, c); during != before {
					t.Fatalf("Close released ownership early: before=%+v during=%+v", before, during)
				}
				unblock()
				waitTCPBudgetSignal(t, replayDone)
				waitTCPBudgetSignal(t, closed)
				if err := <-closeErr; err != nil {
					t.Fatal(err)
				}
				if err := c.lease.WaitCaptureRetired(); err != nil {
					t.Fatal(err)
				}
				if err := c.lease.Close(nil); err != nil {
					t.Fatal(err)
				}
				want := int32(1)
				if transport == "udp" {
					want = 2
				}
				if sends.Load() == 0 || completes.Load() != want {
					t.Fatalf("vacuous/duplicate sends=%d completes=%d", sends.Load(), completes.Load())
				}
				if got := snapshotHeldIO(t, c); got.bytes != 0 || got.global != 0 || got.queued != 0 {
					t.Fatalf("final charge=%+v", got)
				}
				if c.lease.engine.ActiveLeases() != 0 || (transport == "udp" && udpPeerCharge(c.lease.engine) != 0) {
					t.Fatal("terminal release did not retire charges")
				}
			})
		}
	}
}

package desync

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

// Held callbacks may perform synchronous native/helper I/O. They must not
// inherit the flow mutex; state and reservations still belong to the flow.
func assertHeldIOLocksAvailable(t *testing.T, lease *Lease, flow *flowState) {
	t.Helper()
	for _, item := range []struct {
		name string
		mu   *sync.Mutex
	}{{"flow", &flow.mu}, {"lease", &lease.mu}, {"engine", &lease.engine.mu}} {
		if item.mu.TryLock() {
			item.mu.Unlock()
		} else {
			t.Errorf("%s mutex held across synchronous held callback", item.name)
		}
	}
}

func TestHeldIOUnlocksTCPReplayAndCompletion(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "send-error"}[fail], func(t *testing.T) {
			h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`, `{"hold_timeout":"10s"}`)
			flow := h.lease.tcpFlow
			hello := buildClientHello("held-io.example")
			var events []string
			sends, completes := 0, 0
			inject := func([]byte) error {
				assertHeldIOLocksAvailable(t, h.lease, flow)
				sends++
				events = append(events, "send")
				if fail {
					return errors.New("bounded held send failure")
				}
				return nil
			}
			complete := func(Verdict, string, []byte) {
				assertHeldIOLocksAvailable(t, h.lease, flow)
				completes++
				events = append(events, "complete")
			}
			first := buildIPv4TCP(t, hello[:12], 1000, tcpFlagACK|tcpFlagPSH)
			if v := h.lease.HandlePacket(first.Raw, DirectionOutbound, inject, complete); v != VerdictHold {
				t.Fatalf("head verdict=%v", v)
			}
			tail := buildIPv4TCP(t, hello[12:], 1012, tcpFlagACK|tcpFlagPSH)
			h.lease.HandlePacket(tail.Raw, DirectionOutbound, inject, nil)
			if sends == 0 || completes != 1 || events[len(events)-1] != "complete" {
				t.Fatalf("vacuous/order failure sends=%d completes=%d events=%v", sends, completes, events)
			}
			if flow.heldBytes != 0 || h.engine.heldBytes.Load() != 0 || flow.failed != fail {
				t.Fatalf("final local=%d global=%d failed=%v", flow.heldBytes, h.engine.heldBytes.Load(), flow.failed)
			}
		})
	}
}

func TestHeldIOUDPReplayFailurePreservesOriginals(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "partial-send-error", true: "missing-injector"}[missing], func(t *testing.T) {
			c := newHeldIOCase(t, "udp")
			sendErr := errors.New("bounded replay failure")
			sends := 0
			var events []string
			inject := func([]byte) error {
				assertHeldIOLocksAvailable(t, c.lease, c.flow)
				sends++
				events = append(events, "send")
				if sends == 2 {
					return sendErr
				}
				return nil
			}
			completed := 0
			remaining := len(c.head.Raw) + len(c.tail.Raw)
			complete := func(v Verdict, _ string, modified []byte) {
				assertHeldIOLocksAvailable(t, c.lease, c.flow)
				c.flow.mu.Lock()
				if c.flow.heldBytes != remaining || c.lease.engine.heldBytes.Load() != int64(remaining) {
					t.Errorf("reservation released before callback return: local=%d global=%d want=%d", c.flow.heldBytes, c.lease.engine.heldBytes.Load(), remaining)
				}
				c.flow.mu.Unlock()
				if v != VerdictPass || modified != nil {
					t.Errorf("failed replay suppressed original: %v %x", v, modified)
				}
				events = append(events, "complete")
				if completed == 0 {
					remaining -= len(c.head.Raw)
				} else {
					remaining -= len(c.tail.Raw)
				}
				completed++
			}
			if v := c.lease.HandlePacket(c.head.Raw, DirectionOutbound, inject, complete); v != VerdictHold {
				t.Fatalf("head=%v", v)
			}
			if missing {
				inject = nil
			}
			if v := c.lease.HandlePacket(c.tail.Raw, DirectionOutbound, inject, complete); v != VerdictHold {
				t.Fatalf("owned failing tail=%v", v)
			}
			want := []string{"send", "send", "complete", "complete"}
			if missing {
				want = []string{"complete", "complete"}
			}
			if completed != 2 || !reflect.DeepEqual(events, want) || !c.flow.failed || c.lease.Err() == nil {
				t.Fatalf("sends=%d completed=%d events=%v failed=%v error=%v", sends, completed, events, c.flow.failed, c.lease.Err())
			}
			if !missing && !errors.Is(c.lease.Err(), sendErr) {
				t.Fatalf("send error identity lost: %v", c.lease.Err())
			}
			c.flow.flushHeld("repeated")
			if c.flow.heldBytes != 0 || c.lease.engine.heldBytes.Load() != 0 || completed != 2 {
				t.Fatal("failed replay leaked or double-completed originals")
			}
		})
	}
}

func TestHeldIOUnlocksAbortAndTimerCompletion(t *testing.T) {
	for _, transport := range []string{"tcp", "udp"} {
		for _, trigger := range []string{"flush", "timer"} {
			t.Run(transport+"/"+trigger, func(t *testing.T) {
				var flow *flowState
				var lease *Lease
				var admit func(Completer) Verdict
				if transport == "tcp" {
					h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`, `{"hold_timeout":"10s"}`)
					lease, flow = h.lease, h.lease.tcpFlow
					packet := buildIPv4TCP(t, buildClientHello("held-io.example")[:12], 1000, tcpFlagACK|tcpFlagPSH)
					admit = func(c Completer) Verdict { return lease.HandlePacket(packet.Raw, DirectionOutbound, nil, c) }
				} else {
					fixture := newUDPPeerEngine(t, 4, `,"limits":{"hold_timeout":"10s"}`, "["+qa519UDPRules("010203", 1, "")+"]")
					lease = fixture.connected("192.0.2.10:12345", "198.51.100.20:443")
					head, _ := qa519SplitInitials(t, "held-io.example", 40, qa519DCID(0x19), 1, 1)
					packet := udpPeerPacket(t, lease.intent.Source, lease.intent.Destination, head)
					admit = func(c Completer) Verdict { return lease.HandlePacket(packet.Raw, DirectionOutbound, nil, c) }
				}
				calls := 0
				if v := admit(func(v Verdict, _ string, _ []byte) {
					assertHeldIOLocksAvailable(t, lease, flow)
					calls++
					if v != VerdictPass {
						t.Errorf("abort verdict=%v", v)
					}
				}); v != VerdictHold {
					t.Fatalf("head verdict=%v", v)
				}
				if flow == nil {
					flow = lease.udpFlows[flowKey(lease.intent.Destination)]
				}
				if trigger == "flush" {
					flow.flushHeld("abort")
				} else {
					flow.mu.Lock()
					flow.holdDeadline = flow.now()
					gen := flow.holdGen
					flow.mu.Unlock()
					flow.expireGen(gen)
				}
				flow.flushHeld("repeated")
				if !reflect.DeepEqual([]int{calls, flow.heldBytes, int(lease.engine.heldBytes.Load())}, []int{1, 0, 0}) {
					t.Fatalf("calls=%d local=%d global=%d", calls, flow.heldBytes, lease.engine.heldBytes.Load())
				}
			})
		}
	}
}

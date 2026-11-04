//go:build linux

package desync

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

// Positive completed cycles only. No abort, error, Close, expiry or teardown is
// driven here. The real hold timer is stopped by ordinary successful replay.
func TestSource38BatchHeldTCP(t *testing.T) {
	for _, kind := range []string{"two-held", "covered-copy", "covered-control"} {
		t.Run(kind, func(t *testing.T) {
			message := []byte("GET / HTTP/1.1\r\nHost: batch.example\r\n\r\n")
			first := buildIPv4TCP(t, message[:12], 1000, tcpFlagACK|tcpFlagPSH)
			middle := buildIPv4TCP(t, message[12:24], 1012, tcpFlagACK|tcpFlagPSH)
			tail := buildIPv4TCP(t, message[24:], 1024, tcpFlagACK|tcpFlagPSH)
			packets := []*Packet{first, middle, tail}
			covered := -1
			if kind != "two-held" {
				flags := uint8(tcpFlagACK | tcpFlagPSH)
				if kind == "covered-control" {
					flags |= tcpFlagFIN
				}
				copy := buildIPv4TCP(t, message[:12], 1000, flags)
				packets = []*Packet{first, copy, middle, tail}
				covered = 1
			}
			config := `{"enabled":true,"limits":{"hold_timeout":"10s"},"rules":[{"network":["tcp"],"methods":["multisplit"],"multisplit":{"split_pos":["2","14","26"]}}]}`
			l := batchSuccessLease(t, config, first)
			f := l.tcpFlow
			var events, wantEvents []string
			remaining := 0
			for _, p := range packets[:len(packets)-1] {
				remaining += len(p.Raw)
			}
			held := remaining
			_, _, facts := protocolFacts(message)
			calls := 0
			for index, p := range packets {
				want, err := PlanTCP(l.engine.config.Rules[0], p, message, int(p.TCPSeq-1000), facts)
				if err != nil {
					t.Fatal(err)
				}
				inject := packetInjection{
					single: func([]byte) error { t.Error("batch fell back to single"); return nil },
					batch: func(raw [][]byte) (int, error) {
						batchSuccessLocks(t, l)
						if index == covered {
							t.Error("covered record injected")
						}
						if !reflect.DeepEqual(raw, want.Packets) || len(raw) != 2 {
							t.Errorf("record%d bytes/whole batch len%d want%d", index, len(raw), len(want.Packets))
						}
						if index < len(packets)-1 {
							if f.holdRelease == nil || int(l.engine.heldBytes.Load()) != held || f.heldBytes != held {
								t.Errorf("hold budget/release not held for batch%d", index)
							}
						} else if f.holdRelease != nil || f.heldBytes != 0 || l.engine.heldBytes.Load() != 0 {
							t.Error("immediate tail overtook held phase")
						}
						events = append(events, fmt.Sprintf("batch-%d", index))
						calls++
						return len(raw), nil
					},
				}
				complete := func(v Verdict, _ string, modified []byte) {
					batchSuccessLocks(t, l)
					if f.holdRelease == nil || f.heldBytes != remaining || int(l.engine.heldBytes.Load()) != remaining {
						t.Errorf("record%d budget before complete: %d/%d want%d", index, f.heldBytes, l.engine.heldBytes.Load(), remaining)
					}
					wantVerdict := VerdictDrop
					if index == covered && kind == "covered-control" {
						wantVerdict = VerdictPass
					}
					if v != wantVerdict || modified != nil {
						t.Errorf("record%d verdict%v want%v", index, v, wantVerdict)
					}
					events = append(events, fmt.Sprintf("complete-%d", index))
					remaining -= len(p.Raw)
				}
				v := l.handlePacket(p.Raw, DirectionOutbound, inject, complete)
				if index < len(packets)-1 {
					if v != VerdictHold {
						t.Fatalf("hold%d %v", index, v)
					}
				} else if v != VerdictDrop {
					t.Fatalf("tail %v", v)
				}
			}
			for index := range packets[:len(packets)-1] {
				if index != covered {
					wantEvents = append(wantEvents, fmt.Sprintf("batch-%d", index))
				}
			}
			for index := range packets[:len(packets)-1] {
				wantEvents = append(wantEvents, fmt.Sprintf("complete-%d", index))
			}
			wantEvents = append(wantEvents, fmt.Sprintf("batch-%d", len(packets)-1))
			if !reflect.DeepEqual(events, wantEvents) || calls != 3 || remaining != 0 || f.heldBytes != 0 || l.engine.heldBytes.Load() != 0 || f.holdRelease != nil || f.holdTimer != nil || l.Err() != nil {
				t.Fatalf("TCP terminal events=%v want=%v calls=%d remainder=%d err=%v", events, wantEvents, calls, remaining, l.Err())
			}
			t.Logf("M-B03 TCP exact record callbacks/phases: %v", events)
		})
	}
}

func TestSource38BatchHeldQUIC(t *testing.T) {
	head, tail := qa519SplitInitials(t, "batch.example", 40, qa519DCID(0x39), 1, 1)
	first := batchSuccessPacket(t, FamilyIPv4, head)
	last := batchSuccessPacket(t, FamilyIPv4, tail)
	config := `{"enabled":true,"limits":{"hold_timeout":"10s"},"rules":[{"network":["udp"],"protocol":["quic"],"methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"0123456789abcdef"}]},"dup":{"count":1}}]}`
	l := batchSuccessLease(t, config, first)
	var f *flowState
	var events []string
	remaining := len(first.Raw) + len(last.Raw)
	batchCalls := 0
	completes := 0
	complete := func(v Verdict, _ string, modified []byte) {
		batchSuccessLocks(t, l)
		if f.holdRelease == nil || f.heldBytes != remaining || int(l.engine.heldBytes.Load()) != remaining {
			t.Errorf("QUIC callback budget %d/%d want%d", f.heldBytes, l.engine.heldBytes.Load(), remaining)
		}
		if v != VerdictPass || modified != nil {
			t.Errorf("QUIC verdict%v", v)
		}
		events = append(events, fmt.Sprintf("complete-%d", completes))
		if completes == 0 {
			remaining -= len(first.Raw)
		} else {
			remaining -= len(last.Raw)
		}
		completes++
	}
	headInjector := packetInjection{single: func([]byte) error { t.Error("stored head single used"); return nil }, batch: func(b [][]byte) (int, error) {
		t.Error("stored head batch used instead of trigger")
		return len(b), nil
	}}
	if v := l.handlePacket(first.Raw, DirectionOutbound, headInjector, complete); v != VerdictHold {
		t.Fatalf("QUIC head %v", v)
	}
	f = l.udpFlows[flowKey(l.intent.Destination)]
	trigger := packetInjection{
		single: func([]byte) error { t.Error("trigger batch fell back to single"); return nil },
		batch: func(raw [][]byte) (int, error) {
			batchSuccessLocks(t, l)
			if f.holdRelease == nil || f.heldBytes != remaining || int(l.engine.heldBytes.Load()) != remaining {
				t.Error("QUIC injection budget/release")
			}
			original := first
			if batchCalls != 0 {
				original = last
			}
			want, err := planUDPStages(l.engine.config.Rules[0], original, batchCalls == 0)
			if err == nil {
				err = planUDPDup(l.engine.config.Rules[0], original, original, Facts{}, want, DefaultRand)
			}
			expectedCount := 1
			if batchCalls == 0 {
				expectedCount = 3
			}
			if err != nil || len(raw) != expectedCount || !reflect.DeepEqual(raw, want.Packets) {
				t.Errorf("QUIC exact fake+dup plan: call%d len%d error%v", batchCalls, len(raw), err)
			}
			duplicate, parseErr := ParsePacket(raw[len(raw)-1])
			if parseErr != nil || !bytes.Equal(duplicate.Payload, original.Payload) {
				t.Error("dup lost original payload")
			}
			events = append(events, fmt.Sprintf("trigger-batch-%d", batchCalls))
			batchCalls++
			return len(raw), nil
		},
	}
	if v := l.handlePacket(last.Raw, DirectionOutbound, trigger, complete); v != VerdictHold {
		t.Fatalf("QUIC tail %v", v)
	}
	want := []string{"trigger-batch-0", "complete-0", "trigger-batch-1", "complete-1"}
	if !reflect.DeepEqual(events, want) || batchCalls != 2 || completes != 2 || remaining != 0 || f.heldBytes != 0 || l.engine.heldBytes.Load() != 0 || f.holdRelease != nil || f.holdTimer != nil || l.Err() != nil {
		t.Fatalf("QUIC terminal %v remaining%d error%v", events, remaining, l.Err())
	}
	t.Logf("M-B03 authenticated QUIC head-only fake; trigger injector; events=%v", events)
}

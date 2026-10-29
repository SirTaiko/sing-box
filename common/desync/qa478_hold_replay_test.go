package desync

// QA478: the retained row-A wire capture carries the held prefix as H1
// (`seq+0`, 10 bytes) and H2 (`seq+10`, 10 bytes) and then three byte-identical
// 20-byte records at `seq+0`, each with its own IPv4 ID. Those three records are
// native retransmissions of the unacknowledged prefix that the stack emitted
// while the message was deliberately held; the capture held each of them as a
// further pending original for a range an earlier pending original already
// owned, and the flush replayed them after the correct H1/H2 release.
//
// The release rule those regressions pin: every captured record still receives
// exactly one terminal disposition, but a record whose whole payload range is
// already carried by an earlier held original of the same release carries no
// byte of its own and is released as a drop instead of replaying those bytes.
// Nothing is keyed on headers or payload digests, so a retransmission that
// carries even one new byte keeps its own disposition, and a retransmission of
// records that are not pending keeps its normal pass.

import (
	"strings"
	"testing"
)

const qa478Rules = `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`

func qa478EqualVerdicts(got, want []Verdict) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

// The exact rejected byte pattern: two held originals plus the coalesced
// retransmissions of their range. Each retransmission used to get a second pass
// disposition at release, which put the same stream bytes on the wire again.
func TestQA478HeldPrefixRetransmissionsAreNotReplayed(t *testing.T) {
	hello := buildClientHello("qa478.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	first, second, coalesced := hello[:10], hello[10:20], hello[:20]

	for _, testCase := range []struct {
		name   string
		copies int
	}{
		{"single_retransmission", 1},
		{"three_retransmissions", 3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHeldHarness(t, qa478Rules, "")
			if verdict := h.capture(first, 1000); verdict != VerdictHold {
				t.Fatalf("first held original verdict = %d, want hold", verdict)
			}
			if verdict := h.capture(second, 1010); verdict != VerdictHold {
				t.Fatalf("second held original verdict = %d, want hold", verdict)
			}
			for copyIndex := 0; copyIndex < testCase.copies; copyIndex++ {
				// A native retransmission of the whole unacknowledged prefix:
				// the same stream range as the two pending originals together.
				if verdict := h.capture(coalesced, 1000); verdict != VerdictHold {
					t.Fatalf("retransmission %d verdict = %d, want hold", copyIndex, verdict)
				}
			}
			if err := h.lease.Close(nil); err != nil {
				t.Fatalf("close: %v", err)
			}
			want := []Verdict{VerdictPass, VerdictPass}
			for copyIndex := 0; copyIndex < testCase.copies; copyIndex++ {
				want = append(want, VerdictDrop)
			}
			if !qa478EqualVerdicts(h.verdicts, want) {
				t.Fatalf("release dispositions = %v, want %v (every record exactly once, no replay)", h.verdicts, want)
			}
			if h.order[0] != 1000 || h.order[1] != 1010 {
				t.Fatalf("held originals released out of capture order: %v", h.order)
			}
			if len(h.injected) != 0 {
				t.Fatalf("an incomplete held message must not inject: %d packets", len(h.injected))
			}
			for reasonIndex := 2; reasonIndex < len(h.reasons); reasonIndex++ {
				if !strings.Contains(h.reasons[reasonIndex], "duplicate") {
					t.Fatalf("retransmission %d reason = %q, want the duplicate release reason",
						reasonIndex-2, h.reasons[reasonIndex])
				}
			}
		})
	}
}

// A completed message is released through the planned path. The retransmission's
// own planned replacements are the same replay through the replacement path, so
// they must not be sent either.
func TestQA478HeldRetransmissionSkipsPlannedReplacement(t *testing.T) {
	hello := buildClientHello("qa478-planned.example")
	if len(hello) < 30 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa478Rules, "")
	if verdict := h.capture(hello[:10], 1000); verdict != VerdictHold {
		t.Fatalf("first held original verdict = %d", verdict)
	}
	if verdict := h.capture(hello[10:20], 1010); verdict != VerdictHold {
		t.Fatalf("second held original verdict = %d", verdict)
	}
	if verdict := h.capture(hello[:20], 1000); verdict != VerdictHold {
		t.Fatalf("retransmission verdict = %d", verdict)
	}
	// The rest of the message completes it, so every held original is planned
	// before any of them is suppressed.
	if verdict := h.capture(hello[20:], 1020); verdict == VerdictHold {
		t.Fatal("completing segment must not be held")
	}
	if !qa478EqualVerdicts(h.verdicts, []Verdict{VerdictDrop, VerdictPass, VerdictDrop}) {
		t.Fatalf("release dispositions = %v, want planned drop, pass, covered drop", h.verdicts)
	}
	if !strings.Contains(h.reasons[2], "duplicate") {
		t.Fatalf("covered retransmission reason = %q", h.reasons[2])
	}
	// The only replacement bytes belong to the first held original's split:
	// exactly two packets covering its own 10 bytes, no repeated pair.
	if len(h.injected) != 2 {
		t.Fatalf("injected replacements = %d, want the first original's two split segments only", len(h.injected))
	}
	var rebuilt []byte
	for _, raw := range h.injected {
		packet, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("parse replacement: %v", err)
		}
		rebuilt = append(rebuilt, packet.Payload...)
	}
	if string(rebuilt) != string(hello[:10]) {
		t.Fatalf("replacement payloads = %x, want the held prefix exactly once", rebuilt)
	}
}

// Positive controls: without a native retransmission every held original keeps
// its own disposition and ordering, and a flow with nothing held releases
// nothing.
func TestQA478HeldPrefixWithoutRetransmissionKeepsEveryDisposition(t *testing.T) {
	hello := buildClientHello("qa478-control.example")
	for _, testCase := range []struct {
		name    string
		records []struct {
			payload  []byte
			sequence uint32
		}
	}{
		{"held0", nil},
		{"held1", []struct {
			payload  []byte
			sequence uint32
		}{{hello[:10], 3000}}},
		{"held2", []struct {
			payload  []byte
			sequence uint32
		}{{hello[:10], 4000}, {hello[10:20], 4010}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			h := newHeldHarness(t, qa478Rules, "")
			for index, record := range testCase.records {
				if verdict := h.capture(record.payload, record.sequence); verdict != VerdictHold {
					t.Fatalf("record %d verdict = %d, want hold", index, verdict)
				}
			}
			if err := h.lease.Close(nil); err != nil {
				t.Fatalf("close: %v", err)
			}
			want := make([]Verdict, 0, len(testCase.records))
			for range testCase.records {
				want = append(want, VerdictPass)
			}
			if !qa478EqualVerdicts(h.verdicts, want) {
				t.Fatalf("release dispositions = %v, want %v", h.verdicts, want)
			}
			if len(h.injected) != 0 {
				t.Fatalf("injected = %d, want none", len(h.injected))
			}
		})
	}
}

// A retransmission of records that are not pending is ordinary traffic: it is
// not swallowed by a digest cache and it is not held by association.
func TestQA478RetransmissionWithoutHoldStillPasses(t *testing.T) {
	h := newHeldHarness(t, qa478Rules, "")
	opaque := []byte{0x00, 0x01, 0x02}
	if verdict := h.capture(opaque, 5000); verdict != VerdictPass {
		t.Fatalf("unknown-protocol record verdict = %d, want pass", verdict)
	}
	if verdict := h.capture(opaque, 5000); verdict != VerdictPass {
		t.Fatalf("retransmission without a pending hold verdict = %d, want pass", verdict)
	}
	if len(h.verdicts) != 0 || len(h.injected) != 0 {
		t.Fatalf("nothing may be held or injected: %d dispositions, %d injections", len(h.verdicts), len(h.injected))
	}
}

// A record that carries even one new byte keeps its own disposition: only a
// record fully inside already released ranges is a pure duplicate.
func TestQA478RecordWithNewBytesKeepsOwnDisposition(t *testing.T) {
	hello := buildClientHello("qa478-partial.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa478Rules, "")
	if verdict := h.capture(hello[:10], 6000); verdict != VerdictHold {
		t.Fatalf("held original verdict = %d", verdict)
	}
	// Overlaps the held range by five bytes and adds five new ones.
	if verdict := h.capture(hello[5:15], 6005); verdict != VerdictHold {
		t.Fatalf("overlapping record verdict = %d, want hold", verdict)
	}
	if err := h.lease.Close(nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	// QA484: the dispositions alone do not prove the assembly. The
	// resegmented record must have advanced the contiguous stream to the full
	// 15 bytes at its true absolute sequence; revision12 passed this test while
	// storing the new tail at the overlap start, so Contiguous() stopped at 10.
	start, message := h.lease.tcpFlow.reassembler.Contiguous()
	if start != 6000 || string(message) != string(hello[:15]) {
		t.Fatalf("assembled stream = start %d %q, want start 6000 %q", start, message, hello[:15])
	}
	if !qa478EqualVerdicts(h.verdicts, []Verdict{VerdictPass, VerdictPass}) {
		t.Fatalf("release dispositions = %v, want both originals delivered", h.verdicts)
	}
	for _, reason := range h.reasons {
		if strings.Contains(reason, "duplicate") {
			t.Fatalf("a record with new bytes was treated as a duplicate: %q", reason)
		}
	}
}

func TestPayloadIntervalCovered(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		released []payloadInterval
		want     payloadInterval
		covered  bool
	}{
		{"exact", []payloadInterval{{1000, 10}}, payloadInterval{1000, 10}, true},
		{"inside", []payloadInterval{{1000, 20}}, payloadInterval{1005, 5}, true},
		{"two_adjacent", []payloadInterval{{1000, 10}, {1010, 10}}, payloadInterval{1000, 20}, true},
		{"two_adjacent_reversed", []payloadInterval{{1010, 10}, {1000, 10}}, payloadInterval{1000, 20}, true},
		{"gap", []payloadInterval{{1000, 10}, {1011, 9}}, payloadInterval{1000, 20}, false},
		{"partial_tail", []payloadInterval{{1000, 15}}, payloadInterval{1000, 20}, false},
		{"disjoint", []payloadInterval{{2000, 20}}, payloadInterval{1000, 20}, false},
		{"empty_want", []payloadInterval{{1000, 10}}, payloadInterval{1000, 0}, false},
		{"sequence_wrap", []payloadInterval{{0xfffffffb, 5}, {0x00000000, 5}}, payloadInterval{0xfffffffb, 10}, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := payloadIntervalCovered(testCase.released, testCase.want); got != testCase.covered {
				t.Fatalf("covered = %v, want %v", got, testCase.covered)
			}
		})
	}
}

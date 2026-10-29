package desync

// QA484 D1: the bounded reassembler must not lose or misplace bytes when a
// retransmission resegments the pending flight.
//
// The rejected revision12 code trimmed the head of a partially overlapping
// segment with `trimmedStart = existingStart + skip`, which never advances the
// start, so the genuinely new tail bytes were stored at the overlap start and
// `Contiguous()` stopped before them. A same-start shorter record then
// overwrote (and truncated) the pending range. The held message never became
// complete and the deadline released an untransformed request.
//
// These regressions pin the byte stream itself (exact bytes and their absolute
// sequence position), the bounded storage accounting and the real held-message
// path through Lease.HandlePacket - not only the release dispositions.

import (
	"strings"
	"testing"
)

const qa484Rules = `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`

// qa484WantContiguous pins both the absolute start and the exact bytes of the
// contiguous stream; a truncated or mislocated range fails on either.
func qa484WantContiguous(t *testing.T, reassembler *reassembler, wantStart uint32, want string) {
	t.Helper()
	start, message := reassembler.Contiguous()
	if start != wantStart || string(message) != want {
		t.Fatalf("contiguous stream = start %d %q, want start %d %q", start, message, wantStart, want)
	}
}

func qa484Add(t *testing.T, reassembler *reassembler, sequence uint32, data string) {
	t.Helper()
	if err := reassembler.Add(sequence, []byte(data)); err != nil {
		t.Fatalf("add %q at %d: %v", data, sequence, err)
	}
}

// The exact rejected probe: the retransmission starts inside the stored range
// and extends past it. Both records carry the same bytes for the overlap; the
// five new tail bytes must land at 1010, not at 1005.
func TestQA484PartialOverlapKeepsNewTail(t *testing.T) {
	reassembler := newReassembler(1024)
	qa484Add(t, reassembler, 1000, "0123456789")
	qa484Add(t, reassembler, 1005, "56789ABCDE")
	qa484WantContiguous(t, reassembler, 1000, "0123456789ABCDE")
	if reassembler.total != 15 {
		t.Fatalf("stored bytes = %d, want exactly the 15 stream bytes (no duplicated overlap)", reassembler.total)
	}
	if len(reassembler.segments) != 2 {
		t.Fatalf("stored ranges = %d, want the 10-byte prefix and the 5-byte new tail", len(reassembler.segments))
	}
	tail, ok := reassembler.segments[1010]
	if !ok || string(tail) != "ABCDE" {
		t.Fatalf("new tail range at 1010 = %q (present=%v), want %q", tail, ok, "ABCDE")
	}
}

// A shorter retransmission of the same start must not erase or truncate the
// pending tail.
func TestQA484ShorterSameStartRetransmissionKeepsPendingTail(t *testing.T) {
	reassembler := newReassembler(1024)
	qa484Add(t, reassembler, 1000, "0123456789")
	qa484Add(t, reassembler, 1000, "01234")
	qa484WantContiguous(t, reassembler, 1000, "0123456789")
	if reassembler.total != 10 {
		t.Fatalf("stored bytes = %d, want the 10 pending bytes", reassembler.total)
	}
	if len(reassembler.segments) != 1 {
		t.Fatalf("stored ranges = %d, want the pending range untouched", len(reassembler.segments))
	}
}

// A contained record and an exact duplicate add no byte: the stored value and
// the accounting must both stay exactly as they were (the duplicate may not be
// counted twice).
func TestQA484ContainedAndExactDuplicateKeepStream(t *testing.T) {
	reassembler := newReassembler(1024)
	qa484Add(t, reassembler, 1000, "0123456789")
	qa484Add(t, reassembler, 1003, "XX")
	qa484Add(t, reassembler, 1000, "0123456789")
	qa484WantContiguous(t, reassembler, 1000, "0123456789")
	if reassembler.total != 10 {
		t.Fatalf("stored bytes = %d, want 10 (contained/duplicate bytes are not stored again)", reassembler.total)
	}
	if len(reassembler.segments) != 1 {
		t.Fatalf("stored ranges = %d, want 1", len(reassembler.segments))
	}
}

// The same partial overlap in the other arrival order: the tail arrives first,
// then the prefix that partially covers it.
func TestQA484OutOfOrderPartialOverlapAssembles(t *testing.T) {
	reassembler := newReassembler(1024)
	qa484Add(t, reassembler, 1005, "56789ABCDE")
	qa484Add(t, reassembler, 1000, "0123456789")
	qa484WantContiguous(t, reassembler, 1000, "0123456789ABCDE")
	if reassembler.total != 15 {
		t.Fatalf("stored bytes = %d, want 15", reassembler.total)
	}
}

// A resegmented retransmission that crosses the uint32 sequence wrap keeps its
// new tail on the far side of the wrap.
func TestQA484SequenceWrapOverlapAssembles(t *testing.T) {
	reassembler := newReassembler(1024)
	qa484Add(t, reassembler, 0xfffffff8, "01234567")
	qa484Add(t, reassembler, 0xfffffffc, "456789AB")
	qa484WantContiguous(t, reassembler, 0xfffffff8, "0123456789AB")
	if reassembler.total != 12 {
		t.Fatalf("stored bytes = %d, want 12", reassembler.total)
	}
}

// Bounded storage is unchanged: only genuinely new bytes are charged, and an
// add that would exceed the limit is refused without mutating the stream.
func TestQA484OverlapStorageStaysBounded(t *testing.T) {
	reassembler := newReassembler(16)
	qa484Add(t, reassembler, 0, "0123456789")
	qa484Add(t, reassembler, 5, "56789ABCDE")
	if reassembler.total != 15 {
		t.Fatalf("stored bytes = %d, want 15", reassembler.total)
	}
	if err := reassembler.Add(10, []byte("ABCDEFGHIJ")); err == nil {
		t.Fatal("an add that exceeds the reassembly limit must be refused")
	}
	qa484WantContiguous(t, reassembler, 0, "0123456789ABCDE")
	if reassembler.total != 15 {
		t.Fatalf("stored bytes after the refused add = %d, want 15", reassembler.total)
	}
}

// qa484ReplacementPayload concatenates the payloads of the injected packets.
func qa484ReplacementPayload(t *testing.T, injected [][]byte) string {
	t.Helper()
	var rebuilt []byte
	for _, raw := range injected {
		packet, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("parse replacement: %v", err)
		}
		rebuilt = append(rebuilt, packet.Payload...)
	}
	return string(rebuilt)
}

// The real held path: the resegmented retransmission is held, the message must
// complete when the rest arrives, and the planned split must be computed from
// the whole ClientHello. Revision12 instead held the completing segment
// because the assembly was stuck at the truncated prefix.
func TestQA484HeldResegmentedRetransmissionCompletes(t *testing.T) {
	hello := buildClientHello("qa484-reseg.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, "")
	if verdict := h.capture(hello[:10], 1000); verdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[5:15], 1005); verdict != VerdictHold {
		t.Fatalf("resegmented record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[15:], 1015); verdict == VerdictHold {
		t.Fatal("resegmented hold did not complete: the completing segment was held (assembly lost the new tail)")
	}
	if got := h.lease.tcpFlow.facts.MessageLength; got != len(hello) {
		t.Fatalf("planned message length = %d, want the whole %d-byte ClientHello", got, len(hello))
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want one per held record", len(h.verdicts))
	}
	if h.order[0] != 1000 || h.order[1] != 1005 {
		t.Fatalf("release order = %v, want capture order [1000 1005]", h.order)
	}
	if h.verdicts[0] != VerdictDrop {
		t.Fatalf("first held record disposition = %d, want the planned split drop", h.verdicts[0])
	}
	if h.verdicts[1] != VerdictPass {
		t.Fatalf("resegmented record with new bytes kept verdict %d, want its own pass", h.verdicts[1])
	}
	if rebuilt := qa484ReplacementPayload(t, h.injected); rebuilt != string(hello[:10]) {
		t.Fatalf("replacement bytes = %q, want the held prefix %q", rebuilt, hello[:10])
	}
}

// The real held path with a shorter same-start retransmission: the pending tail
// must survive, the message must complete, and the short copy is an exact
// duplicate of released bytes (it keeps the established duplicate drop).
func TestQA484HeldShortRetransmissionKeepsPendingTail(t *testing.T) {
	hello := buildClientHello("qa484-short.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, "")
	if verdict := h.capture(hello[:10], 2000); verdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[:5], 2000); verdict != VerdictHold {
		t.Fatalf("short retransmission verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[10:], 2010); verdict == VerdictHold {
		t.Fatal("short retransmission truncated the pending tail: the completing segment was held")
	}
	if got := h.lease.tcpFlow.facts.MessageLength; got != len(hello) {
		t.Fatalf("planned message length = %d, want the whole %d-byte ClientHello", got, len(hello))
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want 2", len(h.verdicts))
	}
	if h.verdicts[0] != VerdictDrop {
		t.Fatalf("first record disposition = %d, want the planned split drop", h.verdicts[0])
	}
	if h.verdicts[1] != VerdictDrop {
		t.Fatalf("exact short duplicate disposition = %d, want the established covered drop", h.verdicts[1])
	}
	if !strings.Contains(h.reasons[1], "duplicate") {
		t.Fatalf("covered duplicate reason = %q, want the duplicate release reason", h.reasons[1])
	}
	if rebuilt := qa484ReplacementPayload(t, h.injected); rebuilt != string(hello[:10]) {
		t.Fatalf("replacement bytes = %q, want the held prefix exactly once %q", rebuilt, hello[:10])
	}
}

// Out-of-order arrival: the tail arrives before the middle segment, so the
// contiguous stream has a gap until the middle fills it. Dispositions keep
// capture order while the stream is assembled by sequence.
func TestQA484HeldOutOfOrderSegmentsComplete(t *testing.T) {
	hello := buildClientHello("qa484-order.example")
	if len(hello) < 30 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, "")
	if verdict := h.capture(hello[:10], 7000); verdict != VerdictHold {
		t.Fatalf("prefix verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[15:20], 7015); verdict != VerdictHold {
		t.Fatalf("out-of-order tail verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[10:15], 7010); verdict != VerdictHold {
		t.Fatalf("middle segment verdict = %d, want hold (the gap is filled but the hello is not complete)", verdict)
	}
	if verdict := h.capture(hello[20:], 7020); verdict == VerdictHold {
		t.Fatal("out-of-order held segments did not complete")
	}
	if got := h.lease.tcpFlow.facts.MessageLength; got != len(hello) {
		t.Fatalf("planned message length = %d, want %d", got, len(hello))
	}
	if len(h.verdicts) != 3 {
		t.Fatalf("terminal dispositions = %d, want 3", len(h.verdicts))
	}
	if h.order[0] != 7000 || h.order[1] != 7015 || h.order[2] != 7010 {
		t.Fatalf("release order = %v, want capture order [7000 7015 7010]", h.order)
	}
}

// The sequence wrap is exercised through the real hold path too: the
// overlapping record crosses 0xffffffff and must still complete the message.
func TestQA484HeldSequenceWrapCompletes(t *testing.T) {
	hello := buildClientHello("qa484-wrap.example")
	if len(hello) < 24 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	base := uint32(0xfffffff8)
	h := newHeldHarness(t, qa484Rules, "")
	if verdict := h.capture(hello[:8], base); verdict != VerdictHold {
		t.Fatalf("pre-wrap record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[4:16], base+4); verdict != VerdictHold {
		t.Fatalf("wrap-crossing record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[16:], base+16); verdict == VerdictHold {
		t.Fatal("wrap-crossing hold did not complete: the post-wrap tail was lost")
	}
	if got := h.lease.tcpFlow.facts.MessageLength; got != len(hello) {
		t.Fatalf("planned message length = %d, want %d", got, len(hello))
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want 2", len(h.verdicts))
	}
	if h.order[0] != base || h.order[1] != base+4 {
		t.Fatalf("release order = %v, want capture order [%#x %#x]", h.order, base, base+4)
	}
	// Both records are planned splits of their own captured payloads; the
	// replacement packets must carry exactly those bytes at their true
	// sequence, including across the wrap.
	want := []string{string(hello[:5]), string(hello[5:8]), string(hello[4:5]), string(hello[5:16])}
	if len(h.injected) != len(want) {
		t.Fatalf("injected replacements = %d, want %d", len(h.injected), len(want))
	}
	for index, raw := range h.injected {
		packet, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("parse replacement %d: %v", index, err)
		}
		if string(packet.Payload) != want[index] {
			t.Fatalf("replacement %d payload = %q, want %q", index, packet.Payload, want[index])
		}
	}
}

// The hold budgets are unchanged by the repaired overlap handling: the third
// held record still exceeds max_held_packets, the two pending originals are
// released unchanged in capture order and nothing is injected.
func TestQA484HeldBudgetReleaseUnchanged(t *testing.T) {
	hello := buildClientHello("qa484-budget.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, `{"max_held_packets":2,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
	if verdict := h.capture(hello[:10], 4000); verdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[5:15], 4005); verdict != VerdictHold {
		t.Fatalf("overlapping record verdict = %d, want hold", verdict)
	}
	// The third record is still part of the incomplete message, so the packet
	// budget is consulted: two held originals are released unchanged.
	if verdict := h.capture(hello[15:20], 4015); verdict != VerdictPass {
		t.Fatalf("budget-exhausted segment verdict = %d, want pass", verdict)
	}
	if verdict := h.capture(hello[20:], 4020); verdict != VerdictPass {
		t.Fatalf("post-budget segment verdict = %d, want pass (transformations latched off)", verdict)
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want 2", len(h.verdicts))
	}
	for index, verdict := range h.verdicts {
		if verdict != VerdictPass {
			t.Fatalf("budget release disposition %d = %d, want pass", index, verdict)
		}
	}
	if h.order[0] != 4000 || h.order[1] != 4005 {
		t.Fatalf("budget release order = %v, want capture order", h.order)
	}
	for index, reason := range h.reasons {
		if !strings.Contains(reason, "budget") {
			t.Fatalf("budget release reason %d = %q, want the budget reason", index, reason)
		}
	}
	if len(h.injected) != 0 {
		t.Fatalf("budget release injected %d packets, want none", len(h.injected))
	}
}

package desync

// QA484 D2: the held-release covered-record rule must not discard a captured
// record's TCP control effects or genuinely different payload bytes merely
// because its sequence range is already covered.
//
// Revision12 released a covered record as VerdictDrop whenever its payload
// range was inside an earlier held original's range. A retransmission of the
// pending range that carried FIN was therefore dropped whole: QA t_d8938d36
// recorded dispositions [Drop Drop] and no delivered replacement carried FIN,
// so the close never reached the peer. The same range with different payload
// bytes lost those bytes at the wire.
//
// The repaired rule keeps the payload range as the only coverage authority and
// additionally requires a covered record to carry no control flags of its own
// and every payload byte to be equal to the value this release already
// delivers. Anything else passes unchanged (one terminal disposition per
// record, capture order preserved), which is safe for TCP: a repeated range is
// a retransmission, while a lost FIN or substituted byte is not recoverable
// from the release's bookkeeping.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// qa484Record is one captured packet driven through the real Lease.HandlePacket
// path with a recording completer, so a test can assert what the terminal
// disposition actually delivers (the original packet or the modified bytes).
type qa484Record struct {
	packet   *Packet
	verdict  Verdict
	reason   string
	modified []byte
	held     bool
}

// qa484Capture is capture() with explicit TCP flags and a per-record terminal
// disposition recorder. It mirrors heldHarness.capture's injection accounting.
func qa484Capture(h *heldHarness, payload []byte, sequence uint32, flags uint8) (Verdict, *qa484Record) {
	h.t.Helper()
	packet := buildIPv4TCP(h.t, payload, sequence, flags)
	record := &qa484Record{packet: packet}
	index := len(h.injected)
	verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
		h.injected = append(h.injected, append([]byte(nil), replacement...))
		if h.injectFail != nil {
			if err := h.injectFail(index); err != nil {
				return err
			}
		}
		return nil
	}, func(terminal Verdict, reason string, modified []byte) {
		record.verdict, record.reason = terminal, reason
		record.modified = append([]byte(nil), modified...)
		record.held = true
		h.verdicts = append(h.verdicts, terminal)
		h.reasons = append(h.reasons, reason)
		h.modified = append(h.modified, append([]byte(nil), modified...))
		h.order = append(h.order, packet.TCPSeq)
	})
	return verdict, record
}

// The rejected row: the retransmission of the pending prefix carries FIN. Its
// payload range is fully covered, but the record owns the only FIN in the
// release. It must pass unchanged so the close reaches the peer; dropping it
// silently loses a control effect that range coverage cannot represent.
func TestQA484CoveredFINRecordIsDelivered(t *testing.T) {
	hello := buildClientHello("qa484-fin.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, "")
	firstVerdict, first := qa484Capture(h, hello[:10], 2000, tcpFlagACK|tcpFlagPSH)
	if firstVerdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", firstVerdict)
	}
	secondVerdict, second := qa484Capture(h, hello[:10], 2000, tcpFlagACK|tcpFlagPSH|tcpFlagFIN)
	if secondVerdict != VerdictHold {
		t.Fatalf("FIN-carrying retransmission verdict = %d, want hold", secondVerdict)
	}
	if second.packet.TCPFlags&tcpFlagFIN == 0 {
		t.Fatal("probe setup: the retransmission must carry FIN")
	}
	if verdict := h.capture(hello[10:], 2010); verdict == VerdictHold {
		t.Fatal("completing segment must not be held")
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want exactly one per captured record", len(h.verdicts))
	}
	if h.order[0] != 2000 || h.order[1] != 2000 {
		t.Fatalf("release order = %v, want capture order", h.order)
	}
	if first.verdict != VerdictDrop {
		t.Fatalf("first record disposition = %d, want the planned split drop", first.verdict)
	}
	if second.verdict != VerdictPass {
		t.Fatalf("covered FIN record disposition = %d, want pass (the FIN must reach the peer)", second.verdict)
	}
	if second.reason == "" {
		t.Fatal("a covered record that is not dropped must report why it passes")
	}
	if strings.Contains(second.reason, "duplicate of bytes released") {
		t.Fatalf("covered FIN record reason = %q, but its bytes are not the whole record it carries", second.reason)
	}
	// A Pass terminal disposition delivers this captured packet unchanged, so
	// the only FIN in the release is on the wire.
	if !qa484DeliveredFIN([]*qa484Record{first, second}) {
		t.Fatal("no delivered disposition carries the FIN flag")
	}
	if rebuilt := qa484ReplacementPayload(t, h.injected); rebuilt != string(hello[:10]) {
		t.Fatalf("replacement bytes = %q, want the held prefix %q", rebuilt, hello[:10])
	}
}

// Positive control: an exact duplicate without control flags keeps the
// established covered drop (QA482 measured zero duplicate records) and the
// release still carries the prefix exactly once.
func TestQA484CoveredExactDuplicateStillDropped(t *testing.T) {
	hello := buildClientHello("qa484-duplicate.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, "")
	if verdict := h.capture(hello[:10], 3000); verdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[:10], 3000); verdict != VerdictHold {
		t.Fatalf("exact duplicate verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[10:], 3010); verdict == VerdictHold {
		t.Fatal("completing segment must not be held")
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want 2", len(h.verdicts))
	}
	if h.verdicts[0] != VerdictDrop || h.verdicts[1] != VerdictDrop {
		t.Fatalf("release dispositions = %v, want the planned drop and the covered duplicate drop", h.verdicts)
	}
	if !strings.Contains(h.reasons[1], "duplicate") {
		t.Fatalf("covered duplicate reason = %q, want the duplicate release reason", h.reasons[1])
	}
	if rebuilt := qa484ReplacementPayload(t, h.injected); rebuilt != string(hello[:10]) {
		t.Fatalf("replacement bytes = %q, want the held prefix exactly once", rebuilt)
	}
}

// The adjacent conflict: the same range arrives with genuinely different bytes.
// Range coverage is still true, so revision12 dropped the record and the later
// copy silently replaced the earlier one. The repaired rule delivers both: the
// first copy's planned split and the second record's own bytes unchanged.
func TestQA484CoveredDifferentBytesAreDelivered(t *testing.T) {
	hello := buildClientHello("qa484-conflict.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	first := append([]byte(nil), hello[:10]...)
	different := append([]byte(nil), first...)
	// A byte that changes payload content but no length or structure, so the
	// message still parses: the earlier rejected probe flipped a record-header
	// length byte and stalled before any disposition was logged.
	different[9] ^= 0xff
	if string(first) == string(different) {
		t.Fatal("probe setup: the payloads must differ")
	}
	h := newHeldHarness(t, qa484Rules, "")
	firstVerdict, firstRecord := qa484Capture(h, first, 4000, tcpFlagACK|tcpFlagPSH)
	if firstVerdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", firstVerdict)
	}
	secondVerdict, secondRecord := qa484Capture(h, different, 4000, tcpFlagACK|tcpFlagPSH)
	if secondVerdict != VerdictHold {
		t.Fatalf("same-range different-bytes record verdict = %d, want hold", secondVerdict)
	}
	if verdict := h.capture(hello[10:], 4010); verdict == VerdictHold {
		t.Fatal("completing segment must not be held")
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want exactly one per captured record", len(h.verdicts))
	}
	if h.order[0] != 4000 || h.order[1] != 4000 {
		t.Fatalf("release order = %v, want capture order", h.order)
	}
	if firstRecord.verdict != VerdictDrop {
		t.Fatalf("first record disposition = %d, want the planned split drop", firstRecord.verdict)
	}
	if secondRecord.verdict != VerdictPass {
		t.Fatalf("same-range different-bytes disposition = %d, want pass so its bytes reach the wire", secondRecord.verdict)
	}
	if secondRecord.reason == "" {
		t.Fatal("a covered record that is not dropped must report why it passes")
	}
	if strings.Contains(secondRecord.reason, "duplicate of bytes released") {
		t.Fatalf("different-bytes reason = %q, but the bytes are not duplicates", secondRecord.reason)
	}
	// Both byte values are delivered: the first record's own bytes through its
	// planned split, the second record's own bytes through its unchanged pass.
	if rebuilt := qa484ReplacementPayload(t, h.injected); rebuilt != string(first) {
		t.Fatalf("replacement bytes = %q, want the first captured copy %q", rebuilt, first)
	}
	if string(secondRecord.packet.Payload) != string(different) {
		t.Fatalf("delivered second record payload = %x, want the captured different bytes %x",
			secondRecord.packet.Payload, different)
	}
}

// The same FIN loss happens on the deadline release (no planned batch): the
// covered record still owns the only FIN, so it must pass even when the
// message never completed.
func TestQA484CoveredFINRecordPassesOnDeadlineRelease(t *testing.T) {
	hello := buildClientHello("qa484-fin-deadline.example")
	if len(hello) < 20 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules,
		`{"hold_timeout":"40ms","max_held_packets":8,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
	now := time.Unix(2000, 0)
	h.engine.SetHoldClock(func() time.Time { return now })
	if verdict := h.capture(hello[:10], 5000); verdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", verdict)
	}
	if verdict := h.captureFlags(hello[:10], 5000, tcpFlagACK|tcpFlagPSH|tcpFlagFIN); verdict != VerdictHold {
		t.Fatalf("FIN-carrying retransmission verdict = %d, want hold", verdict)
	}
	now = now.Add(41 * time.Millisecond)
	h.lease.tcpFlow.expire()
	if len(h.verdicts) != 2 {
		t.Fatalf("terminal dispositions = %d, want 2", len(h.verdicts))
	}
	if h.verdicts[0] != VerdictPass || h.verdicts[1] != VerdictPass {
		t.Fatalf("deadline release dispositions = %v, want both originals delivered", h.verdicts)
	}
	if h.order[0] != 5000 || h.order[1] != 5000 {
		t.Fatalf("deadline release order = %v, want capture order", h.order)
	}
	if len(h.injected) != 0 {
		t.Fatalf("deadline release injected %d packets, want none", len(h.injected))
	}
	if h.reasons[1] == "" || strings.Contains(h.reasons[1], "duplicate of bytes released") {
		t.Fatalf("covered FIN deadline reason = %q, want an explicit control-flag reason", h.reasons[1])
	}
}

// Exact duplicate suppression stays safe when the earlier record's replacement
// send fails part-way: the failing originals pass with their own bytes, the
// covered duplicate is still dropped exactly once, and capture order holds.
func TestQA484CoveredExactDuplicateWithFailedReplacement(t *testing.T) {
	hello := buildClientHello("qa484-failure.example")
	if len(hello) < 30 {
		t.Fatalf("client hello too short: %d", len(hello))
	}
	h := newHeldHarness(t, qa484Rules, "")
	if verdict := h.capture(hello[:10], 6000); verdict != VerdictHold {
		t.Fatalf("first record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[10:20], 6010); verdict != VerdictHold {
		t.Fatalf("second record verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[:20], 6000); verdict != VerdictHold {
		t.Fatalf("coalesced duplicate verdict = %d, want hold", verdict)
	}
	calls := 0
	h.injectFail = func(int) error {
		calls++
		if calls%2 == 0 {
			return errors.New("qa484 injected send failure")
		}
		return nil
	}
	if verdict := h.capture(hello[20:], 6020); verdict == VerdictHold {
		t.Fatal("completing segment must not be held")
	}
	if len(h.verdicts) != 3 {
		t.Fatalf("terminal dispositions = %d, want exactly 3", len(h.verdicts))
	}
	if h.order[0] != 6000 || h.order[1] != 6010 || h.order[2] != 6000 {
		t.Fatalf("release order = %v, want capture order", h.order)
	}
	if h.verdicts[2] != VerdictDrop {
		t.Fatalf("covered coalesced duplicate disposition = %d, want drop", h.verdicts[2])
	}
	if !strings.Contains(h.reasons[2], "duplicate") {
		t.Fatalf("covered coalesced duplicate reason = %q", h.reasons[2])
	}
}

// Unit coverage for the byte authority behind the covered drop: it keeps the
// first-arrival copy of an overlap, never re-charges covered bytes, and reports
// a differing byte or a gap as not released.
func TestQA484PayloadReleasedExactly(t *testing.T) {
	released := appendReleasedPayload(nil, 1000, []byte("0123456789"))
	if len(released) != 1 || released[0].start != 1000 || string(released[0].data) != "0123456789" {
		t.Fatalf("initial released authority = %+v", released)
	}
	released = appendReleasedPayload(released, 1005, []byte("XXXXXABCDE"))
	if len(released) != 2 || released[1].start != 1010 || string(released[1].data) != "ABCDE" {
		t.Fatalf("resegmented authority = %+v, want only the new tail at 1010", released)
	}
	for _, testCase := range []struct {
		name     string
		released []releasedPayload
		sequence uint32
		payload  string
		want     bool
	}{
		{"exact", released, 1000, "0123456789", true},
		{"resegmented_identical", released, 1005, "56789ABCDE", true},
		{"differing_bytes", released, 1005, "XXXXXABCDE", false},
		{"gap", released, 1000, "0123456789K", false},
		{"sequence_wrap", []releasedPayload{{start: 0xfffffffb, data: []byte("ABCDE")}, {start: 0, data: []byte("FGHIJ")}},
			0xfffffffb, "ABCDEFGHIJ", true},
		{"sequence_wrap_differing", []releasedPayload{{start: 0xfffffffb, data: []byte("ABCDE")}, {start: 0, data: []byte("FGHIJ")}},
			0xfffffffb, "ABCDEFGHIX", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := payloadReleasedExactly(testCase.released, testCase.sequence, []byte(testCase.payload)); got != testCase.want {
				t.Fatalf("payloadReleasedExactly = %v, want %v", got, testCase.want)
			}
		})
	}
}

// qa484DeliveredFIN reports whether a terminal disposition that delivers an
// original (Pass or Modify) carries FIN. Dropped records deliver nothing.
func qa484DeliveredFIN(records []*qa484Record) bool {
	for _, record := range records {
		flags := record.packet.TCPFlags
		var raw []byte
		switch record.verdict {
		case VerdictPass:
			raw = record.packet.Raw
		case VerdictModify:
			raw = record.modified
		default:
			continue
		}
		if packet, err := ParsePacket(raw); err == nil {
			flags = packet.TCPFlags
		}
		if flags&tcpFlagFIN != 0 {
			return true
		}
	}
	return false
}

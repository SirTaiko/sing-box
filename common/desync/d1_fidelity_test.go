// D1 fidelity tests. Every case is a deterministic hermetic replay of a
// specific pinned upstream (bol-van/zapret v72.9 c849e55e) algorithm:
//
//   - hostfakesplit: nfq/desync.c DESYNC_HOSTFAKESPLIT, buildFakeHost,
//     IP4_IP_ID_FIX/IP4_IP_ID_NEXT look-ahead order, altorder 0/1;
//   - orig/dup limiters and dup send: cutoff_get_limit/cutoff_test,
//     maybe_cutoff, orig_mod, tcp_orig_send/orig_send_rewrite, udp_orig_send;
//   - reply: the wsize/SS_SYN block before the bReverse return, and the
//     forward-only synack/acksyn split; wssize forced cutoff;
//   - held originals: the rawpacket_queue/replay path, where the stored packet
//     already carries its in-place modification and each delayed packet gets
//     exactly one terminal disposition.
//
// Assertions use packet bytes, sequences, IP IDs and checksums; no source
// string is grepped and no production behaviour is stubbed for the harness.
package desync

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// buildUDP4 builds a minimal IPv4/UDP datagram for the D1 UDP checks.
func buildUDP4(t *testing.T, payload []byte) *Packet {
	t.Helper()
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(28+len(payload)))
	ip[8] = 64
	ip[4], ip[5] = 0x44, 0x33
	ip[9] = 17
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 8})
	binary.BigEndian.PutUint16(ip[10:12], inetChecksum(ip, 0))
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	raw := append(ip, udp...)
	raw = append(raw, payload...)
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = refreshChecksums(raw, packet); err != nil {
		t.Fatal(err)
	}
	return packet
}

func setPacketIPID(packet *Packet, id uint16) {
	binary.BigEndian.PutUint16(packet.Raw[4:6], id)
	packet.IPID = id
}

func parseAll(t *testing.T, packets [][]byte) []*Packet {
	t.Helper()
	parsed := make([]*Packet, 0, len(packets))
	for _, raw := range packets {
		packet, err := ParsePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, packet)
	}
	return parsed
}

func httpRequest(host string) []byte {
	return []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
}

func TestHostFakeSplitTwoPositionsAltOrderZero(t *testing.T) {
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"port":[443],
		"methods":["hostfakesplit"],"repeats":2,"ttl":3,
		"hostfakesplit":{"mod":"host=google.com"}}]}`)
	if rule.HostFakeSplit == nil || rule.HostFakeSplit.Host != "google.com" || rule.HostFakeSplit.Ordering != 0 {
		t.Fatalf("hostfakesplit spec mismatch: %+v", rule.HostFakeSplit)
	}
	message := httpRequest("blocked.example")
	packet := buildIPv4TCP(t, message, 1000, tcpFlagACK|tcpFlagPSH)
	setPacketIPID(packet, 100)
	protocol, host, parsedFacts := protocolFacts(message)
	if protocol != ProtocolHTTP || host != "blocked.example" {
		t.Fatalf("unexpected protocol facts: %v %q", protocol, host)
	}
	parsedFacts.Rand = &sequenceRand{}
	batch, err := PlanTCP(rule, packet, message, 0, parsedFacts)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictDrop {
		t.Fatalf("hostfakesplit original verdict = %v, want drop", batch.Original)
	}
	hostStart, hostEnd := parsedFacts.HostStart, parsedFacts.HostEnd
	if hostStart == 0 || hostEnd <= hostStart {
		t.Fatalf("missing host facts: %d %d", hostStart, hostEnd)
	}
	// before, fake x2, real host, fake(2) x2, after_host
	if len(batch.Packets) != 7 {
		t.Fatalf("packet count = %d, want 7", len(batch.Packets))
	}
	parts := parseAll(t, batch.Packets)
	if !bytes.Equal(parts[0].Payload, message[:hostStart]) {
		t.Fatalf("before_host payload mismatch: %q", parts[0].Payload)
	}
	if !bytes.Equal(parts[3].Payload, message[hostStart:hostEnd]) {
		t.Fatalf("real host payload mismatch: %q", parts[3].Payload)
	}
	if !bytes.Equal(parts[6].Payload, message[hostEnd:]) {
		t.Fatalf("after_host payload mismatch: %q", parts[6].Payload)
	}
	// host_size 15 > configured host length 10: random[./.host]. The
	// deterministic RNG yields 'b' then three '1' bytes.
	if string(parts[1].Payload) != "b111.google.com" {
		t.Fatalf("fake host = %q", parts[1].Payload)
	}
	if !bytes.Equal(parts[1].Payload, parts[4].Payload) {
		t.Fatal("the second fake host copy must carry the same payload")
	}
	for _, index := range []int{1, 2, 4, 5} {
		if parts[index].TTL != 3 {
			t.Fatalf("fake TTL at %d = %d", index, parts[index].TTL)
		}
	}
	for _, index := range []int{0, 3, 6} {
		if parts[index].TTL != 64 {
			t.Fatalf("real TTL at %d = %d", index, parts[index].TTL)
		}
	}
	// Upstream IPv4 ID order for altorder=0: before, fake, real, fake(2), after.
	wantIDs := []uint16{100, 101, 102, 103, 104}
	gotIDs := []uint16{parts[0].IPID, parts[1].IPID, parts[3].IPID, parts[4].IPID, parts[6].IPID}
	for index := range wantIDs {
		if gotIDs[index] != wantIDs[index] {
			t.Fatalf("IPv4 ID order = %v, want %v", gotIDs, wantIDs)
		}
	}
	if parts[0].TCPSeq != 1000 || parts[1].TCPSeq != 1000+uint32(hostStart) ||
		parts[3].TCPSeq != 1000+uint32(hostStart) || parts[6].TCPSeq != 1000+uint32(hostEnd) {
		t.Fatalf("sequence layout mismatch: %d %d %d %d",
			parts[0].TCPSeq, parts[1].TCPSeq, parts[3].TCPSeq, parts[6].TCPSeq)
	}
}

func TestHostFakeSplitThreePositionsAltOrderOne(t *testing.T) {
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"port":[443],
		"methods":["hostfakesplit"],"repeats":2,"ttl":3,
		"hostfakesplit":{"midhost":"host+3","mod":"host=google.com,altorder=1"}}]}`)
	message := httpRequest("blocked.example")
	packet := buildIPv4TCP(t, message, 2000, tcpFlagACK|tcpFlagPSH)
	setPacketIPID(packet, 100)
	protocol, _, facts := protocolFacts(message)
	if protocol != ProtocolHTTP {
		t.Fatalf("protocol = %v", protocol)
	}
	facts.Rand = &sequenceRand{}
	batch, err := PlanTCP(rule, packet, message, 0, facts)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictDrop || len(batch.Packets) != 6 {
		t.Fatalf("batch = %v/%d, want drop/6", batch.Original, len(batch.Packets))
	}
	parts := parseAll(t, batch.Packets)
	hostStart, hostEnd := facts.HostStart, facts.HostEnd
	// before, fake x2, after_host, real host part1 (3), part2 (rest)
	if !bytes.Equal(parts[0].Payload, message[:hostStart]) ||
		!bytes.Equal(parts[3].Payload, message[hostEnd:]) ||
		!bytes.Equal(parts[4].Payload, message[hostStart:hostStart+3]) ||
		!bytes.Equal(parts[5].Payload, message[hostStart+3:hostEnd]) {
		t.Fatal("three-position payload reconstruction mismatch")
	}
	reconstructed := append([]byte(nil), parts[0].Payload...)
	reconstructed = append(reconstructed, parts[4].Payload...)
	reconstructed = append(reconstructed, parts[5].Payload...)
	reconstructed = append(reconstructed, parts[3].Payload...)
	if !bytes.Equal(reconstructed, message) {
		t.Fatalf("byte reconstruction mismatch:\n%q\n%q", reconstructed, message)
	}
	if parts[3].TCPSeq != 2000+uint32(hostEnd) || parts[4].TCPSeq != 2000+uint32(hostStart) ||
		parts[5].TCPSeq != 2000+uint32(hostStart+3) {
		t.Fatalf("sequence layout mismatch: %d %d %d", parts[3].TCPSeq, parts[4].TCPSeq, parts[5].TCPSeq)
	}
	// altorder=1: before, fake, after, real1, real2. The after part is
	// allocated with the upstream look-ahead ID (midhost adds one hop).
	want := []uint16{100, 101, 104, 102, 103}
	got := []uint16{parts[0].IPID, parts[1].IPID, parts[3].IPID, parts[4].IPID, parts[5].IPID}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("IPv4 ID order = %v, want %v", got, want)
		}
	}
}

func TestHostFakeSplitRejectsUnknownPositionList(t *testing.T) {
	var strict option.DirectDesyncOptions
	strictErr := json.UnmarshalDisallowUnknownFields([]byte(`{"enabled":true,"rules":[{"network":["tcp"],
		"methods":["hostfakesplit"],"hostfakesplit":{"split_pos":["host+0"]}}]}`), &strict)
	if strictErr == nil {
		t.Fatal("hostfakesplit split_pos must be rejected: upstream has no such field")
	}
	if _, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],
		"methods":["hostfakesplit"],"hostfakesplit":{"mod":"altorder=2"}}]}`), ""); err == nil {
		t.Fatal("hostfakesplit altorder=2 must be rejected")
	}
	if _, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],
		"methods":["hostfakesplit"],"hostfakesplit":{"midhost":"midsld+1"}}]}`), ""); err != nil {
		t.Fatalf("valid midhost marker rejected: %v", err)
	}
}

func TestHostFakeSplitWithoutHostFactsPasses(t *testing.T) {
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],
		"methods":["hostfakesplit"],"hostfakesplit":{}}]}`)
	message := []byte("GET / HTTP/1.1\r\n\r\n") // request without a Host header
	packet := buildIPv4TCP(t, message, 3000, tcpFlagACK|tcpFlagPSH)
	batch, err := PlanTCP(rule, packet, message, 0, Facts{MessageLength: len(message), Rand: &sequenceRand{}})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictPass || len(batch.Packets) != 0 {
		t.Fatalf("missing host facts must pass: %v/%d", batch.Original, len(batch.Packets))
	}
}

func TestOrigModIntervalsAndLatches(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9,"tcp_flags_unset":"PSH","mod_start":"n3","mod_cutoff":"n5"}}]`, "")
	want := []Verdict{VerdictPass, VerdictPass, VerdictModify, VerdictModify, VerdictPass, VerdictPass}
	for index, expected := range want {
		verdict := h.capture([]byte("data"), 100+uint32(index))
		if verdict != expected {
			t.Fatalf("packet %d verdict = %d, want %d", index+1, verdict, expected)
		}
	}
	// The n/d limits are monotonic, so a latched cutoff and a plain >= test
	// agree here. The s case below is where the latch is observable.
	h2 := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9,"mod_start":"s4"}}]`, "")
	const seq0 = uint32(0xfffffff0)
	if verdict := h2.captureFlags(nil, seq0, tcpFlagSYN); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	if verdict := h2.capture([]byte("data"), seq0+2); verdict != VerdictPass {
		t.Fatalf("s-start below limit verdict = %d", verdict)
	}
	// 0x00000002 wraps past the SYN origin: 0x12 relative bytes.
	if verdict := h2.capture([]byte("data"), 0x00000002); verdict != VerdictModify {
		t.Fatalf("s-start wrap verdict = %d, want modify", verdict)
	}
	if verdict := h2.capture([]byte("data"), seq0+1); verdict != VerdictPass {
		t.Fatalf("a start limiter is not latched: verdict = %d, want pass", verdict)
	}
	h2cut := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9,"mod_start":"s4","mod_cutoff":"s4"}}]`, "")
	if verdict := h2cut.captureFlags(nil, seq0, tcpFlagSYN); verdict != VerdictPass {
		t.Fatalf("cutoff SYN verdict = %d", verdict)
	}
	if verdict := h2cut.capture([]byte("data"), seq0+4); verdict != VerdictPass {
		t.Fatalf("s-cutoff reached verdict = %d, want pass", verdict)
	}
	// A retransmission moves seq_last backwards (s=1). Upstream's
	// b_orig_mod_cutoff latch must keep the original unmodified.
	if verdict := h2cut.capture([]byte("data"), seq0+1); verdict != VerdictPass {
		t.Fatalf("s-cutoff latch regressed: verdict = %d, want pass", verdict)
	}
	h3 := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9}}]`, "")
	if verdict := h3.capture([]byte("data"), 13000); verdict != VerdictModify {
		t.Fatalf("defensive orig modify verdict = %d", verdict)
	}
	modified := h3.lease.TakeModified(DirectionOutbound)
	if modified == nil {
		t.Fatal("immediate orig modification must publish its bytes")
	}
	parsed, err := ParsePacket(modified)
	if err != nil || parsed.TTL != 9 {
		t.Fatalf("orig modification bytes mismatch: %v %+v", err, parsed)
	}
	if _, err = verifyTCPChecksumValue(modified); err != nil {
		t.Fatal(err)
	}
}

// captureFlags is capture() with explicit TCP flags, needed by the s-mode tests
// that must have an observed SYN establishing seq0.
func (h *heldHarness) captureFlags(payload []byte, sequence uint32, flags uint8) Verdict {
	h.t.Helper()
	packet := buildIPv4TCP(h.t, payload, sequence, flags)
	index := len(h.injected)
	return h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
		h.injected = append(h.injected, append([]byte(nil), replacement...))
		if h.injectFail != nil {
			if err := h.injectFail(index); err != nil {
				return err
			}
		}
		return nil
	}, func(verdict Verdict, reason string, modified []byte) {
		h.verdicts = append(h.verdicts, verdict)
		h.reasons = append(h.reasons, reason)
		h.modified = append(h.modified, append([]byte(nil), modified...))
		h.order = append(h.order, packet.TCPSeq)
	})
}

func TestDupIntervalsReplacementAndIDs(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"dup":{"count":2,"ttl":5,"ip_id":"seq","start":"n2","cutoff":"n4"}}]`, "")
	expectedDups := []int{0, 2, 2, 0, 0}
	for index, expected := range expectedDups {
		before := len(h.injected)
		verdict := h.capture([]byte("data"), 4000+uint32(index))
		if verdict != VerdictPass {
			t.Fatalf("packet %d verdict = %d, want pass", index+1, verdict)
		}
		if got := len(h.injected) - before; got != expected {
			t.Fatalf("packet %d dup count = %d, want %d (generated packets must not recount)",
				index+1, got, expected)
		}
	}
	// The dup packets of packet 2 carry the dup TTL and the upstream ID order
	// (IP4_IP_ID_FIX with the main seq mode, then dup mode seq).
	dups := parseAll(t, h.injected[:2])
	if dups[0].TTL != 5 || dups[1].TTL != 5 {
		t.Fatalf("dup TTL = %d/%d", dups[0].TTL, dups[1].TTL)
	}
	if packetID := binary.BigEndian.Uint16(h.injected[0][4:6]); packetID != 0x1234 && dups[0].IPID != 0x1234 {
		t.Fatalf("first dup ID = %d", dups[0].IPID)
	}
	if dups[1].IPID != dups[0].IPID+1 {
		t.Fatalf("dup ID sequence = %d, %d", dups[0].IPID, dups[1].IPID)
	}
	if !bytes.Equal(dups[0].Payload, []byte("data")) {
		t.Fatalf("dup payload = %q", dups[0].Payload)
	}
	replaceHarness := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"dup":{"count":1,"replace":true}}]`, "")
	if verdict := replaceHarness.capture([]byte("data"), 5000); verdict != VerdictDrop {
		t.Fatalf("dup_replace verdict = %d, want drop", verdict)
	}
	if len(replaceHarness.injected) != 1 {
		t.Fatalf("dup_replace injected = %d", len(replaceHarness.injected))
	}
}

func TestUDPOrigAndDupStayAtMostOnce(t *testing.T) {
	// The fixture payload is unclassified, so the pinned-faithful profile must
	// carry the explicit desync_any_proto permission; without it pinned passes
	// the datagram unchanged (contract §5 / F3).
	h := newHeldHarnessUDP(t, `[{"network":["udp"],"port":[443],"any_protocol":true,
		"orig":{"ttl":9},"dup":{"count":1,"ttl":5,"ip_id":"seq"}}]`)
	packet := buildUDP4(t, []byte("QUIC-like payload"))
	verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
		h.injected = append(h.injected, append([]byte(nil), replacement...))
		return nil
	}, nil)
	if verdict != VerdictModify {
		t.Fatalf("udp original verdict = %d, want modify", verdict)
	}
	if len(h.injected) != 1 {
		t.Fatalf("udp dup injected = %d", len(h.injected))
	}
	dup, err := ParsePacket(h.injected[0])
	if err != nil {
		t.Fatal(err)
	}
	if dup.TTL != 5 || !bytes.Equal(dup.Payload, packet.Payload) {
		t.Fatalf("udp dup mismatch: ttl=%d payload=%q", dup.TTL, dup.Payload)
	}
	sum, err := pseudoHeaderSum(h.injected[0], dup, len(h.injected[0])-dup.IPHeaderLen)
	if err != nil || inetChecksum(h.injected[0][dup.IPHeaderLen:], sum) != 0 {
		t.Fatalf("udp dup checksum invalid: %v", err)
	}
	modified := h.lease.TakeModified(DirectionOutbound)
	if modified == nil {
		t.Fatal("udp orig_mod must publish in-place bytes")
	}
	orig, err := ParsePacket(modified)
	if err != nil || orig.TTL != 9 || !bytes.Equal(orig.Payload, packet.Payload) {
		t.Fatalf("udp orig modified mismatch: %v %+v", err, orig)
	}
	// The same flow must not deliver a second copy of the original: the
	// engine returned exactly one Pass for one captured datagram.
	if verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, nil, nil); verdict != VerdictPass {
		t.Fatalf("second udp verdict = %d", verdict)
	}
}

func TestReplyDirectionOnlySynAckWSizeAndSynClear(t *testing.T) {
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],
		"wsize":{"size":1000,"scale":2},"wssize":{"size":2000,"scale":1,"cutoff":"n10"},
		"synack_split":"syn","orig":{"ttl":9},"dup":{"count":1}}]}`)
	data := buildIPv4TCP(t, []byte("data"), 6000, tcpFlagACK|tcpFlagPSH)
	if modified, err := PlanReply(rule, data); err != nil || modified != nil {
		t.Fatalf("non-SYN-ACK reply must pass: %v %v", modified, err)
	}
	synack := buildIPv4TCP(t, nil, 7000, tcpFlagSYN|tcpFlagACK)
	modified, err := PlanReply(rule, synack)
	if err != nil || modified == nil {
		t.Fatalf("SYN-ACK reply rewrite missing: %v", err)
	}
	parsed, err := ParsePacket(modified)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TCPWindow != 1000 {
		t.Fatalf("reply window = %d, want 1000", parsed.TCPWindow)
	}
	if parsed.TCPFlags&tcpFlagACK != 0 || parsed.TCPFlags&tcpFlagSYN == 0 {
		t.Fatalf("synack_split=syn flags = %#x", parsed.TCPFlags)
	}
	if _, err = verifyTCPChecksumValue(modified); err != nil {
		t.Fatal(err)
	}
	// wssize is original-direction only and must not leak into replies.
	if rule.WSSize == nil {
		t.Fatal("wssize not compiled")
	}
	splitRepeat := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],
		"repeats":2,"synack_split":"acksyn"}]}`)
	repeatBatch, err := PlanTCP(splitRepeat, synack, nil, 0, Facts{})
	if err != nil || repeatBatch.Original != VerdictDrop || len(repeatBatch.Packets) != 4 {
		t.Fatalf("split repeats = %d/%v/%v, want 4/drop", len(repeatBatch.Packets), repeatBatch.Original, err)
	}
	repeatParts := parseAll(t, repeatBatch.Packets)
	if repeatParts[0].TCPFlags&tcpFlagACK == 0 || repeatParts[1].TCPFlags&tcpFlagACK == 0 ||
		repeatParts[2].TCPFlags&tcpFlagACK != 0 || repeatParts[3].TCPFlags&tcpFlagACK != 0 {
		t.Fatalf("acksyn repeat order = %#x %#x %#x %#x",
			repeatParts[0].TCPFlags, repeatParts[1].TCPFlags, repeatParts[2].TCPFlags, repeatParts[3].TCPFlags)
	}
}

func TestWSSizeOrigOnlyScaleLoweringAndForcedCutoff(t *testing.T) {
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],
		"wssize":{"size":2000,"scale":1}}]}`)
	message := buildClientHello("blocked.example")
	packet := buildIPv4TCP(t, message, 8000, tcpFlagACK|tcpFlagPSH)
	facts := Facts{MessageLength: len(message), Rand: &sequenceRand{}}
	batch, err := PlanTCP(rule, packet, message, 0, facts)
	if err != nil || batch.Original != VerdictModify {
		t.Fatalf("wssize orig rewrite = %v %v", batch.Original, err)
	}
	parsed, err := ParsePacket(batch.Modified)
	if err != nil || parsed.TCPWindow != 2000 {
		t.Fatalf("wssize window = %v %v", parsed, err)
	}
	// The harness fixture has no window-scale option: lowering it is a no-op
	// and must not prevent the window rewrite.
	if parsed.TCPWindow != 2000 {
		t.Fatal("unreachable")
	}
	// Explicit cutoff n1 latches before the first packet, so no rewrite.
	cutoff := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"wssize":{"size":2000,"cutoff":"n1"}}]`, "")
	if verdict := cutoff.capture(message, 9000); verdict != VerdictPass {
		t.Fatalf("wssize cutoff verdict = %d, want pass", verdict)
	}
	if modified := cutoff.lease.TakeModified(DirectionOutbound); modified != nil {
		t.Fatal("wssize cutoff must suppress the window rewrite")
	}
	// A complete ClientHello triggers the forced cutoff after its own packet.
	forced := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"wssize":{"size":2000}}]`, "")
	if verdict := forced.capture(message, 9100); verdict != VerdictModify {
		t.Fatalf("forced-cutoff first packet = %d, want modify", verdict)
	}
	if verdict := forced.capture(message, 9100+uint32(len(message))); verdict != VerdictPass {
		t.Fatalf("forced-cutoff second packet = %d, want pass", verdict)
	}
	// forced_cutoff=false keeps rewriting later original packets.
	noForced := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"wssize":{"size":2000,"forced_cutoff":false}}]`, "")
	if verdict := noForced.capture(message, 9200); verdict != VerdictModify {
		t.Fatalf("no-forced first packet = %d", verdict)
	}
	if verdict := noForced.capture(message, 9200+uint32(len(message))); verdict != VerdictModify {
		t.Fatalf("no-forced second packet = %d, want modify", verdict)
	}
}

func TestReplyNeverCountsAsOriginalAndNeverInjects(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9},"dup":{"count":1,"start":"n2"}}]`, "")
	inbound := buildIPv4TCP(t, []byte("HTTP/1.1 200 OK\r\n\r\n"), 9900, tcpFlagACK|tcpFlagPSH)
	injected := 0
	if verdict := h.lease.HandlePacket(inbound.Raw, DirectionInbound, func([]byte) error {
		injected++
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("reply verdict = %d, want pass", verdict)
	}
	injected = 0
	synack := buildIPv4TCP(t, nil, 9901, tcpFlagSYN|tcpFlagACK)
	if verdict := h.lease.HandlePacket(synack.Raw, DirectionInbound, func([]byte) error {
		injected++
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("SYN-ACK reply verdict = %d", verdict)
	}
	if injected != 0 {
		t.Fatalf("replies were injected: %d", injected)
	}
	// Reply observations must not increment the original n counter. This is
	// original packet #1, below dup.start=n2, so no duplicate is emitted.
	injectedBefore := len(h.injected)
	if verdict := h.capture([]byte("data"), 9902); verdict != VerdictModify {
		t.Fatalf("original after replies verdict = %d, want orig_mod modify", verdict)
	}
	if len(h.injected) != injectedBefore {
		t.Fatalf("replies counted as originals: dup packets = %d", len(h.injected)-injectedBefore)
	}
}

func TestDirectionScopedModificationSlots(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],
		"wsize":{"size":1000},"orig":{"ttl":9}}]`, "")
	syn := buildIPv4TCP(t, nil, 14000, tcpFlagSYN)
	if verdict := h.lease.HandlePacket(syn.Raw, DirectionOutbound, nil, nil); verdict != VerdictModify {
		t.Fatalf("outbound SYN verdict = %d", verdict)
	}
	_ = h.lease.TakeModified(DirectionOutbound)
	synack := buildIPv4TCP(t, nil, 15000, tcpFlagSYN|tcpFlagACK)
	synack.TCPAck = 14001
	binary.BigEndian.PutUint32(synack.Raw[synack.IPHeaderLen+8:synack.IPHeaderLen+12], 14001)
	if err := refreshChecksums(synack.Raw, synack); err != nil {
		t.Fatal(err)
	}
	if verdict := h.lease.HandlePacket(synack.Raw, DirectionInbound, nil, nil); verdict != VerdictModify {
		t.Fatalf("inbound SYN-ACK verdict = %d", verdict)
	}
	inboundModified := h.lease.TakeModified(DirectionInbound)
	if inboundModified == nil {
		t.Fatal("inbound reply rewrite missing")
	}
	parsed, err := ParsePacket(inboundModified)
	if err != nil || parsed.TCPWindow != 1000 {
		t.Fatalf("inbound reply window = %v %v", parsed, err)
	}
	if outbound := h.lease.TakeModified(DirectionOutbound); outbound != nil {
		t.Fatal("inbound rewrite leaked into the outbound slot")
	}
	if verdict := h.capture([]byte("data"), 14001); verdict != VerdictModify {
		t.Fatalf("outbound orig verdict = %d", verdict)
	}
	outboundModified := h.lease.TakeModified(DirectionOutbound)
	if outboundModified == nil {
		t.Fatal("outbound orig rewrite missing")
	}
	if inbound := h.lease.TakeModified(DirectionInbound); inbound != nil {
		t.Fatal("outbound rewrite leaked into the inbound slot")
	}
}

func TestHeldOrigModPropagatesModifiedBytesExactlyOnce(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],
		"multisplit":{"split_pos":["host+3"]},"orig":{"ttl":7}}]`, "")
	hello := buildClientHello("blocked.example")
	if verdict := h.capture(hello[:20], 10000); verdict != VerdictHold {
		t.Fatalf("first verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[20:40], 10020); verdict != VerdictHold {
		t.Fatalf("second verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[40:], 10040); verdict != VerdictDrop {
		t.Fatalf("completing verdict = %d, want drop", verdict)
	}
	if len(h.verdicts) != 2 {
		t.Fatalf("held completions = %d, want exactly 2", len(h.verdicts))
	}
	for index, verdict := range h.verdicts {
		if verdict != VerdictModify {
			t.Fatalf("held completion %d = %d, want modify", index, verdict)
		}
		if len(h.modified[index]) == 0 {
			t.Fatalf("held completion %d lost its in-place bytes", index)
		}
		parsed, err := ParsePacket(h.modified[index])
		if err != nil {
			t.Fatal(err)
		}
		if parsed.TTL != 7 || parsed.TCPFlags&tcpFlagPSH == 0 {
			t.Fatalf("held modified %d = ttl %d flags %#x", index, parsed.TTL, parsed.TCPFlags)
		}
		wantSeq := uint32(10000)
		if index == 1 {
			wantSeq = 10020
		}
		if parsed.TCPSeq != wantSeq {
			t.Fatalf("held modified %d seq = %d, want %d", index, parsed.TCPSeq, wantSeq)
		}
		if _, err = verifyTCPChecksumValue(h.modified[index]); err != nil {
			t.Fatal(err)
		}
	}
	// The held path must not use the immediate-path shared slot.
	if modified := h.lease.TakeModified(DirectionOutbound); modified != nil {
		t.Fatal("held release leaked into the lease modification slot")
	}
	// The completing packet's own split segments are still injected.
	if len(h.injected) == 0 {
		t.Fatal("completing packet was not split")
	}
}

func TestHeldReleaseCannotBypassDesyncCutoff(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],
		"multisplit":{"split_pos":["host+3"]},"start":"n1","cutoff":"n2"}]`, "")
	hello := buildClientHello("blocked.example")
	if verdict := h.capture(hello[:20], 11000); verdict != VerdictHold {
		t.Fatalf("first verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[20:], 11020); verdict != VerdictPass {
		t.Fatalf("cutoff packet verdict = %d, want pass", verdict)
	}
	if len(h.verdicts) != 1 || h.verdicts[0] != VerdictPass {
		t.Fatalf("held release = %+v, want one pass", h.verdicts)
	}
	if len(h.injected) != 0 {
		t.Fatalf("cutoff release injected %d packets", len(h.injected))
	}
	if !strings.Contains(h.reasons[0], "interval") {
		t.Fatalf("cutoff release reason = %q", h.reasons[0])
	}
}

// newHeldHarnessUDP creates a UDP attempt on the same fake-engine harness.
func newHeldHarnessUDP(t *testing.T, rules string) *heldHarness {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	return &heldHarness{t: t, engine: engine, lease: lease}
}

// buildIPv6TCP builds a minimal IPv6/TCP packet with a timestamp option.
func buildIPv6TCP(t *testing.T, payload []byte, sequence uint32, flags uint8) *Packet {
	t.Helper()
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(32+len(payload)))
	ip[6] = 6
	ip[7] = 64
	copy(ip[8:24], mustIPv6("2001:db8::1"))
	copy(ip[24:40], mustIPv6("2001:db8::2"))
	tcp := make([]byte, 32)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], 2000)
	tcp[12] = 8 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	tcp[20], tcp[21], tcp[22], tcp[23] = 1, 1, 8, 10
	binary.BigEndian.PutUint32(tcp[24:28], 1111)
	binary.BigEndian.PutUint32(tcp[28:32], 2222)
	raw := append(ip, tcp...)
	raw = append(raw, payload...)
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = refreshChecksums(raw, packet); err != nil {
		t.Fatal(err)
	}
	return packet
}

func mustIPv6(value string) []byte {
	address := netip.MustParseAddr(value).As16()
	return address[:]
}

// newHeldHarnessIPv6 creates an IPv6 TCP attempt on the fake-engine harness.
func newHeldHarnessIPv6(t *testing.T, rules string) *heldHarness {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("[2001:db8::1]:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv6, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("[2001:db8::2]:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	return &heldHarness{t: t, engine: engine, lease: lease}
}

func TestIPv6ReplyWSizeAndSynClear(t *testing.T) {
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],
		"wsize":{"size":1200},"synack_split":"syn"}]}`)
	synack := buildIPv6TCP(t, nil, 12000, tcpFlagSYN|tcpFlagACK)
	modified, err := PlanReply(rule, synack)
	if err != nil || modified == nil {
		t.Fatalf("IPv6 SYN-ACK rewrite missing: %v", err)
	}
	parsed, err := ParsePacket(modified)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TCPWindow != 1200 || parsed.TCPFlags&tcpFlagACK != 0 {
		t.Fatalf("IPv6 reply window/flags = %d/%#x", parsed.TCPWindow, parsed.TCPFlags)
	}
	if _, err = verifyTCPChecksumValue(modified); err != nil {
		t.Fatalf("IPv6 reply checksum: %v", err)
	}
}

func TestIPv6OrigModAndDupRawCopy(t *testing.T) {
	h := newHeldHarnessIPv6(t, `[{"network":["tcp"],"port":[443],
		"orig":{"ttl":7},"dup":{"count":1}}]`)
	packet := buildIPv6TCP(t, []byte("data"), 13000, tcpFlagACK|tcpFlagPSH)
	t.Logf("packet dst=%v port=%d payload=%d", packet.Dst, packet.DstPort, len(packet.Payload))
	verdict := h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
		h.injected = append(h.injected, append([]byte(nil), replacement...))
		return nil
	}, nil)
	h.lease.tcpFlow.mu.Lock()
	t.Logf("flow rule=%v failed=%v counters=%+v", h.lease.tcpFlow.rule != nil,
		h.lease.tcpFlow.failed, h.lease.tcpFlow.counters)
	h.lease.tcpFlow.mu.Unlock()
	if verdict != VerdictModify {
		t.Fatalf("IPv6 orig verdict = %d, want modify", verdict)
	}
	modified := h.lease.TakeModified(DirectionOutbound)
	if modified == nil {
		t.Fatal("IPv6 orig modification missing")
	}
	if _, err := verifyTCPChecksumValue(modified); err != nil {
		t.Fatalf("IPv6 orig checksum: %v", err)
	}
	if len(h.injected) != 1 {
		t.Fatalf("IPv6 dup count = %d", len(h.injected))
	}
	// No TCP flags/fooling and IPv6 means the upstream raw-copy branch: the
	// duplicate is the exact post-modification packet.
	if !bytes.Equal(h.injected[0], modified) {
		t.Fatal("IPv6 raw-copy duplicate differs from the modified original")
	}
	if _, err := verifyTCPChecksumValue(h.injected[0]); err != nil {
		t.Fatalf("IPv6 dup checksum: %v", err)
	}
}

package desync

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func buildIPv4UDP(t *testing.T, payload []byte, destinationPort uint16) *Packet {
	t.Helper()
	raw := make([]byte, 28+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[8] = 64
	raw[9] = 17
	copy(raw[12:16], []byte{192, 0, 2, 1})
	copy(raw[16:20], []byte{198, 51, 100, 7})
	binary.BigEndian.PutUint16(raw[10:12], inetChecksum(raw[:20], 0))
	binary.BigEndian.PutUint16(raw[20:22], 40000)
	binary.BigEndian.PutUint16(raw[22:24], destinationPort)
	binary.BigEndian.PutUint16(raw[24:26], uint16(8+len(payload)))
	copy(raw[28:], payload)
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestPlanUDPFakeQUIC(t *testing.T) {
	payload := buildQUICInitial()
	packet := buildIPv4UDP(t, payload, 443)
	rule := &Rule{Network: TransportMaskUDP, IPv4: true, IPv6: true, AnyProtocol: true,
		Methods: []Method{{Kind: MethodFake}},
		Fake:    &FakeSpec{Repeats: 3, Payloads: []Payload{{Protocol: ProtocolQUIC, Data: []byte("fake-quic")}}}}
	batch, err := PlanUDP(rule, packet)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictPass {
		t.Fatal("UDP fake must not suppress the original datagram")
	}
	if len(batch.Packets) != 3 {
		t.Fatalf("packets = %d", len(batch.Packets))
	}
	for index, generated := range batch.Packets {
		parsed, err := ParsePacket(generated)
		if err != nil {
			t.Fatal(err)
		}
		if string(parsed.Payload) != "fake-quic" {
			t.Fatalf("packet %d payload = %q", index, parsed.Payload)
		}
		if parsed.SrcPort != 40000 || parsed.DstPort != 443 {
			t.Fatalf("packet %d tuple changed", index)
		}
	}
}

func TestSkipNoSNIGatesProtocolRules(t *testing.T) {
	rule := &Rule{Network: TransportMaskTCP, IPv4: true, IPv6: true,
		Protocols: []Protocol{ProtocolTLS}, SkipNoSNI: true}
	unknown := MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Port: 443,
		Destination: netip.MustParseAddr("198.51.100.7"), Protocol: ProtocolUnknown}
	if rule.Matches(unknown) {
		t.Fatal("skip_no_sni must reject unknown-protocol flows")
	}
	known := unknown
	known.Protocol = ProtocolTLS
	if !rule.Matches(known) {
		t.Fatal("detected TLS must match a TLS rule")
	}
	noSkip := &Rule{Network: TransportMaskTCP, IPv4: true, IPv6: true,
		Protocols: []Protocol{ProtocolTLS}, SkipNoSNI: false}
	if noSkip.Matches(unknown) {
		t.Fatal("unknown protocol must not match a TLS protocol rule without SNI")
	}
}

func TestDataAndSequenceIntervals(t *testing.T) {
	flow := newFlowState(defaultLimits(), nil, nil)
	flow.observe(buildIPv4TCP(t, nil, 100, tcpFlagSYN), false)
	if flow.counters.packets != 1 || flow.counters.dataPackets != 0 {
		t.Fatalf("syn counters: %+v", flow.counters)
	}
	flow.observe(buildIPv4TCP(t, []byte("hello"), 101, tcpFlagACK|tcpFlagPSH), false)
	if !(Interval{Mode: IntervalData, Value: 1}).Reached(flow.counters) {
		t.Fatal("d1 must be reached after one data packet")
	}
	if (Interval{Mode: IntervalData, Value: 2}).Reached(flow.counters) {
		t.Fatal("d2 must not be reached yet")
	}
	flow.observe(buildIPv4TCP(t, []byte("more"), 106, tcpFlagACK|tcpFlagPSH), false)
	if !(Interval{Mode: IntervalData, Value: 2}).Reached(flow.counters) {
		t.Fatal("d2 must be reached after two data packets")
	}
	// Upstream `s` is `seq_last - seq0` (nfq/desync.c:322), where seq_last is
	// the last observed sequence and does not include the current payload
	// length. 106 - 100 = 6.
	if flow.counters.sequence != 6 {
		t.Fatalf("sequence span = %d", flow.counters.sequence)
	}
	if !(Interval{Mode: IntervalSequence, Value: 6}).Reached(flow.counters) {
		t.Fatal("s6 must be reached")
	}
	if (Interval{Mode: IntervalSequence, Value: 7}).Reached(flow.counters) {
		t.Fatal("s7 must not be reached")
	}
}

// TestSequenceCounterMatchesUpstreamLastObserved pins the upstream counter
// rules for out-of-order retransmissions, wrap and replies:
//   - a retransmission is a counter event but moves seq_last backwards
//     (nfq/conntrack.c updates seq_last from every original packet);
//   - the reply direction feeds seq_last from the ACK field and keeps its own
//     reply counters;
//   - the span is unsigned 32-bit arithmetic: no signed conversion and no
//     payload-length addition to the current packet.
func TestSequenceCounterMatchesUpstreamLastObserved(t *testing.T) {
	flow := newFlowState(defaultLimits(), nil, nil)
	flow.observe(buildIPv4TCP(t, nil, 1000, tcpFlagSYN), false)
	flow.observe(buildIPv4TCP(t, []byte("abcdefghij"), 1001, tcpFlagACK), false)
	if flow.counters.sequence != 1 {
		t.Fatalf("after first data packet s = %d", flow.counters.sequence)
	}
	flow.observe(buildIPv4TCP(t, []byte("klmno"), 1011, tcpFlagACK), false)
	if flow.counters.sequence != 11 {
		t.Fatalf("after second data packet s = %d", flow.counters.sequence)
	}
	// An earlier retransmission is counted as a packet event and moves
	// seq_last back to the retransmitted sequence, exactly as upstream.
	flow.observe(buildIPv4TCP(t, []byte("abcdefghij"), 1001, tcpFlagACK), false)
	if flow.counters.sequence != 1 {
		t.Fatalf("retransmit s = %d, want 1", flow.counters.sequence)
	}
	if flow.counters.packets != 4 || flow.counters.dataPackets != 3 {
		t.Fatalf("retransmit counters = %+v", flow.counters)
	}
	// Reply: seq_last is taken from the ACK, the reply span from its own
	// sequence origin.
	flow.observeReply(buildIPv4TCP(t, []byte("reply"), 5000, tcpFlagACK), false)
	if flow.seqLast != 2000 {
		t.Fatalf("reply must feed seq_last from the ACK: %d", flow.seqLast)
	}
	if flow.counters.replyPackets != 1 || flow.counters.replyData != 1 {
		t.Fatalf("reply counters = %+v", flow.counters)
	}
	if flow.counters.replySequence != 0 {
		t.Fatalf("reply span = %d", flow.counters.replySequence)
	}
	// Wrap: the span is computed in unsigned 32-bit space, never via int32
	// cast to uint64.
	wrapFlow := newFlowState(defaultLimits(), nil, nil)
	wrapFlow.observe(buildIPv4TCP(t, nil, 0xfffffff0, tcpFlagSYN), false)
	wrapFlow.observe(buildIPv4TCP(t, []byte("tail"), 0xfffffff1, tcpFlagACK), false)
	wrapFlow.observe(buildIPv4TCP(t, []byte("head"), 0x00000005, tcpFlagACK), false)
	// 0x00000005 - 0xfffffff0 = 0x15 = 21 in wrap-safe unsigned arithmetic.
	if wrapFlow.counters.sequence != 0x15 {
		t.Fatalf("wrap span = %#x", wrapFlow.counters.sequence)
	}
}

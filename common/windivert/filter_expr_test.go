package windivert

// Adversarial tests for the filter language compiler and the owned-envelope
// composition. evaluateFilter is a model of the driver's documented decision
// tree (filter.go): evaluate the test at instruction i and follow success or
// failure until an ACCEPT/REJECT terminal. It is a test model, not production
// behaviour; the production output is the instruction array itself.

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

type filterFacts map[uint16]uint32

func evaluateFilter(t *testing.T, f *Filter, facts filterFacts) bool {
	t.Helper()
	encoded, _, err := f.encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(encoded)%filterInstBytes != 0 {
		t.Fatalf("instruction array is not a multiple of %d bytes", filterInstBytes)
	}
	instruction := 0
	for steps := 0; steps <= filterMaxInsts; steps++ {
		if instruction >= len(encoded)/filterInstBytes {
			t.Fatalf("continuation %d out of range", instruction)
		}
		raw := encoded[instruction*filterInstBytes:]
		word0 := binary.LittleEndian.Uint32(raw[0:4])
		word1 := binary.LittleEndian.Uint32(raw[4:8])
		field := uint16(word0 & 0x7FF)
		test := uint8((word0 >> 11) & 0x1F)
		success := uint16(word0 >> 16)
		failure := uint16(word1 & 0xFFFF)
		actual := facts[field]
		expected := binary.LittleEndian.Uint32(raw[8:12])
		matched := false
		switch test {
		case testEQ:
			matched = actual == expected
		case testNEQ:
			matched = actual != expected
		case testLT:
			matched = actual < expected
		case testLEQ:
			matched = actual <= expected
		case testGT:
			matched = actual > expected
		case testGEQ:
			matched = actual >= expected
		}
		if word1&(1<<16) != 0 {
			matched = !matched
		}
		if matched {
			if success == resultAccept {
				return true
			}
			if success == resultReject {
				return false
			}
			instruction = int(success)
			continue
		}
		if failure == resultReject {
			return false
		}
		if failure == resultAccept {
			return true
		}
		instruction = int(failure)
	}
	t.Fatalf("filter did not terminate")
	return false
}

// ownedEnvelope mimics the capture envelope: direction + IPv4 + TCP + exact
// tuple. It is the operand a user expression must never escape.
func ownedEnvelope(t *testing.T) *Filter {
	t.Helper()
	filter, err := OutboundTCP(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.20:443"))
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func TestParseFilterPrecedenceAndParentheses(t *testing.T) {
	// and binds tighter than or.
	filter, err := ParseFilter("outbound and tcp.DstPort == 443 or inbound and tcp.SrcPort == 53")
	if err != nil {
		t.Fatal(err)
	}
	outboundTCP := filterFacts{fieldOutbound: 1, fieldTCP: 1, fieldTCPDstPort: 443}
	if !evaluateFilter(t, filter, outboundTCP) {
		t.Fatal("outbound branch must match")
	}
	if evaluateFilter(t, filter, filterFacts{fieldOutbound: 1, fieldTCP: 1, fieldTCPDstPort: 80}) {
		t.Fatal("unmatched outbound branch must not match")
	}
	if !evaluateFilter(t, filter, filterFacts{fieldInbound: 1, fieldTCP: 1, fieldTCPSrcPort: 53}) {
		t.Fatal("inbound branch must match")
	}
	// Explicit parentheses change the meaning: (a and b or c) is parsed above;
	// now force a different grouping and prove the compiler honours it.
	grouped, err := ParseFilter("outbound and (tcp.DstPort == 443 or tcp.DstPort == 8443)")
	if err != nil {
		t.Fatal(err)
	}
	if !evaluateFilter(t, grouped, filterFacts{fieldOutbound: 1, fieldTCP: 1, fieldTCPDstPort: 8443}) {
		t.Fatal("parenthesized or must match")
	}
}

func TestParseFilterNegation(t *testing.T) {
	filter, err := ParseFilter("!impostor and not loopback and tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !evaluateFilter(t, filter, filterFacts{fieldTCP: 1}) {
		t.Fatal("plain TCP must match")
	}
	if evaluateFilter(t, filter, filterFacts{fieldTCP: 1, fieldImpostor: 1}) {
		t.Fatal("impostor must be excluded")
	}
	if evaluateFilter(t, filter, filterFacts{fieldTCP: 1, fieldLoopback: 1}) {
		t.Fatal("loopback must be excluded")
	}
	// Double negation is identity.
	double, err := ParseFilter("not not tcp")
	if err != nil {
		t.Fatal(err)
	}
	if !evaluateFilter(t, double, filterFacts{fieldTCP: 1}) || evaluateFilter(t, double, filterFacts{}) {
		t.Fatal("double negation changed the meaning")
	}
}

// TestCompositionCannotEscapeOwnership is the security property: no user
// expression, however written, can match a packet outside the owned envelope.
func TestCompositionCannotEscapeOwnership(t *testing.T) {
	envelope := ownedEnvelope(t)
	foreign := filterFacts{fieldOutbound: 1, fieldIP: 1, fieldTCP: 1,
		fieldIPSrcAddr: 0x0A000001, fieldIPDstAddr: 0xC0000201,
		fieldTCPSrcPort: 1234, fieldTCPDstPort: 443}
	for _, expression := range []string{
		"tcp",
		"outbound",
		"true",
		"outbound or inbound",
		"outbound and (tcp or udp)",
		"tcp.DstPort == 443",
		"(outbound and tcp.DstPort == 443) or (ip.SrcAddr != 192.0.2.10)",
		"not (inbound or ipv6)",
	} {
		user, err := ParseFilter(expression)
		if err != nil {
			t.Fatalf("%q: %v", expression, err)
		}
		composed, err := And(envelope, user)
		if err != nil {
			t.Fatalf("%q: %v", expression, err)
		}
		if evaluateFilter(t, composed, foreign) {
			t.Fatalf("expression %q escaped the owned envelope", expression)
		}
	}
	// The owned tuple itself still matches a permissive user expression.
	user, err := ParseFilter("tcp")
	if err != nil {
		t.Fatal(err)
	}
	composed, err := And(envelope, user)
	if err != nil {
		t.Fatal(err)
	}
	owned := filterFacts{fieldOutbound: 1, fieldIP: 1, fieldTCP: 1,
		fieldIPSrcAddr: 0xC000020A, fieldIPDstAddr: 0xC6336414,
		fieldTCPSrcPort: 40000, fieldTCPDstPort: 443}
	if !evaluateFilter(t, composed, owned) {
		t.Fatal("owned tuple must still match")
	}
}

func TestEnvelopeInterfaceDimension(t *testing.T) {
	iface, err := InterfaceIndex(12, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(iface.Expression()) == 0 {
		t.Fatal("interface filter must render")
	}
	owned := filterFacts{fieldOutbound: 1, fieldIP: 1, fieldTCP: 1,
		fieldIPSrcAddr: 0xC000020A, fieldIPDstAddr: 0xC6336414,
		fieldTCPSrcPort: 40000, fieldTCPDstPort: 443, fieldIfIdx: 12}
	other := filterFacts{fieldOutbound: 1, fieldIP: 1, fieldTCP: 1,
		fieldIPSrcAddr: 0xC000020A, fieldIPDstAddr: 0xC6336414,
		fieldTCPSrcPort: 40000, fieldTCPDstPort: 443, fieldIfIdx: 13}
	composed, err := And(ownedEnvelope(t), iface)
	if err != nil {
		t.Fatal(err)
	}
	if !evaluateFilter(t, composed, owned) {
		t.Fatalf("owned interface must match (iface expression %q)", iface.Expression())
	}
	if evaluateFilter(t, composed, other) {
		t.Fatal("a sibling interface must be excluded")
	}
	if _, err = InterfaceIndex(0, 0); err == nil {
		t.Fatal("interface index 0 must be rejected")
	}
	if _, err = InterfaceIndex(70000, 0); err == nil {
		t.Fatal("out-of-range interface index must be rejected")
	}
}

func TestParseFilterRejectsMalformedExpressions(t *testing.T) {
	for _, expression := range []string{
		"",
		"tcp and",
		"(tcp",
		"tcp)",
		"and or tcp",
		"tcp.DstPort",
		"tcp.DstPort ==",
		"tcp.DstPort == 99999",
		"tcp.DstPort == -1",
		"frobnicate == 1",
		"ip.SrcAddr == ::1",
		"ipv6.SrcAddr == 192.0.2.1",
		"tcp.DstPort == 443 and (",
		"tcp.DstPort ~ 443",
		"tcp.DstPort == 443 extra",
		strings.Repeat("tcp and ", 3000) + "tcp",
	} {
		if _, err := ParseFilter(expression); err == nil {
			t.Fatalf("expression %q must be rejected", expression)
		}
	}
}

func TestParseFilterBoundsInstructionCount(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("tcp")
	for index := 0; index < 300; index++ {
		builder.WriteString(" and tcp.DstPort != ")
		builder.WriteString("1024")
	}
	if _, err := ParseFilter(builder.String()); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("over-long filter must be rejected with a size error, got %v", err)
	}
}

func TestFilterExpressionRoundTrip(t *testing.T) {
	filter, err := ParseFilter("outbound and ip and tcp and ip.SrcAddr == 192.0.2.10 and tcp.DstPort == 443")
	if err != nil {
		t.Fatal(err)
	}
	rendered := filter.Expression()
	reparsed, err := ParseFilter(rendered)
	if err != nil {
		t.Fatalf("re-parse %q: %v", rendered, err)
	}
	facts := []filterFacts{
		{fieldOutbound: 1, fieldIP: 1, fieldTCP: 1, fieldIPSrcAddr: 0xC000020A, fieldTCPDstPort: 443},
		{fieldOutbound: 1, fieldIP: 1, fieldTCP: 1, fieldIPSrcAddr: 0xC000020A, fieldTCPDstPort: 80},
		{},
	}
	for index, factSet := range facts {
		if evaluateFilter(t, filter, factSet) != evaluateFilter(t, reparsed, factSet) {
			t.Fatalf("round trip changed the meaning for fact set %d", index)
		}
	}
}

// TestEnvelopeEncodingUnchanged pins that the new compiler reproduces the
// pre-existing instruction encoding byte for byte for the owned constructors.
func TestEnvelopeEncodingUnchanged(t *testing.T) {
	filter := ownedEnvelope(t)
	encoded, flags, err := filter.encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := filterFlagOutbound | filterFlagIP; flags != want {
		t.Fatalf("flags: got %#x, want %#x", flags, want)
	}
	if len(encoded) != 7*filterInstBytes {
		t.Fatalf("instruction count: got %d, want 7", len(encoded)/filterInstBytes)
	}
	last := encoded[6*filterInstBytes:]
	if success := uint16(binary.LittleEndian.Uint32(last[0:4]) >> 16); success != resultAccept {
		t.Fatalf("last success continuation: got %#x, want ACCEPT", success)
	}
	for index := 0; index < 6; index++ {
		raw := encoded[index*filterInstBytes:]
		success := uint16(binary.LittleEndian.Uint32(raw[0:4]) >> 16)
		failure := uint16(binary.LittleEndian.Uint32(raw[4:8]) & 0xFFFF)
		if success != uint16(index+1) || failure != resultReject {
			t.Fatalf("inst %d continuations: success %d failure %#x", index, success, failure)
		}
	}
}

package windivert

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestRejectFilter(t *testing.T) {
	t.Parallel()
	bin, flags, err := reject().encode()
	if err != nil {
		t.Fatal(err)
	}
	if len(bin) != filterInstBytes {
		t.Fatalf("reject filter len: got %d, want %d", len(bin), filterInstBytes)
	}
	if flags != 0 {
		t.Fatalf("reject filter flags: got %x, want 0", flags)
	}
	// word0: field=ZERO=0, test=EQ=0, success=REJECT=0x7FFF
	word0 := binary.LittleEndian.Uint32(bin[0:4])
	if word0 != uint32(resultReject)<<16 {
		t.Fatalf("reject word0 = %08x", word0)
	}
	// word1: failure=REJECT
	word1 := binary.LittleEndian.Uint32(bin[4:8])
	if word1 != uint32(resultReject) {
		t.Fatalf("reject word1 = %08x", word1)
	}
}

// TestInboundFlowFilters pins that reply observation uses an explicitly inbound
// filter for the reversed tuple: direction is part of the filter identity, so a
// reply can never be captured as outbound and re-injected as a replacement.
func TestInboundFlowFilters(t *testing.T) {
	peer := netip.MustParseAddrPort("198.51.100.20:443")
	local := netip.MustParseAddrPort("192.0.2.10:40000")
	tcpFilter, err := InboundTCPFlow(peer, local)
	if err != nil {
		t.Fatal(err)
	}
	if tcpFilter.flags&filterFlagInbound == 0 || tcpFilter.flags&filterFlagOutbound != 0 {
		t.Fatalf("inbound tcp flags = %#x", tcpFilter.flags)
	}
	if _, _, err = tcpFilter.encode(); err != nil {
		t.Fatal(err)
	}
	udpFilter, err := InboundUDPFlow(peer, local)
	if err != nil {
		t.Fatal(err)
	}
	if udpFilter.flags&filterFlagInbound == 0 || udpFilter.flags&filterFlagOutbound != 0 {
		t.Fatalf("inbound udp flags = %#x", udpFilter.flags)
	}
	if _, _, err = udpFilter.encode(); err != nil {
		t.Fatal(err)
	}
	// Mixed families are rejected rather than silently widened.
	if _, err = InboundTCPFlow(netip.MustParseAddrPort("[2001:db8::20]:443"), local); err == nil {
		t.Fatal("mixed IPv4/IPv6 inbound flow must be rejected")
	}
	// The outbound constructor keeps its own direction.
	outbound, err := OutboundTCP(netip.MustParseAddrPort("192.0.2.10:40000"), netip.MustParseAddrPort("198.51.100.20:443"))
	if err != nil {
		t.Fatal(err)
	}
	if outbound.flags&filterFlagOutbound == 0 || outbound.flags&filterFlagInbound != 0 {
		t.Fatalf("outbound flags = %#x", outbound.flags)
	}
}

func TestOutboundTCPFilterIPv4(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddrPort("10.1.2.3:54321")
	dst := netip.MustParseAddrPort("1.2.3.4:443")
	f, err := OutboundTCP(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	bin, flags, err := f.encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := filterFlagOutbound | filterFlagIP; flags != want {
		t.Fatalf("flags: got %x, want %x", flags, want)
	}
	// 7 instructions: OUTBOUND, IP, TCP, IP_SRCADDR, IP_DSTADDR, TCP_SRCPORT, TCP_DSTPORT
	const wantInsts = 7
	if len(bin) != wantInsts*filterInstBytes {
		t.Fatalf("instruction count: got %d, want %d", len(bin)/filterInstBytes, wantInsts)
	}

	// Inst 0: OUTBOUND == 1, success=1, failure=REJECT
	checkInst(t, bin[0*filterInstBytes:], 0, fieldOutbound, testEQ, 1, resultReject, 1)
	// Inst 1: IP == 1, success=2
	checkInst(t, bin[1*filterInstBytes:], 1, fieldIP, testEQ, 2, resultReject, 1)
	// Inst 2: TCP == 1, success=3
	checkInst(t, bin[2*filterInstBytes:], 2, fieldTCP, testEQ, 3, resultReject, 1)
	// Inst 3: IP_SRCADDR == 10.1.2.3 (host-order uint32 = 0x0A010203, arg[1]=0x0000FFFF marker)
	checkInst(t, bin[3*filterInstBytes:], 3, fieldIPSrcAddr, testEQ, 4, resultReject, 0x0A010203)
	checkArg1(t, bin[3*filterInstBytes:], 3, 0x0000FFFF)
	// Inst 4: IP_DSTADDR == 1.2.3.4
	checkInst(t, bin[4*filterInstBytes:], 4, fieldIPDstAddr, testEQ, 5, resultReject, 0x01020304)
	checkArg1(t, bin[4*filterInstBytes:], 4, 0x0000FFFF)
	// Inst 5: TCP_SRCPORT == 54321
	checkInst(t, bin[5*filterInstBytes:], 5, fieldTCPSrcPort, testEQ, 6, resultReject, 54321)
	// Last inst 6: TCP_DSTPORT == 443, success=ACCEPT
	checkInst(t, bin[6*filterInstBytes:], 6, fieldTCPDstPort, testEQ, resultAccept, resultReject, 443)
}

func TestOutboundTCPFilterIPv6(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddrPort("[2001:db8::1]:54321")
	dst := netip.MustParseAddrPort("[2001:db8::2]:443")
	f, err := OutboundTCP(src, dst)
	if err != nil {
		t.Fatal(err)
	}
	bin, flags, err := f.encode()
	if err != nil {
		t.Fatal(err)
	}
	if want := filterFlagOutbound | filterFlagIPv6; flags != want {
		t.Fatalf("flags: got %x, want %x", flags, want)
	}
	// Inst 3: IPv6_SRCADDR. The driver stores the address in reversed
	// word order: arg[0]=low (bytes 12..15)=1, arg[3]=high (bytes 0..3)=0x20010db8.
	off := 3 * filterInstBytes
	a0 := binary.LittleEndian.Uint32(bin[off+8:])
	a1 := binary.LittleEndian.Uint32(bin[off+12:])
	a2 := binary.LittleEndian.Uint32(bin[off+16:])
	a3 := binary.LittleEndian.Uint32(bin[off+20:])
	if a0 != 1 || a1 != 0 || a2 != 0 || a3 != 0x20010db8 {
		t.Fatalf("ipv6 src arg=[%08x %08x %08x %08x], want [1 0 0 0x20010db8]", a0, a1, a2, a3)
	}
}

func TestOutboundTCPFilterMixedFamily(t *testing.T) {
	t.Parallel()
	src := netip.MustParseAddrPort("10.0.0.1:1234")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	if _, err := OutboundTCP(src, dst); err == nil {
		t.Fatal("expected error for mixed families")
	}
}

func checkArg1(t *testing.T, raw []byte, idx int, arg1 uint32) {
	t.Helper()
	got := binary.LittleEndian.Uint32(raw[12:16])
	if got != arg1 {
		t.Errorf("inst %d arg[1]: got %08x, want %08x", idx, got, arg1)
	}
}

func checkInst(t *testing.T, raw []byte, idx int, field uint16, test uint8, success, failure uint16, arg0 uint32) {
	t.Helper()
	word0 := binary.LittleEndian.Uint32(raw[0:4])
	word1 := binary.LittleEndian.Uint32(raw[4:8])
	a0 := binary.LittleEndian.Uint32(raw[8:12])
	gotField := uint16(word0 & 0x7FF)
	gotTest := uint8((word0 >> 11) & 0x1F)
	gotSuccess := uint16(word0 >> 16)
	gotFailure := uint16(word1 & 0xFFFF)
	if gotField != field {
		t.Errorf("inst %d field: got %d, want %d", idx, gotField, field)
	}
	if gotTest != test {
		t.Errorf("inst %d test: got %d, want %d", idx, gotTest, test)
	}
	if gotSuccess != success {
		t.Errorf("inst %d success: got %d, want %d", idx, gotSuccess, success)
	}
	if gotFailure != failure {
		t.Errorf("inst %d failure: got %d, want %d", idx, gotFailure, failure)
	}
	if a0 != arg0 {
		t.Errorf("inst %d arg[0]: got %08x, want %08x", idx, a0, arg0)
	}
}

// TestInboundICMPTimeExceededFilterSemantics pins the owned quoted-ICMP capture
// filter: inbound time-exceeded errors of the owned local address only. PMTU /
// parameter-problem messages, foreign destinations and outbound packets never
// match, so the filter can never widen into a global ICMP capture.
func TestInboundICMPTimeExceededFilterSemantics(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.10")
	filter, err := InboundICMPTimeExceeded([]netip.Addr{local})
	if err != nil {
		t.Fatal(err)
	}
	if filter.flags&filterFlagInbound == 0 || filter.flags&filterFlagIP == 0 {
		t.Fatalf("filter flags = %#x", filter.flags)
	}
	addressOf := func(addr netip.Addr) uint32 {
		bytes := addr.As4()
		return binary.BigEndian.Uint32(bytes[:])
	}
	address := addressOf(local)
	owned := filterFacts{fieldInbound: 1, fieldIP: 1, fieldICMP: 1, fieldICMPType: 11, fieldIPDstAddr: address}
	if !evaluateFilter(t, filter, owned) {
		t.Fatal("owned inbound time-exceeded must match")
	}
	pmtu := filterFacts{fieldInbound: 1, fieldIP: 1, fieldICMP: 1, fieldICMPType: 3, fieldIPDstAddr: address}
	if evaluateFilter(t, filter, pmtu) {
		t.Fatal("PMTU/parameter-problem message matched the time-exceeded filter")
	}
	unreachable := filterFacts{fieldInbound: 1, fieldIP: 1, fieldICMP: 1, fieldICMPType: 11,
		fieldIPDstAddr: addressOf(netip.MustParseAddr("192.0.2.11"))}
	if evaluateFilter(t, filter, unreachable) {
		t.Fatal("foreign destination matched the owned filter")
	}
	outbound := filterFacts{fieldOutbound: 1, fieldIP: 1, fieldICMP: 1, fieldICMPType: 11, fieldIPDstAddr: address}
	if evaluateFilter(t, filter, outbound) {
		t.Fatal("outbound packet matched the inbound ICMP filter")
	}

	ipv6Filter, err := InboundICMPTimeExceededFamily(true)
	if err != nil {
		t.Fatal(err)
	}
	owned6 := filterFacts{fieldInbound: 1, fieldIPv6: 1, fieldICMPv6: 1, fieldICMPv6Type: 3}
	if !evaluateFilter(t, ipv6Filter, owned6) {
		t.Fatal("owned ICMPv6 time-exceeded must match")
	}
	parameterProblem6 := filterFacts{fieldInbound: 1, fieldIPv6: 1, fieldICMPv6: 1, fieldICMPv6Type: 4}
	if evaluateFilter(t, ipv6Filter, parameterProblem6) {
		t.Fatal("ICMPv6 parameter problem matched the time-exceeded filter")
	}
	// The interface narrowing composes with the family variant.
	interfaceFilter, err := InterfaceIndex(7, 0)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := And(ipv6Filter, interfaceFilter)
	if err != nil {
		t.Fatal(err)
	}
	onInterface := filterFacts{fieldInbound: 1, fieldIPv6: 1, fieldICMPv6: 1, fieldICMPv6Type: 3, fieldIfIdx: 7}
	if !evaluateFilter(t, scoped, onInterface) {
		t.Fatal("owned interface time-exceeded must match")
	}
	otherInterface := filterFacts{fieldInbound: 1, fieldIPv6: 1, fieldICMPv6: 1, fieldICMPv6Type: 3, fieldIfIdx: 8}
	if evaluateFilter(t, scoped, otherInterface) {
		t.Fatal("foreign interface matched the owned ICMP filter")
	}
}

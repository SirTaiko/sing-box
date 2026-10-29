package desync

// W1 regressions for the desync-side mapping: the owned envelope builder turns
// an Endpoint into the authoritative kernel filter for one direction. The
// filter semantics themselves are covered in common/windivert; this file pins
// the mapping (family, transport, direction, local port, peer, interface) and
// the shared-builder property of the plain and configured capture paths.

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/windivert"
)

func envelopeEndpoint(t *testing.T, local, peer string, family Family, transport Transport, index uint32) Endpoint {
	t.Helper()
	return Endpoint{
		Family:         family,
		Transport:      transport,
		Source:         mustEndpointAddrPort(t, local),
		Destination:    mustEndpointAddrPort(t, peer),
		InterfaceIndex: index,
	}
}

func mustEndpointAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	parsed, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func matchOwnedEnvelope(t *testing.T, filter *windivert.Filter, facts windivert.FilterFacts) bool {
	t.Helper()
	matched, err := filter.Match(facts)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return matched
}

func TestOwnedWindowsEnvelopeWildcardDefaultBind(t *testing.T) {
	endpoint := envelopeEndpoint(t, "0.0.0.0:53111", "162.159.135.232:443", FamilyIPv4, TransportTCP, 6)
	outbound, err := ownedWindowsEnvelope(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	inbound, err := ownedWindowsEnvelope(endpoint, false)
	if err != nil {
		t.Fatal(err)
	}
	outFacts := windivert.FilterFacts{
		Outbound: true, IPv4: true, TCP: true,
		SrcAddr: netip.MustParseAddr("192.168.31.240"),
		DstAddr: netip.MustParseAddr("162.159.135.232"),
		SrcPort: 53111, DstPort: 443, IfIdx: 6,
	}
	if !matchOwnedEnvelope(t, outbound, outFacts) {
		t.Fatal("outbound envelope missed the default no-bind flow")
	}
	if matchOwnedEnvelope(t, inbound, outFacts) {
		t.Fatal("inbound envelope matched an outbound packet")
	}
	inFacts := windivert.FilterFacts{
		Inbound: true, IPv4: true, TCP: true,
		SrcAddr: netip.MustParseAddr("162.159.135.232"),
		DstAddr: netip.MustParseAddr("192.168.31.240"),
		SrcPort: 443, DstPort: 53111, IfIdx: 6,
	}
	if !matchOwnedEnvelope(t, inbound, inFacts) {
		t.Fatal("inbound envelope missed the reverse tuple")
	}
	// The owned interface fact stays part of both directions.
	foreign := inFacts
	foreign.IfIdx = 9
	if matchOwnedEnvelope(t, inbound, foreign) {
		t.Fatal("inbound envelope dropped the owned interface restriction")
	}
}

func TestOwnedWindowsEnvelopeConfiguredConcreteBind(t *testing.T) {
	endpoint := envelopeEndpoint(t, "192.168.31.240:53111", "162.159.135.232:443", FamilyIPv4, TransportTCP, 0)
	filter, err := ownedWindowsEnvelope(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	facts := windivert.FilterFacts{
		Outbound: true, IPv4: true, TCP: true,
		SrcAddr: netip.MustParseAddr("192.168.31.240"),
		DstAddr: netip.MustParseAddr("162.159.135.232"),
		SrcPort: 53111, DstPort: 443,
	}
	if !matchOwnedEnvelope(t, filter, facts) {
		t.Fatal("concrete envelope missed its own flow")
	}
	other := facts
	other.SrcAddr = netip.MustParseAddr("192.168.31.241")
	if matchOwnedEnvelope(t, filter, other) {
		t.Fatal("concrete envelope accepted another local address")
	}
}

func TestOwnedWindowsEnvelopeUDPAndIPv6(t *testing.T) {
	udp := envelopeEndpoint(t, "0.0.0.0:53000", "162.159.135.232:443", FamilyIPv4, TransportUDP, 0)
	filter, err := ownedWindowsEnvelope(udp, true)
	if err != nil {
		t.Fatal(err)
	}
	facts := windivert.FilterFacts{
		Outbound: true, IPv4: true, UDP: true,
		SrcAddr: netip.MustParseAddr("192.168.31.240"),
		DstAddr: netip.MustParseAddr("162.159.135.232"),
		SrcPort: 53000, DstPort: 443,
	}
	if !matchOwnedEnvelope(t, filter, facts) {
		t.Fatal("UDP envelope missed the owned flow")
	}
	asTCP := facts
	asTCP.UDP, asTCP.TCP = false, true
	if matchOwnedEnvelope(t, filter, asTCP) {
		t.Fatal("UDP envelope matched a TCP packet")
	}

	v6 := envelopeEndpoint(t, "[::]:53001", "[2001:db8::443]:443", FamilyIPv6, TransportUDP, 0)
	v6Filter, err := ownedWindowsEnvelope(v6, true)
	if err != nil {
		t.Fatal(err)
	}
	v6Facts := windivert.FilterFacts{
		Outbound: true, IPv6: true, UDP: true,
		SrcAddr: netip.MustParseAddr("2001:db8::1"),
		DstAddr: netip.MustParseAddr("2001:db8::443"),
		SrcPort: 53001, DstPort: 443,
	}
	if !matchOwnedEnvelope(t, v6Filter, v6Facts) {
		t.Fatal("IPv6 wildcard UDP envelope missed the owned flow")
	}
}

func TestOwnedWindowsEnvelopeSharedBuilder(t *testing.T) {
	// The plain path and the configured path must produce byte-identical
	// filters for the same endpoint and direction; that is what keeps the two
	// capture paths from drifting apart.
	endpoint := envelopeEndpoint(t, "0.0.0.0:53111", "162.159.135.232:443", FamilyIPv4, TransportTCP, 0)
	plain, err := windowsFilter(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ownedWindowsEnvelope(endpoint, true)
	if err != nil {
		t.Fatal(err)
	}
	if plain.Expression() != shared.Expression() {
		t.Fatalf("plain path filter %q differs from the shared builder %q", plain.Expression(), shared.Expression())
	}
}

func TestOwnedWindowsEnvelopeRejectsUnboundedOwnership(t *testing.T) {
	cases := []struct {
		name     string
		endpoint Endpoint
		outbound bool
	}{
		{"no local port", envelopeEndpoint(t, "0.0.0.0:0", "1.2.3.4:443", FamilyIPv4, TransportTCP, 0), true},
		{"inbound listener without peer", Endpoint{Family: FamilyIPv4, Transport: TransportTCP, Source: netip.MustParseAddrPort("0.0.0.0:8080")}, false},
		{"unsupported transport", Endpoint{Family: FamilyIPv4, Source: netip.MustParseAddrPort("0.0.0.0:8080")}, true},
		{"bound address family mismatch", envelopeEndpoint(t, "192.168.1.1:1000", "[2001:db8::1]:443", FamilyIPv6, TransportTCP, 0), true},
	}
	for _, testCase := range cases {
		if _, err := ownedWindowsEnvelope(testCase.endpoint, testCase.outbound); err == nil {
			t.Fatalf("%s: unbounded envelope accepted", testCase.name)
		}
	}
}

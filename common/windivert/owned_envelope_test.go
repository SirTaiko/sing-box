package windivert

// W1 regressions: the owned capture envelope is evaluated against packet facts
// with the driver's decision-tree model. The wildcard (no-bind) case must match
// the real routed flow while a concrete local address stays an equality, and a
// user expression OR-ed into the envelope must never escape it.

import (
	"net/netip"
	"strings"
	"testing"
)

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	parsed, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	parsed, err := netip.ParseAddr(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func matchEnvelope(t *testing.T, filter *Filter, facts FilterFacts) bool {
	t.Helper()
	matched, err := filter.Match(facts)
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	return matched
}

// wildcardOutboundFacts is one real IPv4 flow whose local address is the routed
// interface address, not the unspecified address the socket was bound to.
func wildcardOutboundFacts(t *testing.T) FilterFacts {
	t.Helper()
	return FilterFacts{
		Outbound: true,
		IPv4:     true,
		TCP:      true,
		SrcAddr:  mustAddr(t, "192.168.31.240"),
		DstAddr:  mustAddr(t, "162.159.135.232"),
		SrcPort:  53111,
		DstPort:  443,
	}
}

func TestOwnedFlowEnvelopeWildcardIPv4TCP(t *testing.T) {
	peer := mustAddrPort(t, "162.159.135.232:443")
	filter, err := OwnedFlowEnvelope(OwnedFlow{
		TCP: true, Outbound: true,
		Local: mustAddrPort(t, "0.0.0.0:53111"),
		Peer:  peer,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := wildcardOutboundFacts(t)
	if !matchEnvelope(t, filter, base) {
		t.Fatal("wildcard envelope did not match the real routed flow")
	}
	if strings.Contains(filter.Expression(), "0.0.0.0") {
		t.Fatalf("wildcard envelope encodes the unspecified address: %s", filter.Expression())
	}

	negative := []struct {
		name   string
		mutate func(*FilterFacts)
	}{
		{"wrong local port", func(f *FilterFacts) { f.SrcPort = 53112 }},
		{"wrong peer port", func(f *FilterFacts) { f.DstPort = 8443 }},
		{"wrong peer address", func(f *FilterFacts) { f.DstAddr = mustAddr(t, "1.1.1.1") }},
		{"wrong protocol", func(f *FilterFacts) { f.TCP, f.UDP = false, true }},
		{"wrong direction", func(f *FilterFacts) { f.Outbound, f.Inbound = false, true }},
		{"wrong family", func(f *FilterFacts) {
			f.IPv4, f.IPv6 = false, true
			f.SrcAddr = mustAddr(t, "2001:db8::1")
			f.DstAddr = mustAddr(t, "2001:db8::2")
		}},
	}
	for _, testCase := range negative {
		facts := base
		testCase.mutate(&facts)
		if matchEnvelope(t, filter, facts) {
			t.Fatalf("%s: wildcard envelope matched a foreign packet", testCase.name)
		}
	}

	// The unspecified address itself is not a magic match: the filter must not
	// require the packet source to be 0.0.0.0 either. Both a real address and
	// an unspecified one satisfy the (omitted) local-address dimension, and the
	// remaining tuple facts are what decide.
	unspecified := base
	unspecified.SrcAddr = mustAddr(t, "0.0.0.0")
	if !matchEnvelope(t, filter, unspecified) {
		t.Fatal("wildcard envelope must not constrain the local address at all")
	}
}

func TestOwnedFlowEnvelopeConcreteLocalIPv4(t *testing.T) {
	filter, err := OwnedFlowEnvelope(OwnedFlow{
		TCP: true, Outbound: true,
		Local: mustAddrPort(t, "192.168.31.240:53111"),
		Peer:  mustAddrPort(t, "162.159.135.232:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !matchEnvelope(t, filter, wildcardOutboundFacts(t)) {
		t.Fatal("concrete envelope did not match its own flow")
	}
	other := wildcardOutboundFacts(t)
	other.SrcAddr = mustAddr(t, "192.168.31.241")
	if matchEnvelope(t, filter, other) {
		t.Fatal("concrete envelope accepted another local address")
	}
}

func TestOwnedFlowEnvelopeWildcardIPv6(t *testing.T) {
	filter, err := OwnedFlowEnvelope(OwnedFlow{
		IPv6: true, TCP: true, Outbound: true,
		Local: mustAddrPort(t, "[::]:53111"),
		Peer:  mustAddrPort(t, "[2001:db8::443]:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := FilterFacts{
		Outbound: true, IPv6: true, TCP: true,
		SrcAddr: mustAddr(t, "2001:db8::1"),
		DstAddr: mustAddr(t, "2001:db8::443"),
		SrcPort: 53111, DstPort: 443,
	}
	if !matchEnvelope(t, filter, facts) {
		t.Fatal("IPv6 wildcard envelope did not match")
	}
	wrongPort := facts
	wrongPort.SrcPort = 1
	if matchEnvelope(t, filter, wrongPort) {
		t.Fatal("IPv6 wildcard envelope matched a foreign local port")
	}
	wrongPeer := facts
	wrongPeer.DstAddr = mustAddr(t, "2001:db8::444")
	if matchEnvelope(t, filter, wrongPeer) {
		t.Fatal("IPv6 wildcard envelope matched a foreign peer")
	}
	v4 := facts
	v4.IPv6, v4.IPv4 = false, true
	v4.SrcAddr, v4.DstAddr = mustAddr(t, "192.0.2.1"), mustAddr(t, "192.0.2.2")
	if matchEnvelope(t, filter, v4) {
		t.Fatal("IPv6 wildcard envelope matched an IPv4 packet")
	}
}

func TestOwnedFlowEnvelopeListenerAndInterface(t *testing.T) {
	// A TCP listener has no peer yet: the envelope is an outbound-only
	// local-port scope, narrowed by the owned interface when available.
	filter, err := OwnedFlowEnvelope(OwnedFlow{
		TCP: true, Outbound: true,
		Local:          mustAddrPort(t, "0.0.0.0:8080"),
		InterfaceIndex: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := FilterFacts{
		Outbound: true, IPv4: true, TCP: true,
		SrcAddr: mustAddr(t, "192.168.31.240"),
		DstAddr: mustAddr(t, "203.0.113.9"),
		SrcPort: 8080, DstPort: 51515, IfIdx: 6,
	}
	if !matchEnvelope(t, filter, facts) {
		t.Fatal("listener envelope did not match an outbound packet of the owned port")
	}
	wrongPort := facts
	wrongPort.SrcPort = 8081
	if matchEnvelope(t, filter, wrongPort) {
		t.Fatal("listener envelope matched a foreign local port")
	}
	wrongInterface := facts
	wrongInterface.IfIdx = 7
	if matchEnvelope(t, filter, wrongInterface) {
		t.Fatal("listener envelope matched a foreign interface")
	}
	inbound := facts
	inbound.Outbound, inbound.Inbound = false, true
	if matchEnvelope(t, filter, inbound) {
		t.Fatal("outbound listener envelope matched an inbound packet")
	}
}

func TestOwnedFlowEnvelopeInboundReverseTuple(t *testing.T) {
	filter, err := OwnedFlowEnvelope(OwnedFlow{
		TCP: true, Outbound: false,
		Local: mustAddrPort(t, "0.0.0.0:53111"),
		Peer:  mustAddrPort(t, "162.159.135.232:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	facts := FilterFacts{
		Inbound: true, IPv4: true, TCP: true,
		SrcAddr: mustAddr(t, "162.159.135.232"),
		DstAddr: mustAddr(t, "192.168.31.240"),
		SrcPort: 443, DstPort: 53111,
	}
	if !matchEnvelope(t, filter, facts) {
		t.Fatal("inbound wildcard envelope did not match the reverse tuple")
	}
	// The reverse direction must never widen into the outbound direction.
	outbound := facts
	outbound.Inbound, outbound.Outbound = false, true
	if matchEnvelope(t, filter, outbound) {
		t.Fatal("inbound envelope matched an outbound packet")
	}
	wrongPeer := facts
	wrongPeer.SrcAddr = mustAddr(t, "1.1.1.1")
	if matchEnvelope(t, filter, wrongPeer) {
		t.Fatal("inbound envelope matched a foreign peer")
	}
}

func TestOwnedFlowEnvelopeRejectsIncompleteOwnership(t *testing.T) {
	cases := []struct {
		name string
		flow OwnedFlow
	}{
		{"zero local port", OwnedFlow{TCP: true, Outbound: true, Local: mustAddrPort(t, "0.0.0.0:0")}},
		{"invalid local", OwnedFlow{TCP: true, Outbound: true, Local: netip.AddrPort{}}},
		{"inbound without peer", OwnedFlow{TCP: true, Outbound: false, Local: mustAddrPort(t, "0.0.0.0:53111")}},
		{"peer without port", OwnedFlow{TCP: true, Outbound: true, Local: mustAddrPort(t, "0.0.0.0:53111"), Peer: netip.AddrPortFrom(mustAddr(t, "1.1.1.1"), 0)}},
		{"local family mismatch", OwnedFlow{IPv6: true, TCP: true, Outbound: true, Local: mustAddrPort(t, "192.168.1.1:53111")}},
		{"peer family mismatch", OwnedFlow{IPv6: false, TCP: true, Outbound: true, Local: mustAddrPort(t, "0.0.0.0:53111"), Peer: mustAddrPort(t, "[2001:db8::1]:443")}},
	}
	for _, testCase := range cases {
		if _, err := OwnedFlowEnvelope(testCase.flow); err == nil {
			t.Fatalf("%s: accepted", testCase.name)
		}
	}
}

// TestOwnedEnvelopeUserExpressionCannotEscape proves the AND composition the
// configured capture path uses: a user `or` stays inside its own parentheses and
// cannot re-open a direction, peer or port the envelope already fixed.
func TestOwnedEnvelopeUserExpressionCannotEscape(t *testing.T) {
	envelope, err := OwnedFlowEnvelope(OwnedFlow{
		TCP: true, Outbound: true,
		Local: mustAddrPort(t, "0.0.0.0:53111"),
		Peer:  mustAddrPort(t, "162.159.135.232:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := ParseFilter("(tcp.DstPort == 8443 or ip.SrcAddr == 203.0.113.9)")
	if err != nil {
		t.Fatal(err)
	}
	combined, err := And(envelope, user)
	if err != nil {
		t.Fatal(err)
	}
	base := wildcardOutboundFacts(t)
	if matchEnvelope(t, combined, base) {
		t.Fatal("combined filter matched a flow the user expression excludes")
	}
	// The user's own branch alone must not satisfy the combined filter when the
	// envelope's tuple is wrong.
	escaped := base
	escaped.SrcPort = 1
	escaped.SrcAddr = mustAddr(t, "203.0.113.9")
	if matchEnvelope(t, combined, escaped) {
		t.Fatal("a user expression branch escaped the owned envelope")
	}
	// A flow that satisfies both the envelope and the user expression matches.
	both := base
	both.DstPort = 8443
	if matchEnvelope(t, combined, both) {
		t.Fatal("combined filter matched although the envelope fixes port 443")
	}
	negativeControl := base
	negativeControl.DstPort = 8443
	peerWide, err := OwnedFlowEnvelope(OwnedFlow{TCP: true, Outbound: true, Local: mustAddrPort(t, "0.0.0.0:53111")})
	if err != nil {
		t.Fatal(err)
	}
	peerWideCombined, err := And(peerWide, user)
	if err != nil {
		t.Fatal(err)
	}
	if !matchEnvelope(t, peerWideCombined, negativeControl) {
		t.Fatal("positive control: a user port branch with an unconstrained peer must match")
	}
}

// TestLegacyExactAddressFilterMissesWildcardFlow is the targeted regression
// mutant for the original defect: the pre-repair exact-address helper, given the
// unspecified local address the socket was bound to, cannot match the real
// routed flow. The owned envelope matches the same facts.
func TestLegacyExactAddressFilterMissesWildcardFlow(t *testing.T) {
	legacy, err := OutboundTCP(mustAddrPort(t, "0.0.0.0:53111"), mustAddrPort(t, "162.159.135.232:443"))
	if err != nil {
		t.Fatal(err)
	}
	if matchEnvelope(t, legacy, wildcardOutboundFacts(t)) {
		t.Fatal("the legacy exact-address filter unexpectedly matched the wildcard flow")
	}
	repaired, err := OwnedFlowEnvelope(OwnedFlow{
		TCP: true, Outbound: true,
		Local: mustAddrPort(t, "0.0.0.0:53111"),
		Peer:  mustAddrPort(t, "162.159.135.232:443"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !matchEnvelope(t, repaired, wildcardOutboundFacts(t)) {
		t.Fatal("the repaired owned envelope did not match the wildcard flow")
	}
	if legacy.InstructionCount() <= 0 || repaired.InstructionCount() <= 0 {
		t.Fatal("both filters must compile to instructions")
	}
}

package desync

// O2-B regressions: a cold packet-mode flow must apply the ordered
// host-scoped rule to the FIRST eligible L7 message instead of keeping the
// provisional host-less selection made on the SYN/datagram.
//
// Source: nfq/desync.c re-runs dp_find() when the L7 protocol or hostname is
// revealed ("desync profile changed by revealed l7 protocol or hostname !")
// and passes the original when no profile matches (reasm_orig_cancel +
// send_orig). The limiter latches keep their OR semantics and the zero stage is
// not replayed. No test here sets ip_cache.hostname: the cold cache is the
// shipping default and must not be a prerequisite.

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	o2bHostMarker    = []byte("HOSTRULE")
	o2bGenericMarker = []byte("GENERICRULE")
)

func o2bHex(marker []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(marker)*2)
	for _, value := range marker {
		out = append(out, digits[value>>4], digits[value&0x0f])
	}
	return string(out)
}

// o2bPatternFile writes an overlap pattern file and returns it as a JSON string
// literal. seqovl_pattern is a file path in the product schema, exactly like
// the upstream --dpi-desync-split-seqovl-pattern argument.
func o2bPatternFile(t *testing.T, marker []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seqovl_pattern.bin")
	if err := os.WriteFile(path, marker, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// o2bLease starts one attempt for the given transport with production defaults.
func o2bLease(t *testing.T, config *Config, transport Transport) *Lease {
	t.Helper()
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: transport,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close(nil) })
	return lease
}

// o2bCapture records every injected replacement packet.
type o2bCapture struct {
	packets [][]byte
}

func (c *o2bCapture) inject(raw []byte) error {
	c.packets = append(c.packets, append([]byte(nil), raw...))
	return nil
}

func (c *o2bCapture) containing(marker []byte) int {
	count := 0
	for _, raw := range c.packets {
		if bytes.Contains(raw, marker) {
			count++
		}
	}
	return count
}

func o2bConfig(t *testing.T, body string) *Config {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,`+body+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if config.IPCache.hostnameEnabled {
		t.Fatal("O2-B regressions must run with the shipping default ip_cache.hostname=false")
	}
	return config
}

// TestO2BColdFlowAppliesHostRuleToFirstClientHello is the primary O2-B
// regression: SYN-time selection can only see the generic rule, and the first
// ClientHello must re-select the earlier host-scoped rule in place. The
// candidate wire for QA profile 03 emitted the 661-byte generic fake here.
func TestO2BColdFlowAppliesHostRuleToFirstClientHello(t *testing.T) {
	config := o2bConfig(t, `"rules":[
		{"name":"host","network":["tcp"],"port":[443],"domain":["www.youtube.com"],
		 "methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bHostMarker)+`"}]}},
		{"name":"generic","network":["tcp"],"port":[443],
		 "methods":["fake"],"fake":{"repeats":5,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bGenericMarker)+`"}]}}]`)
	lease := o2bLease(t, config, TransportTCP)
	capture := &o2bCapture{}
	// The cold SYN can only satisfy the generic rule.
	if verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	if len(capture.packets) != 0 {
		t.Fatalf("SYN must not emit a first-stage fake: %d packets", len(capture.packets))
	}
	hello := buildClientHello("www.youtube.com")
	if verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 101, tcpFlagACK|tcpFlagPSH).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("ClientHello verdict = %d", verdict)
	}
	if got := capture.containing(o2bHostMarker); got != 2 {
		t.Fatalf("host-rule fake injections = %d, want the configured 2 (packets=%d)", got, len(capture.packets))
	}
	if got := capture.containing(o2bGenericMarker); got != 0 {
		t.Fatalf("generic-rule fake injections = %d, want 0 after the host rule wins", got)
	}
}

// TestO2BUnmatchedHostDoesNotFallBackToTheProvisionalRule proves the demote
// path is not a fallback latch: a host that satisfies no rule passes the
// first message unchanged, exactly like upstream's reasm_orig_cancel.
func TestO2BUnmatchedHostDoesNotFallBackToTheProvisionalRule(t *testing.T) {
	config := o2bConfig(t, `"rules":[
		{"name":"host","network":["tcp"],"port":[443],"domain":["www.youtube.com"],
		 "methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bHostMarker)+`"}]}},
		{"name":"generic","network":["tcp"],"port":[443],"domain_exclude":["unrelated.example"],
		 "methods":["fake"],"fake":{"repeats":5,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bGenericMarker)+`"}]}}]`)
	lease := o2bLease(t, config, TransportTCP)
	capture := &o2bCapture{}
	if verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	// The generic rule still covers hosts no earlier rule claims.
	listed := buildClientHello("other.example")
	if verdict := lease.HandlePacket(buildIPv4TCP(t, listed, 101, tcpFlagACK|tcpFlagPSH).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	if got := capture.containing(o2bGenericMarker); got != 5 {
		t.Fatalf("generic injections = %d, want 5 for an unlisted host", got)
	}
	if got := capture.containing(o2bHostMarker); got != 0 {
		t.Fatalf("host injections = %d, want 0", got)
	}
}

// TestO2BProtocolDiscoveryReselectsWithoutHost covers the L7-protocol half of
// the upstream trigger: a TLS-only rule ahead of a generic rule must win as
// soon as the message is recognized, even with no SNI in it.
func TestO2BProtocolDiscoveryReselectsWithoutHost(t *testing.T) {
	config := o2bConfig(t, `"rules":[
		{"name":"tls","network":["tcp"],"port":[443],"protocol":["tls"],
		 "methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bHostMarker)+`"}]}},
		{"name":"generic","network":["tcp"],"port":[443],"any_protocol":true,
		 "methods":["fake"],"fake":{"repeats":4,"payloads":[{"protocol":"unknown","hex":"`+o2bHex(o2bGenericMarker)+`"}]}}]`)
	lease := o2bLease(t, config, TransportTCP)
	capture := &o2bCapture{}
	if verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	// A ClientHello without SNI still reveals the TLS protocol.
	hello := buildClientHello("")
	if verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 101, tcpFlagACK|tcpFlagPSH).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	if got := capture.containing(o2bHostMarker); got != 1 {
		t.Fatalf("protocol-rule injections = %d, want 1", got)
	}
	if got := capture.containing(o2bGenericMarker); got != 0 {
		t.Fatalf("generic injections = %d, want 0", got)
	}
}

// TestO2BFragmentedClientHelloReselectsHeldOriginals covers the fragmented L7
// case through the existing bounded hold: the provisional rule cannot plan the
// message, and the completed ClientHello is planned once with the host rule.
func TestO2BFragmentedClientHelloReselectsHeldOriginals(t *testing.T) {
	config := o2bConfig(t, `"rules":[
		{"name":"host","network":["tcp"],"port":[443],"domain":["www.youtube.com"],
		 "methods":["multisplit"],"multisplit":{"split_pos":["1"],"seqovl":600,
		 "seqovl_pattern":`+o2bPatternFile(t, o2bHostMarker)+`}},
		{"name":"generic","network":["tcp"],"port":[443],
		 "methods":["multisplit"],"multisplit":{"split_pos":["1"],"seqovl":400,
		 "seqovl_pattern":`+o2bPatternFile(t, o2bGenericMarker)+`}}]`)
	lease := o2bLease(t, config, TransportTCP)
	capture := &o2bCapture{}
	completed := 0
	complete := func(verdict Verdict, reason string, modified []byte) { completed++ }
	if verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw,
		DirectionOutbound, capture.inject, complete); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	hello := buildClientHello("www.youtube.com")
	split := len(hello) / 2
	first := buildIPv4TCP(t, hello[:split], 101, tcpFlagACK|tcpFlagPSH)
	if verdict := lease.HandlePacket(first.Raw, DirectionOutbound, capture.inject, complete); verdict != VerdictHold {
		t.Fatalf("incomplete ClientHello verdict = %d, want hold", verdict)
	}
	second := buildIPv4TCP(t, hello[split:], uint32(101+split), tcpFlagACK|tcpFlagPSH)
	if verdict := lease.HandlePacket(second.Raw, DirectionOutbound, capture.inject, complete); verdict != VerdictPass {
		t.Fatalf("completed ClientHello verdict = %d", verdict)
	}
	if completed != 1 {
		t.Fatalf("held originals released = %d, want exactly 1", completed)
	}
	if got := capture.containing(o2bHostMarker); got == 0 {
		t.Fatalf("the host rule's seqovl pattern must reach the wire (packets=%d)", len(capture.packets))
	}
	if got := capture.containing(o2bGenericMarker); got != 0 {
		t.Fatalf("generic seqovl pattern injected %d times, want 0", got)
	}
}

// TestO2BZeroStageIsNotReplayedAcrossRuleChange pins the ownership of the SYN
// stage: the provisional rule's zero stage runs once on the SYN and is never
// re-executed when the host rule takes over on the first message.
func TestO2BZeroStageIsNotReplayedAcrossRuleChange(t *testing.T) {
	config := o2bConfig(t, `"rules":[
		{"name":"host","network":["tcp"],"port":[443],"domain":["www.youtube.com"],
		 "methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bHostMarker)+`"}]}},
		{"name":"generic","network":["tcp"],"port":[443],
		 "methods":["synack","fake"],"fake":{"repeats":3,"payloads":[{"protocol":"tls","hex":"`+o2bHex(o2bGenericMarker)+`"}]}}]`)
	lease := o2bLease(t, config, TransportTCP)
	capture := &o2bCapture{}
	if verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	if len(capture.packets) != 1 {
		t.Fatalf("zero-stage packets = %d, want 1", len(capture.packets))
	}
	if zero, err := ParsePacket(capture.packets[0]); err != nil {
		t.Fatal(err)
	} else if zero.TCPFlags&(tcpFlagSYN|tcpFlagACK) != tcpFlagSYN|tcpFlagACK {
		t.Fatalf("zero stage did not emit the SYN|ACK packet: flags=%#x", zero.TCPFlags)
	}
	hello := buildClientHello("www.youtube.com")
	if verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 101, tcpFlagACK|tcpFlagPSH).Raw,
		DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	for index, raw := range capture.packets[1:] {
		packet, err := ParsePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		if packet.TCPFlags&tcpFlagSYN != 0 {
			t.Fatalf("packet %d repeats the zero stage after the rule change: flags=%#x", index+1, packet.TCPFlags)
		}
	}
	if got := capture.containing(o2bGenericMarker); got != 0 {
		t.Fatalf("provisional-rule first stage injected %d packets, want 0", got)
	}
	if got := capture.containing(o2bHostMarker); got != 2 {
		t.Fatalf("host-rule first stage injected %d packets, want 2", got)
	}
}

// TestO2BExplicitEmptyIPFileImposesNoPositiveRestriction pins the conversion-side
// invariant the QA profiles rely on: `--ipset=<empty file>` in the reference
// imposes no positive restriction. Pinned zapret v72.9 nfq/ipset.c:221-232 says
// "old behavior compat: all include lists are empty means check passes" and
// checks exclusions first. The schema expresses the same source as
// ip_cidr_file, so an all-empty positive IP union must not reject a
// destination, while a nonempty union keeps its exact OR membership/family
// semantics. An earlier revision of this test asserted the opposite; the
// QA500 captured-IP replay and the native reference debug log are the measured
// evidence for the correction.
func TestO2BExplicitEmptyIPFileImposesNoPositiveRestriction(t *testing.T) {
	directory := t.TempDir()
	empty := filepath.Join(directory, "ipset-all.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	nonEmpty := filepath.Join(directory, "ipset-some.txt")
	if err := os.WriteFile(nonEmpty, []byte("203.0.113.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	compile := func(name string, lists ...string) *Rule {
		t.Helper()
		encoded := make([]string, 0, len(lists))
		for _, list := range lists {
			encoded = append(encoded, jsonPath(t, list))
		}
		config, err := Compile(enabledOption(`{"enabled":true,"rules":[
			{"name":"bound","network":["tcp"],"port":[443],"ip_cidr_file":[`+strings.Join(encoded, ",")+`],
			 "methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"tls","hex":"16030100"}]}}]}`), directory)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return config.Rules[0]
	}
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Port: 443, Protocol: ProtocolTLS}
	inside := facts
	inside.Destination = netip.MustParseAddr("203.0.113.9")
	outside := facts
	outside.Destination = netip.MustParseAddr("198.51.100.7")
	ipv6 := facts
	ipv6.Family = FamilyIPv6
	ipv6.Destination = netip.MustParseAddr("2001:db8::7")

	if rule := compile("empty", empty); !rule.Matches(inside) || !rule.Matches(outside) ||
		!rule.Matches(ipv6) {
		t.Fatal("an all-empty positive IP include set must impose no positive-IP restriction")
	}
	rule := compile("non-empty", nonEmpty)
	if !rule.Matches(inside) {
		t.Fatal("a configured prefix must still select its own address")
	}
	if rule.Matches(outside) {
		t.Fatal("a configured prefix must still exclude other addresses")
	}
	if rule.Matches(ipv6) {
		t.Fatal("a configured IPv4-only prefix must not match an IPv6 destination")
	}
	combined := compile("empty+non-empty", empty, nonEmpty)
	if !combined.Matches(inside) {
		t.Fatal("a nonempty include must keep matching alongside an empty one")
	}
	if combined.Matches(outside) {
		t.Fatal("a nonempty include must keep restricting alongside an empty one")
	}
}

// TestO2BSeqOvlPatternFailureIsRejected keeps the split stage honest: a
// configured seqovl_pattern that cannot be read must fail compilation instead
// of silently compiling to a rule without its split object (which would be a
// silent no-op on the wire — the ALT7-style strategy would simply not run).
func TestO2BSeqOvlPatternFailureIsRejected(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.bin")
	encoded, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{"multisplit", "multidisorder"} {
		if _, err = Compile(enabledOption(`{"enabled":true,"rules":[
			{"name":"split","network":["tcp"],"port":[443],
			 "methods":["`+method+`"],"`+method+`":{"split_pos":["1"],"seqovl":679,
			 "seqovl_pattern":`+string(encoded)+`}}]}`), ""); err == nil {
			t.Fatalf("%s with an unreadable seqovl_pattern must be rejected", method)
		}
	}
}

// TestO2BUDPInitialReselectsHostRule is the UDP analogue: a generic rule that
// matched the first Initial must yield to the host-scoped rule once the
// decrypted CRYPTO ClientHello names the host.
func TestO2BUDPInitialReselectsHostRule(t *testing.T) {
	config := o2bConfig(t, `"rules":[
		{"name":"host","network":["udp"],"port":[443],"protocol":["quic"],"domain":["quic.example"],
		 "methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"`+o2bHex(o2bHostMarker)+`"}]}},
		{"name":"generic","network":["udp"],"port":[443],"any_protocol":true,
		 "methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"quic","hex":"`+o2bHex(o2bGenericMarker)+`"}]}}]`)
	lease := o2bLease(t, config, TransportUDP)
	capture := &o2bCapture{}
	dcid := []byte{5, 5, 5, 5, 5, 5, 5, 5}
	// First Initial: a host no rule claims, so the generic rule is provisional.
	other := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{rawQUICClientHello("other.example")}, 240), dcid, 1, 1)
	if verdict := lease.HandlePacket(buildIPv4UDP(t, other, 443).Raw, DirectionOutbound,
		capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	if got := capture.containing(o2bGenericMarker); got != 1 {
		t.Fatalf("provisional generic injections = %d, want 1", got)
	}
	// Second Initial of the same flow: the decrypted SNI must re-select.
	matching := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{rawQUICClientHello("quic.example")}, 240), dcid, 1, 2)
	if verdict := lease.HandlePacket(buildIPv4UDP(t, matching, 443).Raw, DirectionOutbound,
		capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	if got := capture.containing(o2bHostMarker); got != 2 {
		t.Fatalf("host-rule injections = %d, want 2", got)
	}
	if got := capture.containing(o2bGenericMarker); got != 1 {
		t.Fatalf("generic injections = %d, want no repeat after the host rule wins", got)
	}
}

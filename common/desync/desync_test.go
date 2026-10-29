package desync

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func optionDesyncDisabled(enabled bool) option.DirectDesyncOptions {
	return option.DirectDesyncOptions{Enabled: &enabled}
}

func enabledOption(content string) *option.DirectDesyncOptions {
	var options option.DirectDesyncOptions
	err := json.Unmarshal([]byte(content), &options)
	if err != nil {
		panic(err)
	}
	return &options
}

func buildIPv4TCP(t *testing.T, payload []byte, sequence uint32, flags uint8) *Packet {
	t.Helper()
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(52+len(payload)))
	ip[8] = 64
	ip[4], ip[5] = 0x12, 0x34
	ip[9] = 6
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{198, 51, 100, 7})
	binary.BigEndian.PutUint16(ip[10:12], inetChecksum(ip, 0))
	tcp := make([]byte, 32)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	binary.BigEndian.PutUint32(tcp[4:8], sequence)
	binary.BigEndian.PutUint32(tcp[8:12], 2000)
	tcp[12] = 8 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	// NOP,NOP,TIMESTAMP
	tcp[20], tcp[21], tcp[22], tcp[23] = 1, 1, 8, 10
	binary.BigEndian.PutUint32(tcp[24:28], 1111)
	binary.BigEndian.PutUint32(tcp[28:32], 2222)
	raw := append(ip, tcp...)
	raw = append(raw, payload...)
	sum, err := pseudoHeaderSum(raw, &Packet{Family: FamilyIPv4, Transport: TransportTCP}, len(raw)-20)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(raw[36:38], inetChecksum(raw[20:], sum))
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func verifyTCPChecksum(t *testing.T, raw []byte) {
	t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := pseudoHeaderSum(raw, packet, len(raw)-packet.IPHeaderLen)
	if err != nil {
		t.Fatal(err)
	}
	if inetChecksum(raw[packet.IPHeaderLen:], sum) != 0 {
		t.Fatal("invalid TCP checksum in generated packet")
	}
}

func TestBuildTCPModifiesTSValOnly(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("hello"), 1000, tcpFlagACK|tcpFlagPSH)
	sequence := uint32(900)
	mods := TCPMods{Seq: &sequence, TSIncrement: -600000}
	generated, err := BuildTCP(packet, []byte("fake"), mods)
	if err != nil {
		t.Fatal(err)
	}
	verifyTCPChecksum(t, generated)
	parsed, err := ParsePacket(generated)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.TCPSeq != 900 {
		t.Fatalf("sequence = %d", parsed.TCPSeq)
	}
	if string(parsed.Payload) != "fake" {
		t.Fatalf("payload = %q", parsed.Payload)
	}
	expectedTSVal := int32(1111) - 600000
	if got := binary.BigEndian.Uint32(generated[44:48]); got != uint32(expectedTSVal) {
		t.Fatalf("TSval = %d", got)
	}
	if got := binary.BigEndian.Uint32(generated[48:52]); got != 2222 {
		t.Fatalf("TSecr changed to %d", got)
	}
}

func TestBuildTCPFailsWithoutTimestampOption(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("hello"), 1, tcpFlagACK)
	// Rewrite the options to all NOPs (no timestamp).
	for index := 20; index < 32; index++ {
		packet.Raw[index+20] = 1
	}
	packet.Raw = append([]byte(nil), packet.Raw...)
	reparsed, err := ParsePacket(packet.Raw)
	if err != nil {
		t.Fatal(err)
	}
	sequence := uint32(0)
	if _, err = BuildTCP(reparsed, []byte("x"), TCPMods{Seq: &sequence, TSIncrement: -1}); err == nil {
		t.Fatal("expected missing timestamp to be an error")
	}
}

func TestBuildTCPZeroIPID(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("hello"), 1, tcpFlagACK)
	generated, err := BuildTCP(packet, []byte("fake"), TCPMods{IPIDSet: true, IPID: 0})
	if err != nil {
		t.Fatal(err)
	}
	if id := binary.BigEndian.Uint16(generated[4:6]); id != 0 {
		t.Fatalf("IPv4 ID = %d", id)
	}
	if inetChecksum(generated[:20], 0) != 0 {
		t.Fatal("IPv4 header checksum not updated")
	}
}

func TestParseRejectsFragments(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("x"), 1, tcpFlagACK)
	raw := append([]byte(nil), packet.Raw...)
	binary.BigEndian.PutUint16(raw[6:8], 0x2000)
	if _, err := ParsePacket(raw); err == nil {
		t.Fatal("expected fragmented packet to be rejected")
	}
}

func TestMultisplitOverlapOnFirstInterval(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("0123456789ABCDEFGHIJ"), 5000, tcpFlagACK|tcpFlagPSH)
	rule := &Rule{Methods: []Method{{Kind: MethodMultiSplit}},
		MultiSplit: &SplitSpec{Positions: []Position{{Kind: positionAbsolute, Offset: 10}},
			Overlap: 4, OverlapPattern: []byte("WXYZ")}}
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{MessageLength: len(packet.Payload)})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictDrop {
		t.Fatal("split must suppress the original")
	}
	if len(batch.Packets) != 2 {
		t.Fatalf("packets = %d", len(batch.Packets))
	}
	first, err := ParsePacket(batch.Packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Payload) != "WXYZ0123456789" {
		t.Fatalf("first payload = %q", first.Payload)
	}
	if first.TCPSeq != 5000-4 {
		t.Fatalf("first sequence = %d", first.TCPSeq)
	}
	second, err := ParsePacket(batch.Packets[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(second.Payload) != "ABCDEFGHIJ" || second.TCPSeq != 5010 {
		t.Fatalf("second payload=%q seq=%d", second.Payload, second.TCPSeq)
	}
	verifyTCPChecksum(t, batch.Packets[0])
	verifyTCPChecksum(t, batch.Packets[1])
}

func TestMultidisorderOrderAndOverlapOnFirstBoundaryInterval(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("0123456789ABCDEFGHIJ"), 5000, tcpFlagACK|tcpFlagPSH)
	rule := &Rule{Methods: []Method{{Kind: MethodMultiDisorder}},
		MultiDisorder: &SplitSpec{
			Positions: []Position{
				{Kind: positionAbsolute, Offset: 10},
				{Kind: positionAbsolute, Offset: 14},
			},
			Overlap: 4, OverlapPattern: []byte("WXYZ")}}
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{MessageLength: len(packet.Payload)})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 3 {
		t.Fatalf("packets = %d", len(batch.Packets))
	}
	// Descending loop: [14,end), [10,14)+overlap, [0,10).
	last, err := ParsePacket(batch.Packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(last.Payload) != "EFGHIJ" || last.TCPSeq != 5014 {
		t.Fatalf("first transmitted payload=%q seq=%d", last.Payload, last.TCPSeq)
	}
	middle, err := ParsePacket(batch.Packets[1])
	if err != nil {
		t.Fatal(err)
	}
	if string(middle.Payload) != "WXYZABCD" || middle.TCPSeq != 5006 {
		t.Fatalf("middle payload=%q seq=%d", middle.Payload, middle.TCPSeq)
	}
	first, err := ParsePacket(batch.Packets[2])
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Payload) != "0123456789" || first.TCPSeq != 5000 {
		t.Fatalf("final payload=%q seq=%d", first.Payload, first.TCPSeq)
	}
}

func TestMultidisorderCancelsOverlapAtFirstBoundary(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("0123456789"), 100, tcpFlagACK|tcpFlagPSH)
	rule := &Rule{Methods: []Method{{Kind: MethodMultiDisorder}},
		MultiDisorder: &SplitSpec{
			Positions: []Position{
				{Kind: positionAbsolute, Offset: 2},
				{Kind: positionAbsolute, Offset: 5},
			},
			Overlap: 4, OverlapPattern: []byte("ZZZZ")}}
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{MessageLength: len(packet.Payload)})
	if err != nil {
		t.Fatal(err)
	}
	middle, err := ParsePacket(batch.Packets[1])
	if err != nil {
		t.Fatal(err)
	}
	// overlap 4 >= from 2 -> upstream cancels the overlap.
	if string(middle.Payload) != "234" || middle.TCPSeq != 102 {
		t.Fatalf("payload=%q seq=%d", middle.Payload, middle.TCPSeq)
	}
}

func TestFakePayloadMajorRepeatsAndSequence(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("real"), 1000, tcpFlagACK|tcpFlagPSH)
	rule := &Rule{Methods: []Method{{Kind: MethodFake}}, Fake: &FakeSpec{
		Repeats: 2, TSIncrement: -600000, Fooling: Fooling{Timestamp: true},
		Payloads: []Payload{
			{Protocol: ProtocolTLS, Data: []byte("AAAA")},
			{Protocol: ProtocolTLS, Data: []byte("BB")},
		},
	}}
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{MessageLength: 4, HostKnown: true, Protocol: ProtocolTLS})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictPass {
		t.Fatal("fake must keep the original")
	}
	expected := []string{"AAAA", "AAAA", "BB", "BB"}
	if len(batch.Packets) != len(expected) {
		t.Fatalf("packets = %d", len(batch.Packets))
	}
	for index, want := range expected {
		parsed, err := ParsePacket(batch.Packets[index])
		if err != nil {
			t.Fatal(err)
		}
		if string(parsed.Payload) != want {
			t.Fatalf("packet %d payload = %q", index, parsed.Payload)
		}
		if parsed.TCPSeq != 1000 {
			// Upstream sends every fake at the captured packet's sequence
			// (nfq/desync.c:1972 sequence0 = ntohl(th_seq)); the previous
			// expectation 1000-len encoded a fork-local shift that QA417 F-3
			// found on the wire against the pinned reference.
			t.Fatalf("packet %d sequence = %d", index, parsed.TCPSeq)
		}
		verifyTCPChecksum(t, batch.Packets[index])
	}
}

func TestFlowCountersExcludeEmptyACKAndCountRetransmits(t *testing.T) {
	config := &Config{Rules: []*Rule{{Name: "r", Network: TransportMaskTCP, IPv4: true, IPv6: true,
		AnyProtocol: true, Cutoff: Interval{Mode: IntervalPackets, Value: 4}}}}
	flow := newFlowState(defaultLimits(), nil, nil)
	flow.rule = config.Rules[0]
	syn := buildIPv4TCP(t, nil, 100, tcpFlagSYN)
	flow.observe(syn, false)
	ack := buildIPv4TCP(t, nil, 101, tcpFlagACK)
	flow.observe(ack, false)
	if flow.counters.packets != 1 {
		t.Fatalf("empty ACK must not increment n: %d", flow.counters.packets)
	}
	data := buildIPv4TCP(t, []byte("hello"), 101, tcpFlagACK|tcpFlagPSH)
	flow.observe(data, false)
	flow.observe(data, false) // native retransmission
	if flow.counters.packets != 3 {
		t.Fatalf("n = %d", flow.counters.packets)
	}
	if flow.counters.dataPackets != 2 {
		t.Fatalf("d = %d", flow.counters.dataPackets)
	}
	flow.observe(buildIPv4TCP(t, []byte("more"), 106, tcpFlagACK), false)
	if !config.Rules[0].Cutoff.Reached(flow.counters) {
		t.Fatal("cutoff must latch at n>=4")
	}
	// The empty ACK becomes eligible only with the explicit override.
	flow2 := newFlowState(defaultLimits(), nil, nil)
	flow2.observe(ack, true)
	if flow2.counters.packets != 1 {
		t.Fatal("explicit tcp_empty_ack must count empty ACKs")
	}
}

func TestReassemblerDeduplicatesRetransmissions(t *testing.T) {
	reassembler := newReassembler(1024)
	if err := reassembler.Add(100, []byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := reassembler.Add(101, []byte("bc")); err != nil {
		t.Fatal(err)
	}
	if err := reassembler.Add(103, []byte("def")); err != nil {
		t.Fatal(err)
	}
	start, message := reassembler.Contiguous()
	if start != 100 || string(message) != "abcdef" {
		t.Fatalf("start=%d message=%q", start, message)
	}
}

func TestReassemblerBound(t *testing.T) {
	reassembler := newReassembler(4)
	if err := reassembler.Add(1, []byte("12345")); err == nil {
		t.Fatal("expected bounded reassembly error")
	}
}

func TestMatcherDomainPortAndIPSemantics(t *testing.T) {
	rule := &Rule{Network: TransportMaskTCP, IPv4: true, IPv6: true,
		AnyProtocol: true, Ports: []PortRange{{From: 443, To: 443}},
		Domains:        &domainSet{entries: []string{"example.com"}},
		DomainsExclude: &domainSet{entries: []string{"ads.example.com"}},
		IPs:            &ipSet{}, IPsExclude: &ipSet{prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}}
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Port: 443,
		Destination: netip.MustParseAddr("198.51.100.1"), Protocol: ProtocolTLS,
		Host: "www.example.com", HostKnown: true}
	if !rule.Matches(facts) {
		t.Fatal("subdomain must match the parent domain entry")
	}
	excluded := facts
	excluded.Destination = netip.MustParseAddr("203.0.113.9")
	if rule.Matches(excluded) {
		t.Fatal("excluded IP must win")
	}
	badPort := facts
	badPort.Port = 8443
	if rule.Matches(badPort) {
		t.Fatal("port exclusion must apply")
	}
	badHost := facts
	badHost.Host = "ads.example.com"
	if rule.Matches(badHost) {
		t.Fatal("domain exclusion must win")
	}
	unknown := facts
	unknown.HostKnown = false
	if rule.Matches(unknown) {
		t.Fatal("host-filtered rule must not match without a host")
	}
}

func TestIPSetAnyRemovesPositiveRestriction(t *testing.T) {
	rule := &Rule{Network: TransportMaskUDP, IPv4: true, IPv6: true, AnyProtocol: true,
		IPs: &ipSet{any: true}, IPsExclude: &ipSet{prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}
	facts := MatchFacts{Family: FamilyIPv4, Transport: TransportUDP, Destination: netip.MustParseAddr("1.1.1.1"), Port: 443}
	if !rule.Matches(facts) {
		t.Fatal("any must remove the positive IP restriction")
	}
	facts.Destination = netip.MustParseAddr("10.1.1.1")
	if rule.Matches(facts) {
		t.Fatal("exclusion must still apply with any")
	}
}

func TestUDPClassification(t *testing.T) {
	initial := buildQUICInitial()
	discord := make([]byte, 74)
	discord[1] = 1
	discord[3] = 70
	dht := append([]byte("d1:ad2:id20:"), make([]byte, 20)...)
	dht = append(dht, 'e')
	cases := []struct {
		name    string
		payload []byte
		want    Protocol
	}{
		{"stun", []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ProtocolSTUN},
		{"quic-initial", initial, ProtocolQUIC},
		{"wireguard", func() []byte { value := make([]byte, 148); value[0] = 1; return value }(), ProtocolWireGuard},
		{"dht-d1", dht, ProtocolDHT},
		{"discord-ip-discovery", discord, ProtocolDiscord},
		{"unknown", []byte{9, 9, 9, 9}, ProtocolUnknown},
		// Negative controls: approximate shapes must stay unknown.
		{"quic-short-long-header", []byte{0xc3, 0, 0, 0, 1, 0, 0, 0, 0}, ProtocolUnknown},
		{"quic-unknown-version", func() []byte {
			value := buildQUICInitial()
			value[1], value[2], value[3], value[4] = 0xde, 0xad, 0xbe, 0xef
			return value
		}(), ProtocolUnknown},
		{"quic-non-initial-type", func() []byte { value := buildQUICInitial(); value[0] = 0xd0; return value }(), ProtocolUnknown},
		{"discord-wrong-length", discord[:73], ProtocolUnknown},
		{"discord-nonzero-address", func() []byte { value := append([]byte(nil), discord...); value[20] = 1; return value }(), ProtocolUnknown},
		{"dht-wrong-terminator", append(append([]byte("d1:ad2:id20:"), make([]byte, 20)...), 'x'), ProtocolUnknown},
		{"stun-bad-length", []byte{0, 1, 0, 9, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, ProtocolUnknown},
		{"wireguard-typed-4byte", []byte{1, 0, 0, 0, 1, 2, 3, 4}, ProtocolUnknown},
	}
	for _, testCase := range cases {
		packet := &Packet{Transport: TransportUDP, DstPort: 443, Payload: testCase.payload}
		if got := classifyUDPPayload(packet); got != testCase.want {
			t.Fatalf("%s: got %v want %v", testCase.name, got, testCase.want)
		}
	}
}

// buildQUICInitial builds a structurally valid QUIC v1 Initial long header with
// a bounded token/payload-length varint pair, for classification tests.
func buildQUICInitial() []byte {
	data := []byte{0xc0, 0, 0, 0, 1, 8}
	data = append(data, make([]byte, 8)...)       // DCID
	data = append(data, 0)                        // SCID length
	data = append(data, 0)                        // token length
	payload := make([]byte, 200)                  // >= 96 byte payload
	data = append(data, 0x40, byte(len(payload))) // 2-byte varint length
	data = append(data, payload...)
	for len(data) < quicInitialMinLen {
		data = append(data, 0)
	}
	return data
}

func TestTLSClientHelloParsing(t *testing.T) {
	hello := buildClientHello("example.com")
	protocol, host, facts := protocolFacts(hello)
	if protocol != ProtocolTLS || host != "example.com" {
		t.Fatalf("protocol=%v host=%q", protocol, host)
	}
	if string(hello[facts.HostStart:facts.HostEnd]) != "example.com" {
		t.Fatalf("host offsets %d:%d", facts.HostStart, facts.HostEnd)
	}
	if facts.SLDEnd <= facts.SLDStart {
		t.Fatal("SLD anchors not computed")
	}
	positions := ResolvePositions([]Position{{Kind: positionHost}, {Kind: positionEndHost}, {Kind: positionMidSLD}}, facts)
	// endhost resolves to the end of the message for this single-host hello and
	// is therefore not a valid split; host and midsld remain.
	if len(positions) != 2 {
		t.Fatalf("resolved = %v", positions)
	}
	if positions[0] != facts.HostStart {
		t.Fatalf("host position = %d", positions[0])
	}
	if positions[1] != (facts.SLDStart+facts.SLDEnd)/2 {
		t.Fatalf("midsld position = %d", positions[1])
	}
}

func TestHTTPHostParsing(t *testing.T) {
	message := []byte("GET / HTTP/1.1\r\nHost: www.example.org\r\nUser-Agent: x\r\n\r\n")
	protocol, host, facts := protocolFacts(message)
	if protocol != ProtocolHTTP || host != "www.example.org" {
		t.Fatalf("protocol=%v host=%q", protocol, host)
	}
	if string(message[facts.HostStart:facts.HostEnd]) != host {
		t.Fatal("host offsets do not delimit the host")
	}
}

func buildClientHello(host string) []byte {
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression methods
	extension := make([]byte, 0, 64)
	name := []byte(host)
	entry := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
	sni := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	extension = append(extension, 0, 0, byte(len(sni)>>8), byte(len(sni)))
	extension = append(extension, sni...)
	body = append(body, byte(len(extension)>>8), byte(len(extension)))
	body = append(body, extension...)
	handshake := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return record
}

func TestCompileDisabledAndValidation(t *testing.T) {
	disabled := false
	disabledOptions := optionDesyncDisabled(disabled)
	config, err := Compile(&disabledOptions, "")
	if err != nil || config != nil {
		t.Fatalf("disabled desync must compile to nil: %v %v", config, err)
	}
	if _, err = Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],"fake":{"payloads":[{"protocol":"tls","hex":"00"}]},"multisplit":{"split_pos":["1"]}}]}`), ""); err == nil {
		t.Fatal("method-owned object without its method must be rejected")
	}
	if _, err = Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"methods":["multisplit"],"multisplit":{"split_pos":["1"],"seqovl":2,"seqovl_pattern":"x"}}]}`), ""); err == nil {
		t.Fatal("split methods must be rejected on UDP rules")
	}
	if _, err = Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],"fake":{"payloads":[{"protocol":"tls","hex":"00"},{"protocol":"tls","hex":"11"}],"fooling":["ts"]},"ip_id":"zero"}]}`), ""); err != nil {
		t.Fatalf("valid fake rule rejected: %v", err)
	}
}

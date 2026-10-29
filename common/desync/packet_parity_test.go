package desync

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

type sequenceRand struct {
	values []uint32
	index  int
}

func (r *sequenceRand) Uint32() uint32 {
	if len(r.values) == 0 {
		return 1
	}
	value := r.values[r.index%len(r.values)]
	r.index++
	return value
}

func (r *sequenceRand) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.Uint32() % uint32(n))
}

func TestStageGrammarAliasesAndValidation(t *testing.T) {
	methods, err := CompileMethods([]string{"synack", "fake", "split"}, TransportMaskTCP)
	if err != nil {
		t.Fatalf("zero/first/second with aliases rejected: %v", err)
	}
	if len(methods) != 3 || methods[2].Name != "fakedsplit" {
		t.Fatalf("alias did not canonicalize: %+v", methods)
	}
	if _, err = CompileMethods([]string{"disorder", "fake"}, TransportMaskTCP); err == nil {
		t.Fatal("out-of-order stages accepted")
	}
	if methods, err = CompileMethods([]string{"synack", "multisplit"}, TransportMaskTCP); err != nil {
		t.Fatalf("zero+second (upstream-valid, ALT5 form) rejected: %v", err)
	} else if len(methods) != 2 || methods[0].Name != "synack" || methods[1].Name != "multisplit" {
		t.Fatalf("zero+second order not preserved: %+v", methods)
	}
	if _, err = CompileMethods([]string{"synack"}, TransportMaskUDP); err == nil {
		t.Fatal("zero stage accepted on UDP")
	}
	if _, err = CompileMethods([]string{"rst"}, TransportMaskUDP); err == nil {
		t.Fatal("TCP-only first stage accepted on UDP")
	}
	if _, err = CompileMethods([]string{"udplen"}, TransportMaskTCP); err == nil {
		t.Fatal("UDP-only second stage accepted on TCP")
	}
	if _, err = CompileMethods([]string{"ipfrag2"}, TransportMaskTCP|TransportMaskUDP); err != nil {
		t.Fatalf("ipfrag2 must be applicable to both transports: %v", err)
	}
	if _, err = CompileMethods([]string{"nonsense"}, TransportMaskTCP); err == nil {
		t.Fatal("unknown method accepted")
	}
}

func TestCompileNewStageObjects(t *testing.T) {
	var options option.DirectDesyncOptions
	err := json.Unmarshal([]byte(`{"enabled":true,"rules":[{
		"network":["tcp"],"methods":["synack","fake","fakeddisorder"],"repeats":2,
		"ttl":3,"autottl":"-1:3-20","tcp_flags_set":"PSH,ACK","fooling":["ts","md5sig"],
		"ip_id":"rnd",
		"fake":{"payloads":[{"protocol":"tls","hex":"1603010005","tls_mod":"rnd"}],"repeats":2},
		"fakeddisorder":{"split_pos":["2"],"fake_pattern":"0xdeadbeef","fake_mod":"altorder=2"}
	}]}`), &options)
	if err != nil {
		t.Fatal(err)
	}
	config, err := Compile(&options, "")
	if err != nil {
		t.Fatalf("valid staged rule rejected: %v", err)
	}
	rule := config.Rules[0]
	if rule.FakeDisorder == nil || len(rule.FakeDisorder.Pattern) != 4 || rule.FakeDisorder.Ordering != 2 {
		t.Fatalf("fakeddisorder spec mismatch: %+v", rule.FakeDisorder)
	}
	if rule.Mods.FlagsSet != 0x18 || rule.Mods.AutoTTL.Delta != -1 {
		t.Fatalf("modifiers mismatch: %+v", rule.Mods)
	}
	if _, err = Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"methods":["synack","fake"],"fake":{"payloads":[{"protocol":"tls","hex":"00"}]},"udplen":{"increment":4}}]}`), ""); err == nil {
		t.Fatal("udplen object without the udplen method accepted")
	}
	if _, err = Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"methods":["ipfrag2"],"ipfrag_pos_tcp":30}]}`), ""); err == nil {
		t.Fatal("unaligned ipfrag position accepted")
	}
}

func TestAutoTTLMatchesUpstream(t *testing.T) {
	if HopCountGuess(60) != 4 || HopCountGuess(120) != 8 || HopCountGuess(250) != 5 || HopCountGuess(70) != 0 {
		t.Fatalf("hop count guess mismatch: %d %d %d %d", HopCountGuess(60), HopCountGuess(120), HopCountGuess(250), HopCountGuess(70))
	}
	auto, err := parseAutoTTL("-1:3-20")
	if err != nil {
		t.Fatal(err)
	}
	if value, ok := auto.Eval(5); !ok || value != 4 {
		t.Fatalf("autottl delta mismatch: %d %v", value, ok)
	}
	if _, ok := auto.Eval(3); ok {
		t.Fatal("autottl must refuse a guess not below the hop count")
	}
	if value, ok := auto.Eval(64); !ok || value != 20 {
		t.Fatalf("autottl maximum clamp mismatch: %d %v", value, ok)
	}
	if _, err = parseAutoTTL("1:20-3"); err == nil {
		t.Fatal("inverted autottl range accepted")
	}
	mods := &ModifierSet{TTL: 7, AutoTTL: auto}
	if ttl := mods.TTLFor(FamilyIPv4, 64, 5, true); ttl != 4 {
		t.Fatalf("autottl must override explicit ttl: %d", ttl)
	}
	if ttl := mods.TTLFor(FamilyIPv4, 64, 0, false); ttl != 7 {
		t.Fatalf("explicit ttl fallback mismatch: %d", ttl)
	}
}

func TestTCPFlagParsing(t *testing.T) {
	if flags, err := parseTCPFlags("FIN,SYN,ACK"); err != nil || flags != 0x13 {
		t.Fatalf("flag list mismatch: %x %v", flags, err)
	}
	if flags, err := parseTCPFlags("0x12"); err != nil || flags != 0x12 {
		t.Fatalf("hex flags mismatch: %x %v", flags, err)
	}
	if _, err := parseTCPFlags("BOGUS"); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestIPIDModes(t *testing.T) {
	packet := buildIPv4TCP(t, nil, 1, tcpFlagACK)
	packet.IPID = 100
	random := &sequenceRand{values: []uint32{7, 9}}
	seq := newIPAllocator(&Rule{IPID: IPIDSeq}, packet, random)
	first, _ := seq.Value()
	second, _ := seq.Value()
	if first != 100 || second != 101 {
		t.Fatalf("seq ip id mismatch: %d %d", first, second)
	}
	zero := newIPAllocator(&Rule{IPID: IPIDZero}, packet, random)
	if value, _ := zero.Value(); value != 0 {
		t.Fatalf("zero ip id mismatch: %d", value)
	}
	same := newIPAllocator(&Rule{IPID: IPIDSame}, packet, random)
	if value, _ := same.Value(); value != 100 {
		t.Fatalf("same ip id mismatch: %d", value)
	}
	rnd := newIPAllocator(&Rule{IPID: IPIDRandom}, packet, &sequenceRand{values: []uint32{0}})
	if value, _ := rnd.Value(); value == 0 {
		t.Fatal("rnd ip id produced zero")
	}
}

func buildPaddedClientHello(host string) []byte {
	base := buildClientHello(host)
	// Append a padding extension (type 21) with 12 zero bytes, keeping all
	// length fields consistent. The extensions length field starts at byte 50
	// (5 record + 4 handshake + 41 ClientHello body).
	padding := make([]byte, 4+12)
	padding[0], padding[1] = 0, 21
	padding[2], padding[3] = 0, 12
	extensionLength := int(binary.BigEndian.Uint16(base[50:]))
	putUint16(base[50:], extensionLength+len(padding))
	handshakeLength := readUint24(base[6:])
	putUint24(base[6:], handshakeLength+len(padding))
	recordLength := int(binary.BigEndian.Uint16(base[3:]))
	putUint16(base[3:], recordLength+len(padding))
	return append(base, padding...)
}

func buildClientHelloWithSID(host string, sid []byte) []byte {
	base := buildClientHello(host)
	// Insert the session id after the one-byte session-id length field.
	out := make([]byte, 0, len(base)+len(sid))
	out = append(out, base[:43]...)
	out = append(out, byte(len(sid)))
	out = append(out, sid...)
	out = append(out, base[44:]...)
	putUint16(out[3:], int(binary.BigEndian.Uint16(out[3:]))+len(sid))
	putUint24(out[6:], readUint24(out[6:])+len(sid))
	return out
}

func TestTLSModifiers(t *testing.T) {
	hello := buildPaddedClientHello("example.com")
	layout, ok := parseTLSHelloLayout(hello)
	if !ok || layout.sni == 0 || layout.paddingLen == 0 {
		t.Fatalf("clienthello layout not parsed: %+v %v", layout, ok)
	}
	random := &sequenceRand{values: []uint32{1, 2, 3, 4, 5, 6, 7, 8}}
	rnd, applied := applyTLSMod(hello, TLSMod{Randomize: true}, nil, random)
	if !applied || bytes.Equal(rnd[11:43], hello[11:43]) {
		t.Fatal("rnd tls mod did not randomize")
	}
	withSID := buildClientHelloWithSID("example.com", []byte("12345678"))
	if _, ok := parseTLSHelloLayout(withSID); !ok {
		t.Fatal("session id fixture is not a valid ClientHello")
	}
	original := buildClientHelloWithSID("example.com", []byte("ABCDEFGH"))
	dup, applied := applyTLSMod(withSID, TLSMod{DupSID: true}, original, random)
	if !applied {
		t.Fatal("dupsid tls mod did not apply")
	}
	dupLayout, ok := parseTLSHelloLayout(dup)
	if !ok || !bytes.Equal(dup[dupLayout.sessionID:dupLayout.sessionID+8], []byte("ABCDEFGH")) {
		t.Fatal("dupsid tls mod did not copy the original session id")
	}
	sni, applied := applyTLSMod(withSID, TLSMod{SNI: "a-much-longer.example"}, nil, random)
	if !applied {
		t.Fatal("sni tls mod did not apply")
	}
	if _, ok := parseTLSHelloLayout(sni); !ok {
		t.Fatal("sni tls mod produced an invalid ClientHello")
	}
	if int(binary.BigEndian.Uint16(sni[3:])) != len(sni)-5 {
		t.Fatal("sni tls mod did not update the record length")
	}
	padded, applied := applyTLSMod(hello, TLSMod{PadEncap: true}, make([]byte, 100), random)
	if !applied {
		t.Fatal("padencap tls mod did not apply")
	}
	if int(binary.BigEndian.Uint16(padded[3:])) != int(binary.BigEndian.Uint16(hello[3:]))+100 {
		t.Fatal("padencap did not increase the record length")
	}
}

func TestBuildTCPExModifiers(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("hello"), 1000, tcpFlagACK|tcpFlagPSH)
	flags := uint8(tcpFlagACK | tcpFlagPSH)
	ttl := uint8(3)
	seq := uint32(10)
	spec := BuildSpec{
		Flags: &flags, TTL: ttl, TTLSet: true, Seq: &seq,
		IPID: 1, IPIDSet: true, CopyOptions: true,
		Fooling: Fooling{BadChecksum: true, MD5Signature: true, DataNoACK: true},
		Payload: []byte("fake"), Rand: &sequenceRand{values: []uint32{5}},
		CorruptSum: true,
	}
	raw, err := BuildTCPEx(packet, spec)
	if err != nil {
		t.Fatal(err)
	}
	built, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if built.TTL != 3 || built.TCPSeq != 10 || built.IPID != 1 {
		t.Fatalf("header modifiers not applied: ttl=%d seq=%d id=%d", built.TTL, built.TCPSeq, built.IPID)
	}
	if built.TCPFlags&tcpFlagACK != 0 {
		t.Fatal("datanoack did not clear ACK")
	}
	if !built.HasTimestamp || built.TSVal != 1111 {
		t.Fatalf("timestamp option was not copied: %+v", built.TCPOptions)
	}
	if !built.HasSACK && !hasOption(built.TCPOptions, 19) {
		t.Fatal("md5sig option missing")
	}
	if _, err := verifyTCPChecksumValue(raw); err == nil {
		t.Fatal("badsum must corrupt the checksum")
	}
}

func hasOption(options []byte, kind byte) bool {
	for index := 0; index < len(options); {
		if options[index] == 0 {
			return false
		}
		if options[index] == 1 {
			index++
			continue
		}
		if index+1 >= len(options) || options[index+1] < 2 {
			return false
		}
		if options[index] == kind {
			return true
		}
		index += int(options[index+1])
	}
	return false
}

func verifyTCPChecksumValue(raw []byte) (uint16, error) {
	packet, err := ParsePacket(raw)
	if err != nil {
		return 0, err
	}
	sum, err := pseudoHeaderSum(raw, packet, len(raw)-packet.IPHeaderLen)
	if err != nil {
		return 0, err
	}
	provided := binary.BigEndian.Uint16(raw[packet.IPHeaderLen+16:])
	copyRaw := append([]byte(nil), raw...)
	copyRaw[packet.IPHeaderLen+16], copyRaw[packet.IPHeaderLen+17] = 0, 0
	calculated := inetChecksum(copyRaw[packet.IPHeaderLen:], sum)
	if calculated != provided {
		return 0, errChecksum
	}
	return provided, nil
}

type checksumError struct{}

func (checksumError) Error() string { return "checksum mismatch" }

var errChecksum = checksumError{}

func TestFragmentIPv4Reassembles(t *testing.T) {
	packet := buildIPv4TCP(t, bytes.Repeat([]byte{0xab}, 200), 5000, tcpFlagACK)
	first, second, err := FragmentPair(packet.Raw, 64, 0x1234, &sequenceRand{values: []uint32{1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("empty fragment")
	}
	if binary.BigEndian.Uint16(first[6:8])&0x2000 == 0 {
		t.Fatal("first fragment has no MF bit")
	}
	if binary.BigEndian.Uint16(second[6:8]) != 8 {
		t.Fatalf("second fragment offset mismatch: %x", binary.BigEndian.Uint16(second[6:8]))
	}
	if !bytes.Equal(first[20:], packet.Raw[20:20+64]) {
		t.Fatal("first fragment bytes differ")
	}
	reassembled := append(append([]byte(nil), first[20:]...), second[20:]...)
	if !bytes.Equal(reassembled, packet.Raw[20:]) {
		t.Fatal("fragments do not reassemble to the original payload")
	}
	if _, _, err = FragmentPair(packet.Raw, 30, 0, nil); err == nil {
		t.Fatal("unaligned fragment position accepted")
	}
}

func TestIPv6ExtensionAndFragment(t *testing.T) {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 8+4)
	ip[6] = 17
	ip[7] = 64
	copy(ip[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(ip[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	udp := make([]byte, 8+4)
	binary.BigEndian.PutUint16(udp[0:2], 5000)
	binary.BigEndian.PutUint16(udp[2:4], 443)
	binary.BigEndian.PutUint16(udp[4:6], 12)
	copy(udp[8:], []byte("test"))
	raw := append(append([]byte(nil), ip...), udp...)
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	built, err := BuildUDPEx(packet, BuildSpec{Payload: []byte("test"), TTL: 7, TTLSet: true, ExtHeaders: []uint8{0, 60}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePacket(built)
	if err != nil {
		t.Fatalf("generated extension chain does not parse: %v", err)
	}
	if parsed.TTL != 7 {
		t.Fatal("hop limit not applied")
	}
	inserted, err := InsertIPv6Extension(raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParsePacket(inserted); err != nil {
		t.Fatalf("inserted extension header does not parse: %v", err)
	}
	first, second, err := FragmentPair(raw, 8, 0x99, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range [][]byte{first, second} {
		if _, err = ParsePacket(fragment); err == nil {
			t.Fatal("fragmented IPv6 packet must not parse as unfragmented")
		}
		if fragment[6] != 44 {
			t.Fatalf("fragment header missing: %d", fragment[6])
		}
	}
	if binary.BigEndian.Uint32(first[44:]) != 0x99 {
		t.Fatal("fragment identification mismatch")
	}
}

func TestUDPLenPaddingPattern(t *testing.T) {
	packet := buildIPv4UDP(t, []byte("x"), 443)
	payload := append([]byte("abc"), bytes.Repeat([]byte{0}, 9)...)
	fillPattern(payload[3:], []byte{0xaa, 0xbb}, 0)
	raw, err := BuildUDPEx(packet, BuildSpec{Payload: payload, TTL: 4, TTLSet: true})
	if err != nil {
		t.Fatal(err)
	}
	built, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.Payload) != 12 || built.Payload[3] != 0xaa || built.Payload[4] != 0xbb {
		t.Fatalf("udplen padding mismatch: %x", built.Payload)
	}
}

func mustTestRule(t *testing.T, content string) *Rule {
	t.Helper()
	options := enabledOption(content)
	config, err := Compile(options, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return config.Rules[0]
}

func TestZeroStageSynAckAndSynData(t *testing.T) {
	syn := buildIPv4TCP(t, nil, 7000, tcpFlagSYN)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["synack","fake"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},"ttl":4}]}`)
	batch, err := PlanTCP(rule, syn, nil, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 1 || batch.Original != VerdictPass {
		t.Fatalf("synack stage mismatch: %d %v", len(batch.Packets), batch.Original)
	}
	generated, err := ParsePacket(batch.Packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if generated.TCPFlags != tcpFlagSYN|tcpFlagACK || generated.TTL != 4 {
		t.Fatalf("synack flags/ttl mismatch: %x %d", generated.TCPFlags, generated.TTL)
	}
	dataRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["syndata","fake"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]}}]}`)
	batch, err = PlanTCP(dataRule, syn, nil, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 1 || batch.Original != VerdictDrop {
		t.Fatalf("syndata stage mismatch: %d %v", len(batch.Packets), batch.Original)
	}
	generated, err = ParsePacket(batch.Packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Payload) != 16 || generated.TCPFlags != tcpFlagSYN {
		t.Fatalf("syndata payload/flags mismatch: %d %x", len(generated.Payload), generated.TCPFlags)
	}
}

func TestFirstStageRSTAndFakeKnown(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("GET / HTTP/1.1\r\n"), 100, tcpFlagACK|tcpFlagPSH)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["rstack"]}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 1 {
		t.Fatal("rstack packet missing")
	}
	generated, _ := ParsePacket(batch.Packets[0])
	if generated.TCPFlags != tcpFlagRST|tcpFlagACK {
		t.Fatalf("rstack flags mismatch: %x", generated.TCPFlags)
	}
	known := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fakeknown"],
		"fakeknown":{"payloads":[{"protocol":"tls","hex":"00"}]}}]}`)
	batch, err = PlanTCP(known, packet, packet.Payload, 0, Facts{Protocol: ProtocolUnknown})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 0 {
		t.Fatal("fakeknown must not fire for an unknown protocol")
	}
}

func TestIPFrag2UDPLenAndTamper(t *testing.T) {
	packet := buildIPv4TCP(t, bytes.Repeat([]byte{0x11}, 64), 100, tcpFlagACK|tcpFlagPSH)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake","ipfrag2"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},"ipfrag_pos_tcp":40}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictDrop || len(batch.Packets) < 3 {
		t.Fatalf("ipfrag2 mismatch: %v %d", batch.Original, len(batch.Packets))
	}
	udpPacket := buildIPv4UDP(t, []byte("hello"), 443)
	udpRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["udp"],"methods":["fake","udplen"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},"udplen":{"increment":5,"pattern":"0xaabb"}}]}`)
	udpBatch, err := PlanUDP(udpRule, udpPacket)
	if err != nil {
		t.Fatal(err)
	}
	if len(udpBatch.Packets) != 2 {
		t.Fatalf("udplen packets mismatch: %d", len(udpBatch.Packets))
	}
	generated, err := ParsePacket(udpBatch.Packets[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(generated.Payload) != 10 {
		t.Fatalf("udplen payload mismatch: %d", len(generated.Payload))
	}
	dht := append([]byte("d1:"), bytes.Repeat([]byte("a"), 10)...)
	dht = append(dht, 'e')
	tamperPacket := buildIPv4UDP(t, dht, 6881)
	tamperRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["udp"],"methods":["fake","tamper"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]}}]}`)
	tamperBatch, err := PlanUDP(tamperRule, tamperPacket)
	if err != nil {
		t.Fatal(err)
	}
	generated, err = ParsePacket(tamperBatch.Packets[len(tamperBatch.Packets)-1])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(generated.Payload, []byte("d2:001:x")) {
		t.Fatalf("tamper payload mismatch: %q", generated.Payload)
	}
}

func TestFakeSplitOrdering(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("0123456789"), 100, tcpFlagACK|tcpFlagPSH)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake","fakedsplit"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},
		"fakedsplit":{"split_pos":["4"],"fake_pattern":"0xff","fake_mod":"altorder=0"}}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictDrop || len(batch.Packets) < 3 {
		t.Fatalf("fakedsplit mismatch: %v %d", batch.Original, len(batch.Packets))
	}
	found := false
	for _, candidate := range batch.Packets {
		fake, err := ParsePacket(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(fake.Payload, []byte{0xff, 0xff, 0xff, 0xff}) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("fake pattern segment missing")
	}
}

func TestOrigDupAndReplyTransform(t *testing.T) {
	packet := buildIPv4TCP(t, []byte("data"), 100, tcpFlagACK|tcpFlagPSH)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},
		"orig":{"ttl":9,"tcp_flags_unset":"PSH"},
		"dup":{"count":2,"ttl":5,"ip_id":"zero"}}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Original != VerdictModify || batch.Modified == nil {
		t.Fatalf("orig modification missing: %v", batch.Original)
	}
	modified, err := ParsePacket(batch.Modified)
	if err != nil {
		t.Fatal(err)
	}
	if modified.TTL != 9 || modified.TCPFlags&tcpFlagPSH != 0 {
		t.Fatalf("orig modifiers not applied: ttl=%d flags=%x", modified.TTL, modified.TCPFlags)
	}
	if _, err := verifyTCPChecksumValue(batch.Modified); err != nil {
		t.Fatal("modified original has an invalid checksum")
	}
	if len(batch.Packets) != 3 {
		t.Fatalf("dup packet count mismatch: %d", len(batch.Packets))
	}
	windowRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},
		"wsize":{"size":1234}}]}`)
	synackWindow := buildIPv4TCP(t, nil, 500, tcpFlagSYN|tcpFlagACK)
	reply, err := PlanReply(windowRule, synackWindow)
	if err != nil || reply == nil {
		t.Fatalf("reply window rewrite missing: %v", err)
	}
	rewritten, err := ParsePacket(reply)
	if err != nil {
		t.Fatal(err)
	}
	if rewritten.TCPWindow != 1234 {
		t.Fatalf("reply window mismatch: %d", rewritten.TCPWindow)
	}
	if _, err := verifyTCPChecksumValue(reply); err != nil {
		t.Fatal("reply rewrite has an invalid checksum")
	}
	if reply, err = PlanReply(windowRule, packet); err != nil || reply != nil {
		t.Fatalf("wsize must not rewrite a non-SYN-ACK packet: %v %v", reply, err)
	}
	wssizeRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},
		"wssize":{"size":1234}}]}`)
	origBatch, err := PlanTCP(wssizeRule, packet, packet.Payload, 0, Facts{})
	if err != nil || origBatch.Original != VerdictModify || origBatch.Modified == nil {
		t.Fatalf("wssize original rewrite missing: %v %v", err, origBatch.Original)
	}
	origWindow, err := ParsePacket(origBatch.Modified)
	if err != nil || origWindow.TCPWindow != 1234 {
		t.Fatalf("wssize original window mismatch: %v %v", origWindow, err)
	}
	if reply, err = PlanReply(wssizeRule, synackWindow); err != nil || reply != nil {
		t.Fatalf("wssize must never rewrite replies: %v %v", reply, err)
	}
	synack := buildIPv4TCP(t, nil, 500, tcpFlagSYN|tcpFlagACK)
	splitRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],
		"fake":{"payloads":[{"protocol":"unknown","hex":"00"}]},"synack_split":"acksyn"}]}`)
	parts, err := SynAckSplitPackets(splitRule, synack)
	if err != nil || len(parts) != 2 {
		t.Fatalf("synack split mismatch: %d %v", len(parts), err)
	}
	first, _ := ParsePacket(parts[0])
	second, _ := ParsePacket(parts[1])
	if first.TCPFlags != tcpFlagACK || second.TCPFlags != tcpFlagSYN {
		t.Fatalf("acksyn order mismatch: %x %x", first.TCPFlags, second.TCPFlags)
	}
}

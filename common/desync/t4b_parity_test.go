package desync

// QA417 F-3/F-4 regressions: absolute packet placement and the TLS server_name
// extension anchor must match the pinned source, not merely reach HTTP 200.
//
// Source: bol-van/zapret v72.9 c849e55ef0f1c244206f5a05ff7b1ab41a3824ee
//   nfq/desync.c:1972  sequence0 = ntohl(dis->tcp->th_seq)  (fake base = the
//                      captured packet sequence, shared by every fake)
//   nfq/desync.c:2002  rawsend_rep(desync_repeats, ...)      (one packet,
//                      repeated N times, same sequence)
//   nfq/desync.c:2008  if (dp->tcp_mod.seq) sequence += fake_size  (advance
//                      per fake payload item, not per repeat)
//   nfq/desync.c:2295  net32_add(dis->tcp->th_seq, from - seqovl)  (multisplit
//                      first interval starts seqovl bytes before the stream)
//   nfq/protocol.c:462-470  *ext = data after data += 4  (ext points at the
//                      extension BODY, past the 4-byte extension header)
//   nfq/protocol.c:549-554  PM_SNI_EXT -> CheckPos(sz, ext-data+pos)
//   nfq/protocol.c:85       CheckPos: 0 unless 0 <= offset < size

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// t4bClientHello builds a ClientHello with the layout the QA campaign captured
// (32-byte session id, 62-byte cipher suite list, Go-style extension order) and
// pads it to target bytes with a padding extension. Placeholder random and
// key-share bytes keep the fixture deterministic.
func t4bClientHello(host string, target int) []byte {
	return t4bBuildClientHello(host, target, true)
}

// t4bClientHelloNoSNI builds the same framing without a server_name extension.
func t4bClientHelloNoSNI(target int) []byte { return t4bBuildClientHello("", target, false) }

func t4bBuildClientHello(host string, target int, withSNI bool) []byte {
	body := make([]byte, 0, 512)
	body = append(body, 0x03, 0x03)
	for i := 0; i < 32; i++ {
		body = append(body, byte(i+1))
	}
	body = append(body, 32)
	for i := 0; i < 32; i++ {
		body = append(body, byte(0x40+i))
	}
	suites := []uint16{0x1302, 0x1303, 0x1301, 0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa,
		0xc02b, 0xc02f, 0x009e, 0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067,
		0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033, 0x009d, 0x009c, 0x003d,
		0x003c, 0x0035, 0x002f, 0x00ff}
	body = append(body, byte(len(suites)*2>>8), byte(len(suites)*2))
	for _, s := range suites {
		body = append(body, byte(s>>8), byte(s))
	}
	body = append(body, 1, 0)
	ext := make([]byte, 0, 512)
	name := []byte(host)
	if withSNI {
		// server_name: list length, name type host_name(0), name length, value.
		sniBody := append([]byte{byte((len(name) + 3) >> 8), byte(len(name) + 3), 0, byte(len(name) >> 8), byte(len(name))}, name...)
		ext = append(ext, 0, 0, byte(len(sniBody)>>8), byte(len(sniBody)))
		ext = append(ext, sniBody...)
	}
	ext = append(ext, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02)
	ext = append(ext, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,
		0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04)
	ext = append(ext, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1')
	ext = append(ext, 0x00, 0x16, 0x00, 0x00)
	ext = append(ext, 0x00, 0x17, 0x00, 0x00)
	ext = append(ext, 0x00, 0x31, 0x00, 0x00)
	ext = append(ext, 0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
		0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05,
		0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02,
		0x04, 0x02, 0x05, 0x02, 0x06, 0x02)
	ext = append(ext, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03)
	ext = append(ext, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01)
	keyShare := append([]byte{0x00, 0x1d, 0x00, 0x20}, make([]byte, 32)...)
	for i := range keyShare[4:] {
		keyShare[4+i] = byte(0xa0 + i)
	}
	ext = append(ext, 0x00, 0x33, 0x00, byte(len(keyShare)>>8), byte(len(keyShare)))
	ext = append(ext, keyShare...)
	if need := target - (5 + 4 + len(body) + 2 + len(ext) + 4); need > 0 {
		ext = append(ext, 0x00, 0x15, byte(need>>8), byte(need))
		ext = append(ext, make([]byte, need)...)
	}
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	handshake := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

// t4bSNILayout is an independent walk of the ClientHello that returns the
// absolute offsets upstream TLSPos works with: the extension body start (the
// two-byte server_name list length) and the host_name value.
func t4bSNILayout(t *testing.T, hello []byte) (bodyStart, hostStart, hostEnd int) {
	t.Helper()
	if len(hello) < 5+4 || hello[0] != 0x16 {
		t.Fatalf("not a ClientHello record: %x", hello[:minIntLocal(5, len(hello))])
	}
	hs := hello[5:]
	off := 4 + 2 + 32
	off += 1 + int(hs[off])
	off += 2 + int(binary.BigEndian.Uint16(hs[off:off+2]))
	off += 1 + int(hs[off])
	extEnd := off + 2 + int(binary.BigEndian.Uint16(hs[off:off+2]))
	off += 2
	for off+4 <= extEnd {
		kind := binary.BigEndian.Uint16(hs[off : off+2])
		length := int(binary.BigEndian.Uint16(hs[off+2 : off+4]))
		body := off + 4
		if kind == 0 {
			nameLen := int(binary.BigEndian.Uint16(hs[body+3 : body+5]))
			return 5 + body, 5 + body + 5, 5 + body + 5 + nameLen
		}
		off = body + length
	}
	t.Fatal("fixture has no server_name extension")
	return 0, 0, 0
}

func minIntLocal(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// t4bPatternFile writes a seqovl_pattern file and returns it as a JSON string
// literal, exactly like the upstream --dpi-desync-split-seqovl-pattern path.
func t4bPatternFile(t *testing.T, pattern []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seqovl_pattern.bin")
	if err := os.WriteFile(path, pattern, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type t4bCapture struct {
	packets [][]byte
}

func (c *t4bCapture) inject(raw []byte) error {
	c.packets = append(c.packets, append([]byte(nil), raw...))
	return nil
}

func t4bLease(t *testing.T, body string) *Lease {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,`+body+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "t4b"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close(nil) })
	if verdict := lease.HandlePacket(buildIPv4TCP(t, nil, 100, tcpFlagSYN).Raw, DirectionOutbound, (&t4bCapture{}).inject, nil); verdict != VerdictPass {
		t.Fatalf("SYN verdict = %d", verdict)
	}
	return lease
}

func t4bParsed(t *testing.T, raw []byte) *Packet {
	t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

// TestF3FakeSequenceIsCapturedPacketSequence pins nfq/desync.c:1972/2002: every
// fake repeat is transmitted at the captured packet's sequence.
func TestF3FakeSequenceIsCapturedPacketSequence(t *testing.T) {
	fake := t4bClientHello("www.google.com", 681)
	lease := t4bLease(t, `"rules":[{"name":"r","network":["tcp"],"port":[443],
		"methods":["fake"],
		"fake":{"repeats":3,"fooling":["ts"],"payloads":[{"protocol":"tls","hex":"`+hex.EncodeToString(fake)+`"}]}}]`)
	capture := &t4bCapture{}
	hello := t4bClientHello("www.youtube.com", 517)
	verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 40000, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, capture.inject, nil)
	if verdict != VerdictPass {
		t.Fatalf("fake-only verdict = %d, want pass (nfq/desync.c:2011 bFake keeps the original)", verdict)
	}
	if len(capture.packets) != 3 {
		t.Fatalf("fake packets = %d, want 3", len(capture.packets))
	}
	for index, raw := range capture.packets {
		packet := t4bParsed(t, raw)
		if !bytes.Equal(packet.Payload, fake) {
			t.Fatalf("fake %d payload differs from the configured payload", index)
		}
		if packet.TCPSeq != 40000 {
			t.Fatalf("fake %d sequence = %d, want the captured sequence 40000 (nfq/desync.c:1972)", index, packet.TCPSeq)
		}
	}
}

// TestF3FakeSequenceModeAdvancesPerPayload pins nfq/desync.c:2002-2008:
// tcp_mod.seq advances the sequence once per fake payload item, after all of
// that item's repeats, never per repeat.
func TestF3FakeSequenceModeAdvancesPerPayload(t *testing.T) {
	lease := t4bLease(t, `"rules":[{"name":"r","network":["tcp"],"port":[443],
		"methods":["fake"],
		"fake":{"repeats":2,"seq":true,"payloads":[
			{"protocol":"tls","hex":"41414141"},{"protocol":"tls","hex":"4242"}]}}]`)
	capture := &t4bCapture{}
	hello := t4bClientHello("www.youtube.com", 517)
	if verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 40000, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, capture.inject, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	if len(capture.packets) != 4 {
		t.Fatalf("fake packets = %d, want 4", len(capture.packets))
	}
	want := []struct {
		payload string
		seq     uint32
	}{
		{"AAAA", 40000},
		{"AAAA", 40000},
		{"BB", 40000 + 4},
		{"BB", 40000 + 4},
	}
	for index, expected := range want {
		packet := t4bParsed(t, capture.packets[index])
		if string(packet.Payload) != expected.payload || packet.TCPSeq != expected.seq {
			t.Fatalf("packet %d payload=%q seq=%d, want %q seq=%d", index,
				packet.Payload, packet.TCPSeq, expected.payload, expected.seq)
		}
	}
}

// TestF3MultiSplitSeqOverlapPlacement reproduces QA profile 03 (split_pos 1,
// seqovl 681, fake 8x681) and pins the absolute mapping the pinned reference
// writes: fakes at the captured sequence, the first interval seqovl bytes
// earlier carrying the overlap pattern plus the first real byte, and the
// remainder at split_pos (nfq/desync.c:1972, :2295).
func TestF3MultiSplitSeqOverlapPlacement(t *testing.T) {
	pattern := t4bClientHello("www.google.ru", 681)
	path := t4bPatternFile(t, pattern)
	lease := t4bLease(t, `"rules":[{"name":"r","network":["tcp"],"port":[443],
		"methods":["fake","multisplit"],
		"fooling":["ts"],
		"fake":{"repeats":8,"payloads":[{"protocol":"tls","hex":"`+hex.EncodeToString(pattern)+`"}]},
		"multisplit":{"split_pos":["1"],"seqovl":681,"seqovl_pattern":`+path+`}}]`)
	capture := &t4bCapture{}
	hello := t4bClientHello("www.youtube.com", 517)
	verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 40000, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, capture.inject, nil)
	if verdict != VerdictDrop {
		t.Fatalf("fake+multisplit verdict = %d, want drop (multisplit suppresses the original)", verdict)
	}
	if len(capture.packets) != 10 {
		t.Fatalf("packets = %d, want 8 fakes + 2 real intervals", len(capture.packets))
	}
	for index := 0; index < 8; index++ {
		packet := t4bParsed(t, capture.packets[index])
		if packet.TCPSeq != 40000 || !bytes.Equal(packet.Payload, pattern) {
			t.Fatalf("fake %d seq=%d len=%d, want seq 40000 len %d", index, packet.TCPSeq, len(packet.Payload), len(pattern))
		}
	}
	first := t4bParsed(t, capture.packets[8])
	if first.TCPSeq != 40000-681 {
		t.Fatalf("first interval sequence = %d, want %d (seqovl shift)", first.TCPSeq, 40000-681)
	}
	wantFirst := append(append([]byte(nil), pattern...), hello[0])
	if !bytes.Equal(first.Payload, wantFirst) {
		t.Fatalf("first interval payload len=%d, want %d overlap bytes + real byte", len(first.Payload), len(wantFirst))
	}
	second := t4bParsed(t, capture.packets[9])
	if second.TCPSeq != 40000+1 || !bytes.Equal(second.Payload, hello[1:]) {
		t.Fatalf("remainder seq=%d len=%d, want seq 102 len %d", second.TCPSeq, len(second.Payload), len(hello)-1)
	}
}

// TestF4SNIExtAnchorIsExtensionBodyStart pins nfq/protocol.c:462-470/549-554:
// sniext resolves from the server_name extension BODY start (the two-byte list
// length after the 4-byte extension header), for every hostname length.
func TestF4SNIExtAnchorIsExtensionBodyStart(t *testing.T) {
	cases := []struct {
		host string
		sld  string
	}{
		{"www.youtube.com", "youtube"},
		{"a.io", "a"},
		{"a-rather-long-sni-name.example", "a-rather-long-sni-name"},
	}
	for _, testCase := range cases {
		host := testCase.host
		hello := t4bClientHello(host, 517)
		bodyStart, hostStart, hostEnd := t4bSNILayout(t, hello)
		_, gotHost, facts := protocolFacts(hello)
		if gotHost != host {
			t.Fatalf("%s: parsed host = %q", host, gotHost)
		}
		if facts.SNIExtEnd != bodyStart {
			t.Fatalf("%s: sniext anchor = %d, want extension body start %d", host, facts.SNIExtEnd, bodyStart)
		}
		// Equivalent existing anchors must stay on the host value.
		if facts.HostStart != hostStart || facts.HostEnd != hostEnd {
			t.Fatalf("%s: host anchors %d:%d, want %d:%d", host, facts.HostStart, facts.HostEnd, hostStart, hostEnd)
		}
		if got := string(hello[facts.SLDStart:facts.SLDEnd]); got != testCase.sld || facts.SLDEnd > facts.HostEnd {
			t.Fatalf("%s: sld anchors %d:%d = %q, want %q inside the host value", host, facts.SLDStart, facts.SLDEnd, got, testCase.sld)
		}
		for _, check := range []struct {
			position string
			want     int
		}{
			{"host", hostStart},
			{"endhost", hostEnd},
			{"sld", facts.SLDStart},
			{"endsld", facts.SLDEnd},
		} {
			position, err := ParsePosition(check.position)
			if err != nil {
				t.Fatalf("%s: %v", check.position, err)
			}
			if got, ok := position.Resolve(facts); !ok || got != check.want {
				t.Fatalf("%s: %s resolves %d(ok=%v), want %d", host, check.position, got, ok, check.want)
			}
		}
		if len(testCase.sld) > 1 {
			// midsld stays on FindNLD; the one-byte-SLD special case
			// (upstream p+1) is a separate pre-existing packet-path
			// difference and is deliberately not asserted here.
			position, err := ParsePosition("midsld")
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := position.Resolve(facts); !ok || got != (facts.SLDStart+facts.SLDEnd)/2 {
				t.Fatalf("%s: midsld resolves %d(ok=%v), want %d", host, got, ok, (facts.SLDStart+facts.SLDEnd)/2)
			}
		}
		for _, check := range []struct {
			position string
			offset   int
		}{
			{"sniext", 0},
			{"sniext+1", 1},
			{"sniext+7", 7},
			{"sniext-1", -1},
			{"sniext-5", -5},
		} {
			position, err := ParsePosition(check.position)
			if err != nil {
				t.Fatalf("%s: %v", check.position, err)
			}
			got, ok := position.Resolve(facts)
			if !ok || got != bodyStart+check.offset {
				t.Fatalf("%s: %s resolves %d(ok=%v), want %d", host, check.position, got, ok, bodyStart+check.offset)
			}
		}
		// CheckPos (nfq/protocol.c:85) drops positions outside the message.
		for _, positionString := range []string{"sniext+517", "sniext-4096"} {
			position, err := ParsePosition(positionString)
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := position.Resolve(facts); ok {
				t.Fatalf("%s: out-of-range %s resolved to %d", host, positionString, got)
			}
		}
	}
}

// TestF4SNIExtAnchorWithoutSNIDropsThePosition is the negative control: a
// ClientHello without a server_name extension has no sniext anchor and the
// marker resolves to no split at all, like upstream TLSPos returning 0.
func TestF4SNIExtAnchorWithoutSNIDropsThePosition(t *testing.T) {
	hello := t4bClientHelloNoSNI(517)
	if _, _, facts := protocolFacts(hello); facts.SNIExtEnd != 0 {
		t.Fatalf("sniext anchor without SNI = %d", facts.SNIExtEnd)
	}
	position, err := ParsePosition("sniext+1")
	if err != nil {
		t.Fatal(err)
	}
	_, _, facts := protocolFacts(hello)
	if got, ok := position.Resolve(facts); ok {
		t.Fatalf("sniext+1 without SNI resolved to %d", got)
	}
}

// TestF4MultiSplitSNIExtMatchesPinnedReference reproduces QA profile 11
// (split_pos [2, sniext+1], seqovl 679) on the 517-byte ClientHello and pins
// the three intervals the pinned reference wrote for that exact framing:
// 681 @ S-679, 147 @ S+2, 368 @ S+149.
func TestF4MultiSplitSNIExtMatchesPinnedReference(t *testing.T) {
	pattern := t4bClientHello("www.google.ru", 681)
	path := t4bPatternFile(t, pattern)
	lease := t4bLease(t, `"rules":[{"name":"r","network":["tcp"],"port":[443],
		"methods":["multisplit"],"ip_id":"zero",
		"multisplit":{"split_pos":["2","sniext+1"],"seqovl":679,"seqovl_pattern":`+path+`}}]`)
	capture := &t4bCapture{}
	hello := t4bClientHello("www.youtube.com", 517)
	if verdict := lease.HandlePacket(buildIPv4TCP(t, hello, 40000, tcpFlagACK|tcpFlagPSH).Raw, DirectionOutbound, capture.inject, nil); verdict != VerdictDrop {
		t.Fatalf("verdict = %d, want drop", verdict)
	}
	if len(capture.packets) != 3 {
		t.Fatalf("packets = %d, want 3", len(capture.packets))
	}
	first := t4bParsed(t, capture.packets[0])
	if first.TCPSeq != 40000-679 || len(first.Payload) != 681 {
		t.Fatalf("first interval seq=%d len=%d, want seq %d len 681", first.TCPSeq, len(first.Payload), 40000-679)
	}
	wantFirst := append(append([]byte(nil), pattern[:679]...), hello[0], hello[1])
	if !bytes.Equal(first.Payload, wantFirst) {
		t.Fatal("first interval must be the overlap pattern plus the first two real bytes")
	}
	second := t4bParsed(t, capture.packets[1])
	if second.TCPSeq != 40000+2 || len(second.Payload) != 147 || !bytes.Equal(second.Payload, hello[2:149]) {
		t.Fatalf("middle interval seq=%d len=%d, want seq %d len 147", second.TCPSeq, len(second.Payload), 40000+2)
	}
	third := t4bParsed(t, capture.packets[2])
	if third.TCPSeq != 40000+149 || len(third.Payload) != 368 || !bytes.Equal(third.Payload, hello[149:]) {
		t.Fatalf("last interval seq=%d len=%d, want seq %d len 368", third.TCPSeq, len(third.Payload), 40000+149)
	}
	// The full real client hello must be reconstructible from the intervals at
	// exactly the upstream offsets: byte k of the stream lives at sequence S+k.
	stream := make([]byte, len(hello))
	for _, raw := range capture.packets {
		packet := t4bParsed(t, raw)
		rel := int(int32(packet.TCPSeq - 40000))
		if rel < 0 {
			for i := 0; i < len(packet.Payload); i++ {
				if rel+i >= 0 {
					stream[rel+i] = packet.Payload[i]
				}
			}
			continue
		}
		copy(stream[rel:], packet.Payload)
	}
	if !bytes.Equal(stream, hello) {
		sum := sha256.Sum256(stream)
		t.Fatalf("reconstructed stream differs from the real ClientHello: sha256=%x", sum)
	}
}

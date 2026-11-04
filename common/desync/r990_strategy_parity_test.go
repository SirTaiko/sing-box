package desync

// R990 focused compatibility regressions for the staged TCP builder.
//
// Pinned reference: bol-van/zapret c849e55ef0f1c244206f5a05ff7b1ab41a3824ee
//   darkmagic.c:170-176  memcpy(tcpopt+t+2, timestamps, 8); FOOL_TS forges
//                        only the TSval word, so the template TSecr survives.
//   desync.c:1429        one IPv4 ID cursor per captured packet (IP4_IP_ID_FIX)
//   desync.c:1991-2008   each fake payload is built once, rawsend_rep repeats
//                        those exact bytes, then IP4_IP_ID_NEXT advances once
//                        per fake payload item.
//   desync.c:2293-2301   multisplit builds one packet per interval and calls
//                        IP4_IP_ID_NEXT after every rawsend, so a fake burst
//                        followed by two intervals consumes three IDs.
//
// The tests drive the actual current callers (PlanTCP -> BuildTCPEx/BuildTCP),
// not the older in-place BuildTCP timestamp path alone.

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// r990IPv4TCP returns the shared fixture with a chosen IPv4 ID and with the
// NOP,NOP,TIMESTAMP option block either preserved (TSval 1111, TSecr 2222) or
// replaced by NOPs.
func r990IPv4TCP(t *testing.T, payload []byte, ipid uint16, timestamp bool) *Packet {
	t.Helper()
	packet := buildIPv4TCP(t, payload, 1000, tcpFlagACK|tcpFlagPSH)
	raw := append([]byte(nil), packet.Raw...)
	binary.BigEndian.PutUint16(raw[4:6], ipid)
	if !timestamp {
		for index := 20; index < 32; index++ {
			raw[20+index] = 1
		}
	}
	reparsed, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if reparsed.IPID != ipid || reparsed.HasTimestamp != timestamp {
		t.Fatalf("fixture ipid=%d timestamp=%v, want %d/%v",
			reparsed.IPID, reparsed.HasTimestamp, ipid, timestamp)
	}
	return reparsed
}

// r990Timestamp extracts the timestamp option words of a generated packet.
func r990Timestamp(t *testing.T, packet *Packet) (tsval uint32, tsecr uint32, ok bool) {
	t.Helper()
	options := packet.TCPOptions
	for index := 0; index < len(options); {
		kind := options[index]
		if kind == 0 {
			return 0, 0, false
		}
		if kind == 1 {
			index++
			continue
		}
		if index+1 >= len(options) {
			return 0, 0, false
		}
		length := int(options[index+1])
		if length < 2 || index+length > len(options) {
			return 0, 0, false
		}
		if kind == 8 {
			if length != 10 {
				t.Fatalf("timestamp option length = %d", length)
			}
			return binary.BigEndian.Uint32(options[index+2:]),
				binary.BigEndian.Uint32(options[index+6:]), true
		}
		index += length
	}
	return 0, 0, false
}

// TestR990FakePreservesTemplateTimestampEcho pins darkmagic.c:170-176 on the
// real fake caller: a timestamped template with a nonzero TSecr must keep that
// echo, and only the decorated TSval moves by the configured increment. Real
// multisplit intervals of the same batch keep both template words.
func TestR990FakePreservesTemplateTimestampEcho(t *testing.T) {
	packet := r990IPv4TCP(t, []byte("GET / HTTP/1.1\r\n"), 0x1234, true)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake","multisplit"],
		"fake":{"repeats":2,"fooling":["ts"],"ts_increment":-600000,"payloads":[{"protocol":"unknown","hex":"aabb"}]},
		"multisplit":{"split_pos":["8"]}}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 4 || batch.Original != VerdictDrop {
		t.Fatalf("batch = %d packets verdict %v, want 4/drop", len(batch.Packets), batch.Original)
	}
	increment := int32(-600000)
	wantFakeTSVal := uint32(int32(1111) + increment)
	for index := 0; index < 2; index++ {
		verifyTCPChecksum(t, batch.Packets[index])
		fake := parseAll(t, batch.Packets[index:index+1])[0]
		if fake.TCPSeq != packet.TCPSeq || fake.TCPFlags != packet.TCPFlags || fake.TTL != packet.TTL {
			t.Fatalf("fake %d control bytes seq=%d flags=%#x ttl=%d", index,
				fake.TCPSeq, fake.TCPFlags, fake.TTL)
		}
		if !bytes.Equal(fake.Payload, []byte{0xaa, 0xbb}) {
			t.Fatalf("fake %d payload = %x", index, fake.Payload)
		}
		tsval, tsecr, ok := r990Timestamp(t, fake)
		if !ok {
			t.Fatalf("fake %d lost the copied timestamp option", index)
		}
		if tsval != wantFakeTSVal {
			t.Fatalf("fake %d TSval = %d, want %d", index, tsval, wantFakeTSVal)
		}
		if tsecr != 2222 {
			t.Fatalf("fake %d TSecr = %d, want template echo 2222", index, tsecr)
		}
	}
	for index := 2; index < 4; index++ {
		verifyTCPChecksum(t, batch.Packets[index])
		real := parseAll(t, batch.Packets[index:index+1])[0]
		tsval, tsecr, ok := r990Timestamp(t, real)
		if !ok || tsval != 1111 || tsecr != 2222 {
			t.Fatalf("real interval %d timestamp tsval=%d tsecr=%d ok=%v, want 1111/2222",
				index, tsval, tsecr, ok)
		}
	}
	// Absent timestamp control: the same decorated fake must build without a
	// timestamp option and without an error.
	bare := r990IPv4TCP(t, []byte("GET / HTTP/1.1\r\n"), 0x1234, false)
	bareBatch, err := PlanTCP(rule, bare, bare.Payload, 0, Facts{})
	if err != nil {
		t.Fatalf("absent timestamp control: %v", err)
	}
	if len(bareBatch.Packets) != 4 {
		t.Fatalf("absent timestamp control packets = %d", len(bareBatch.Packets))
	}
	bareFake := parseAll(t, bareBatch.Packets[0:1])[0]
	if _, _, ok := r990Timestamp(t, bareFake); ok {
		t.Fatal("absent timestamp control gained a timestamp option")
	}
}

// TestR990FakeRepeatsShareOneIPID pins desync.c:1991-2008: one fake payload
// item is built once and its repeats reuse the exact bytes and IP ID; the next
// distinct payload item advances the cursor once.
func TestR990FakeRepeatsShareOneIPID(t *testing.T) {
	packet := r990IPv4TCP(t, []byte("0123456789abcdef"), 0x1234, false)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],
		"fake":{"repeats":8,"payloads":[{"protocol":"unknown","hex":"aabb"}]}}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 8 {
		t.Fatalf("fake packets = %d, want 8", len(batch.Packets))
	}
	first := parseAll(t, batch.Packets[0:1])[0]
	if first.IPID != 0x1234 {
		t.Fatalf("first fake ID = %d, want template ID 4660", first.IPID)
	}
	for index := 1; index < len(batch.Packets); index++ {
		if !bytes.Equal(batch.Packets[index], batch.Packets[0]) {
			t.Fatalf("fake repeat %d differs from the first built packet", index)
		}
	}

	// Two distinct payload items: each group shares one ID, and the second
	// group consumes exactly one cursor step.
	twoRule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],
		"fake":{"repeats":3,"payloads":[{"protocol":"unknown","hex":"aa"},{"protocol":"unknown","hex":"bb"}]}}]}`)
	twoBatch, err := PlanTCP(twoRule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(twoBatch.Packets) != 6 {
		t.Fatalf("two-payload packets = %d, want 6", len(twoBatch.Packets))
	}
	wantIDs := []uint16{0x1234, 0x1234, 0x1234, 0x1235, 0x1235, 0x1235}
	wantPayloads := [][]byte{{0xaa}, {0xbb}}
	for index, raw := range twoBatch.Packets {
		generated := parseAll(t, [][]byte{raw})[0]
		if generated.IPID != wantIDs[index] {
			t.Fatalf("payload group %d ID = %d, want %d", index, generated.IPID, wantIDs[index])
		}
		if !bytes.Equal(generated.Payload, wantPayloads[index/3]) {
			t.Fatalf("payload group %d data = %x", index, generated.Payload)
		}
	}
}

// TestR990FakeToMultiSplitIPIDSequence pins the shared cursor across stages:
// eight fake repeats keep the captured ID, then the two multisplit intervals
// take the next sequential IDs (desync.c:2007/2301).
func TestR990FakeToMultiSplitIPIDSequence(t *testing.T) {
	packet := r990IPv4TCP(t, []byte("0123456789abcdef"), 0x1234, false)
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake","multisplit"],
		"fake":{"repeats":8,"payloads":[{"protocol":"unknown","hex":"aabb"}]},
		"multisplit":{"split_pos":["8"]}}]}`)
	batch, err := PlanTCP(rule, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 10 || batch.Original != VerdictDrop {
		t.Fatalf("batch = %d packets verdict %v, want 10/drop", len(batch.Packets), batch.Original)
	}
	wantIDs := []uint16{0x1234, 0x1234, 0x1234, 0x1234,
		0x1234, 0x1234, 0x1234, 0x1234, 0x1235, 0x1236}
	for index, raw := range batch.Packets {
		generated := parseAll(t, [][]byte{raw})[0]
		if generated.IPID != wantIDs[index] {
			t.Fatalf("packet %d ID = %d, want %d", index, generated.IPID, wantIDs[index])
		}
	}
	for index := 1; index < 8; index++ {
		if !bytes.Equal(batch.Packets[index], batch.Packets[0]) {
			t.Fatalf("fake repeat %d differs from the first fake", index)
		}
	}
	first := parseAll(t, batch.Packets[8:9])[0]
	second := parseAll(t, batch.Packets[9:10])[0]
	if !bytes.Equal(first.Payload, packet.Payload[:8]) || !bytes.Equal(second.Payload, packet.Payload[8:]) {
		t.Fatalf("split payload layout = %x / %x", first.Payload, second.Payload)
	}
	if first.TCPSeq != packet.TCPSeq || second.TCPSeq != packet.TCPSeq+8 {
		t.Fatalf("split seq = %d/%d", first.TCPSeq, second.TCPSeq)
	}
}

// TestR990IPIDModesAndIPv6Controls keeps the explicit upstream modes and the
// IPv6 (no IPv4 ID field) behaviour intact around the repaired cursor.
func TestR990IPIDModesAndIPv6Controls(t *testing.T) {
	packet := r990IPv4TCP(t, []byte("0123456789abcdef"), 0x1234, false)
	modeRule := func(ipid string) *Rule {
		return mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake","multisplit"],
			"ip_id":"`+ipid+`",
			"fake":{"repeats":2,"payloads":[{"protocol":"unknown","hex":"aabb"}]},
			"multisplit":{"split_pos":["8"]}}]}`)
	}
	// No fake at all: the first interval takes IP4_IP_ID_FIX (the captured
	// non-zero ID) and the second takes IP4_IP_ID_NEXT.
	noFake := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["multisplit"],
		"multisplit":{"split_pos":["8"]}}]}`)
	batch, err := PlanTCP(noFake, packet, packet.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 2 {
		t.Fatalf("no-fake packets = %d, want 2", len(batch.Packets))
	}
	for index, want := range []uint16{0x1234, 0x1235} {
		generated := parseAll(t, batch.Packets[index:index+1])[0]
		if generated.IPID != want {
			t.Fatalf("no-fake interval %d ID = %d, want %d", index, generated.IPID, want)
		}
	}

	cases := []struct {
		mode string
		want func(index int) uint16
	}{
		{"zero", func(int) uint16 { return 0 }},
		{"same", func(int) uint16 { return 0x1234 }},
		{"rnd", func(int) uint16 { return 0 }}, // checked for non-zero below
	}
	for _, testCase := range cases {
		batch, err := PlanTCP(modeRule(testCase.mode), packet, packet.Payload, 0, Facts{})
		if err != nil {
			t.Fatalf("mode %s: %v", testCase.mode, err)
		}
		if len(batch.Packets) != 4 {
			t.Fatalf("mode %s packets = %d", testCase.mode, len(batch.Packets))
		}
		for index, raw := range batch.Packets {
			generated := parseAll(t, [][]byte{raw})[0]
			if testCase.mode == "rnd" {
				if generated.IPID == 0 {
					t.Fatalf("rnd mode packet %d has ID 0", index)
				}
				continue
			}
			if want := testCase.want(index); generated.IPID != want {
				t.Fatalf("mode %s packet %d ID = %d, want %d", testCase.mode, index, generated.IPID, want)
			}
		}
		if testCase.mode == "rnd" && !bytes.Equal(batch.Packets[0], batch.Packets[1]) {
			t.Fatal("rnd mode fake repeats must reuse the one allocated packet")
		}
	}

	// IPv6 has no IPv4 ID word; repeats must still reuse one built packet and
	// the split layout must stay intact.
	ipv6 := buildIPv6TCP(t, []byte("0123456789abcdef"), 2000, tcpFlagACK|tcpFlagPSH)
	ipv6Rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake","multisplit"],
		"fake":{"repeats":3,"fooling":["ts"],"payloads":[{"protocol":"unknown","hex":"aabb"}]},
		"multisplit":{"split_pos":["8"]}}]}`)
	ipv6Batch, err := PlanTCP(ipv6Rule, ipv6, ipv6.Payload, 0, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ipv6Batch.Packets) != 5 {
		t.Fatalf("IPv6 packets = %d, want 5", len(ipv6Batch.Packets))
	}
	for index := 1; index < 3; index++ {
		if !bytes.Equal(ipv6Batch.Packets[index], ipv6Batch.Packets[0]) {
			t.Fatalf("IPv6 fake repeat %d differs", index)
		}
	}
	for index, want := range [][]byte{ipv6.Payload[:8], ipv6.Payload[8:]} {
		generated := parseAll(t, ipv6Batch.Packets[3+index:4+index])[0]
		if !bytes.Equal(generated.Payload, want) {
			t.Fatalf("IPv6 split %d payload = %x", index, generated.Payload)
		}
	}
}

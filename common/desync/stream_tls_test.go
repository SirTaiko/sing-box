package desync

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// Source mapping: tpws tamper.c TLS branch and protocol.c TLSFindExt /
// TLSPos (zapret v72.9 c849e55e). A ClientHello record is split into two
// records at the resolved position; the second record keeps content type and
// version bytes and both lengths are rewritten.

func expectedTLSRecordSplit(t *testing.T, record []byte, position int) []byte {
	t.Helper()
	length := int(record[3])<<8 | int(record[4])
	if position <= 5 {
		t.Fatal("position must be inside the handshake body")
	}
	if position-5 >= length {
		position = 6
	}
	expected := make([]byte, 0, len(record)+5)
	expected = append(expected, record[0:3]...)
	expected = append(expected, byte((position-5)>>8), byte(position-5))
	expected = append(expected, record[5:position]...)
	expected = append(expected, record[0:3]...)
	firstLength := length - (position - 5)
	expected = append(expected, byte(firstLength>>8), byte(firstLength))
	expected = append(expected, record[position:]...)
	return expected
}

func splitHello(t *testing.T, host string, spec *tlsRecordSpec, positions []int) ([]byte, []int) {
	t.Helper()
	record := buildClientHello(host)
	block := make([]byte, len(record), streamBlockCapacity)
	copy(block, record)
	facts, ok := tlsRecordFacts(block)
	if !ok {
		t.Fatal("fixture ClientHello facts failed")
	}
	split, shifted, applied := splitTLSRecord(block, spec, streamFactSet{Facts: facts}, positions)
	if !applied {
		t.Fatal("record split was not applied")
	}
	return split, shifted
}

func TestTLSRecordFactsAnchors(t *testing.T) {
	record := buildClientHello("example.com")
	facts, ok := tlsRecordFacts(record)
	if !ok {
		t.Fatal("facts parse failed")
	}
	if facts.Host != "example.com" || !facts.HostKnown {
		t.Fatalf("host=%q", facts.Host)
	}
	if !bytes.Equal(record[facts.HostStart:facts.HostEnd], []byte("example.com")) {
		t.Fatalf("host anchors %d:%d", facts.HostStart, facts.HostEnd)
	}
	valueStart := bytes.Index(record, []byte("example.com"))
	if facts.SNIExtEnd != valueStart-5 {
		t.Fatalf("SNI extension anchor %d, want %d", facts.SNIExtEnd, valueStart-5)
	}
	if got := string(record[facts.SLDStart:facts.SLDEnd]); got != "example" {
		t.Fatalf("SLD anchors = %q", got)
	}
}

func TestTLSRecordSplitNumericGolden(t *testing.T) {
	record := buildClientHello("example.com")
	split, _ := splitHello(t, "example.com", &tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: 10}}, nil)
	if len(split) != len(record)+5 {
		t.Fatalf("split length %d, want %d", len(split), len(record)+5)
	}
	if got := split[3:5]; !bytes.Equal(got, []byte{0x00, 0x05}) {
		t.Fatalf("first record length = %x", got)
	}
	if got := split[5:10]; !bytes.Equal(got, record[5:10]) {
		t.Fatalf("first record payload differs: %x vs %x", got, record[5:10])
	}
	if !bytes.Equal(split[10:13], record[0:3]) {
		t.Fatalf("second record header %x, want %x", split[10:13], record[0:3])
	}
	firstLength := (int(record[3])<<8 | int(record[4])) - 5
	if got := int(split[13])<<8 | int(split[14]); got != firstLength {
		t.Fatalf("second record length %d, want %d", got, firstLength)
	}
	if !bytes.Equal(split[15:], record[10:]) {
		t.Fatal("second record payload must preserve the remaining handshake bytes")
	}
	if want := expectedTLSRecordSplit(t, record, 10); !bytes.Equal(split, want) {
		t.Fatalf("full record bytes differ\n got %x\nwant %x", split, want)
	}
}

func TestTLSRecordSplitDeprecatedSNIAlias(t *testing.T) {
	record := buildClientHello("example.com")
	facts, _ := tlsRecordFacts(record)
	// tlsrec/split-tls "sni" is PM_HOST with pos=1.
	split, _ := splitHello(t, "example.com", &tlsRecordSpec{position: Position{Kind: positionHost, Offset: 1}}, nil)
	position := facts.HostStart + 1
	if got := int(split[3])<<8 | int(split[4]); got != position-5 {
		t.Fatalf("split position %d, want %d", got, position-5)
	}
	if !bytes.Equal(split, expectedTLSRecordSplit(t, record, position)) {
		t.Fatal("sni alias split bytes differ from the source formula")
	}
}

func TestTLSRecordSplitPositionBeyondRecordClampsToSix(t *testing.T) {
	record := buildClientHello("example.com")
	length := int(record[3])<<8 | int(record[4])
	// tpos-5 >= record length but tpos is still inside the block (the block
	// carries bytes after the first record) => tpws sets tpos = 5+1.
	block := make([]byte, len(record)+64, streamBlockCapacity)
	copy(block, record)
	position := length + 6
	facts, ok := tlsRecordFacts(block)
	if !ok {
		t.Fatal("facts parse failed")
	}
	expected := expectedTLSRecordSplit(t, block, position)
	split, _, applied := splitTLSRecord(block, &tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: position}}, streamFactSet{Facts: facts}, nil)
	if !applied {
		t.Fatal("record split was not applied")
	}
	if got := int(split[3])<<8 | int(split[4]); got != 1 {
		t.Fatalf("clamped first record payload = %d, want 1", got)
	}
	if !bytes.Equal(split, expected) {
		t.Fatal("clamped split bytes differ")
	}
}

func TestTLSRecordSplitDoesNotApplyOutsideRecord(t *testing.T) {
	record := buildClientHello("example.com")
	block := make([]byte, len(record), streamBlockCapacity)
	copy(block, record)
	facts, _ := tlsRecordFacts(block)
	for _, position := range []int{1, 5, len(record) + 5} {
		_, _, applied := splitTLSRecord(block, &tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: position}}, streamFactSet{Facts: facts}, nil)
		if position <= 5 && applied {
			t.Fatalf("split at %d must not apply", position)
		}
	}
}

func TestTLSRecordSplitShiftsSplitPositions(t *testing.T) {
	_, shifted := splitHello(t, "example.com",
		&tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: 10}}, []int{4, 10, 12, 20})
	want := []int{4, 10, 17, 25}
	if len(shifted) != len(want) {
		t.Fatalf("shifted = %v", shifted)
	}
	for index := range want {
		if shifted[index] != want[index] {
			t.Fatalf("shifted = %v, want %v", shifted, want)
		}
	}
}

func TestTLSMultiRecordHelloFacts(t *testing.T) {
	hello := buildClientHello("multi.example")
	// Split the handshake body across two records, like a partial/multirecord
	// ClientHello. Matching must still recover the SNI.
	recordLength := int(hello[3])<<8 | int(hello[4])
	handshake := hello[5 : 5+recordLength]
	cut := 20
	first := append([]byte{0x16, 0x03, 0x01, byte(cut >> 8), byte(cut)}, handshake[:cut]...)
	second := append([]byte{0x16, 0x03, 0x01, byte((len(handshake) - cut) >> 8), byte(len(handshake) - cut)}, handshake[cut:]...)
	message := append(first, second...)
	set := streamBlockFacts(ProtocolTLS, message)
	if !set.HostKnown || set.Host != "multi.example" {
		t.Fatalf("multirecord host=%q known=%v", set.Host, set.HostKnown)
	}
	if _, needMore := classifyStreamBlock(message); needMore {
		t.Fatal("complete two-record message must not ask for more bytes")
	}
	partial := message[:len(first)-3]
	if protocol, needMore := classifyStreamBlock(partial); protocol != ProtocolUnknown || !needMore {
		t.Fatalf("partial record protocol=%v needMore=%v", protocol, needMore)
	}
}

func TestCompileTLSRecordPositionAliases(t *testing.T) {
	build := func(pos string, numeric int) (*tlsRecordSpec, error) {
		return compileTLSRecord(&option.DirectDesyncStreamTLSRecord{Pos: pos, RecordPos: numeric})
	}
	for _, value := range []string{"10", "-10", "host", "endhost", "sld", "endsld", "midsld", "sniext", "sni", "snisld", "host+2", "midsld-1"} {
		if _, err := build(value, 0); err != nil {
			t.Fatalf("position %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"0", "bogus", "sni+x"} {
		if _, err := build(value, 0); err == nil {
			t.Fatalf("position %q must be rejected", value)
		}
	}
	spec, err := build("", 7)
	if err != nil || spec.position.Kind != positionAbsolute || spec.position.Offset != 7 {
		t.Fatalf("record_pos alias: %+v %v", spec, err)
	}
	if _, err = build("10", 7); err == nil {
		t.Fatal("both pos and record_pos must be rejected")
	}
}

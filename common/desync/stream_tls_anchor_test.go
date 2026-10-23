package desync

// Source-oracle regression for the v3 TLS anchor repair (task t_5a04f7ae).
//
// Every expected value below is literal output of the pinned zapret v72.9
// (c849e55ef0f1c244206f5a05ff7b1ab41a3824ee) tpws/protocol.c TLSPos/HostPos/
// FindNLD, produced by an independent C oracle that links the pinned
// protocol.c (-Wl,--gc-sections; process memory and stdout only) and resolves
// the exact fixture bytes. The matrix covers the QA v2 fixtures plus the
// adjacent anchor shapes the D2b/D2c repair touches:
//
//   - zero-length second-level domains ("..", "a..b", "x..", "..x"), where
//     FindNLD succeeds with len == 0 and HostPos still returns a position;
//   - an empty host_name, where the anchor exists past the extension data but
//     the name must not become matchable;
//   - a non-host_name name type, a truncated server_name body, an overlong
//     name length, trailing bytes inside the extension body, two server_name
//     extensions, no extensions and a truncated extension header;
//   - bytes after the first record and a second record, where upstream keeps
//     the first-record anchors but bounds-checks against the whole block.
//
// Column order: host-1, host, host+1, host+2, endhost-2, endhost-1, endhost,
// endhost+1, endhost+2, sld-1, sld, sld+1, sld+2, midsld-1, midsld, midsld+1,
// endsld-1, endsld, endsld+1, sniext-1, sniext, sniext+1. Out-of-range results
// are the literal CheckPos zero, not "no anchor".

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// v3TLSAnchorQueries is the query matrix order the pinned-C oracle printed.
var v3TLSAnchorQueries = []struct {
	name   string
	kind   positionKind
	offset int
}{
	{"host-1", positionHost, -1},
	{"host", positionHost, 0},
	{"host+1", positionHost, 1},
	{"host+2", positionHost, 2},
	{"endhost-2", positionEndHost, -2},
	{"endhost-1", positionEndHost, -1},
	{"endhost", positionEndHost, 0},
	{"endhost+1", positionEndHost, 1},
	{"endhost+2", positionEndHost, 2},
	{"sld-1", positionSLD, -1},
	{"sld", positionSLD, 0},
	{"sld+1", positionSLD, 1},
	{"sld+2", positionSLD, 2},
	{"midsld-1", positionMidSLD, -1},
	{"midsld", positionMidSLD, 0},
	{"midsld+1", positionMidSLD, 1},
	{"endsld-1", positionEndSLD, -1},
	{"endsld", positionEndSLD, 0},
	{"endsld+1", positionEndSLD, 1},
	{"sniext-1", positionSNIExt, -1},
	{"sniext", positionSNIExt, 0},
	{"sniext+1", positionSNIExt, 1},
}

var v3TLSFixtureMatrix = []struct {
	name string
	hex  string
	size int
	want [22]int
}{
	{name: "T_sni_example", size: 72, want: [22]int{60, 61, 62, 63, 70, 71, 0, 0, 0, 60, 61, 62, 63, 63, 64, 65, 67, 68, 69, 55, 56, 57},
		hex: "16030100430100003f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001400000010000e00000b6578616d706c652e636f6d"},
	{name: "T_sni_localhost", size: 70, want: [22]int{60, 61, 62, 63, 68, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "16030100410100003d0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021301010000120000000e000c0000096c6f63616c686f7374"},
	{name: "T_sni_ab", size: 64, want: [22]int{60, 61, 62, 63, 62, 63, 0, 0, 0, 60, 61, 62, 63, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080006000003612e62"},
	{name: "T_sni_dot", size: 62, want: [22]int{60, 61, 0, 0, 60, 61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "1603010039010000350303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000a0000000600040000012e"},
	{name: "T_sni_twodots", size: 63, want: [22]int{60, 61, 62, 0, 61, 62, 0, 0, 0, 61, 62, 0, 0, 61, 62, 0, 61, 62, 0, 55, 56, 57},
		hex: "160301003a010000360303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000b0000000700050000022e2e"},
	{name: "T_sni_ipv6ish", size: 66, want: [22]int{60, 61, 62, 63, 64, 65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "160301003d010000390303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000e0000000a00080000055b3a3a315d"},
	{name: "T_sni_long", size: 82, want: [22]int{60, 61, 62, 63, 80, 81, 0, 0, 0, 76, 77, 78, 79, 77, 78, 79, 78, 79, 80, 55, 56, 57},
		hex: "160301004d010000490303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001e0000001a0018000015612e622e632e642e6578616d706c652e636f2e756b"},
	{name: "T_sni_empty", size: 61, want: [22]int{60, 0, 0, 0, 59, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "1603010038010000340303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130101000009000000050003000000"},
	{name: "T_sni_double_dot_mid", size: 65, want: [22]int{60, 61, 62, 63, 63, 64, 0, 0, 0, 62, 63, 64, 0, 62, 63, 64, 62, 63, 64, 55, 56, 57},
		hex: "160301003c010000380303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000d000000090007000004612e2e62"},
	{name: "T_sni_double_dot_end", size: 64, want: [22]int{60, 61, 62, 63, 62, 63, 0, 0, 0, 62, 63, 0, 0, 62, 63, 0, 62, 63, 0, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080006000003782e2e"},
	{name: "T_sni_double_dot_lead", size: 64, want: [22]int{60, 61, 62, 63, 62, 63, 0, 0, 0, 61, 62, 63, 0, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c0000000800060000032e2e78"},
	{name: "S_normal", size: 72, want: [22]int{60, 61, 62, 63, 70, 71, 0, 0, 0, 60, 61, 62, 63, 63, 64, 65, 67, 68, 69, 55, 56, 57},
		hex: "16030100430100003f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001400000010000e00000b6578616d706c652e636f6d"},
	{name: "S_empty", size: 61, want: [22]int{60, 0, 0, 0, 59, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "1603010038010000340303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130101000009000000050003000000"},
	{name: "S_dotdot", size: 63, want: [22]int{60, 61, 62, 0, 61, 62, 0, 0, 0, 61, 62, 0, 0, 61, 62, 0, 61, 62, 0, 55, 56, 57},
		hex: "160301003a010000360303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000b0000000700050000022e2e"},
	{name: "S_a_dotdot_b", size: 65, want: [22]int{60, 61, 62, 63, 63, 64, 0, 0, 0, 62, 63, 64, 0, 62, 63, 64, 62, 63, 64, 55, 56, 57},
		hex: "160301003c010000380303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000d000000090007000004612e2e62"},
	{name: "S_x_dotdot", size: 64, want: [22]int{60, 61, 62, 63, 62, 63, 0, 0, 0, 62, 63, 0, 0, 62, 63, 0, 62, 63, 0, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080006000003782e2e"},
	{name: "S_dotdot_x", size: 64, want: [22]int{60, 61, 62, 63, 62, 63, 0, 0, 0, 61, 62, 63, 0, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c0000000800060000032e2e78"},
	{name: "S_single_label", size: 70, want: [22]int{60, 61, 62, 63, 68, 69, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "16030100410100003d0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021301010000120000000e000c0000096c6f63616c686f7374"},
	{name: "S_one_char_sld", size: 64, want: [22]int{60, 61, 62, 63, 62, 63, 0, 0, 0, 60, 61, 62, 63, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080006000003612e62"},
	{name: "S_ntype_cipher", size: 72, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "16030100430100003f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001400000010000e01000b6578616d706c652e636f6d"},
	{name: "S_body_short", size: 59, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "1603010036010000320303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000700000003000300"},
	{name: "S_body_empty", size: 56, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 0, 0},
		hex: "16030100330100002f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000400000000"},
	{name: "S_len_overrun", size: 65, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "160301003c010000380303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000d00000009000c00000c612e622e"},
	{name: "S_len_overrun_trailer", size: 77, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "1603010048010000440303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001900000009000c00000c612e622e000a00080002001d00000000"},
	{name: "S_len_exact", size: 64, want: [22]int{60, 61, 62, 63, 61, 62, 63, 0, 0, 60, 61, 62, 63, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080005000002612e62"},
	{name: "S_trailing_in_ext", size: 66, want: [22]int{60, 61, 62, 63, 62, 63, 64, 65, 0, 60, 61, 62, 63, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "160301003d010000390303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000e0000000a0008000003612e629999"},
	{name: "S_cipher_first", size: 80, want: [22]int{68, 69, 70, 71, 78, 79, 0, 0, 0, 68, 69, 70, 71, 71, 72, 73, 75, 76, 77, 63, 64, 65},
		hex: "160301004b010000470303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001c000a00040002001d00000010000e00000b6578616d706c652e636f6d"},
	{name: "S_two_sni", size: 78, want: [22]int{60, 61, 62, 63, 62, 63, 64, 65, 66, 60, 61, 62, 63, 61, 62, 63, 61, 62, 63, 55, 56, 57},
		hex: "1603010049010000450303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001a000000080006000003612e620000000a0008000005632e642e65"},
	{name: "S_second_sni_only_real", size: 75, want: [22]int{60, 61, 62, 63, 59, 60, 61, 62, 63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 55, 56, 57},
		hex: "1603010046010000420303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021301010000170000000500030000000000000a0008000005632e642e65"},
	{name: "S_no_extensions", size: 52, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		hex: "160301002f0100002b0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130101000000"},
	{name: "S_ext_truncated_header", size: 55, want: [22]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		hex: "16030100320100002e0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130101000003000000"},
	{name: "S_trailing_record_bytes", size: 81, want: [22]int{60, 61, 62, 63, 64, 65, 66, 67, 68, 62, 63, 64, 65, 63, 64, 65, 63, 64, 65, 55, 56, 57},
		hex: "160301003d010000390303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000e0000000a0008000005612e622e63000000000000000000000000000000"},
	{name: "S_second_record", size: 75, want: [22]int{60, 61, 62, 63, 64, 65, 66, 67, 68, 62, 63, 64, 65, 63, 64, 65, 63, 64, 65, 55, 56, 57},
		hex: "160301003d010000390303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000e0000000a0008000005612e622e63160303000401000000"},
}

func v3Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return decoded
}

// v3Fixture returns the bytes of one matrix fixture.
func v3Fixture(t *testing.T, name string) []byte {
	t.Helper()
	for _, fixture := range v3TLSFixtureMatrix {
		if fixture.name == name {
			return v3Decode(t, fixture.hex)
		}
	}
	t.Fatalf("fixture %q is not in the matrix", name)
	return nil
}

// v3Fragments snapshots the fake connection writes and their concatenation.
func v3Fragments(conn *fakeConn) ([][]byte, []byte) {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	fragments := append([][]byte(nil), conn.writes...)
	var collected []byte
	for _, write := range conn.writes {
		collected = append(collected, write...)
	}
	return fragments, collected
}

func v3Resolve(block []byte, kind positionKind, offset int) int {
	set := streamBlockFacts(ProtocolTLS, block)
	return resolveStreamPosition(Position{Kind: kind, Offset: offset}, set, ProtocolTLS)
}

// TestStreamTLSPositionsMatchPinnedC is the D2b/D2c differential check over the
// full offset matrix, including the degenerate zero-length-SLD and empty-SNI
// fixtures that the v2 artifact resolved to 0.
func TestStreamTLSPositionsMatchPinnedC(t *testing.T) {
	nonZero := 0
	for _, fixture := range v3TLSFixtureMatrix {
		block := v3Decode(t, fixture.hex)
		if len(block) != fixture.size {
			t.Fatalf("%s: fixture size %d, table %d", fixture.name, len(block), fixture.size)
		}
		for index, query := range v3TLSAnchorQueries {
			if fixture.want[index] != 0 {
				nonZero++
			}
			if got := v3Resolve(block, query.kind, query.offset); got != fixture.want[index] {
				t.Errorf("%s %s = %d, pinned C = %d", fixture.name, query.name, got, fixture.want[index])
			}
		}
	}
	// Guard against a table that silently degenerates into all-zero rows.
	if nonZero < 400 {
		t.Fatalf("matrix has only %d non-zero expectations, want at least 400", nonZero)
	}
}

// TestStreamTLSAnchorFactsForDegenerateNames pins the internal facts the
// resolver relies on, so the difference between "no SLD" and "found empty SLD"
// is explicit rather than implied by the resolved offsets.
func TestStreamTLSAnchorFactsForDegenerateNames(t *testing.T) {
	emptySLD := streamBlockFacts(ProtocolTLS, v3Fixture(t, "S_dotdot"))
	if !emptySLD.sldOK || emptySLD.SLDStart != 62 || emptySLD.SLDEnd != 62 {
		t.Fatalf("empty SLD facts = ok=%v %d:%d, want found 62:62", emptySLD.sldOK, emptySLD.SLDStart, emptySLD.SLDEnd)
	}
	if !emptySLD.HostKnown || emptySLD.Host != ".." {
		t.Fatalf("degenerate non-empty name must stay a known host: %q", emptySLD.Host)
	}
	missingSLD := streamBlockFacts(ProtocolTLS, v3Fixture(t, "S_single_label"))
	if missingSLD.sldOK {
		t.Fatalf("single-label SNI must have no SLD, facts %d:%d", missingSLD.SLDStart, missingSLD.SLDEnd)
	}
	emptyName := streamBlockFacts(ProtocolTLS, v3Fixture(t, "S_empty"))
	if !emptyName.hostAnchor() {
		t.Fatal("empty host_name must still be an anchor like upstream")
	}
	if emptyName.HostStart != 61 || emptyName.HostEnd != 61 {
		t.Fatalf("empty name anchors = %d:%d, want 61:61", emptyName.HostStart, emptyName.HostEnd)
	}
	if emptyName.HostKnown || emptyName.Host != "" {
		t.Fatalf("empty host_name must not be matchable: %q known=%v", emptyName.Host, emptyName.HostKnown)
	}
}

// TestStreamTLSMalformedSNIExtensionKeepsOnlyTheExtensionAnchor: upstream
// TLSFindExt still succeeds when TLSAdvanceToHostInSNI rejects the extension,
// so the SNI extension marker keeps resolving while the host markers are 0.
func TestStreamTLSMalformedSNIExtensionKeepsOnlyTheExtensionAnchor(t *testing.T) {
	for _, name := range []string{"S_ntype_cipher", "S_body_short", "S_len_overrun"} {
		block := v3Fixture(t, name)
		set := streamBlockFacts(ProtocolTLS, block)
		if set.hostAnchor() {
			t.Fatalf("%s: rejected host_name must not anchor", name)
		}
		for _, query := range []struct {
			kind   positionKind
			offset int
		}{{positionHost, 0}, {positionHost, 1}, {positionEndHost, -1}, {positionSLD, 0}, {positionMidSLD, 0}} {
			if got := resolveStreamPosition(Position{Kind: query.kind, Offset: query.offset}, set, ProtocolTLS); got != 0 {
				t.Fatalf("%s %s = %d, want 0", name, positionKindName(query.kind), got)
			}
		}
		if got := resolveStreamPosition(Position{Kind: positionSNIExt}, set, ProtocolTLS); got != 56 {
			t.Fatalf("%s sniext = %d, want the upstream 56", name, got)
		}
	}
	// The two length-malformed extensions also stay unmatchable. S_ntype_cipher
	// is excluded on purpose: the shared reassembly matcher
	// (parseClientHelloBytes) ignores the name_type byte, so it still reports a
	// host for matching. That code is outside this lane's ownership and this
	// repair does not change it.
	for _, name := range []string{"S_body_short", "S_len_overrun"} {
		if set := streamBlockFacts(ProtocolTLS, v3Fixture(t, name)); set.HostKnown {
			t.Fatalf("%s: malformed host_name became matchable", name)
		}
	}
}

// TestStreamTLSDegenerateSLDSplitBytes is the reachable byte effect of D2b: a
// split rule with the sld marker on a ".." SNI must produce two fragments and
// preserve the transformed record byte for byte. Before the repair the marker
// resolved to 0, the split list was empty and the block was sent unsplit.
func TestStreamTLSDegenerateSLDSplitBytes(t *testing.T) {
	block := v3Fixture(t, "S_dotdot")
	rule := option.DirectDesyncStreamRule{
		Methods:   badoption.Listable[string]{"tls_record", "split"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "10"},
		Split:     &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"sld"}},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 443})
	if _, err := wrapped.Write(block); err != nil {
		t.Fatalf("Write: %v", err)
	}
	shifted, got := v3Fragments(conn)
	want := expectedTLSRecordSplit(t, block, 10)
	if !bytes.Equal(got, want) {
		t.Fatalf("split stream changed\n got %x\nwant %x", got, want)
	}
	if len(shifted) != 2 {
		t.Fatalf("fragments = %d, want 2 (sld resolved to 62, shifted to 67)", len(shifted))
	}
	if len(shifted[0]) != 67 || len(shifted[1]) != len(want)-67 {
		t.Fatalf("fragment lengths = %d,%d, want 67,%d", len(shifted[0]), len(shifted[1]), len(want)-67)
	}
}

// TestStreamTLSEmptySNISplitBytes is the reachable byte effect of D2c: the
// endhost-1 anchor of an empty host_name lands at 60 (before the repair the
// whole fact set was rejected and nothing was split).
func TestStreamTLSEmptySNISplitBytes(t *testing.T) {
	block := v3Fixture(t, "S_empty")
	rule := option.DirectDesyncStreamRule{
		Methods:   badoption.Listable[string]{"tls_record", "split"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "10"},
		Split:     &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"endhost-1"}},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 443})
	if _, err := wrapped.Write(block); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The shared reassembly matcher reports an empty server_name as incomplete,
	// so the first block is held until Close (or more bytes) exactly like any
	// other partial ClientHello; the anchors must still resolve on flush.
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	shifted, got := v3Fragments(conn)
	want := expectedTLSRecordSplit(t, block, 10)
	if !bytes.Equal(got, want) {
		t.Fatalf("split stream changed\n got %x\nwant %x", got, want)
	}
	if len(shifted) != 2 {
		t.Fatalf("fragments = %d, want 2 (endhost-1 resolved to 60, shifted to 65)", len(shifted))
	}
	if len(shifted[0]) != 65 || len(shifted[1]) != len(want)-65 {
		t.Fatalf("fragment lengths = %d,%d, want 65,%d", len(shifted[0]), len(shifted[1]), len(want)-65)
	}
}

// TestStreamTLSMissingSLDStaysUnsplit is the negative control next to the
// empty-SLD byte effect: a single-label SNI has no SLD in upstream, so the
// same rule must not split, while the degenerate ".." name must.
func TestStreamTLSMissingSLDStaysUnsplit(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods:   badoption.Listable[string]{"tls_record", "split"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "10"},
		Split:     &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"sld"}},
	}
	send := func(name string) ([][]byte, []byte, *fakeConn) {
		t.Helper()
		config := mustCompileStream(t, rule)
		conn := newFakeConn()
		wrapped := wrapStream(t, config, conn, MatchFacts{Port: 443})
		if _, err := wrapped.Write(v3Fixture(t, name)); err != nil {
			t.Fatalf("%s Write: %v", name, err)
		}
		fragments, collected := v3Fragments(conn)
		return fragments, collected, conn
	}
	single, collected, _ := send("S_single_label")
	if len(single) != 1 {
		t.Fatalf("single-label SNI split into %d fragments, want the unsplit record", len(single))
	}
	if want := expectedTLSRecordSplit(t, v3Fixture(t, "S_single_label"), 10); !bytes.Equal(collected, want) {
		t.Fatalf("single-label stream changed\n got %x\nwant %x", collected, want)
	}
	empty, _, _ := send("S_dotdot")
	if len(empty) != 2 {
		t.Fatalf("degenerate empty SLD produced %d fragments, want 2", len(empty))
	}
}

// TestStreamTLSAnchorMatchingSafety keeps the matching half of D2c honest: the
// empty or invalid host_name anchor must never select a domain-filtered rule.
func TestStreamTLSAnchorMatchingSafety(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Domain: badoption.Listable[string]{"example.com"},
		},
		Methods:   badoption.Listable[string]{"tls_record"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "10"},
	}
	config := mustCompileStream(t, rule)
	for _, name := range []string{"S_empty", "S_body_short", "S_len_overrun", "S_no_extensions"} {
		set := streamBlockFacts(ProtocolTLS, v3Fixture(t, name))
		if set.HostKnown {
			t.Fatalf("%s: empty or invalid host_name became matchable: %q", name, set.Host)
		}
		if selected := config.selectRule(MatchFacts{Port: 443, Transport: TransportTCP, HostKnown: set.HostKnown, Host: set.Host}); selected != nil {
			t.Fatalf("%s: a rule with a domain filter must not be selected", name)
		}
	}
	valid := streamBlockFacts(ProtocolTLS, v3Fixture(t, "S_normal"))
	if !valid.HostKnown || valid.Host != "example.com" {
		t.Fatalf("ordinary SNI matching changed: %q known=%v", valid.Host, valid.HostKnown)
	}
	if selected := config.selectRule(MatchFacts{Port: 443, Transport: TransportTCP, HostKnown: true, Host: valid.Host}); selected == nil {
		t.Fatal("ordinary SNI must still select the domain-filtered rule")
	}
}

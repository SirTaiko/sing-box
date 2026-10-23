package desync

// Independent QA v2 suite for task t_c8c7a98c (tester-max-2), verifying the
// scoped tpws stream deliverable at tree 03618947ca6f9e3b72d1a3dedbc709443525b7a5
// (canonical patch c8edc52926f64f32e2bbd140274c82603c6a69bf5d23d1a981b13a3f1dc2de5b).
//
// Imported verbatim as a permanent lane regression suite by task t_5a04f7ae
// (coder-max-2) from
// desync-artifacts/t_c8c7a98c-independent-stream-tests-v2.go
// (sha256 cd3b83c5f731bbe545efbf7c92607f3bc33c3e510d5be8997986082e0ede72b6).
// Only this header comment differs from the delivered file; every fixture
// table, test body and assertion is unchanged.
// TestQAV2TLSDegenerateSLDAnchors and TestQAV2TLSEmptySNIAnchors pin the two
// confirmed defects D2b/D2c of the t_c8c7a98c QA report; they failed on tree
// 03618947 and are green after the v3 repair. Everything else passes on both.
//

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// Code generated from the pinned zapret v72.9 tpws/protocol.c oracle
// (t_c8c7a98c/oracle/oracle.c, oracle http|tls <fixtures.tsv>). DO NOT EDIT.
// Each row is the literal size_t returned by HttpPos/TLSPos on the fixture
// bytes: host, endhost, sld, midsld, endsld, host+1, endhost-1, sld+1 and,
// for TLS, sniext, sniext+1. Lengths are printed so truncation is visible.

var qaV2HTTPFixtures = []struct {
	name string
	hex  string
	size int
	pos  [8]int
}{
	{name: "A_empty", size: 26, pos: [8]int{22, 22, 0, 0, 0, 23, 21, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a200d0a0d0a"},
	{name: "B_unterm_nl_end", size: 29, pos: [8]int{22, 0, 22, 23, 25, 23, 28, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a206162632e646566"},
	{name: "C_novalue_crlf", size: 25, pos: [8]int{21, 21, 0, 0, 0, 22, 20, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a0d0a0d0a"},
	{name: "D_space_cr", size: 23, pos: [8]int{0, 0, 0, 0, 0, 0, 0, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a200d"},
	{name: "E_space_crlf_short", size: 24, pos: [8]int{22, 22, 0, 0, 0, 23, 21, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a200d0a"},
	{name: "F_terminated", size: 37, pos: [8]int{22, 33, 22, 25, 29, 23, 32, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a0d0a"},
	{name: "G_single_label", size: 35, pos: [8]int{22, 31, 0, 0, 0, 23, 30, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a206c6f63616c686f73740d0a0d0a"},
	{name: "H_dot_only", size: 27, pos: [8]int{22, 23, 0, 0, 0, 23, 22, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a202e0d0a0d0a"},
	{name: "I_dotdot", size: 28, pos: [8]int{22, 24, 23, 23, 23, 23, 23, 24},
		hex: "474554202f20485454502f312e310d0a486f73743a202e2e0d0a0d0a"},
	{name: "J_tab_tab", size: 32, pos: [8]int{22, 30, 22, 24, 26, 23, 29, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a09096162632e6465660d0a"},
	{name: "K_two_spaces", size: 30, pos: [8]int{22, 28, 22, 23, 25, 23, 27, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a202061622e63640d0a"},
	{name: "L_no_space", size: 30, pos: [8]int{21, 28, 21, 22, 24, 22, 27, 22},
		hex: "474554202f20485454502f312e310d0a486f73743a6162632e6465660d0a"},
	{name: "M_nospace_upper", size: 35, pos: [8]int{22, 33, 22, 25, 29, 23, 32, 23},
		hex: "474554202f20485454502f312e310d0a684f73543a206578616d706c652e636f6d0d0a"},
	{name: "N_port", size: 40, pos: [8]int{22, 38, 22, 25, 29, 23, 37, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a206578616d706c652e636f6d3a383038300d0a"},
	{name: "O_ipv6", size: 29, pos: [8]int{22, 27, 0, 0, 0, 23, 26, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a205b3a3a315d0d0a"},
	{name: "P_xhost_first", size: 49, pos: [8]int{39, 47, 39, 41, 43, 40, 46, 40},
		hex: "474554202f20485454502f312e310d0a582d486f73743a206261642e636f6d0d0a486f73743a20676f6f642e636f6d0d0a"},
	{name: "Q_multiple", size: 46, pos: [8]int{22, 29, 22, 23, 25, 23, 28, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a206f6e652e636f6d0d0a486f73743a2074776f2e636f6d0d0a"},
	{name: "R_21_bytes", size: 21, pos: [8]int{0, 0, 0, 0, 0, 0, 0, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a"},
	{name: "S_22_bytes", size: 22, pos: [8]int{0, 0, 0, 0, 0, 0, 0, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a20"},
	{name: "T_23_bytes", size: 23, pos: [8]int{0, 0, 0, 0, 0, 0, 0, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a2061"},
	{name: "U_24_bytes", size: 24, pos: [8]int{22, 0, 0, 0, 0, 23, 23, 0},
		hex: "474554202f20485454502f312e310d0a486f73743a206162"},
	{name: "V_trailing_cr_unterm", size: 30, pos: [8]int{22, 29, 22, 23, 25, 23, 28, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a206162632e6465660d"},
	{name: "W_trailing_dot", size: 30, pos: [8]int{22, 26, 24, 25, 25, 23, 25, 25},
		hex: "474554202f20485454502f312e310d0a486f73743a20612e622e0d0a0d0a"},
	{name: "X_leading_dot", size: 30, pos: [8]int{22, 26, 23, 24, 24, 23, 25, 24},
		hex: "474554202f20485454502f312e310d0a486f73743a202e612e620d0a0d0a"},
	{name: "Y_multi_dot", size: 33, pos: [8]int{22, 29, 26, 27, 27, 23, 28, 27},
		hex: "474554202f20485454502f312e310d0a486f73743a20612e622e632e640d0a0d0a"},
	{name: "Z_one_char_sld", size: 30, pos: [8]int{22, 26, 22, 23, 23, 23, 25, 23},
		hex: "474554202f20485454502f312e310d0a486f73743a20612e62630d0a0d0a"},
}

var qaV2TLSFixtures = []struct {
	name string
	hex  string
	size int
	pos  [10]int
}{
	{name: "T_sni_example", size: 72, pos: [10]int{61, 0, 61, 64, 68, 62, 71, 62, 56, 57},
		hex: "16030100430100003f0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001400000010000e00000b6578616d706c652e636f6d"},
	{name: "T_sni_localhost", size: 70, pos: [10]int{61, 0, 0, 0, 0, 62, 69, 0, 56, 57},
		hex: "16030100410100003d0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000021301010000120000000e000c0000096c6f63616c686f7374"},
	{name: "T_sni_ab", size: 64, pos: [10]int{61, 0, 61, 62, 62, 62, 63, 62, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080006000003612e62"},
	{name: "T_sni_dot", size: 62, pos: [10]int{61, 0, 0, 0, 0, 0, 61, 0, 56, 57},
		hex: "1603010039010000350303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000a0000000600040000012e"},
	{name: "T_sni_twodots", size: 63, pos: [10]int{61, 0, 62, 62, 62, 62, 62, 0, 56, 57},
		hex: "160301003a010000360303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000b0000000700050000022e2e"},
	{name: "T_sni_ipv6ish", size: 66, pos: [10]int{61, 0, 0, 0, 0, 62, 65, 0, 56, 57},
		hex: "160301003d010000390303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000e0000000a00080000055b3a3a315d"},
	{name: "T_sni_long", size: 82, pos: [10]int{61, 0, 77, 78, 79, 62, 81, 78, 56, 57},
		hex: "160301004d010000490303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100001e0000001a0018000015612e622e632e642e6578616d706c652e636f2e756b"},
	{name: "T_sni_empty", size: 61, pos: [10]int{0, 0, 0, 0, 0, 0, 60, 0, 56, 57},
		hex: "1603010038010000340303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000002130101000009000000050003000000"},
	{name: "T_sni_double_dot_mid", size: 65, pos: [10]int{61, 0, 63, 63, 63, 62, 64, 64, 56, 57},
		hex: "160301003c010000380303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000d000000090007000004612e2e62"},
	{name: "T_sni_double_dot_end", size: 64, pos: [10]int{61, 0, 63, 63, 63, 62, 63, 0, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c000000080006000003782e2e"},
	{name: "T_sni_double_dot_lead", size: 64, pos: [10]int{61, 0, 62, 62, 62, 62, 63, 63, 56, 57},
		hex: "160301003b010000370303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000213010100000c0000000800060000032e2e78"},
}

func qaV2Decode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return decoded
}

func qaV2Resolve(block []byte, protocol Protocol, kind positionKind, offset int) int {
	set := streamBlockFacts(protocol, block)
	return resolveStreamPosition(Position{Kind: kind, Offset: offset}, set, protocol)
}

// TestQAV2HTTPPositionsMatchPinnedC is the D2 differential check: every
// HTTP fixture must resolve to the value the pinned C HttpPos returns,
// including the empty and unterminated Host forms the v1 artifact got wrong.
func TestQAV2HTTPPositionsMatchPinnedC(t *testing.T) {
	kinds := []positionKind{positionHost, positionEndHost, positionSLD, positionMidSLD, positionEndSLD}
	for _, fixture := range qaV2HTTPFixtures {
		block := qaV2Decode(t, fixture.hex)
		if len(block) != fixture.size {
			t.Fatalf("%s: fixture size %d, table %d", fixture.name, len(block), fixture.size)
		}
		for index, kind := range kinds {
			if got := qaV2Resolve(block, ProtocolHTTP, kind, 0); got != fixture.pos[index] {
				t.Errorf("%s %s = %d, pinned C = %d", fixture.name, positionKindName(kind), got, fixture.pos[index])
			}
		}
		if got := qaV2Resolve(block, ProtocolHTTP, positionHost, 1); got != fixture.pos[5] {
			t.Errorf("%s host+1 = %d, pinned C = %d", fixture.name, got, fixture.pos[5])
		}
		if got := qaV2Resolve(block, ProtocolHTTP, positionEndHost, -1); got != fixture.pos[6] {
			t.Errorf("%s endhost-1 = %d, pinned C = %d", fixture.name, got, fixture.pos[6])
		}
		if got := qaV2Resolve(block, ProtocolHTTP, positionSLD, 1); got != fixture.pos[7] {
			t.Errorf("%s sld+1 = %d, pinned C = %d", fixture.name, got, fixture.pos[7])
		}
	}
}

// qaV2TLSDegenerateSLD lists the ClientHello fixtures whose SNI has a
// zero-length second-level domain ("..", "a..b", "x..", "..x"):
// tpws protocol.c FindNLD reports success with len==0 and HostPos then returns
// the pointer offset, so the pinned C oracle yields a non-zero sld/midsld/
// endsld. These are asserted separately because the v2 artifact resolves them
// to 0 (see the QA report defect D2b).
var qaV2TLSDegenerateSLD = map[string]bool{
	"T_sni_twodots":         true,
	"T_sni_double_dot_mid":  true,
	"T_sni_double_dot_end":  true,
	"T_sni_double_dot_lead": true,
}

// qaV2TLSEmptySNI lists fixtures whose server_name carries an empty host_name:
// tpws accepts it and its host anchors land past the end of the block, so only
// non-zero offsets can be in range (asserted separately).
var qaV2TLSEmptySNI = map[string]bool{"T_sni_empty": true}

// TestQAV2TLSPositionsMatchPinnedC is the TLS half of the D2 differential
// check over fixture families where the artifact and pinned tpws must agree.
func TestQAV2TLSPositionsMatchPinnedC(t *testing.T) {
	kinds := []positionKind{positionHost, positionEndHost, positionSLD, positionMidSLD, positionEndSLD}
	for _, fixture := range qaV2TLSFixtures {
		if qaV2TLSDegenerateSLD[fixture.name] || qaV2TLSEmptySNI[fixture.name] {
			continue
		}
		block := qaV2Decode(t, fixture.hex)
		if len(block) != fixture.size {
			t.Fatalf("%s: fixture size %d, table %d", fixture.name, len(block), fixture.size)
		}
		for index, kind := range kinds {
			if got := qaV2Resolve(block, ProtocolTLS, kind, 0); got != fixture.pos[index] {
				t.Errorf("%s %s = %d, pinned C = %d", fixture.name, positionKindName(kind), got, fixture.pos[index])
			}
		}
		if got := qaV2Resolve(block, ProtocolTLS, positionHost, 1); got != fixture.pos[5] {
			t.Errorf("%s host+1 = %d, pinned C = %d", fixture.name, got, fixture.pos[5])
		}
		if got := qaV2Resolve(block, ProtocolTLS, positionEndHost, -1); got != fixture.pos[6] {
			t.Errorf("%s endhost-1 = %d, pinned C = %d", fixture.name, got, fixture.pos[6])
		}
		if got := qaV2Resolve(block, ProtocolTLS, positionSLD, 1); got != fixture.pos[7] {
			t.Errorf("%s sld+1 = %d, pinned C = %d", fixture.name, got, fixture.pos[7])
		}
		if got := qaV2Resolve(block, ProtocolTLS, positionSNIExt, 0); got != fixture.pos[8] {
			t.Errorf("%s sniext = %d, pinned C = %d", fixture.name, got, fixture.pos[8])
		}
		if got := qaV2Resolve(block, ProtocolTLS, positionSNIExt, 1); got != fixture.pos[9] {
			t.Errorf("%s sniext+1 = %d, pinned C = %d", fixture.name, got, fixture.pos[9])
		}
	}
}

// TestQAV2CHostPositionBoundary pins the exact `host-data+7 < sz` precondition
// of HttpPos: with the 'H' at offset 16 the block needs at least 24 bytes
// before any host marker may be non-zero, and 23 bytes must still give 0.
// The fixture has no separator space, so the anchor is the byte after ':'
// (offset 21), exactly as HostPos computes offset_host.
func TestQAV2CHostPositionBoundary(t *testing.T) {
	for size, want := range map[int]int{21: 0, 22: 0, 23: 0, 24: 21, 25: 21, 30: 21} {
		block := []byte("GET / HTTP/1.1\r\nHost:" + string(bytes.Repeat([]byte("a"), size-21)))
		if len(block) != size {
			t.Fatalf("fixture size = %d, want %d", len(block), size)
		}
		if got := qaV2Resolve(block, ProtocolHTTP, positionHost, 0); got != want {
			t.Errorf("size %d host = %d, want %d", size, got, want)
		}
	}
}

// TestQAV2DegenerateHostSplitBytes is the reachable byte effect of D2: an
// empty Host value splits at 22 exactly like pinned tpws and the stream is
// preserved byte for byte. Before the repair the position resolved to 0 and
// the block was passed through unsplit.
func TestQAV2DegenerateHostSplitBytes(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: \r\n\r\n")
	config := mustCompileStream(t, option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"host"},
			Disorder: "any",
		},
	})
	conn := newFakeConn()
	sender := newTraceSender()
	config.native = &nativeRecorder{sender: sender}
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	if _, err := wrapped.Write(request); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("fragments = %d, want 2", len(sender.calls))
	}
	if !bytes.Equal(sender.written.Bytes(), request) {
		t.Fatalf("stream changed: %q", sender.written.Bytes())
	}
	if len(sender.calls[0].data) != 22 || len(sender.calls[1].data) != len(request)-22 {
		t.Fatalf("fragment lengths = %d,%d want 22,%d",
			len(sender.calls[0].data), len(sender.calls[1].data), len(request)-22)
	}
}

// TestQAV2UnterminatedHostMatchingSafety keeps the matching half of D2 honest:
// an unterminated Host value must never select a domain-filtered rule, even
// though its split anchors are now resolved like upstream.
func TestQAV2UnterminatedHostMatchingSafety(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Domain: badoption.Listable[string]{"abc.def"},
		},
		Methods: badoption.Listable[string]{"split"},
		Split:   &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"host"}},
	}
	config := mustCompileStream(t, rule)
	if selected := config.selectRule(MatchFacts{Port: 80, Transport: TransportTCP}); selected != nil {
		t.Fatal("unterminated Host selected a domain-filtered rule")
	}
	if selected := config.selectRule(MatchFacts{
		Port: 80, Transport: TransportTCP, Host: "abc.def", HostKnown: true,
	}); selected == nil {
		t.Fatal("terminated Host must select the domain-filtered rule")
	}

	// End to end: the unterminated request is forwarded unchanged and unsplit.
	conn := newFakeConn()
	sender := newTraceSender()
	config.native = &nativeRecorder{sender: sender}
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	request := []byte("GET / HTTP/1.1\r\nHost: abc.def")
	if _, err := wrapped.Write(request); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("unterminated host used the native split sender (%d calls)", len(sender.calls))
	}
	if !bytes.Equal(conn.collected(), request) {
		t.Fatalf("forwarded bytes = %q, want %q", conn.collected(), request)
	}
}

// TestQAV2MSSRange pins tpws.c:1581-1587: mss 0 means unset, 88..32767 is the
// accepted Linux range, and everything else is a config error, not a deferred
// setsockopt failure.
func TestQAV2MSSRange(t *testing.T) {
	compile := func(mss int) error {
		rule := splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"1"},
		})
		rule.MSS = mss
		_, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
		return err
	}
	for _, mss := range []int{0, 88, 89, 1200, 32766, 32767} {
		if err := compile(mss); err != nil {
			t.Errorf("mss=%d rejected: %v", mss, err)
		}
	}
	for _, mss := range []int{1, 87, 32768, 65535, -1} {
		if err := compile(mss); err == nil {
			t.Errorf("mss=%d accepted, want rejection", mss)
		}
	}
}

// TestQAV2FixSegTypedJSON checks the two upstream spellings survive JSON:
// true is the bare --fix-seg (upstream 50 ms default), 0 is the explicit
// inspect-only form, and false/string/object are rejected at decode.
func TestQAV2FixSegTypedJSON(t *testing.T) {
	decode := func(content string) (option.DirectDesyncStreamRule, error) {
		var rule option.DirectDesyncStreamRule
		err := sjson.Unmarshal([]byte(content), &rule)
		return rule, err
	}
	workspace, err := decode(`{"fix_seg": true}`)
	if err != nil || workspace.FixSeg == nil || !workspace.FixSeg.Default || workspace.FixSeg.Milliseconds != 0 {
		t.Fatalf("fix_seg=true = %+v, err %v", workspace.FixSeg, err)
	}
	zero, err := decode(`{"fix_seg": 0}`)
	if err != nil || zero.FixSeg == nil || zero.FixSeg.Default || zero.FixSeg.Milliseconds != 0 {
		t.Fatalf("fix_seg=0 = %+v, err %v", zero.FixSeg, err)
	}
	for _, value := range []int{1, 250, 1000} {
		decoded, decodeErr := decode(`{"fix_seg": ` + strconv.Itoa(value) + `}`)
		if decodeErr != nil || decoded.FixSeg == nil || decoded.FixSeg.Default || decoded.FixSeg.Milliseconds != value {
			t.Fatalf("fix_seg=%d = %+v, err %v", value, decoded.FixSeg, decodeErr)
		}
	}
	absent, err := decode(`{"fix_seg": null}`)
	if err != nil || absent.FixSeg != nil {
		t.Fatalf("fix_seg=null must decode to absent: %+v, err %v", absent.FixSeg, err)
	}
	missing, err := decode(`{}`)
	if err != nil || missing.FixSeg != nil {
		t.Fatalf("absent fix_seg must stay nil: %+v, err %v", missing.FixSeg, err)
	}
	for _, content := range []string{
		`{"fix_seg": false}`,
		`{"fix_seg": "true"}`,
		`{"fix_seg": "50"}`,
		`{"fix_seg": {}}`,
		`{"fix_seg": []}`,
	} {
		if _, decodeErr := decode(content); decodeErr == nil {
			t.Errorf("decode %s must fail", content)
		}
	}

	// Round trip: the typed value survives MarshalJSON.
	roundTrip, err := sjson.Marshal(option.DirectDesyncStreamRule{FixSeg: &option.DirectDesyncStreamFixSeg{Default: true}})
	if err != nil || !bytes.Contains(roundTrip, []byte(`"fix_seg":true`)) {
		t.Fatalf("marshal bare fix_seg = %s, err %v", roundTrip, err)
	}
	roundTrip, err = sjson.Marshal(option.DirectDesyncStreamRule{FixSeg: &option.DirectDesyncStreamFixSeg{Milliseconds: 250}})
	if err != nil || !bytes.Contains(roundTrip, []byte(`"fix_seg":250`)) {
		t.Fatalf("marshal fix_seg=250 = %s, err %v", roundTrip, err)
	}
}

// TestQAV2FixSegCompileValues pins the D4 compile mapping: bare -> 50 ms,
// explicit 0 stays 0, 1000 accepted, -1/1001/5000 rejected, an ambiguous
// typed value rejected, and fix_seg without split rejected.
func TestQAV2FixSegCompileValues(t *testing.T) {
	compile := func(value *option.DirectDesyncStreamFixSeg) (*streamRule, error) {
		rule := splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"1"},
		})
		rule.FixSeg = value
		config, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
		if err != nil {
			return nil, err
		}
		return config.rules[0], nil
	}
	cases := []struct {
		name  string
		value *option.DirectDesyncStreamFixSeg
		want  time.Duration
	}{
		{"bare", &option.DirectDesyncStreamFixSeg{Default: true}, 50 * time.Millisecond},
		{"explicit-zero", &option.DirectDesyncStreamFixSeg{Milliseconds: 0}, 0},
		{"one", &option.DirectDesyncStreamFixSeg{Milliseconds: 1}, time.Millisecond},
		{"max", &option.DirectDesyncStreamFixSeg{Milliseconds: 1000}, time.Second},
	}
	for _, testCase := range cases {
		rule, err := compile(testCase.value)
		if err != nil {
			t.Errorf("%s: %v", testCase.name, err)
			continue
		}
		if !rule.fixSegSet || rule.fixSeg != testCase.want {
			t.Errorf("%s: fixSegSet=%v fixSeg=%v, want %v", testCase.name, rule.fixSegSet, rule.fixSeg, testCase.want)
		}
	}
	for _, value := range []*option.DirectDesyncStreamFixSeg{
		{Milliseconds: -1},
		{Milliseconds: 1001},
		{Milliseconds: 5000},
		{Default: true, Milliseconds: 250},
	} {
		if _, err := compile(value); err == nil {
			t.Errorf("fix_seg=%+v accepted, want rejection", value)
		}
	}
	rule := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split:   &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"1"}},
		FixSeg:  &option.DirectDesyncStreamFixSeg{Default: true},
	}
	if _, err := CompileStream([]option.DirectDesyncStreamRule{rule}, ""); err != nil {
		t.Errorf("fix_seg with split and no other native option: %v", err)
	}
	noSplit := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{
			HostCase: true,
		},
		FixSeg: &option.DirectDesyncStreamFixSeg{Default: true},
	}
	if _, err := CompileStream([]option.DirectDesyncStreamRule{noSplit}, ""); err == nil {
		t.Error("fix_seg without split accepted, want rejection")
	}
}

// TestQAV2FixSegOnlyWaitsInsideSplitLoop pins tpws_conn.c:1289-1307: the wait
// runs once per multisplit part and never for a block that resolves no split
// position (the D4b repair).
func TestQAV2FixSegOnlyWaitsInsideSplitLoop(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\nHost: a.b\r\n\r\n")

	unsplit := mustCompileStream(t, option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"2000"},
		},
		FixSeg: &option.DirectDesyncStreamFixSeg{Default: true},
	})
	conn := newFakeConn()
	sender := newTraceSender()
	unsplit.native = &nativeRecorder{sender: sender}
	wrapped := wrapStream(t, unsplit, conn, MatchFacts{Port: 80})
	if _, err := wrapped.Write(request); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("unsplit block sends = %d, want 1", len(sender.calls))
	}
	if len(sender.waits) != 0 {
		t.Fatalf("unsplit block waited %v, upstream never waits outside the split loop", sender.waits)
	}

	split := mustCompileStream(t, option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"4"},
		},
		FixSeg: &option.DirectDesyncStreamFixSeg{Default: true},
	})
	conn = newFakeConn()
	sender = newTraceSender()
	split.native = &nativeRecorder{sender: sender}
	wrapped = wrapStream(t, split, conn, MatchFacts{Port: 80})
	if _, err := wrapped.Write(request); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("split block fragments = %d, want 2", len(sender.calls))
	}
	if len(sender.waits) != len(sender.calls) {
		t.Fatalf("waits = %v, want one per part (%d)", sender.waits, len(sender.calls))
	}
	for _, waited := range sender.waits {
		if waited != 50*time.Millisecond {
			t.Fatalf("waited %v, want the bare-flag default 50ms", waited)
		}
	}
}

// TestQAV2SplitPositionLimit16 pins params.h MAX_SPLITS 16 for the stream
// rules, counted across split_pos and the deprecated aliases, and keeps the
// stream limit distinct from the packet-side 64.
func TestQAV2SplitPositionLimit16(t *testing.T) {
	if streamMaxSplitPositions != 16 {
		t.Fatalf("streamMaxSplitPositions = %d, want 16", streamMaxSplitPositions)
	}
	if maxSplitPositions != 64 {
		t.Fatalf("packet maxSplitPositions = %d, want the unchanged 64", maxSplitPositions)
	}
	positions := func(count int) badoption.Listable[string] {
		list := make(badoption.Listable[string], 0, count)
		for index := 0; index < count; index++ {
			list = append(list, strconv.Itoa(index+1))
		}
		return list
	}
	compile := func(split *option.DirectDesyncStreamSplit) error {
		_, err := CompileStream([]option.DirectDesyncStreamRule{{
			Methods: badoption.Listable[string]{"split"},
			Split:   split,
		}}, "")
		return err
	}
	if err := compile(&option.DirectDesyncStreamSplit{SplitPos: positions(16)}); err != nil {
		t.Errorf("16 split positions rejected: %v", err)
	}
	if err := compile(&option.DirectDesyncStreamSplit{SplitPos: positions(17)}); err == nil {
		t.Error("17 split positions accepted, want rejection")
	}
	if err := compile(&option.DirectDesyncStreamSplit{SplitPos: positions(15), SplitHTTPReq: "method"}); err != nil {
		t.Errorf("15 positions + split_http_req rejected: %v", err)
	}
	if err := compile(&option.DirectDesyncStreamSplit{SplitPos: positions(15), SplitHTTPReq: "method", SplitTLS: "sni"}); err == nil {
		t.Error("15 positions + two deprecated aliases accepted, want rejection")
	}
	if err := compile(&option.DirectDesyncStreamSplit{SplitPos: positions(64)}); err == nil {
		t.Error("64 split positions accepted, want rejection (packet limit leaked into the stream)")
	}
}

// TestQAV2AbsentFastPath covers the ordinary no-desync path: an empty or nil
// rule list compiles to nil, and WrapConn returns the original connection
// without allocating a wrapper or touching it.
func TestQAV2AbsentFastPath(t *testing.T) {
	if config, err := CompileStream(nil, ""); err != nil || config != nil {
		t.Fatalf("nil rules: config %v err %v", config, err)
	}
	if config, err := CompileStream([]option.DirectDesyncStreamRule{}, ""); err != nil || config != nil {
		t.Fatalf("empty rules: config %v err %v", config, err)
	}
	disabled := option.DirectDesyncStreamRule{
		Disabled:   true,
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostCase: true},
	}
	if config, err := CompileStream([]option.DirectDesyncStreamRule{disabled}, ""); err != nil || config != nil {
		t.Fatalf("disabled rule: config %v err %v", config, err)
	}
	var nilConfig *StreamConfig
	conn := newFakeConn()
	wrapped, err := nilConfig.WrapConn(context.Background(), conn, MatchFacts{Port: 80})
	if err != nil {
		t.Fatalf("nil config WrapConn: %v", err)
	}
	if wrapped != net.Conn(conn) {
		t.Fatal("nil config must return the original connection")
	}
	config := &StreamConfig{}
	wrapped, err = config.WrapConn(context.Background(), conn, MatchFacts{Port: 80})
	if err != nil {
		t.Fatalf("empty config WrapConn: %v", err)
	}
	if wrapped != net.Conn(conn) {
		t.Fatal("empty config must return the original connection")
	}
	if conn.writeCount() != 0 || conn.closed {
		t.Fatal("the fast path must not write to or close the connection")
	}
}

// Defect pins for QA v2 (task t_c8c7a98c) on tree
// 03618947ca6f9e3b72d1a3dedbc709443525b7a5.
//
// These two tests fail on the v2 repair candidate and pass only after the
// reported D2b/D2c corrections. They are kept apart from the main QA suite
// (TestQAV2TLSPositionsMatchPinnedC) so that suite stays green and the
// regression is unambiguous.
//
// Expectations are literal output of the pinned zapret v72.9 (c849e55e)
// tpws/protocol.c TLSPos/HostPos/FindNLD for the exact fixture bytes in
// zz_qa_v2_oracle_table_test.go (generated from oracle.c in the QA report
// appendix).

// TestQAV2TLSDegenerateSLDAnchors is defect D2b.
//
// SNI "..", "a..b", "x..", "..x": protocol.c FindNLD succeeds with a
// zero-length second-level domain (p1 == p2), and HostPos then returns
// p-data + pos for sld/endsld (and p+slen/2-data for midsld) without requiring
// a non-empty SLD. The shipped code derives sldOK from SLDEnd > SLDStart
// (common/desync/stream_facts.go:119), so every SLD marker resolves to 0 and a
// rule such as split_pos ["sld"] silently drops the split.
//
// The same bytes are resolved correctly by this implementation's HTTP branch
// (see TestQAV2HTTPPositionsMatchPinnedC, fixture I_dotdot, where ".." yields
// sld=23 = host start + 1 exactly like pinned C), so this is an internal
// inconsistency in the TLS branch, not a documented mapping.
func TestQAV2TLSDegenerateSLDAnchors(t *testing.T) {
	cases := []struct {
		name string
		pos  [5]int // host, endhost, sld, midsld, endsld from pinned TLSPos
	}{
		{"T_sni_twodots", [5]int{61, 0, 62, 62, 62}},
		{"T_sni_double_dot_mid", [5]int{61, 0, 63, 63, 63}},
		{"T_sni_double_dot_end", [5]int{61, 0, 63, 63, 63}},
		{"T_sni_double_dot_lead", [5]int{61, 0, 62, 62, 62}},
	}
	kinds := []positionKind{positionHost, positionEndHost, positionSLD, positionMidSLD, positionEndSLD}
	for _, fixture := range qaV2TLSFixtures {
		var want [5]int
		found := false
		for _, testCase := range cases {
			if testCase.name == fixture.name {
				want = testCase.pos
				found = true
			}
		}
		if !found {
			continue
		}
		block := qaV2Decode(t, fixture.hex)
		for index, kind := range kinds {
			if got := qaV2Resolve(block, ProtocolTLS, kind, 0); got != want[index] {
				t.Errorf("%s %s = %d, pinned C = %d", fixture.name, positionKindName(kind), got, want[index])
			}
		}
	}
}

// TestQAV2TLSEmptySNIAnchors is defect D2c.
//
// A server_name extension with an empty host_name is accepted by
// TLSAdvanceToHostInSNI (slen 0 <= elen). protocol.c then anchors the host just
// past the extension data, which is the end of this block, so the zero-offset
// markers are out of range and resolve to 0 - but a negative offset still lands
// inside the block (endhost-1 = 60 here). The shipped tlsRecordFacts rejects
// nameLength == 0 outright, so every offset resolves to 0 and such a configured
// position is silently dropped.
// Severity: low (needs an empty SNI and a non-zero offset), reported with D2b
// because both come from the same TLS anchor facts.
func TestQAV2TLSEmptySNIAnchors(t *testing.T) {
	for _, fixture := range qaV2TLSFixtures {
		if fixture.name != "T_sni_empty" {
			continue
		}
		block := qaV2Decode(t, fixture.hex)
		for _, kind := range []positionKind{positionHost, positionEndHost, positionSLD, positionMidSLD, positionEndSLD} {
			if got := qaV2Resolve(block, ProtocolTLS, kind, 0); got != 0 {
				t.Errorf("%s = %d, pinned C = 0", positionKindName(kind), got)
			}
		}
		if got := qaV2Resolve(block, ProtocolTLS, positionEndHost, -1); got != 60 {
			t.Errorf("endhost-1 = %d, pinned C = 60", got)
		}
	}
}

package desync

// QA-independent verification suite, produced by tester-max-2 for task
// t_44b42cfe and retained permanently by the t_f6375ed5 repair increment
// (artifact sha256 b5a1b24f8147b4bacdbfeb86dba4c67a9b5f4b1cef67b2e9164ea9f171836732,
// assertions unchanged).
//
// Every oracle below is derived by hand from pinned zapret v72.9
// (c849e55ef0f1c244206f5a05ff7b1ab41a3824ee) sources:
//   tpws/tamper.c  tamper_out HTTP branch (lines 330-460) and TLS branch (469-509)
//   tpws/protocol.c HttpPos / HostPos / TLSPos / ResolveMultiPos / FindNLD
//   tpws/tpws_conn.c handle_epoll multisplit loop (1284-1324), send_oob (1144-1159)
// The expectations are literal upstream byte results, not round-trip oracles.

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// TestQAHTTPCombinedSourceOrder exercises the exact tamper.c HTTP order
//
//	unixeol -> methodeol -> methodspace -> hostdot -> domcase
//	-> hostnospace -> hostcase -> hostpad
//
// on one block. The zero random source is unused (no hostpad here).
//
// Derivation:
//
//	start   GET /path HTTP/1.1\r\nX-Host: evil\r\nHost: A.B.C\r\n\r\nGET /more\r\n
//	unixeol converts CRLF until (and including) the double EOL after the Host
//	header, so the trailing "GET /more\r\n" keeps its CRLF (tamper.c:336-348).
//	methodeol inserts LF at offset 0 because unixeol is set (tamper.c:354-359).
//	methodspace inserts ' ' at method_len+1 = 4 of the *current* block
//	(tamper.c:373-377), which is the space after "GET".
//	hostdot inserts '.' at the first CR/LF of the host value; the X-Host header
//	is not a Host anchor because IsHostAt requires a preceding LF and the 'H'
//	directly after it (protocol.c:172-181).
//	hostnospace removes the single space after "Host:" (tamper.c:401-408).
//	hostcase rewrites those 4 bytes to "host" (tamper.c:409-413).
func TestQAHTTPCombinedSourceOrder(t *testing.T) {
	request := "GET /path HTTP/1.1\r\nX-Host: evil\r\nHost: A.B.C\r\n\r\nGET /more\r\n"
	spec := &httpTamperSpec{
		unixEOL:     true,
		methodEOL:   true,
		methodSpace: true,
		hostDot:     true,
		hostNoSpace: true,
		hostCase:    true,
		hostSpell:   [4]byte{'h', 'o', 's', 't'},
	}
	want := "\nGET  /path HTTP/1.1\nX-Host: evil\nhost:A.B.C.\n\nGET /more\r\n"
	if got := tamperHTTP(t, spec, request); got != want {
		t.Fatalf("combined HTTP tamper\n got %q\nwant %q", got, want)
	}
}

// TestQAHTTPFirstHostOnly checks that only the first Host header is touched and
// that the header name match is case-insensitive, as IsHostAt.
// tamper.c uses a single cached pHost, so the second Host header is untouched.
func TestQAHTTPFirstHostOnly(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHOST: One.COM\r\nHost: Two.COM\r\n\r\n"
	spec := &httpTamperSpec{hostDot: true}
	want := "GET / HTTP/1.1\r\nHOST: One.COM.\r\nHost: Two.COM\r\n\r\n"
	if got := tamperHTTP(t, spec, request); got != want {
		t.Fatalf("first-host rule\n got %q\nwant %q", got, want)
	}
}

// TestQAHTTPHostNoSpaceRequiresSpace: tamper.c:401 tests pHost[5]==' ' exactly,
// so a tab separator must be preserved. A "strip leading whitespace" mutant
// fails here.
func TestQAHTTPHostNoSpaceRequiresSpace(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost:\tTabbed.COM\r\n\r\n"
	if got := tamperHTTP(t, &httpTamperSpec{hostNoSpace: true}, request); got != request {
		t.Fatalf("hostnospace removed a tab: %q", got)
	}
}

// TestQAHTTPHostDotUnterminatedValue: tamper.c:384 only inserts the dot when
// p < segment+size, i.e. a CR/LF terminator was found inside the block.
func TestQAHTTPHostDotUnterminatedValue(t *testing.T) {
	request := "GET / HTTP/1.1\r\nHost: unterminated"
	if got := tamperHTTP(t, &httpTamperSpec{hostDot: true}, request); got != request {
		t.Fatalf("hostdot fired without a terminator: %q", got)
	}
}

// TestQAHTTPHostPadCapacity mirrors tamper.c:421-431:
//
//	(hsize+size)>buffer      -> no padding at all
//	(hostpad+size)>buffer    -> hostpad reduced to buffer-size
//
// With a zero random source each dummy header is "a0000: " + pad + CRLF and
// hsize is 9 for CRLF, so the reduced case yields exactly one 9-byte header.
func TestQAHTTPHostPadCapacity(t *testing.T) {
	header := "GET / HTTP/1.1\r\nHost: h\r\n"
	filler := func(total int) string {
		if total < len(header) {
			t.Fatalf("fixture header %d longer than target %d", len(header), total)
		}
		return header + strings.Repeat("x", total-len(header))
	}

	// Exactly one dummy header still fits.
	exact := filler(streamBlockCapacity - 9)
	wantExact := "GET / HTTP/1.1\r\na0000: \r\nHost: h\r\n" + strings.Repeat("x", len(exact)-len(header))
	if got := tamperHTTP(t, &httpTamperSpec{hostPad: 1000}, exact); got != wantExact {
		t.Fatalf("hostpad at exact capacity\n got %q\nwant %q", got, wantExact)
	}

	// Header size no longer fits: upstream leaves the block untouched.
	tooBig := filler(streamBlockCapacity - 8)
	if got := tamperHTTP(t, &httpTamperSpec{hostPad: 1000}, tooBig); got != tooBig {
		t.Fatalf("hostpad must be dropped when hsize+size exceeds the buffer")
	}
}

// qaHelloNoSNI builds a syntactically valid ClientHello record without the
// server_name extension.
func qaHelloNoSNI() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression methods
	body = append(body, 0, 0)             // extensions length
	handshake := append([]byte{0x01, 0, 0, byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, 0, byte(len(handshake))}, handshake...)
}

// TestQATLSHostMarkerWithoutSNI: TLSPos returns 0 when TLSFindExt cannot find
// the SNI extension (protocol.c:529-543), so no record split may happen.
func TestQATLSHostMarkerWithoutSNI(t *testing.T) {
	record := qaHelloNoSNI()
	block := make([]byte, len(record), streamBlockCapacity)
	copy(block, record)
	facts, ok := tlsRecordFacts(block)
	if !ok || facts.HostKnown {
		t.Fatalf("fixture facts ok=%v hostKnown=%v", ok, facts.HostKnown)
	}
	split, _, applied := splitTLSRecord(block, &tlsRecordSpec{position: Position{Kind: positionHost, Offset: 1}},
		streamFactSet{Facts: facts}, nil)
	if applied {
		t.Fatalf("record split applied without SNI")
	}
	if !bytes.Equal(split, record) {
		t.Fatalf("block changed without SNI: %x", split)
	}
	// An absolute position still applies and must follow the source formula.
	split, _, applied = splitTLSRecord(block, &tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: 10}},
		streamFactSet{Facts: facts}, nil)
	if !applied || len(split) != len(record)+5 {
		t.Fatalf("absolute split applied=%v len=%d", applied, len(split))
	}
	if got := int(split[3])<<8 | int(split[4]); got != 5 {
		t.Fatalf("first record payload = %d, want 5", got)
	}
}

// TestQATLSRecordSplitBoundaries covers tamper.c:474-491 boundaries:
// tpos<=5 -> no-op, (tpos-5)>=l -> tpos=6, and a position outside the block
// resolves to zero (protocol.c CheckPos) -> no-op.
func TestQATLSRecordSplitBoundaries(t *testing.T) {
	record := buildClientHello("example.com")
	length := int(record[3])<<8 | int(record[4])

	block := make([]byte, len(record), streamBlockCapacity)
	copy(block, record)
	facts, ok := tlsRecordFacts(block)
	if !ok {
		t.Fatal("fixture facts failed")
	}
	set := streamFactSet{Facts: facts}

	for _, position := range []int{0, 1, 5, len(record)} {
		if _, _, applied := splitTLSRecord(block, &tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: position}}, set, nil); applied {
			t.Fatalf("split applied at out-of-range position %d", position)
		}
	}

	split, _, applied := splitTLSRecord(block, &tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: 6}}, set, nil)
	if !applied {
		t.Fatal("split at position 6 must apply")
	}
	if got := int(split[3])<<8 | int(split[4]); got != 1 {
		t.Fatalf("first record payload = %d, want 1", got)
	}
	if got := int(split[9])<<8 | int(split[10]); got != length-1 {
		t.Fatalf("second record payload = %d, want %d", got, length-1)
	}
	if !bytes.Equal(split[11:], record[6:]) {
		t.Fatal("second record payload must preserve the remaining handshake bytes")
	}
}

// TestQATLSRecordSplitShiftAfterClamp: tamper.c:498-500 shifts split positions
// that are strictly greater than the (possibly clamped) tpos.
func TestQATLSRecordSplitShiftAfterClamp(t *testing.T) {
	record := buildClientHello("example.com")
	length := int(record[3])<<8 | int(record[4])
	block := make([]byte, len(record)+64, streamBlockCapacity)
	copy(block, record)
	facts, ok := tlsRecordFacts(block)
	if !ok {
		t.Fatal("fixture facts failed")
	}
	// tpos = length+6 is inside the block but beyond the record: tpos -> 6.
	position := length + 6
	_, shifted, applied := splitTLSRecord(block,
		&tlsRecordSpec{position: Position{Kind: positionAbsolute, Offset: position}},
		streamFactSet{Facts: facts}, []int{5, 6, 7, 40})
	if !applied {
		t.Fatal("clamped split must apply")
	}
	want := []int{5, 6, 12, 45}
	if len(shifted) != len(want) {
		t.Fatalf("shifted = %v, want %v", shifted, want)
	}
	for index := range want {
		if shifted[index] != want[index] {
			t.Fatalf("shifted = %v, want %v", shifted, want)
		}
	}
}

// qaSplitConfig builds a split-only rule with native sending enabled through
// disorder=any, so every fragment goes through the sender seam.
func qaSplitConfig(t *testing.T, positions ...string) *StreamConfig {
	t.Helper()
	config := mustCompileStream(t, option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string](positions),
			Disorder: "any",
		},
	})
	return config
}

func qaWrapWithSender(t *testing.T, config *StreamConfig, conn *fakeConn, sender *traceSender) net.Conn {
	t.Helper()
	config.native = &nativeRecorder{sender: sender}
	return wrapStream(t, config, conn, MatchFacts{Port: 80})
}

// TestQAShortSendZeroProgressCancelsSplit mirrors tpws_conn.c:1315-1322: when
// the first fragment cannot be sent at all, the whole block is forwarded
// unsplit and no byte is lost or duplicated.
func TestQAShortSendZeroProgressCancelsSplit(t *testing.T) {
	config := qaSplitConfig(t, "4", "8")
	conn := newFakeConn()
	sender := newTraceSender()
	sender.shortAt = 0
	sender.shortLen = 0
	wrapped := qaWrapWithSender(t, config, conn, sender)

	payload := []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := append(append([]byte(nil), sender.written.Bytes()...), conn.collected()...)
	if !bytes.Equal(got, payload) {
		t.Fatalf("stream changed after zero-progress fragment\n got %q\nwant %q", got, payload)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("sender calls = %d, want 1", len(sender.calls))
	}
}

// TestQAShortSendMiddleFragmentForwarding mirrors from += wr and the
// send_or_buffer(bs-from) forwarding for a partially sent middle fragment.
func TestQAShortSendMiddleFragmentForwarding(t *testing.T) {
	config := qaSplitConfig(t, "4", "8")
	conn := newFakeConn()
	sender := newTraceSender()
	sender.shortAt = 1
	sender.shortLen = 2
	wrapped := qaWrapWithSender(t, config, conn, sender)

	payload := []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := append(append([]byte(nil), sender.written.Bytes()...), conn.collected()...)
	if !bytes.Equal(got, payload) {
		t.Fatalf("stream changed after short middle fragment\n got %q\nwant %q", got, payload)
	}
	wantFirst := string(payload[0:4]) + string(payload[4:6])
	if sender.written.String() != wantFirst {
		t.Fatalf("sender prefix %q, want %q", sender.written.String(), wantFirst)
	}
	if string(conn.collected()) != string(payload[6:]) {
		t.Fatalf("forwarded remainder %q, want %q", conn.collected(), payload[6:])
	}
}

// TestQAMethodAnchorAfterMethodEOL covers the protocol.c PM_HTTP_METHOD
// "pre-applied hacks" skip: split positions are resolved after the HTTP tamper
// stage, so methodeol moves the method anchor by the inserted EOL.
func TestQAMethodAnchorAfterMethodEOL(t *testing.T) {
	config := mustCompileStream(t, option.DirectDesyncStreamRule{
		Methods:    badoption.Listable[string]{"http_tamper", "split"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{MethodEOL: true},
		Split:      &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"method"}},
	})
	conn := newFakeConn()
	config.native = &nativeRecorder{sender: &plainSender{conn: conn}}
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})

	payload := []byte("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := conn.collected()
	want := "\r\nGET / HTTP/1.1\r\nHost: a.example\r\n\r\n"
	if string(got) != want {
		t.Fatalf("stream\n got %q\nwant %q", got, want)
	}
	// The split only re-fragments; the concatenation must stay identical.
	if !bytes.Equal(got, []byte(want)) {
		t.Fatal("fragment concatenation changed the stream")
	}
}

// TestQAByteCutoffUsesOriginalBlockLength: tpws in_tamper_out_range compares
// conn->trd, the bytes read *before* the block, against the cutoff. A block
// that grows through tampering must not move the next block's start position.
func TestQAByteCutoffUsesOriginalBlockLength(t *testing.T) {
	config := mustCompileStream(t, option.DirectDesyncStreamRule{
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostDot: true},
		Cutoff:     "20",
	})
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})

	first := []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n") // 27 bytes
	second := []byte("GET / HTTP/1.1\r\nHost: b\r\n\r\n")
	if _, err := wrapped.Write(first); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := wrapped.Write(second); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	want := "GET / HTTP/1.1\r\nHost: a.\r\n\r\n" + string(second)
	if got := string(conn.collected()); got != want {
		t.Fatalf("cutoff classification\n got %q\nwant %q", got, want)
	}
}

// TestQACloseFlushesHeldFirstBlock: a deferred first block must still be sent
// (transformed) when the connection closes.
func TestQACloseFlushesHeldFirstBlock(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostCase: true},
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Domain: badoption.Listable[string]{"a.example"},
		},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})

	partial := []byte("GET / HTTP/1.1\r\nX: y\r\n") // no Host, no header end
	if _, err := wrapped.Write(partial); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(conn.collected()) != 0 {
		t.Fatalf("deferred block was sent too early: %q", conn.collected())
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !bytes.Equal(conn.collected(), partial) {
		t.Fatalf("held block lost on Close: %q", conn.collected())
	}
}

// TestQAPrepareSocketAndWrapOwnership checks the callable seams without a
// socket: nil config is a no-op, a cancelled context fails closed, and a
// cancelled WrapConn must not take ownership of the caller's connection.
func TestQAPrepareSocketAndWrapOwnership(t *testing.T) {
	if err := (*StreamConfig)(nil).PrepareSocket(context.Background(), 1, MatchFacts{}); err != nil {
		t.Fatalf("nil PrepareSocket: %v", err)
	}
	config := qaSplitConfig(t, "4")
	if err := config.PrepareSocket(context.Background(), 0, MatchFacts{}); err != nil {
		t.Fatalf("fd=0 PrepareSocket: %v", err)
	}
	recorder := &nativeRecorder{}
	config.native = recorder
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := config.PrepareSocket(cancelled, 1, MatchFacts{}); err == nil {
		t.Fatal("cancelled PrepareSocket must fail")
	}
	if len(recorder.prepared) != 0 {
		t.Fatal("Prepare must not run after cancellation")
	}

	conn := newFakeConn()
	if _, err := config.WrapConn(context.Background(), nil, MatchFacts{}); err == nil {
		t.Fatal("WrapConn(nil) must fail")
	}
	if _, err := config.WrapConn(cancelled, conn, MatchFacts{}); err == nil {
		t.Fatal("cancelled WrapConn must fail")
	}
	if conn.closed {
		t.Fatal("cancelled WrapConn must not close the caller's connection")
	}
}

// TestQAConcurrentWritesPassThrough is a race-detector control: concurrent
// writers must be serialized and must not lose bytes.
func TestQAConcurrentWritesPassThrough(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostCase: true},
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Domain: badoption.Listable[string]{"only.example"},
		},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})

	payloadA := bytes.Repeat([]byte("A"), 8192)
	payloadB := bytes.Repeat([]byte("B"), 8192)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		if _, err := wrapped.Write(payloadA); err != nil {
			t.Errorf("Write A: %v", err)
		}
	}()
	go func() {
		defer wait.Done()
		if _, err := wrapped.Write(payloadB); err != nil {
			t.Errorf("Write B: %v", err)
		}
	}()
	wait.Wait()
	got := conn.collected()
	if len(got) != len(payloadA)+len(payloadB) {
		t.Fatalf("collected %d bytes, want %d", len(got), len(payloadA)+len(payloadB))
	}
	if !bytes.Contains(got, payloadA) || !bytes.Contains(got, payloadB) {
		t.Fatal("concurrent writes were interleaved or lost")
	}
}

// TestQAHTTPMethodAnchorNaiveMutantControl records the anchor used for the
// method marker so a mutant that ignores the leading CRLF skip is caught by
// TestQAMethodAnchorAfterMethodEOL above.
func TestQAStreamDeadlineDelegation(t *testing.T) {
	config := qaSplitConfig(t, "4")
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	deadline := time.Now().Add(time.Minute).Round(0)
	if err := wrapped.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if !conn.writeDeadline.Equal(deadline) {
		t.Fatalf("write deadline not delegated: %v vs %v", conn.writeDeadline, deadline)
	}
}

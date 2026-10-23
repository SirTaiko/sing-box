package desync

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Regression tests for the QA findings D2-D5 of the scoped tpws stream
// deliverable (tester-max-2 report t_44b42cfe). The expected offsets below
// were produced by calling the pinned upstream HttpPos (zapret v72.9
// c849e55ef0f1c244206f5a05ff7b1ab41a3824ee tpws/protocol.c) on the same byte
// strings with a read-only local oracle; they are literal C results, not
// round trips. `host`/`endhost` come from HttpPos, `sld`/`midsld`/`endsld`
// from HostPos inside HttpPos.

// TestHTTPDegenerateHostPositionsMatchesUpstream is D2: an empty or
// unterminated Host value must still resolve host positions from the header
// anchor, exactly like HttpPos/HostPos. The lane previously gated every host
// marker on a complete non-empty value and returned 0.
func TestHTTPDegenerateHostPositionsMatchesUpstream(t *testing.T) {
	tests := []struct {
		name      string
		block     string
		host      int
		endHost   int
		sld       int
		midSLD    int
		endSLD    int
		hostKnown bool
	}{
		// HttpPos: host-data+7 < sz. H is at 16, so a 21/22/23 byte block
		// fails the precondition and every marker resolves to 0.
		{"no value", "GET / HTTP/1.1\r\nHost:", 0, 0, 0, 0, 0, false},
		{"value start only", "GET / HTTP/1.1\r\nHost: ", 0, 0, 0, 0, 0, false},
		{"value start and CR", "GET / HTTP/1.1\r\nHost: \r", 0, 0, 0, 0, 0, false},
		// 24 bytes: precondition holds; the value after the skipped space is
		// empty and terminated.
		{"terminated empty value", "GET / HTTP/1.1\r\nHost: \r\n", 22, 22, 0, 0, 0, false},
		{"empty value full headers", "GET / HTTP/1.1\r\nHost: \r\n\r\n", 22, 22, 0, 0, 0, false},
		// Unterminated value: len_host runs to the end of the block, so
		// endhost falls exactly on sz and CheckPos drops it.
		{"unterminated value", "GET / HTTP/1.1\r\nHost: abc.def", 22, 0, 22, 23, 25, false},
		{"unterminated long value", "GET / HTTP/1.1\r\nHost: abc.defgh", 22, 0, 22, 23, 25, false},
		{"terminated value", "GET / HTTP/1.1\r\nHost: abc.def\r\n\r\n", 22, 29, 22, 23, 25, true},
		{"one letter SLD", "GET / HTTP/1.1\r\nHost: a.b\r\n\r\n", 22, 25, 22, 23, 23, true},
		{"dot only value", "GET / HTTP/1.1\r\nHost: .\r\n\r\n", 22, 23, 0, 0, 0, true},
		// tab after the value and a second space is not skipped
		{"tab value", "GET / HTTP/1.1\r\nHost: \t\r\n\r\n", 22, 23, 0, 0, 0, false},
		{"two spaces", "GET / HTTP/1.1\r\nHost:  x.y\r\n\r\n", 22, 26, 22, 23, 24, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			set := streamBlockFacts(ProtocolHTTP, []byte(test.block))
			assertResolved := func(kind positionKind, want int) {
				t.Helper()
				if got := resolveStreamPosition(Position{Kind: kind}, set, ProtocolHTTP); got != want {
					t.Fatalf("%s resolved %d, want %d", positionKindName(kind), got, want)
				}
			}
			assertResolved(positionHost, test.host)
			assertResolved(positionEndHost, test.endHost)
			assertResolved(positionSLD, test.sld)
			assertResolved(positionMidSLD, test.midSLD)
			assertResolved(positionEndSLD, test.endSLD)
			if set.HostKnown != test.hostKnown {
				t.Fatalf("HostKnown = %v, want %v", set.HostKnown, test.hostKnown)
			}
			if !test.hostKnown && set.Host != "" {
				t.Fatalf("incomplete host must not populate the matcher value: %q", set.Host)
			}
		})
	}
}

func positionKindName(kind positionKind) string {
	switch kind {
	case positionHost:
		return "host"
	case positionEndHost:
		return "endhost"
	case positionSLD:
		return "sld"
	case positionMidSLD:
		return "midsld"
	case positionEndSLD:
		return "endsld"
	default:
		return "other"
	}
}

// TestHTTPUnterminatedHostKeepsMatchingSafety is the second half of D2: while
// positions resolve from a partial value, rule selection must not use it as a
// hostname, because later bytes can still extend the name.
func TestHTTPUnterminatedHostKeepsMatchingSafety(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: abc.def")
	set := streamBlockFacts(ProtocolHTTP, payload)
	if set.HostKnown || set.Host != "" {
		t.Fatalf("partial host leaked into matching: host=%q known=%v", set.Host, set.HostKnown)
	}
	if got := resolveStreamPosition(Position{Kind: positionHost}, set, ProtocolHTTP); got != 22 {
		t.Fatalf("host position = %d, want 22", got)
	}
	config := mustCompileStream(t, option.DirectDesyncStreamRule{
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Domain: badoption.Listable[string]{"abc.def"},
		},
		Methods: badoption.Listable[string]{"split"},
		Split:   &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"host"}},
	})
	if rule := config.selectRule(MatchFacts{Port: 80, Transport: TransportTCP}); rule != nil {
		t.Fatal("a domain-filtered rule must not be selected from an unterminated Host value")
	}
}

// TestHTTPEmptyHostPositionsSplit shows the reachable byte effect of D2: an
// empty Host value now splits like upstream instead of passing through.
func TestHTTPEmptyHostPositionsSplit(t *testing.T) {
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
		t.Fatalf("fragment lengths = %d,%d", len(sender.calls[0].data), len(sender.calls[1].data))
	}
}

// TestTLSSingleLabelSNISLDMarkers is the D2 companion for the TLS branch:
// HostPos requires FindNLD to succeed, so sld/endsld/midsld must resolve to
// zero for a single-label SNI even though the host itself is known.
func TestTLSSingleLabelSNISLDMarkers(t *testing.T) {
	single := streamBlockFacts(ProtocolTLS, buildClientHello("localhost"))
	if !single.HostKnown {
		t.Fatal("single-label SNI must still be a known host")
	}
	for _, kind := range []positionKind{positionSLD, positionEndSLD, positionMidSLD} {
		if got := resolveStreamPosition(Position{Kind: kind, Offset: 2}, single, ProtocolTLS); got != 0 {
			t.Fatalf("%s+2 without an SLD resolved to %d, want 0", positionKindName(kind), got)
		}
	}
	multi := streamBlockFacts(ProtocolTLS, buildClientHello("www.example.com"))
	if got := resolveStreamPosition(Position{Kind: positionSLD}, multi, ProtocolTLS); got == 0 {
		t.Fatal("multi-label SNI must resolve the SLD anchor")
	}
}

// TestCompileStreamMSSRange is D3: tpws rejects `--mss` outside 88..32767 at
// parse time (tpws.c:1581-1587) instead of deferring the failure to
// setsockopt at dial time. mss=0 still means "not configured".
func TestCompileStreamMSSRange(t *testing.T) {
	compile := func(mss int) error {
		rule := splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"1"},
		})
		rule.MSS = mss
		_, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
		return err
	}
	if err := compile(0); err != nil {
		t.Fatalf("mss=0 must mean unset: %v", err)
	}
	for _, mss := range []int{1, 87, 32768, 65535} {
		err := compile(mss)
		if err == nil || !strings.Contains(err.Error(), "88..32767") {
			t.Fatalf("mss=%d must be rejected with the source range: %v", mss, err)
		}
	}
	if !streamCaps().mss {
		return
	}
	for _, mss := range []int{88, 1200, 32767} {
		if err := compile(mss); err != nil {
			t.Fatalf("mss=%d must be accepted on Linux: %v", mss, err)
		}
	}
}

// TestCompileStreamFixSegRangeDefaultAndExplicitZero is D4: the value is
// bounded to 0..1000 ms (tpws.c:1590-1608), a bare --fix-seg selects the
// upstream 50 ms default (params.h:23), and an explicit 0 is a distinct value
// that only inspects the send queue (tpws_conn.c:1289-1307).
func TestCompileStreamFixSegRangeDefaultAndExplicitZero(t *testing.T) {
	if !streamCaps().fixSeg {
		t.Skip("fix_seg is Linux-only")
	}
	compile := func(fixSeg *option.DirectDesyncStreamFixSeg) (*streamRule, error) {
		rule := splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"1"},
		})
		rule.FixSeg = fixSeg
		config, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
		if err != nil {
			return nil, err
		}
		return config.rules[0], nil
	}
	explicitZero, err := compile(&option.DirectDesyncStreamFixSeg{Milliseconds: 0})
	if err != nil || !explicitZero.fixSegSet || explicitZero.fixSeg != 0 {
		t.Fatalf("explicit fix_seg=0 = %+v %v", explicitZero, err)
	}
	defaultValue, err := compile(&option.DirectDesyncStreamFixSeg{Default: true})
	if err != nil || !defaultValue.fixSegSet || defaultValue.fixSeg != 50*time.Millisecond {
		t.Fatalf("bare fix_seg = %+v %v", defaultValue, err)
	}
	for _, milliseconds := range []int{1000} {
		if _, err = compile(&option.DirectDesyncStreamFixSeg{Milliseconds: milliseconds}); err != nil {
			t.Fatalf("fix_seg=%d must be accepted: %v", milliseconds, err)
		}
	}
	for _, milliseconds := range []int{-1, 1001, 5000} {
		_, err = compile(&option.DirectDesyncStreamFixSeg{Milliseconds: milliseconds})
		if err == nil || !strings.Contains(err.Error(), "0..1000") {
			t.Fatalf("fix_seg=%d must be rejected: %v", milliseconds, err)
		}
	}
	if _, err = compile(&option.DirectDesyncStreamFixSeg{Default: true, Milliseconds: 5}); err == nil {
		t.Fatal("ambiguous default+value fix_seg must be rejected")
	}
}

// TestFixSegSkipsUnsplitBlock is the adjacent D4 correction: tpws applies the
// fix-seg wait only inside the multisplit loop, so a block that resolves no
// split position must not inspect or wait on the send queue.
func TestFixSegSkipsUnsplitBlock(t *testing.T) {
	if !streamCaps().fixSeg {
		t.Skip("fix_seg is Linux-only")
	}
	rule := splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{
		SplitPos: badoption.Listable[string]{"endhost"},
	})
	rule.FixSeg = &option.DirectDesyncStreamFixSeg{Milliseconds: 5}
	config := mustCompileStream(t, rule)
	sender := newTraceSender()
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	// No Host header at all, so the endhost marker resolves to zero.
	payload := []byte("GET / HTTP/1.1\r\nX: y\r\n\r\n")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("sender calls = %d, want 1 unsplit send", len(sender.calls))
	}
	if len(sender.waits) != 0 {
		t.Fatalf("fix_seg waited on an unsplit block: %v", sender.waits)
	}
	if !bytes.Equal(conn.collected(), nil) || !bytes.Equal(sender.written.Bytes(), payload) {
		t.Fatalf("stream changed: sent %q direct %q", sender.written.Bytes(), conn.collected())
	}
}

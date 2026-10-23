package desync

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Compile-level acceptance for the tpws stream option surface. Rejected knobs
// are errors, never accepted no-ops.

func streamOptions(methods ...string) option.DirectDesyncStreamRule {
	return option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string](methods),
	}
}

func httpTamperOptions(methods []string, tamper *option.DirectDesyncStreamHTTPTamper) option.DirectDesyncStreamRule {
	rule := streamOptions(methods...)
	rule.HTTPTamper = tamper
	return rule
}

func splitOptions(methods []string, split *option.DirectDesyncStreamSplit) option.DirectDesyncStreamRule {
	rule := streamOptions(methods...)
	rule.Split = split
	return rule
}

func TestCompileStreamEmptyAndDisabled(t *testing.T) {
	if config, err := CompileStream(nil, ""); err != nil || config != nil {
		t.Fatalf("empty stream rules must compile to nil: %v %v", config, err)
	}
	disabled := streamOptions("http_tamper")
	disabled.Disabled = true
	disabled.HTTPTamper = &option.DirectDesyncStreamHTTPTamper{HostCase: true}
	if config, err := CompileStream([]option.DirectDesyncStreamRule{disabled}, ""); err != nil || config != nil {
		t.Fatalf("all-disabled stream rules must compile to nil: %v %v", config, err)
	}
}

func TestCompileStreamValid(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			Port:       badoption.Listable[uint16]{443},
			Domain:     badoption.Listable[string]{"example.com"},
			IPVersion:  badoption.Listable[int]{4, 6},
			Network:    badoption.Listable[string]{"tcp"},
			IPCIDR:     badoption.Listable[string]{"10.0.0.0/8"},
			PortRange:  badoption.Listable[string]{"8000-9000"},
			Protocol:   badoption.Listable[string]{"http", "tls"},
			DomainFile: nil,
			IPCIDRFile: nil,
		},
		Name:    "full",
		Methods: badoption.Listable[string]{"http_tamper", "tls_record", "split"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{
			HostCase: true, HostSpell: "HoSt", HostDot: true, DomCase: true,
		},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "sniext"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos:         badoption.Listable[string]{"1", "host+2", "midsld"},
			SplitHTTPReq:     "method",
			SplitTLS:         "sni",
			Disorder:         "any",
			OOB:              "tls",
			SplitAnyProtocol: true,
		},
		Start:  "n2",
		Cutoff: "100",
		MSS:    1200,
	}
	config, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	if err != nil {
		t.Fatalf("valid stream rule rejected: %v", err)
	}
	if config == nil || len(config.rules) != 1 {
		t.Fatalf("compiled config = %+v", config)
	}
	compiled := config.rules[0]
	if compiled.name != "full" || !compiled.start.block || compiled.start.value != 2 {
		t.Fatalf("rule metadata = %+v", compiled)
	}
	if compiled.cutoff.block || compiled.cutoff.value != 100 {
		t.Fatalf("cutoff = %+v", compiled.cutoff)
	}
	if len(compiled.split.positions) != 5 {
		t.Fatalf("split positions = %d, want 5", len(compiled.split.positions))
	}
}

func TestCompileStreamRejections(t *testing.T) {
	split := func(positions ...string) *option.DirectDesyncStreamSplit {
		return &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string](positions)}
	}
	tamper := func(value *option.DirectDesyncStreamHTTPTamper) *option.DirectDesyncStreamHTTPTamper { return value }
	tests := []struct {
		name string
		rule option.DirectDesyncStreamRule
		want string
	}{
		{
			name: "udp network",
			rule: func() option.DirectDesyncStreamRule {
				rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
				rule.Network = badoption.Listable[string]{"udp"}
				return rule
			}(),
			want: "TCP-only",
		},
		{
			name: "unknown method",
			rule: streamOptions("fake"),
			want: "not implemented",
		},
		{
			name: "duplicate method",
			rule: httpTamperOptions([]string{"http_tamper", "http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true}),
			want: "duplicate",
		},
		{
			name: "split before tamper",
			rule: func() option.DirectDesyncStreamRule {
				rule := splitOptions([]string{"split", "http_tamper"}, split("1"))
				rule.HTTPTamper = &option.DirectDesyncStreamHTTPTamper{HostCase: true}
				return rule
			}(),
			want: "split must be the last",
		},
		{
			name: "object without method",
			rule: splitOptions(nil, split("1")),
			want: "without the split method",
		},
		{
			name: "method without object",
			rule: streamOptions("tls_record"),
			want: "without a tls_record object",
		},
		{
			name: "empty http tamper",
			rule: httpTamperOptions([]string{"http_tamper"}, tamper(&option.DirectDesyncStreamHTTPTamper{})),
			want: "no transformation",
		},
		{
			name: "hostdot and hosttab",
			rule: httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostDot: true, HostTab: true}),
			want: "mutually exclusive",
		},
		{
			name: "hostspell length",
			rule: httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostSpell: "hostt"}),
			want: "exactly 4",
		},
		{
			name: "negative hostpad",
			rule: httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostPad: -1}),
			want: "negative hostpad",
		},
		{
			name: "http tamper on tls-only rule",
			rule: func() option.DirectDesyncStreamRule {
				rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
				rule.Protocol = badoption.Listable[string]{"tls"}
				return rule
			}(),
			want: "excludes http",
		},
		{
			name: "tls record on http-only rule",
			rule: func() option.DirectDesyncStreamRule {
				rule := streamOptions("tls_record")
				rule.TLSRecord = &option.DirectDesyncStreamTLSRecord{Pos: "sni"}
				rule.Protocol = badoption.Listable[string]{"http"}
				return rule
			}(),
			want: "excludes tls",
		},
		{
			name: "tls record without pos",
			rule: func() option.DirectDesyncStreamRule {
				rule := streamOptions("tls_record")
				rule.TLSRecord = &option.DirectDesyncStreamTLSRecord{}
				return rule
			}(),
			want: "requires pos",
		},
		{
			name: "split without positions",
			rule: splitOptions([]string{"split"}, split()),
			want: "requires split_pos",
		},
		{
			name: "split position zero",
			rule: splitOptions([]string{"split"}, split("0")),
			want: "zero",
		},
		{
			name: "invalid deprecated split form",
			rule: func() option.DirectDesyncStreamRule {
				split := split("1")
				split.SplitHTTPReq = "path"
				return splitOptions([]string{"split"}, split)
			}(),
			want: "invalid split_http_req",
		},
		{
			name: "oob data without oob",
			rule: func() option.DirectDesyncStreamRule {
				oobByte := option.DirectDesyncOOBByte{Value: 1}
				split := split("1")
				split.OOBData = &oobByte
				return splitOptions([]string{"split"}, split)
			}(),
			want: "oob_data requires oob",
		},
		{
			name: "skip nodelay with split",
			rule: func() option.DirectDesyncStreamRule {
				rule := splitOptions([]string{"split"}, split("1"))
				rule.SkipNoDelay = true
				return rule
			}(),
			want: "incompatible with split",
		},
		{
			name: "fix seg without split",
			rule: func() option.DirectDesyncStreamRule {
				rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
				rule.FixSeg = &option.DirectDesyncStreamFixSeg{Milliseconds: 10}
				return rule
			}(),
			want: "requires the split method",
		},
		{
			name: "negative mss",
			rule: func() option.DirectDesyncStreamRule {
				rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
				rule.MSS = -1
				return rule
			}(),
			want: "negative mss",
		},
		{
			name: "bad start",
			rule: func() option.DirectDesyncStreamRule {
				rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
				rule.Start = "n"
				return rule
			}(),
			want: "invalid stream interval",
		},
		{
			name: "bad cutoff",
			rule: func() option.DirectDesyncStreamRule {
				rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
				rule.Cutoff = "-2"
				return rule
			}(),
			want: "invalid stream interval",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileStream([]option.DirectDesyncStreamRule{test.rule}, "")
			if err == nil {
				t.Fatalf("expected rejection containing %q", test.want)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error %q does not mention %q", err, test.want)
			}
		})
	}
}

func TestCompileStreamOOBDisorderPlatform(t *testing.T) {
	rule := func() option.DirectDesyncStreamRule {
		split := &option.DirectDesyncStreamSplit{
			SplitPos: badoption.Listable[string]{"1"},
			Disorder: "any",
			OOB:      "any",
		}
		return splitOptions([]string{"split"}, split)
	}()
	config, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	if streamCaps().oobDisorder {
		if err != nil || config == nil {
			t.Fatalf("Linux must accept oob+disorder: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("non-Linux must reject oob+disorder instead of claiming support")
	}
}

func TestCompileStreamNativeKnobsPlatform(t *testing.T) {
	rule := func() option.DirectDesyncStreamRule {
		split := &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"1"}}
		rule := splitOptions([]string{"split"}, split)
		rule.MSS = 1200
		rule.FixSeg = &option.DirectDesyncStreamFixSeg{Milliseconds: 5}
		return rule
	}()
	_, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	caps := streamCaps()
	if caps.mss && caps.fixSeg {
		if err != nil {
			t.Fatalf("Linux must accept mss/fix_seg: %v", err)
		}
	} else if err == nil {
		t.Fatal("platform without mss/fix_seg must reject them")
	}
}

func TestCompileStreamSplitPositionLimit(t *testing.T) {
	// The literals are the pinned tpws params.h MAX_SPLITS value; they are
	// deliberately not derived from the implementation constant so that
	// changing the limit fails this test.
	if streamMaxSplitPositions != 16 {
		t.Fatalf("streamMaxSplitPositions = %d, want upstream MAX_SPLITS 16", streamMaxSplitPositions)
	}
	build := func(count int) []option.DirectDesyncStreamRule {
		positions := make([]string, count)
		for index := range positions {
			positions[index] = "1"
		}
		return []option.DirectDesyncStreamRule{
			splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{SplitPos: positions}),
		}
	}
	if _, err := CompileStream(build(16), ""); err != nil {
		t.Fatalf("16 split positions must compile: %v", err)
	}
	_, err := CompileStream(build(17), "")
	if err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("17 split positions must be rejected: %v", err)
	}
	// Deprecated split_http_req/split_tls entries occupy the same budget:
	// 14 explicit positions + 2 deprecated aliases = 16 (accepted), while
	// 15 + 2 = 17 must be rejected.
	deprecated := func(explicit int) []option.DirectDesyncStreamRule {
		rule := splitOptions([]string{"split"}, &option.DirectDesyncStreamSplit{
			SplitPos:     build(explicit)[0].Split.SplitPos,
			SplitHTTPReq: "method",
			SplitTLS:     "sni",
		})
		return []option.DirectDesyncStreamRule{rule}
	}
	if _, err = CompileStream(deprecated(14), ""); err != nil {
		t.Fatalf("14 positions plus 2 deprecated aliases must compile: %v", err)
	}
	if _, err = CompileStream(deprecated(15), ""); err == nil || !strings.Contains(err.Error(), "exceed") {
		t.Fatalf("15 positions plus 2 deprecated aliases must be rejected: %v", err)
	}
}

func TestStreamIntervalRange(t *testing.T) {
	start, err := parseStreamInterval("n2")
	if err != nil || !start.block || start.value != 2 {
		t.Fatalf("n2 interval = %+v %v", start, err)
	}
	cutoff, err := parseStreamInterval("10")
	if err != nil || cutoff.block || cutoff.value != 10 {
		t.Fatalf("10 interval = %+v %v", cutoff, err)
	}
	rule := &streamRule{start: start, cutoff: cutoff}
	// start=n2: the first block is out of range, the second is in range.
	if rule.inRange(1, 0) {
		t.Fatal("block 1 must be before start=n2")
	}
	if !rule.inRange(2, 0) {
		t.Fatal("block 2 must be inside start=n2")
	}
	// cutoff=10 uses the stream position at the block start: a block starting
	// at 0 is fully tampered even when it extends beyond 10.
	cutoffOnly := &streamRule{cutoff: cutoff}
	if !cutoffOnly.inRange(1, 0) {
		t.Fatal("cutoff must not stop a block that starts before it")
	}
	if cutoffOnly.inRange(1, 10) {
		t.Fatal("cutoff=10 must stop a block starting at position 10")
	}
}

type prepareRecord struct {
	fd     uintptr
	config streamSocketConfig
}

type recordingNative struct {
	prepared []prepareRecord
	sender   streamSender
	err      error
}

func (n *recordingNative) Prepare(fd uintptr, config streamSocketConfig) error {
	n.prepared = append(n.prepared, prepareRecord{fd: fd, config: config})
	return n.err
}

func (n *recordingNative) NewSender(netConn net.Conn, _ func() time.Time) (streamSender, error) {
	if n.err != nil {
		return nil, n.err
	}
	if n.sender == nil {
		return &plainSender{conn: netConn}, nil
	}
	return n.sender, nil
}

func TestPrepareSocketNativeSeam(t *testing.T) {
	rule := func() option.DirectDesyncStreamRule {
		rule := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
		rule.Port = badoption.Listable[uint16]{443}
		rule.SkipNoDelay = true
		rule.MSS = 1200
		return rule
	}()
	config, err := CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	recorder := &recordingNative{}
	config.native = recorder
	if err = config.PrepareSocket(t.Context(), 42, MatchFacts{Port: 443}); err != nil {
		t.Fatalf("PrepareSocket: %v", err)
	}
	if len(recorder.prepared) != 1 || recorder.prepared[0].fd != 42 {
		t.Fatalf("prepared = %+v", recorder.prepared)
	}
	if recorder.prepared[0].config.mss != 1200 || !recorder.prepared[0].config.skipNoDelay {
		t.Fatalf("native config = %+v", recorder.prepared[0].config)
	}
	// A different port does not select the rule and performs no native work.
	recorder.prepared = nil
	if err = config.PrepareSocket(t.Context(), 42, MatchFacts{Port: 8443}); err != nil {
		t.Fatalf("PrepareSocket: %v", err)
	}
	if len(recorder.prepared) != 0 {
		t.Fatal("non-matching facts must not touch the socket")
	}
	// A cancelled context fails instead of applying controls.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = config.PrepareSocket(ctx, 42, MatchFacts{Port: 443}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}

func TestSelectRuleFirstMatch(t *testing.T) {
	first := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
	first.Name = "first"
	first.Port = badoption.Listable[uint16]{443}
	second := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostDot: true})
	second.Name = "second"
	second.Port = badoption.Listable[uint16]{443}
	config, err := CompileStream([]option.DirectDesyncStreamRule{first, second}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rule := config.selectRule(MatchFacts{Port: 443})
	if rule == nil || rule.name != "first" {
		t.Fatalf("first-match selected %+v", rule)
	}
	if rule := config.selectRule(MatchFacts{Port: 80}); rule != nil {
		t.Fatalf("port mismatch selected %+v", rule)
	}
	// Domains cannot match before the host is known.
	domain := httpTamperOptions([]string{"http_tamper"}, &option.DirectDesyncStreamHTTPTamper{HostCase: true})
	domain.Domain = badoption.Listable[string]{"example.com"}
	config, err = CompileStream([]option.DirectDesyncStreamRule{domain}, "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if rule := config.selectRule(MatchFacts{Port: 443}); rule != nil {
		t.Fatal("domain rule must not match unknown host")
	}
	if rule := config.selectRule(MatchFacts{Port: 443, Host: "example.com", HostKnown: true}); rule == nil {
		t.Fatal("domain rule must match a known host")
	}
}

package tools

// QA v2 tests (tester-max-3, task t_be788118): independent re-verification of
// the D1/D3/D4 repairs on the v2 artifact. Persisted in the v3 artifact (task
// t_f7bf08bd); the behavioral assertions are unchanged from the independent QA
// run.

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
)

// TestQAV2FormatIPv6Dump dumps formatIPv6 for a list of textual addresses so a
// libc inet_ntop(AF_INET6) probe can be compared byte for byte.
func TestQAV2FormatIPv6Dump(t *testing.T) {
	inputPath := os.Getenv("QA_V6_INPUT")
	outputPath := os.Getenv("QA_V6_OUTPUT")
	if inputPath == "" || outputPath == "" {
		t.Skip("QA_V6_INPUT/QA_V6_OUTPUT not set")
	}
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if text == "" {
		t.Fatal("empty address list")
	}
	var builder strings.Builder
	for _, line := range strings.Split(text, "\n") {
		address, parseErr := netip.ParseAddr(line)
		if parseErr != nil {
			t.Fatalf("%s: %v", line, parseErr)
		}
		builder.WriteString(formatIPv6(address.As16()))
		builder.WriteByte('\n')
	}
	if err = os.WriteFile(outputPath, []byte(builder.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("dumped %d formatted addresses", strings.Count(builder.String(), "\n"))
}

// TestQAV2IP2NetV6CompatibleEndToEnd checks the D1 fix through the public
// aggregation entry point, including an aggregated network whose start is an
// IPv4-compatible address.
func TestQAV2IP2NetV6CompatibleEndToEnd(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		input  string
		output string
	}{
		{"single-compatible", "::1.2.3.4\n", "::1.2.3.4\n"},
		{"hex-compatible-collapses", "::102:304\n", "::1.2.3.4\n"},
		{"contrast-zero", "::\n", "::\n"},
		{"contrast-one", "::1\n", "::1\n"},
		{"contrast-two", "::2\n", "::2\n"},
		{"contrast-mapped", "::ffff:192.0.2.7\n", "::ffff:192.0.2.7\n"},
		{"contrast-group6-zero", "::0.0.1.0\n", "::100\n"},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			output, _, err := runIP2Net(t, IP2NetOptions{Family: FamilyIPv6}, testCase.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if output != testCase.output {
				t.Fatalf("got %q want %q", output, testCase.output)
			}
		})
	}
	// An aggregated network whose start address is IPv4-compatible keeps the
	// dotted rendering (prefix-length 120 => zct 8, five addresses >= 5).
	output, _, err := runIP2Net(t, IP2NetOptions{Family: FamilyIPv6, PrefixLengthMin: 120, PrefixLengthMax: 120},
		"::1.2.3.0\n::1.2.3.1\n::1.2.3.2\n::1.2.3.3\n::1.2.3.4\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != "::1.2.3.0/120\n" {
		t.Fatalf("aggregated compatible start: got %q", output)
	}
}

// TestQAV2IP2NetThresholdUint32Edges exercises the D3 repair: the library must
// accept the full uint32 option range and do the threshold arithmetic exactly
// (no truncation to a narrower type, no overflow).
func TestQAV2IP2NetThresholdUint32Edges(t *testing.T) {
	t.Parallel()
	maxU32 := ^uint32(0)
	// /30 => subnet size 4. floor(4*(2^32-2)/(2^32-1)) = 3, so four
	// addresses are dense and two are not.
	output, _, err := runIP2Net(t, IP2NetOptions{
		Family:          FamilyIPv4,
		PrefixLengthMin: 30,
		PrefixLengthMax: 30,
		V4ThresholdMul:  maxU32 - 1,
		V4ThresholdDiv:  maxU32,
	}, "10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3\n")
	if err != nil {
		t.Fatalf("mul=2^32-2 div=2^32-1 must be accepted: %v", err)
	}
	if output != "10.0.0.0/30\n" {
		t.Fatalf("unexpected exact-boundary output: %q", output)
	}
	output, _, err = runIP2Net(t, IP2NetOptions{
		Family:          FamilyIPv4,
		PrefixLengthMin: 30,
		PrefixLengthMax: 30,
		V4ThresholdMul:  maxU32 - 1,
		V4ThresholdDiv:  maxU32,
	}, "10.0.0.0\n10.0.0.1\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if output != "10.0.0.0\n10.0.0.1\n" {
		t.Fatalf("threshold 3 must keep two addresses bare: %q", output)
	}
	// Same integer boundary with a barely different ratio must flip the
	// decision: floor(4*(2^32-4)/(2^32-1)) = 3 as well, but
	// floor(4*1/(2^32-1)) = 0 is impossible because mul>=1; instead pin
	// mul=1/div=max where the exact threshold is 0 and any pair aggregates.
	output, _, err = runIP2Net(t, IP2NetOptions{
		Family:          FamilyIPv4,
		PrefixLengthMin: 30,
		PrefixLengthMax: 30,
		V4ThresholdMul:  1,
		V4ThresholdDiv:  maxU32,
	}, "10.0.0.0\n10.0.0.1\n")
	if err != nil {
		t.Fatalf("mul=1 div=2^32-1 must be accepted: %v", err)
	}
	if output != "10.0.0.0/30\n" {
		t.Fatalf("threshold 0 must aggregate: %q", output)
	}
	// IPv6 threshold at the uint32 maximum is accepted and bare.
	output, _, err = runIP2Net(t, IP2NetOptions{Family: FamilyIPv6, V6Threshold: maxU32},
		"2001:db8::1\n2001:db8::2\n2001:db8::3\n")
	if err != nil {
		t.Fatalf("v6 threshold 2^32-1 must be accepted: %v", err)
	}
	if output != "2001:db8::1\n2001:db8::2\n2001:db8::3\n" {
		t.Fatalf("unexpected v6 max-threshold output: %q", output)
	}
	// Invalid ratios stay rejected at the widened range.
	for _, options := range []IP2NetOptions{
		{Family: FamilyIPv4, V4ThresholdMul: maxU32, V4ThresholdDiv: maxU32},
		{Family: FamilyIPv4, V4ThresholdMul: 0, V4ThresholdDiv: maxU32},
		{Family: FamilyIPv4, V4ThresholdMul: 1, V4ThresholdDiv: 1},
		{Family: FamilyIPv6, PrefixLengthMin: 0, PrefixLengthMax: 30},
	} {
		if _, _, err = runIP2Net(t, options, "10.0.0.0\n"); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
}

// TestQAV2IP2Net64BitDivergence pins the documented deliberate difference with
// an input where it is actually observable. With prefix-length 1, threshold
// 3/2^31 the C code computes the density threshold in 32 bits:
// (3 * 2^31) mod 2^32 = 2^31, / 2^31 = 1, and the wrapped pre-check admits the
// cursor, so the C tool aggregates 0.0.0.0/1. The 64-bit Go implementation
// computes the exact threshold 3, so the two addresses stay bare.
func TestQAV2IP2Net64BitDivergence(t *testing.T) {
	t.Parallel()
	input := "0.0.0.0\n0.0.0.1\n"
	for _, options := range []IP2NetOptions{
		{Family: FamilyIPv4, PrefixLengthMin: 1, PrefixLengthMax: 1, V4ThresholdMul: 3, V4ThresholdDiv: 1 << 31},
		{Family: FamilyIPv4, PrefixLengthMin: 2, PrefixLengthMax: 2, V4ThresholdMul: 5, V4ThresholdDiv: 1 << 30},
	} {
		output, _, err := runIP2Net(t, options, input)
		if err != nil {
			t.Fatalf("%+v: unexpected error: %v", options, err)
		}
		if strings.Contains(output, "/") {
			t.Fatalf("%+v: 64-bit arithmetic must not aggregate here: %q", options, output)
		}
		if output != input {
			t.Fatalf("%+v: unexpected output: %q", options, output)
		}
	}
}

// TestQAV2IP2NetWorkBudget pins the hostile-input work bound (D3 "work
// bounds"): the aggregation loop must stop with an explicit error instead of
// running unbounded.
func TestQAV2IP2NetWorkBudget(t *testing.T) {
	saved := ip2netWorkBudget
	ip2netWorkBudget = 64
	defer func() { ip2netWorkBudget = saved }()
	var builder strings.Builder
	for index := 0; index < 4096; index++ {
		fmt.Fprintf(&builder, "10.0.%d.%d\n", index>>8, index&0xFF)
	}
	output, _, err := runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, PrefixLengthMin: 1, PrefixLengthMax: 30}, builder.String())
	if err == nil {
		t.Fatalf("work budget must stop the run, got output %q", output)
	}
	if !strings.Contains(err.Error(), "work limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestQAV2DNSReadBoundary confirms the constant and the boundary through the
// package API without reusing the repository test.
func TestQAV2DNSReadBoundary(t *testing.T) {
	t.Parallel()
	if dnsMaxResponseSize != 8192 {
		t.Fatalf("unexpected response buffer constant %d", dnsMaxResponseSize)
	}
	accepted := bytes.Repeat([]byte{0x41}, 8191)
	if message, err := ReadDNSResponse(bytes.NewReader(accepted)); err != nil || len(message) != 8191 {
		t.Fatalf("8191 must be accepted: len=%d err=%v", len(message), err)
	}
	rejected := bytes.Repeat([]byte{0x41}, 8192)
	if _, err := ReadDNSResponse(bytes.NewReader(rejected)); err == nil {
		t.Fatal("8192 must be rejected")
	}
	larger := bytes.Repeat([]byte{0x41}, 9000)
	if _, err := ReadDNSResponse(bytes.NewReader(larger)); err == nil {
		t.Fatal("9000 must be rejected, not truncated")
	}
}

// TestQAV2ParseStructuralErrorIsSilent proves ParseDNSResponse returns no
// addresses on a structurally invalid blob (atomicity at the library level).
func TestQAV2ParseStructuralErrorIsSilent(t *testing.T) {
	t.Parallel()
	header := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}
	answer := func(last bool) []byte {
		record := []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C}
		if last {
			record = append(record, 0x00, 0x10, 1, 2, 3, 4)
		} else {
			record = append(record, 0x00, 0x04, 1, 2, 3, 4)
		}
		return record
	}
	blob := append(append(append([]byte{}, header...), answer(false)...), answer(true)...)
	addresses, err := ParseDNSResponse(blob)
	if err == nil {
		t.Fatalf("truncated second answer must fail, got %v", addresses)
	}
	if len(addresses) != 0 {
		t.Fatalf("structural error must not return partial addresses: %v", addresses)
	}
}

// TestQAV2IP2NetCancellation checks the context seam still stops aggregation.
func TestQAV2IP2NetCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output strings.Builder
	_, err := IP2Net(ctx, strings.NewReader("10.0.0.1\n10.0.0.2\n"), &output, IP2NetOptions{Family: FamilyIPv4})
	if err == nil {
		t.Fatal("cancelled context must fail")
	}
}

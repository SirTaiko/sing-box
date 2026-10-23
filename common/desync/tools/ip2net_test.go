package tools

import (
	"context"
	"errors"
	"math/rand"
	"strings"
	"testing"
)

func runIP2Net(t *testing.T, options IP2NetOptions, input string) (string, IP2NetStats, error) {
	t.Helper()
	var output strings.Builder
	stats, err := IP2Net(context.Background(), strings.NewReader(input), &output, options)
	return output.String(), stats, err
}

// TestIP2NetV4Defaults is a source-linked table against ip2net/ip2net.c at
// bol-van/zapret v72.9 c849e55ef0f1c244206f5a05ff7b1ab41a3824ee. "source" names
// the pinned code path whose observable behavior the case pins.
func TestIP2NetV4Defaults(t *testing.T) {
	t.Parallel()
	tests := []ip2netTableCase{
		{
			name:   "dense /30 is aggregated",
			input:  "0.0.0.0\n0.0.0.1\n0.0.0.2\n0.0.0.3\n",
			output: "0.0.0.0/30\n",
			source: "ip2net.c:469-510 density loop, 3/4 of 4 addresses",
		},
		{
			name:   "two addresses stay bare",
			input:  "10.0.0.2\n10.0.0.1\n",
			output: "10.0.0.1\n10.0.0.2\n",
			source: "ip2net.c:485 threshold 3 of 4 addresses",
		},
		{
			name:   "three addresses fill a /30",
			input:  "10.0.0.3\n10.0.0.1\n10.0.0.2\n",
			output: "10.0.0.0/30\n",
			source: "ip2net.c:485-493 count >= subnet*pctmult/pctdiv",
		},
		{
			name:   "dense /24 with sparse tail",
			input:  v4RangeInput("0.0.0.0", "0.0.0.199"),
			output: "0.0.0.0/24\n",
			source: "ip2net.c:475-497 largest qualifying network wins",
		},
		{
			name:   "cursor skip picks the dense sub-block",
			input:  "0.0.0.202\n0.0.0.200\n0.0.0.201\n",
			output: "0.0.0.200/30\n",
			source: "ip2net.c:480-481 density pre-check skips /22../28 and accepts /30",
		},
		{
			name:     "equal count prefers the smaller network",
			input:    v4RangeInput("0.0.0.0", "0.0.1.255"),
			output:   "0.0.0.0/23\n",
			source:   "ip2net.c:487-495 tie-break replaces an equal count at a longer prefix",
			opt:      IP2NetOptions{V4ThresholdMul: 1, V4ThresholdDiv: 2},
			withOpts: true,
		},
		{
			name:   "prefix length passthrough is not masked",
			input:  "10.1.2.3/24\n",
			output: "10.1.2.3/24\n",
			source: "ip2net.c:439-445 x.x.x.x/y printed as parsed",
		},
		{
			name:   "slash 32 becomes a host address",
			input:  "1.2.3.4/32\n",
			output: "1.2.3.4\n",
			source: "ip2net.c:439 i==5, zct==32 falls through to the address list",
		},
		{
			name:   "prefix longer than 32 is dropped",
			input:  "1.2.3.4/33\n1.2.3.5/32\n",
			output: "1.2.3.5\n",
			source: "ip2net.c:443-444 zct<32 only",
		},
		{
			name:   "range passthrough is re-rendered",
			input:  "01.2.3.4-1.2.3.9\n",
			output: "1.2.3.4-1.2.3.9\n",
			source: "ip2net.c:429-434 printf from the parsed octets",
		},
		{
			name:   "reversed range is still passed through",
			input:  "9.9.9.9-1.1.1.1\n",
			output: "9.9.9.9-1.1.1.1\n",
			source: "ip2net.c:429-434 no ordering check",
		},
		{
			name:   "invalid lines are filtered",
			input:  "256.1.1.1\n1.2.3\n\n0.0.0.0\n",
			output: "0.0.0.0\n",
			source: "ip2net.c:436-438 octet mask check, unmatched lines ignored",
		},
		{
			name:   "sscanf trailing bytes are ignored",
			input:  "1.2.3.4.5\n",
			output: "1.2.3.4\n",
			source: "ip2net.c:436 sscanf stops after four octets",
		},
		{
			name:   "leading blanks are accepted like sscanf",
			input:  " 1.2.3.4\n",
			output: "1.2.3.4\n",
			source: "ip2net.c:436 %u skips leading whitespace",
		},
		{
			name:   "unparsable prefix length falls back to a host",
			input:  "1.2.3.4/abc\n",
			output: "1.2.3.4\n",
			source: "ip2net.c:436-439 i==4 branch",
		},
		{
			name:   "duplicates are collapsed",
			input:  "10.0.0.9\n10.0.0.8\n10.0.0.9\n",
			output: "10.0.0.8\n10.0.0.9\n",
			source: "ip2net.c:466-467 gnu_quicksort + unique",
		},
		{
			name:   "passthrough lines keep input order",
			input:  "9.9.9.0/24\n1.1.1.0-1.1.1.9\n",
			output: "9.9.9.0/24\n1.1.1.0-1.1.1.9\n",
			source: "ip2net.c:429-445 passthrough is emitted while reading",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := IP2NetOptions{Family: FamilyIPv4}
			if test.withOpts {
				options = test.opt
				options.Family = FamilyIPv4
			}
			output, _, err := runIP2Net(t, options, test.input)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", test.source, err)
			}
			if output != test.output {
				t.Fatalf("%s: output mismatch\n got: %q\nwant: %q", test.source, output, test.output)
			}
		})
	}
}

type ip2netTableCase struct {
	name     string
	input    string
	output   string
	source   string
	opt      IP2NetOptions
	withOpts bool
}

func v4RangeInput(start, end string) string {
	startAddr, _, _, _ := parseIPv4PrefixLine(start)
	endAddr, _, _, _ := parseIPv4PrefixLine(end)
	var builder strings.Builder
	for value := startAddr; ; value++ {
		builder.WriteString(formatIPv4(value))
		builder.WriteByte('\n')
		if value == endAddr {
			break
		}
	}
	return builder.String()
}

func TestIP2NetV4PrefixBounds(t *testing.T) {
	t.Parallel()
	// --prefix-length=30 restricts aggregation to /30 only.
	output, _, err := runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, PrefixLengthMin: 30, PrefixLengthMax: 30}, v4RangeInput("10.0.0.0", "10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.0/30\n" {
		t.Fatalf("unexpected output %q", output)
	}
	// --prefix-length=24 forbids the /30 that the default accepts.
	output, _, err = runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, PrefixLengthMin: 24, PrefixLengthMax: 24}, v4RangeInput("10.0.0.0", "10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3\n" {
		t.Fatalf("unexpected output %q", output)
	}
	// A /29 with 6 of 8 addresses meets 3/4 only when /29 is allowed.
	output, _, err = runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, PrefixLengthMin: 29, PrefixLengthMax: 29}, v4RangeInput("10.0.0.0", "10.0.0.5"))
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.0/29\n" {
		t.Fatalf("unexpected output %q", output)
	}
}

func TestIP2NetV4ThresholdBoundaries(t *testing.T) {
	t.Parallel()
	// 7/8 of a /30 (4 addresses) is 3.5 -> integer division 3, so three
	// addresses satisfy the threshold when the first one is the network start.
	output, _, err := runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, V4ThresholdMul: 7, V4ThresholdDiv: 8}, v4RangeInput("10.0.0.0", "10.0.0.2"))
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.0/30\n" {
		t.Fatalf("unexpected output %q", output)
	}
	// The source pre-check skips a network when the first address is deeper
	// than the (1-pct) part of the block, so .1-.3 never reaches /30 at 7/8.
	output, _, err = runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, V4ThresholdMul: 7, V4ThresholdDiv: 8}, v4RangeInput("10.0.0.1", "10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.1\n10.0.0.2\n10.0.0.3\n" {
		t.Fatalf("unexpected output %q", output)
	}
	// 2/3 of 4 addresses is integer 2, so two addresses qualify.
	output, _, err = runIP2Net(t, IP2NetOptions{Family: FamilyIPv4, V4ThresholdMul: 2, V4ThresholdDiv: 3}, v4RangeInput("10.0.0.0", "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.0/30\n" {
		t.Fatalf("unexpected output %q", output)
	}
}

func TestIP2NetV6(t *testing.T) {
	t.Parallel()
	tests := []ip2netTableCase{
		{
			name:   "five addresses reach the default /64 threshold",
			input:  "2001:db8::5\n2001:db8::4\n2001:db8::3\n2001:db8::2\n2001:db8::1\n",
			output: "2001:db8::/64\n",
			source: "ip2net.c:377-418 DEFAULT_V6_THRESHOLD 5, zct 64",
		},
		{
			name:   "four addresses stay bare below the threshold",
			input:  "2001:db8::4\n2001:db8::3\n2001:db8::2\n2001:db8::1\n",
			output: "2001:db8::1\n2001:db8::2\n2001:db8::3\n2001:db8::4\n",
			source: "ip2net.c:396 count >= v6_threshold",
		},
		{
			name:     "threshold three groups three addresses",
			input:    "2001:db8::3\n2001:db8::2\n2001:db8::1\n",
			output:   "2001:db8::/64\n",
			source:   "ip2net.c:396 configurable v6 threshold",
			opt:      IP2NetOptions{V6Threshold: 3},
			withOpts: true,
		},
		{
			name:   "ipv6 prefix passthrough keeps the input spelling",
			input:  "2001:DB8::/48\n",
			output: "2001:DB8::/48\n",
			source: "ip2net.c:341-345 printf %s of the truncated input",
		},
		{
			name:   "slash 128 becomes a canonical host",
			input:  "2001:DB8::1/128\n",
			output: "2001:db8::1\n",
			source: "ip2net.c:341 zct!=128 gate, inet_ntop output",
		},
		{
			name:   "prefix longer than 128 is dropped",
			input:  "2001:db8::1/129\n",
			output: "",
			source: "ip2net.c:343 zct<128 only",
		},
		{
			name:   "range passthrough is verbatim",
			input:  "2001:DB8::1-2001:db8::ff\n",
			output: "2001:DB8::1-2001:db8::ff\n",
			source: "ip2net.c:347-351 printf %s-%s",
		},
		{
			name:   "range with invalid end is dropped",
			input:  "2001:db8::1-notanaddress\n",
			output: "",
			source: "ip2net.c:347-351 both ends must parse as IPv6",
		},
		{
			name:   "unparsable prefix length falls back to a host",
			input:  "2001:db8::1/abc\n",
			output: "2001:db8::1\n",
			source: "ip2net.c:341-351 sscanf failure falls through to the list",
		},
		{
			name:   "zone identifiers are invalid",
			input:  "fe80::1%eth0\n",
			output: "",
			source: "ip2net.c:335 inet_pton(AF_INET6) rejects scoped literals",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := IP2NetOptions{Family: FamilyIPv6}
			if test.withOpts {
				options = test.opt
				options.Family = FamilyIPv6
			}
			output, _, err := runIP2Net(t, options, test.input)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", test.source, err)
			}
			if output != test.output {
				t.Fatalf("%s: output mismatch\n got: %q\nwant: %q", test.source, output, test.output)
			}
		})
	}
}

func TestFormatIPv6(t *testing.T) {
	t.Parallel()
	tests := []struct {
		text   string
		output string
	}{
		{"::", "::"},
		{"::1", "::1"},
		{"::2", "::2"},
		{"2001:db8::1", "2001:db8::1"},
		{"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1"},
		{"2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1"},
		{"::ffff:1.2.3.4", "::ffff:1.2.3.4"},
		{"::ffff:0:1.2.3.4", "::ffff:0:102:304"},
		// glibc renders every address whose first 96 bits are zero and whose
		// seventh group is non-zero in the IPv4-compatible dotted form. These
		// cases come from an inet_ntop(AF_INET6) corpus probe (libc, not the
		// reference tool); the contrasts pin the class boundary.
		{"::1.2.3.4", "::1.2.3.4"},
		{"::0.1.2.3", "::0.1.2.3"},
		{"::db8:1", "::13.184.0.1"},
		{"::1:0", "::0.1.0.0"},
		{"::ffff:0", "::255.255.0.0"},
		{"::0.0.1.0", "::100"},
		{"::102:304", "::1.2.3.4"},
		{"::0:1.2.3.4", "::1.2.3.4"},
		{"::ffff:0:0", "::ffff:0.0.0.0"},
		{"::ffff:1:2", "::ffff:0.1.0.2"},
		{"::fffe:1.2.3.4", "::fffe:102:304"},
		{"1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:102:304"},
		{"1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"},
	}
	for _, test := range tests {
		address, err := parseIPv4PrefixLike(test.text)
		if err != nil {
			t.Fatalf("%s: %v", test.text, err)
		}
		if formatted := formatIPv6(address); formatted != test.output {
			t.Fatalf("%s: got %q want %q", test.text, formatted, test.output)
		}
	}
}

func parseIPv4PrefixLike(text string) ([16]byte, error) {
	kind, _, address := classifyIPv6Line(text)
	if kind != ipv6LinePush {
		return [16]byte{}, errors.New("not an IPv6 address")
	}
	return address, nil
}

// TestIP2NetV6CompatibleFormatting is the end-to-end control for the libc
// rendering rule: the pinned tool prints every address with inet_ntop(AF_INET6),
// so an IPv4-compatible address and the ::102:304 spelling of the same address
// must both come out as ::1.2.3.4, while ::, ::1, ::2 and the mapped form keep
// their distinct spellings (ip2net.c:414, inet_ntop compatible class).
func TestIP2NetV6CompatibleFormatting(t *testing.T) {
	t.Parallel()
	output, _, err := runIP2Net(t, IP2NetOptions{Family: FamilyIPv6},
		"::1\n::2\n::1.2.3.4\n::102:304\n::ffff:192.0.2.7\n")
	if err != nil {
		t.Fatal(err)
	}
	// The duplicate ::1.2.3.4/::102:304 pair collapses to one address.
	expected := "::1\n::2\n::1.2.3.4\n::ffff:192.0.2.7\n"
	if output != expected {
		t.Fatalf("unexpected output\n got: %q\nwant: %q", output, expected)
	}
}

func TestIP2NetErrors(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	_, err := IP2Net(context.Background(), strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{})
	if err == nil {
		t.Fatal("expected a missing family error")
	}
	_, err = IP2Net(context.Background(), strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{Family: FamilyIPv4 | FamilyIPv6})
	if err == nil {
		t.Fatal("expected a both-families rejection")
	}
	_, err = IP2Net(context.Background(), strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{Family: FamilyIPv4, PrefixLengthMin: 24})
	if err == nil {
		t.Fatal("expected a prefix length bound error")
	}
	_, err = IP2Net(context.Background(), strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{Family: FamilyIPv4, PrefixLengthMin: 32, PrefixLengthMax: 32})
	if err == nil {
		t.Fatal("expected a prefix length range error")
	}
	_, err = IP2Net(context.Background(), strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{Family: FamilyIPv4, V4ThresholdMul: 4, V4ThresholdDiv: 4})
	if err == nil {
		t.Fatal("expected a v4 threshold error")
	}
	_, err = IP2Net(context.Background(), strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{Family: FamilyIPv4, MaxEntries: -1})
	if err == nil {
		t.Fatal("expected an address limit error")
	}
}

func TestIP2NetLargeInputBounded(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	_, err := IP2Net(context.Background(), strings.NewReader("0.0.0.1\n0.0.0.2\n"), &output, IP2NetOptions{Family: FamilyIPv4, MaxEntries: 1})
	if err == nil {
		t.Fatal("expected an address limit error")
	}
	if !strings.Contains(err.Error(), "address limit") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIP2NetOverlongLine(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	_, err := IP2Net(context.Background(), strings.NewReader(strings.Repeat("1", 64)+"\n"), &output, IP2NetOptions{Family: FamilyIPv4, MaxLineLength: 32})
	if err == nil {
		t.Fatal("expected a line length error")
	}
}

func TestIP2NetCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output strings.Builder
	_, err := IP2Net(ctx, strings.NewReader("0.0.0.0\n"), &output, IP2NetOptions{Family: FamilyIPv4})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestIP2NetWorkBudget(t *testing.T) {
	// Not parallel: the budget is a package level bound shared with other tests.
	saved := ip2netWorkBudget
	ip2netWorkBudget = 1
	defer func() { ip2netWorkBudget = saved }()
	var output strings.Builder
	_, err := IP2Net(context.Background(), strings.NewReader(v4RangeInput("10.0.0.0", "10.0.0.9")), &output, IP2NetOptions{Family: FamilyIPv4})
	if err == nil || !strings.Contains(err.Error(), "work limit") {
		t.Fatalf("expected a work limit error, got %v", err)
	}
}

func TestIP2NetIPv4OverflowSafety(t *testing.T) {
	t.Parallel()
	// The pinned C code also computes the cursor pre-check in 32-bit
	// arithmetic (ip2net.c:480). At /2 with pctdiv 2^20 both the density
	// product and the pre-check product wrap, and the wrapped pre-check skips
	// the block, so the C tool prints the four bare addresses as well: this
	// input does not distinguish the implementations. It still pins that the
	// 64-bit Go path does not aggregate from the wrapped density product. A
	// genuinely divergent input (C aggregates in 32 bits, Go does not) is
	// pinned by TestQAV2IP2Net64BitDivergence.
	options := IP2NetOptions{
		Family:          FamilyIPv4,
		V4ThresholdMul:  1,
		V4ThresholdDiv:  1 << 20,
		PrefixLengthMin: 2,
		PrefixLengthMax: 2,
	}
	output, _, err := runIP2Net(t, options, v4RangeInput("10.0.0.0", "10.0.0.3"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "/") {
		t.Fatalf("unexpected aggregation from wrapped arithmetic: %q", output)
	}
}

// TestIP2NetThresholdUint32Range pins the upstream option range: both
// thresholds are parsed with sscanf("%u") into uint32 fields and accept every
// uint32 value with 1 <= mul < div (ip2net.c:286-301). The implementation must
// not impose a smaller cap, and the widened options must not overflow the
// 64-bit arithmetic.
func TestIP2NetThresholdUint32Range(t *testing.T) {
	t.Parallel()
	maxUint32 := ^uint32(0)
	output, _, err := runIP2Net(t, IP2NetOptions{
		Family:          FamilyIPv4,
		V4ThresholdMul:  maxUint32 - 1,
		V4ThresholdDiv:  maxUint32,
		PrefixLengthMin: 30,
		PrefixLengthMax: 30,
	}, "10.0.0.0\n10.0.0.1\n")
	if err != nil {
		t.Fatalf("full uint32 threshold must be accepted: %v", err)
	}
	// 2 < 4*(2^32-2)/(2^32-1) = 3, so the pair stays bare. The 32-bit C
	// multiplication wraps here, which is the documented arithmetic difference.
	if output != "10.0.0.0\n10.0.0.1\n" {
		t.Fatalf("unexpected output for a near-1 threshold: %q", output)
	}
	output, _, err = runIP2Net(t, IP2NetOptions{Family: FamilyIPv6, V6Threshold: maxUint32},
		"2001:db8::1\n2001:db8::2\n2001:db8::3\n")
	if err != nil {
		t.Fatalf("full uint32 v6 threshold must be accepted: %v", err)
	}
	if output != "2001:db8::1\n2001:db8::2\n2001:db8::3\n" {
		t.Fatalf("unexpected output for the maximum v6 threshold: %q", output)
	}
}

// TestIP2NetInvariants is a differential property check that does not depend on
// the tie-break order: for deterministic pseudo-random sparse and dense inputs
// every input address must be covered exactly once, emitted networks must be
// ascending and disjoint, and every emitted network must really satisfy the
// density threshold of its size.
func TestIP2NetInvariants(t *testing.T) {
	t.Parallel()
	random := rand.New(rand.NewSource(20261022))
	thresholds := []struct {
		mul uint32
		div uint32
	}{
		{mul: 3, div: 4},
		{mul: 1, div: 2},
	}
	for _, threshold := range thresholds {
		for iteration := 0; iteration < 20; iteration++ {
			count := 1 + random.Intn(120)
			base := uint32(0x0A000000) + uint32(random.Intn(8))*256
			seen := make(map[uint32]struct{}, count)
			addresses := make([]uint32, 0, count)
			var input strings.Builder
			for len(addresses) < count {
				address := base + uint32(random.Intn(1024))
				if _, duplicate := seen[address]; duplicate {
					continue
				}
				seen[address] = struct{}{}
				addresses = append(addresses, address)
				input.WriteString(formatIPv4(address))
				input.WriteByte('\n')
			}
			output, _, err := runIP2Net(t, IP2NetOptions{
				Family:         FamilyIPv4,
				V4ThresholdMul: threshold.mul,
				V4ThresholdDiv: threshold.div,
			}, input.String())
			if err != nil {
				t.Fatal(err)
			}
			covered := make(map[uint32]int, len(addresses))
			var lastEnd uint64
			for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
				address, bits, hasBits, ok := parseIPv4PrefixLine(line)
				if !ok {
					t.Fatalf("emitted line does not parse: %q", line)
				}
				var start, end uint64
				if hasBits {
					// ipv4Mask takes the upstream zero-bit count, not the
					// prefix length.
					mask := ipv4Mask(uint32(32 - bits))
					start = uint64(address & mask)
					end = uint64(address | ^mask)
					size := uint64(^mask) + 1
					inside := 0
					for candidate := start; candidate <= end; candidate++ {
						if _, listed := seen[uint32(candidate)]; listed {
							inside++
						}
					}
					if uint64(inside) < size*uint64(threshold.mul)/uint64(threshold.div) {
						t.Fatalf("network %s does not satisfy %d/%d: %d of %d", line, threshold.mul, threshold.div, inside, size)
					}
				} else {
					start = uint64(address)
					end = start
				}
				if start <= lastEnd {
					t.Fatalf("emitted networks are not ascending and disjoint at %q", line)
				}
				lastEnd = end
				for candidate := start; candidate <= end; candidate++ {
					if _, listed := seen[uint32(candidate)]; listed {
						covered[uint32(candidate)]++
					}
				}
			}
			for _, address := range addresses {
				if covered[address] != 1 {
					t.Fatalf("address %s covered %d times", formatIPv4(address), covered[address])
				}
			}
			for address, times := range covered {
				if times != 1 {
					t.Fatalf("address %s covered %d times", formatIPv4(address), times)
				}
			}
		}
	}
}

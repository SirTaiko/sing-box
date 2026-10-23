package tools

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// Family is a DNS/IP address family bit set.
type Family uint8

const (
	FamilyIPv4 Family = 1 << iota
	FamilyIPv6
)

// ParseFamily parses the operator spelling of an address family.
//
// The upstream tools accept "4", "6" and "46"; "both" is the long spelling used
// by this command surface. The ip2net command only accepts a single family and
// rejects FamilyIPv4|FamilyIPv6 itself.
func ParseFamily(value string) (Family, error) {
	switch value {
	case "4", "ipv4":
		return FamilyIPv4, nil
	case "6", "ipv6":
		return FamilyIPv6, nil
	case "46", "both", "ipv4+ipv6":
		return FamilyIPv4 | FamilyIPv6, nil
	}
	return 0, E.New("unknown address family: ", value)
}

// String returns the single-family operator spelling.
func (f Family) String() string {
	switch f {
	case FamilyIPv4:
		return "4"
	case FamilyIPv6:
		return "6"
	case FamilyIPv4 | FamilyIPv6:
		return "46"
	}
	return "?"
}

// Family bits used by the resolver seam.
func (f Family) Has(family Family) bool {
	return f&family != 0
}

const (
	// ip2net defaults from ip2net.c (DEFAULT_PCTMULT/DEFAULT_PCTDIV,
	// DEFAULT_V4_ZCT_MAX/DEFAULT_V4_ZCT_MIN, DEFAULT_V6_ZCT_MAX/ZCT_MIN,
	// DEFAULT_V6_THRESHOLD).
	ip2netDefaultV4PrefixMin = 22
	ip2netDefaultV4PrefixMax = 30
	ip2netDefaultV6PrefixMin = 56
	ip2netDefaultV6PrefixMax = 64
	ip2netDefaultV4Mul       = 3
	ip2netDefaultV4Div       = 4
	ip2netDefaultV6Threshold = 5

	// Bounds that keep hostile input bounded. They do not change the result for
	// any input accepted by the pinned implementation within its own limits.
	ip2netDefaultMaxEntries = 4 << 20
	ip2netDefaultMaxLine    = 4096
)

// ip2netWorkBudget bounds the aggregation inner loops so hostile input cannot
// turn the greedy scan quadratic. It is a variable only so tests can lower it.
var ip2netWorkBudget = 1 << 28

// IP2NetOptions configures the ip2net aggregation.
//
// A zero value uses the pinned upstream defaults: IPv4, prefix length 22-30,
// --v4-threshold 3/4, --v6-threshold 5.
type IP2NetOptions struct {
	Family Family
	// PrefixLengthMin/PrefixLengthMax are the shortest and the longest prefix
	// that may be aggregated ("--prefix-length=min-max"). Both must be set, or
	// both zero for the family default.
	PrefixLengthMin int
	PrefixLengthMax int
	// V4ThresholdMul/V4ThresholdDiv is the IPv4 density threshold ("mul/div").
	// Zero for both selects 3/4.
	V4ThresholdMul uint32
	V4ThresholdDiv uint32
	// V6Threshold is the minimum number of IPv6 addresses in a subnet. Zero
	// selects 5.
	V6Threshold uint32
	// MaxEntries bounds the number of bare addresses kept in memory.
	MaxEntries int
	// MaxLineLength bounds a single input line. Over-long lines are an error,
	// never a silent split.
	MaxLineLength int
}

// IP2NetStats is the accounting of one ip2net run. It is not printed by the
// command: the command is silent apart from the normalized list.
type IP2NetStats struct {
	InputLines        int
	Addresses         int
	UniqueAddresses   int
	PrefixPassthrough int
	RangePassthrough  int
	InvalidLines      int
	OutputEntries     int
}

type ip2netParams struct {
	ipv6       bool
	bits       int
	prefixMin  int
	prefixMax  int
	zctMin     uint32
	zctMax     uint32
	mul        uint64
	div        uint64
	v6Thresh   uint64
	maxEntries int
	maxLine    int
}

func (o IP2NetOptions) resolve() (ip2netParams, error) {
	var p ip2netParams
	switch o.Family {
	case FamilyIPv4:
	case FamilyIPv6:
		p.ipv6 = true
	case 0:
		return p, E.New("ip2net: --family is required (4 or 6)")
	default:
		return p, E.New("ip2net: --family must be 4 or 6, not both")
	}
	p.bits = 32
	p.prefixMin = ip2netDefaultV4PrefixMin
	p.prefixMax = ip2netDefaultV4PrefixMax
	if p.ipv6 {
		p.bits = 128
		p.prefixMin = ip2netDefaultV6PrefixMin
		p.prefixMax = ip2netDefaultV6PrefixMax
	}
	if o.PrefixLengthMin != 0 || o.PrefixLengthMax != 0 {
		if o.PrefixLengthMin == 0 || o.PrefixLengthMax == 0 {
			return p, E.New("ip2net: --prefix-length needs min and max")
		}
		p.prefixMin = o.PrefixLengthMin
		p.prefixMax = o.PrefixLengthMax
	}
	if p.prefixMin < 1 || p.prefixMax >= p.bits {
		return p, E.New("ip2net: --prefix-length must be within 1-", p.bits-1)
	}
	if p.prefixMin > p.prefixMax {
		return p, E.New("ip2net: --prefix-length min must not exceed max")
	}
	p.zctMin = uint32(p.bits - p.prefixMax)
	p.zctMax = uint32(p.bits - p.prefixMin)

	p.mul = ip2netDefaultV4Mul
	p.div = ip2netDefaultV4Div
	if o.V4ThresholdMul != 0 || o.V4ThresholdDiv != 0 {
		if o.V4ThresholdMul == 0 || o.V4ThresholdDiv == 0 {
			return p, E.New("ip2net: --v4-threshold needs mul/div")
		}
		p.mul = uint64(o.V4ThresholdMul)
		p.div = uint64(o.V4ThresholdDiv)
	}
	if p.div < 2 || p.mul < 1 || p.mul >= p.div {
		return p, E.New("ip2net: --v4-threshold must be mul/div with 1 <= mul < div")
	}

	p.v6Thresh = ip2netDefaultV6Threshold
	if o.V6Threshold != 0 {
		p.v6Thresh = uint64(o.V6Threshold)
	}
	if p.v6Thresh < 1 {
		return p, E.New("ip2net: --v6-threshold must be at least 1")
	}

	p.maxEntries = o.MaxEntries
	if p.maxEntries == 0 {
		p.maxEntries = ip2netDefaultMaxEntries
	}
	if p.maxEntries < 1 {
		return p, E.New("ip2net: invalid address limit")
	}
	p.maxLine = o.MaxLineLength
	if p.maxLine == 0 {
		p.maxLine = ip2netDefaultMaxLine
	}
	if p.maxLine < 16 {
		return p, E.New("ip2net: invalid line length limit")
	}
	return p, nil
}

// IP2Net normalizes a newline separated address list into the smallest set of
// networks that satisfies the configured density/min-count thresholds.
//
// It reproduces ip2net/ip2net.c: bare addresses of the selected family are
// sorted, deduplicated and aggregated; "ip/bits" and "ip1-ip2" lines are passed
// through (the IPv4 forms are re-rendered from the parsed numbers exactly like
// printf in the source, the IPv6 forms are emitted verbatim like the source
// does); every other line is dropped.
func IP2Net(ctx context.Context, in io.Reader, out io.Writer, opts IP2NetOptions) (IP2NetStats, error) {
	var stats IP2NetStats
	params, err := opts.resolve()
	if err != nil {
		return stats, err
	}
	if in == nil || out == nil {
		return stats, E.New("ip2net: input and output streams are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	writer := &firstErrorWriter{writer: bufio.NewWriterSize(out, 64*1024)}
	if params.ipv6 {
		err = runIP2Net6(ctx, in, writer, params, &stats)
	} else {
		err = runIP2Net4(ctx, in, writer, params, &stats)
	}
	if err != nil {
		return stats, err
	}
	if err = writer.flush(); err != nil {
		return stats, E.Cause(err, "ip2net: write output")
	}
	return stats, nil
}

// firstErrorWriter records the first write error and swallows the rest so the
// aggregation loop does not need error handling on every line.
type firstErrorWriter struct {
	writer *bufio.Writer
	err    error
}

func (w *firstErrorWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return len(p), nil
	}
	n, err := w.writer.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *firstErrorWriter) WriteString(s string) {
	_, _ = w.Write([]byte(s))
}

func (w *firstErrorWriter) flush() error {
	if w.err != nil {
		return w.err
	}
	return w.writer.Flush()
}

func newLineScanner(in io.Reader, maxLine int) *bufio.Scanner {
	scanner := bufio.NewScanner(in)
	initial := 512
	if maxLine < initial {
		initial = maxLine
	}
	scanner.Buffer(make([]byte, 0, initial), maxLine)
	return scanner
}

// rtrim mirrors the C rtrim helper: trailing '\n', '\r', ' ' and '\t' only.
func rtrim(value string) string {
	return strings.TrimRight(value, "\r\n \t")
}

func runIP2Net4(ctx context.Context, in io.Reader, w *firstErrorWriter, params ip2netParams, stats *IP2NetStats) error {
	addresses := make([]uint32, 0, 1024)
	scanner := newLineScanner(in, params.maxLine)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		stats.InputLines++
		line := rtrim(scanner.Text())
		if line == "" {
			stats.InvalidLines++
			continue
		}
		if start, end, ok := parseIPv4Range(line); ok {
			stats.RangePassthrough++
			w.WriteString(formatIPv4(start) + "-" + formatIPv4(end) + "\n")
			continue
		}
		address, bits, hasBits, ok := parseIPv4PrefixLine(line)
		if !ok {
			stats.InvalidLines++
			continue
		}
		if hasBits && bits != 32 {
			if bits < 32 {
				stats.PrefixPassthrough++
				w.WriteString(formatIPv4(address) + "/" + strconv.FormatUint(uint64(bits), 10) + "\n")
			} else {
				// ip2net.c:436-445: a prefix longer than /32 is dropped.
				stats.InvalidLines++
			}
			continue
		}
		if len(addresses) >= params.maxEntries {
			return E.New("ip2net: input exceeds the address limit of ", params.maxEntries)
		}
		addresses = append(addresses, address)
	}
	if err := scanner.Err(); err != nil {
		return E.Cause(err, "ip2net: read input (line limit ", params.maxLine, ")")
	}
	stats.Addresses = len(addresses)
	slices.Sort(addresses)
	unique := addresses[:0]
	for index, address := range addresses {
		if index == 0 || address != addresses[index-1] {
			unique = append(unique, address)
		}
	}
	stats.UniqueAddresses = len(unique)
	return aggregateIPv4(ctx, unique, params, w, stats)
}

// aggregateIPv4 is a pure re-implementation of the greedy loop in
// ip2net/ip2net.c:469-510.
//
// For each cursor position the source walks prefix lengths from the largest
// network (zctMax) to the smallest (zctMin), skips a prefix length when the
// first address is already too deep inside the network to reach the density
// threshold, counts the contiguous sorted addresses inside the network and
// keeps the densest network. An equal count reached at a shorter prefix
// replaces the previous candidate, which is the source tie-break ("do not do
// carpet bombing if possible"). The cursor then jumps behind the accepted
// network, or advances by one when no network qualified.
func aggregateIPv4(ctx context.Context, addresses []uint32, params ip2netParams, w *firstErrorWriter, stats *IP2NetStats) error {
	position := 0
	work := 0
	for position < len(addresses) {
		if position%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		var bestCount uint32
		var bestZCT uint32
		positionEnd := position + 1
		for zct := int(params.zctMax); zct >= int(params.zctMin); zct-- {
			work++
			if work > ip2netWorkBudget {
				return E.New("ip2net: aggregation work limit exceeded")
			}
			mask := ipv4Mask(uint32(zct))
			networkStart := addresses[position] & mask
			subnetSize := uint64(^mask) + 1
			// ip2net.c:480-481: skip when the cursor address is beyond the
			// dense part of the network.
			if uint64(addresses[position]) > uint64(networkStart)+subnetSize*(params.div-params.mul)/params.div {
				continue
			}
			networkEnd := networkStart | ^mask
			count := uint32(1)
			next := position + 1
			for next < len(addresses) && addresses[next] <= networkEnd {
				count++
				next++
				work++
				if work > ip2netWorkBudget {
					return E.New("ip2net: aggregation work limit exceeded")
				}
			}
			if count == 1 {
				break
			}
			if uint64(count) >= subnetSize*params.mul/params.div {
				if bestCount == 0 || count == bestCount {
					bestCount = count
					bestZCT = uint32(zct)
					positionEnd = next
				} else {
					break
				}
			}
		}
		if bestZCT != 0 {
			network := addresses[position] & ipv4Mask(bestZCT)
			w.WriteString(formatIPv4(network) + "/" + strconv.FormatUint(uint64(32-bestZCT), 10) + "\n")
			position = positionEnd
		} else {
			w.WriteString(formatIPv4(addresses[position]) + "\n")
			position++
		}
		stats.OutputEntries++
	}
	return nil
}

type ipv6LineKind uint8

const (
	ipv6LineInvalid ipv6LineKind = iota
	ipv6LinePush
	ipv6LinePassthrough
	ipv6LineDrop
)

func runIP2Net6(ctx context.Context, in io.Reader, w *firstErrorWriter, params ip2netParams, stats *IP2NetStats) error {
	addresses := make([][16]byte, 0, 1024)
	scanner := newLineScanner(in, params.maxLine)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		stats.InputLines++
		line := rtrim(scanner.Text())
		if line == "" {
			stats.InvalidLines++
			continue
		}
		kind, text, address := classifyIPv6Line(line)
		switch kind {
		case ipv6LinePush:
			if len(addresses) >= params.maxEntries {
				return E.New("ip2net: input exceeds the address limit of ", params.maxEntries)
			}
			addresses = append(addresses, address)
		case ipv6LinePassthrough:
			if strings.ContainsRune(text, '/') {
				stats.PrefixPassthrough++
			} else {
				stats.RangePassthrough++
			}
			w.WriteString(text + "\n")
		case ipv6LineDrop:
			stats.InvalidLines++
		default:
			stats.InvalidLines++
		}
	}
	if err := scanner.Err(); err != nil {
		return E.Cause(err, "ip2net: read input (line limit ", params.maxLine, ")")
	}
	stats.Addresses = len(addresses)
	slices.SortFunc(addresses, func(a, b [16]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	unique := addresses[:0]
	for index, address := range addresses {
		if index == 0 || address != addresses[index-1] {
			unique = append(unique, address)
		}
	}
	stats.UniqueAddresses = len(unique)
	return aggregateIPv6(ctx, unique, params, w, stats)
}

// classifyIPv6Line mirrors ip2net/ip2net.c:326-365.
func classifyIPv6Line(line string) (ipv6LineKind, string, [16]byte) {
	var empty [16]byte
	slash := strings.IndexByte(line, '/')
	dash := strings.IndexByte(line, '-')
	switch {
	case slash >= 0:
		left := line[:slash]
		address, err := netip.ParseAddr(left)
		if err != nil || !address.Is6() || address.Zone() != "" {
			return ipv6LineInvalid, "", empty
		}
		bits, ok := parsePrefixNumber(line[slash+1:])
		if ok && bits != 128 {
			if bits < 128 {
				return ipv6LinePassthrough, left + "/" + strconv.FormatUint(uint64(bits), 10), empty
			}
			return ipv6LineDrop, "", empty
		}
		return ipv6LinePush, "", address.As16()
	case dash >= 0:
		left := line[:dash]
		right := line[dash+1:]
		start, startErr := netip.ParseAddr(left)
		end, endErr := netip.ParseAddr(right)
		if startErr != nil || endErr != nil || !start.Is6() || !end.Is6() || start.Zone() != "" || end.Zone() != "" {
			return ipv6LineInvalid, "", empty
		}
		return ipv6LinePassthrough, left + "-" + right, empty
	}
	address, err := netip.ParseAddr(line)
	if err != nil || !address.Is6() || address.Zone() != "" {
		return ipv6LineInvalid, "", empty
	}
	return ipv6LinePush, "", address.As16()
}

func aggregateIPv6(ctx context.Context, addresses [][16]byte, params ip2netParams, w *firstErrorWriter, stats *IP2NetStats) error {
	position := 0
	work := 0
	for position < len(addresses) {
		if position%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		var bestCount uint32
		var bestZCT uint32
		positionEnd := position + 1
		for zct := int(params.zctMax); zct >= int(params.zctMin); zct-- {
			work++
			if work > ip2netWorkBudget {
				return E.New("ip2net: aggregation work limit exceeded")
			}
			mask := ipv6Mask(uint32(zct))
			networkStart := ipv6And(addresses[position], mask)
			count := uint32(1)
			next := position + 1
			for next < len(addresses) && ipv6And(addresses[next], mask) == networkStart {
				count++
				next++
				work++
				if work > ip2netWorkBudget {
					return E.New("ip2net: aggregation work limit exceeded")
				}
			}
			if count == 1 {
				break
			}
			if uint64(count) >= params.v6Thresh {
				if bestCount == 0 || count == bestCount {
					bestCount = count
					bestZCT = uint32(zct)
					positionEnd = next
				} else {
					break
				}
			}
		}
		if bestZCT != 0 {
			network := ipv6And(addresses[position], ipv6Mask(bestZCT))
			w.WriteString(formatIPv6(network) + "/" + strconv.FormatUint(uint64(128-bestZCT), 10) + "\n")
			position = positionEnd
		} else {
			w.WriteString(formatIPv6(addresses[position]) + "\n")
			position++
		}
		stats.OutputEntries++
	}
	return nil
}

func ipv4Mask(zct uint32) uint32 {
	if zct < 32 {
		return ^((uint32(1) << zct) - 1)
	}
	return 0
}

func formatIPv4(value uint32) string {
	return strconv.FormatUint(uint64(value>>24), 10) + "." +
		strconv.FormatUint(uint64(value>>16&0xFF), 10) + "." +
		strconv.FormatUint(uint64(value>>8&0xFF), 10) + "." +
		strconv.FormatUint(uint64(value&0xFF), 10)
}

// ipv6Mask mirrors mask_from_bitcount6_make (ip2net.c:132-143).
func ipv6Mask(zct uint32) [16]byte {
	var mask [16]byte
	if zct >= 128 {
		return mask
	}
	n := int((127 - zct) >> 3)
	for index := 0; index < n; index++ {
		mask[index] = 0xFF
	}
	mask[n] = ^byte((uint32(1) << (zct & 7)) - 1)
	return mask
}

func ipv6And(value [16]byte, mask [16]byte) [16]byte {
	var result [16]byte
	for index := range result {
		result[index] = value[index] & mask[index]
	}
	return result
}

// formatIPv6 renders a 16 byte address like inet_ntop(AF_INET6): lowercase hex,
// the first longest run of two or more zero groups compressed to "::",
// IPv4-mapped addresses as "::ffff:a.b.c.d" and the IPv4-compatible class
// (best zero run exactly the first six groups) as "::a.b.c.d".
//
// The compatible rule mirrors glibc's inet_ntop6: when the best run starts at
// group 0 and has length exactly 6, the last 32 bits are printed in dotted
// form. That is equivalent to "the first 96 bits are zero and group 6 is
// non-zero", so :: and ::1 (whose zero run covers group 6 as well) keep the
// compressed form while ::1.2.3.4, ::db8:1 and ::ffff:0 do not.
func formatIPv6(value [16]byte) string {
	if isIPv4Mapped(value) {
		return "::ffff:" + formatIPv4(uint32(value[12])<<24|uint32(value[13])<<16|uint32(value[14])<<8|uint32(value[15]))
	}
	if isIPv4CompatibleForm(value) {
		return "::" + formatIPv4(uint32(value[12])<<24|uint32(value[13])<<16|uint32(value[14])<<8|uint32(value[15]))
	}
	var groups [8]uint16
	for index := range groups {
		groups[index] = uint16(value[index*2])<<8 | uint16(value[index*2+1])
	}
	zeroStart, zeroLength := -1, 0
	for index := 0; index < 8; {
		if groups[index] != 0 {
			index++
			continue
		}
		start := index
		for index < 8 && groups[index] == 0 {
			index++
		}
		if index-start > zeroLength {
			zeroStart, zeroLength = start, index-start
		}
	}
	if zeroLength < 2 {
		zeroStart, zeroLength = -1, 0
	}
	var builder strings.Builder
	builder.Grow(46)
	lastColon := false
	for index := 0; index < 8; {
		if index == zeroStart {
			builder.WriteString("::")
			lastColon = true
			index += zeroLength
			continue
		}
		if builder.Len() > 0 && !lastColon {
			builder.WriteByte(':')
		}
		builder.WriteString(strconv.FormatUint(uint64(groups[index]), 16))
		lastColon = false
		index++
	}
	return builder.String()
}

func isIPv4Mapped(value [16]byte) bool {
	for index := 0; index < 10; index++ {
		if value[index] != 0 {
			return false
		}
	}
	return value[10] == 0xFF && value[11] == 0xFF
}

// isIPv4CompatibleForm reports the glibc inet_ntop6 dotted-output class: the
// first 96 bits are zero and group 6 is non-zero, so the best zero run is
// exactly groups 0-5. :: and ::1 have a longer zero run and stay compressed.
func isIPv4CompatibleForm(value [16]byte) bool {
	for index := 0; index < 12; index++ {
		if value[index] != 0 {
			return false
		}
	}
	return value[12] != 0 || value[13] != 0
}

// numberScanner reproduces the sscanf("%u") parts of the pinned parser: leading
// blanks and an optional '+' are accepted, and the value must fit uint32.
type numberScanner struct {
	text  string
	index int
}

func (s *numberScanner) skipBlanks() {
	for s.index < len(s.text) && (s.text[s.index] == ' ' || s.text[s.index] == '\t') {
		s.index++
	}
}

func (s *numberScanner) uint32() (uint32, bool) {
	s.skipBlanks()
	if s.index >= len(s.text) {
		return 0, false
	}
	if s.text[s.index] == '+' {
		s.index++
	}
	start := s.index
	var value uint64
	for s.index < len(s.text) {
		character := s.text[s.index]
		if character < '0' || character > '9' {
			break
		}
		value = value*10 + uint64(character-'0')
		if value > 0xFFFFFFFF {
			return 0, false
		}
		s.index++
	}
	if s.index == start {
		return 0, false
	}
	return uint32(value), true
}

func (s *numberScanner) literal(character byte) bool {
	if s.index < len(s.text) && s.text[s.index] == character {
		s.index++
		return true
	}
	return false
}

// parseIPv4Range parses "a.b.c.d-e.f.g.h" like the first sscanf of the source.
// Trailing bytes after the last octet are ignored, matching sscanf.
func parseIPv4Range(line string) (start uint32, end uint32, ok bool) {
	var octets [8]uint32
	scanner := numberScanner{text: line}
	for index := 0; index < 8; index++ {
		if index > 0 {
			separator := byte('.')
			if index == 4 {
				separator = '-'
			}
			if !scanner.literal(separator) {
				return 0, 0, false
			}
		}
		value, valid := scanner.uint32()
		if !valid || value > 255 {
			return 0, 0, false
		}
		octets[index] = value
	}
	start = octets[0]<<24 | octets[1]<<16 | octets[2]<<8 | octets[3]
	end = octets[4]<<24 | octets[5]<<16 | octets[6]<<8 | octets[7]
	return start, end, true
}

// parseIPv4PrefixLine parses "a.b.c.d" optionally followed by "/bits" like the
// second sscanf of the source. A '/'-suffix that does not start with a number
// leaves hasBits false, which the source treats as a bare address.
func parseIPv4PrefixLine(line string) (address uint32, bits uint32, hasBits bool, ok bool) {
	var octets [4]uint32
	scanner := numberScanner{text: line}
	for index := 0; index < 4; index++ {
		if index > 0 && !scanner.literal('.') {
			return 0, 0, false, false
		}
		value, valid := scanner.uint32()
		if !valid || value > 255 {
			return 0, 0, false, false
		}
		octets[index] = value
	}
	address = octets[0]<<24 | octets[1]<<16 | octets[2]<<8 | octets[3]
	if scanner.literal('/') {
		value, valid := scanner.uint32()
		if valid {
			return address, value, true, true
		}
	}
	return address, 0, false, true
}

// parsePrefixNumber parses the "%u" prefix length of an IPv6 "ip/bits" line.
func parsePrefixNumber(text string) (uint32, bool) {
	scanner := numberScanner{text: text}
	return scanner.uint32()
}

package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// ListKind is the operator spelling of a provider list kind.
type ListKind string

const (
	ListKindDomain ListKind = "domain"
	ListKindIP     ListKind = "ip"
)

const (
	// ListManifestFormat is the versioned provenance manifest format.
	ListManifestFormat = "desync.list-manifest/v1"

	listDefaultMaxInputBytes        = 64 << 20
	listDefaultMaxDecompressedBytes = 128 << 20
	listDefaultMaxEntries           = 2 << 20
	listDefaultMaxLine              = 8192
	listMaxDomainLength             = 253
	listMaxLabelLength              = 63

	// listDefaultMaxExclusionWork bounds the deterministic number of prefix
	// comparisons of one IP exclusion pass. The prefix index makes the real
	// work at most one lookup per distinct exclusion prefix length and entry
	// (<= 129 for IPv6), so the default is a backstop well above any bounded
	// input; tests set a small budget to observe enforcement.
	listDefaultMaxExclusionWork = 1 << 30

	// listExclusionCancelInterval is how many processed entries may pass
	// between two context checks inside the exclusion build/filter loops.
	listExclusionCancelInterval = 1024
)

// ListNormalizeOptions configures one local provider snapshot normalization.
//
// The zero value uses the documented defaults; there is no implicit download,
// schedule, archive extraction or publication to a running instance.
type ListNormalizeOptions struct {
	Kind ListKind
	// MaxInputBytes bounds the raw file size (compressed when gzip).
	MaxInputBytes int64
	// MaxDecompressedBytes bounds the decompressed size.
	MaxDecompressedBytes int64
	// MaxEntries bounds the number of normalized entries kept in memory.
	MaxEntries int
	// MaxExclusionEntries bounds the total number of exclusion entries
	// collected from every --exclude snapshot together. Zero uses MaxEntries.
	MaxExclusionEntries int
	// MaxExclusionWork bounds the deterministic prefix comparisons of IP
	// exclusion filtering. Zero uses the documented default.
	MaxExclusionWork int64
	// MaxLineLength bounds one input line.
	MaxLineLength int
}

// ListInput is one operator supplied snapshot. Path is provenance metadata only;
// the caller owns opening the file (or stdin with Path "-").
type ListInput struct {
	Path   string
	Reader io.Reader
}

// ListSource reports the provenance and the counts of one input snapshot.
type ListSource struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
	Compression  string `json:"compression"`
	Decompressed int64  `json:"decompressed_size"`
	Lines        int    `json:"lines"`
	Accepted     int    `json:"accepted"`
	Invalid      int    `json:"invalid"`
	Duplicates   int    `json:"duplicates"`
	Excluded     int    `json:"excluded"`
}

// ListOutput reports the normalized output provenance.
type ListOutput struct {
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Entries int    `json:"entries"`
}

// ListManifest is the provenance record written next to a normalized list.
type ListManifest struct {
	Format   string       `json:"format"`
	Kind     ListKind     `json:"kind"`
	Source   ListSource   `json:"source"`
	Excluded []ListSource `json:"excluded"`
	Output   ListOutput   `json:"output"`
}

func (o ListNormalizeOptions) resolve() (ListNormalizeOptions, error) {
	switch o.Kind {
	case ListKindDomain:
	case ListKindIP:
	default:
		return o, E.New("list-normalize: --kind must be domain or ip")
	}
	if o.MaxInputBytes == 0 {
		o.MaxInputBytes = listDefaultMaxInputBytes
	}
	if o.MaxInputBytes < 0 {
		return o, E.New("list-normalize: invalid input size limit")
	}
	if o.MaxDecompressedBytes == 0 {
		o.MaxDecompressedBytes = listDefaultMaxDecompressedBytes
	}
	if o.MaxDecompressedBytes < 0 {
		return o, E.New("list-normalize: invalid decompressed size limit")
	}
	if o.MaxEntries == 0 {
		o.MaxEntries = listDefaultMaxEntries
	}
	if o.MaxEntries < 0 {
		return o, E.New("list-normalize: invalid entry limit")
	}
	if o.MaxExclusionEntries == 0 {
		o.MaxExclusionEntries = o.MaxEntries
	}
	if o.MaxExclusionEntries < 0 {
		return o, E.New("list-normalize: invalid exclusion entry limit")
	}
	if o.MaxExclusionWork == 0 {
		o.MaxExclusionWork = listDefaultMaxExclusionWork
	}
	if o.MaxExclusionWork < 0 {
		return o, E.New("list-normalize: invalid exclusion work limit")
	}
	if o.MaxLineLength == 0 {
		o.MaxLineLength = listDefaultMaxLine
	}
	if o.MaxLineLength < 16 {
		return o, E.New("list-normalize: invalid line length limit")
	}
	return o, nil
}

// NormalizeList reads one local text or gzip provider snapshot, normalizes and
// sorts its entries, removes entries contained in the explicit exclusion
// snapshots and writes the canonical newline terminated list to out.
//
// The input is never fetched, the output is never published to a running
// instance and no shell, archive extractor or path from the file is executed.
// Decompression and the number of entries are bounded by the options.
func NormalizeList(ctx context.Context, input ListInput, out io.Writer, excludes []ListInput, options ListNormalizeOptions) (ListManifest, error) {
	var manifest ListManifest
	options, err := options.resolve()
	if err != nil {
		return manifest, err
	}
	if input.Reader == nil || out == nil {
		return manifest, E.New("list-normalize: input and output streams are required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	source, raw, err := readListSnapshot(ctx, input, options)
	if err != nil {
		return manifest, err
	}
	entries, parseStats, err := parseListSnapshot(ctx, raw, options)
	if err != nil {
		return manifest, err
	}
	source.Lines = parseStats.lines
	source.Accepted = parseStats.accepted
	source.Invalid = parseStats.invalid
	source.Duplicates = parseStats.duplicates
	manifest = ListManifest{
		Format:   ListManifestFormat,
		Kind:     options.Kind,
		Source:   source,
		Excluded: []ListSource{},
	}
	unique := entries
	excludedEntries, err := collectExclusions(ctx, excludes, options, &manifest)
	if err != nil {
		return manifest, err
	}
	if options.Kind == ListKindDomain {
		unique, manifest.Source.Excluded = excludeDomains(unique, excludedEntries)
	} else {
		unique, manifest.Source.Excluded, err = excludeIPs(ctx, unique, excludedEntries, options.MaxExclusionWork)
		if err != nil {
			return manifest, err
		}
	}
	if err = ctx.Err(); err != nil {
		return manifest, err
	}
	output := buildListOutput(unique, options)
	if int64(len(output)) > options.MaxDecompressedBytes {
		return manifest, E.New("list-normalize: output exceeds the size limit")
	}
	written, err := out.Write(output)
	if err != nil {
		return manifest, E.Cause(err, "list-normalize: write output")
	}
	if written != len(output) {
		return manifest, io.ErrShortWrite
	}
	digest := sha256.Sum256(output)
	manifest.Output = ListOutput{
		SHA256:  hex.EncodeToString(digest[:]),
		Size:    int64(len(output)),
		Entries: len(unique),
	}
	return manifest, nil
}

// WriteListManifest writes the manifest as deterministic JSON with a trailing
// newline. Field order is fixed by the struct definition.
func WriteListManifest(writer io.Writer, manifest ListManifest) error {
	if writer == nil {
		return E.New("list-normalize: manifest output is required")
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		return E.Cause(err, "list-normalize: encode manifest")
	}
	return nil
}

type listParseStats struct {
	lines      int
	accepted   int
	invalid    int
	duplicates int
	unique     []string
}

func readListSnapshot(ctx context.Context, input ListInput, options ListNormalizeOptions) (ListSource, []byte, error) {
	source := ListSource{Path: listProvenancePath(input.Path)}
	raw, err := io.ReadAll(io.LimitReader(input.Reader, options.MaxInputBytes+1))
	if err != nil {
		return source, nil, E.Cause(err, "list-normalize: read ", source.Path)
	}
	if int64(len(raw)) > options.MaxInputBytes {
		return source, nil, E.New("list-normalize: ", source.Path, " exceeds the input size limit of ", options.MaxInputBytes, " bytes")
	}
	digest := sha256.Sum256(raw)
	source.SHA256 = hex.EncodeToString(digest[:])
	source.Size = int64(len(raw))
	source.Compression = "none"
	data := raw
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		source.Compression = "gzip"
		reader, gzipErr := gzip.NewReader(bytes.NewReader(raw))
		if gzipErr != nil {
			return source, nil, E.Cause(gzipErr, "list-normalize: ", source.Path, " is not a valid gzip stream")
		}
		defer reader.Close()
		decompressed, readErr := io.ReadAll(io.LimitReader(reader, options.MaxDecompressedBytes+1))
		if readErr != nil {
			return source, nil, E.Cause(readErr, "list-normalize: decompress ", source.Path)
		}
		if int64(len(decompressed)) > options.MaxDecompressedBytes {
			return source, nil, E.New("list-normalize: ", source.Path, " exceeds the decompressed size limit of ", options.MaxDecompressedBytes, " bytes")
		}
		data = decompressed
	}
	source.Decompressed = int64(len(data))
	return source, data, nil
}

func parseListSnapshot(ctx context.Context, data []byte, options ListNormalizeOptions) ([]string, listParseStats, error) {
	var stats listParseStats
	seen := make(map[string]struct{})
	scanner := newLineScanner(bytes.NewReader(data), options.MaxLineLength)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, stats, err
		}
		stats.lines++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		normalized, ok := normalizeListEntry(line, options.Kind)
		if !ok {
			stats.invalid++
			continue
		}
		stats.accepted++
		if _, duplicate := seen[normalized]; duplicate {
			stats.duplicates++
			continue
		}
		seen[normalized] = struct{}{}
		stats.unique = append(stats.unique, normalized)
		if len(stats.unique) > options.MaxEntries {
			return nil, stats, E.New("list-normalize: entry count exceeds the limit of ", options.MaxEntries)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, stats, E.Cause(err, "list-normalize: read input (line limit ", options.MaxLineLength, ")")
	}
	return stats.unique, stats, nil
}

func normalizeListEntry(line string, kind ListKind) (string, bool) {
	if kind == ListKindIP {
		return normalizeIPEntry(line)
	}
	return normalizeDomainEntry(line)
}

// normalizeDomainEntry lowercases the entry, removes one trailing root dot and
// validates the labels. A leading dot (upstream "subdomains only" spelling) is
// preserved so the normalizer never changes matching semantics.
func normalizeDomainEntry(line string) (string, bool) {
	subdomainOnly := strings.HasPrefix(line, ".")
	if subdomainOnly {
		line = line[1:]
	}
	line = strings.ToLower(line)
	line = strings.TrimSuffix(line, ".")
	if line == "" || len(line) > listMaxDomainLength {
		return "", false
	}
	for _, label := range strings.Split(line, ".") {
		if len(label) == 0 || len(label) > listMaxLabelLength {
			return "", false
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
				character == '-' || character == '_' {
				continue
			}
			return "", false
		}
	}
	if subdomainOnly {
		return "." + line, true
	}
	return line, true
}

// normalizeIPEntry canonicalizes an address or masks a prefix to its network
// address so the output is stable regardless of provider formatting.
func normalizeIPEntry(line string) (string, bool) {
	if strings.ContainsRune(line, '/') {
		prefix, err := netip.ParsePrefix(line)
		if err != nil || prefix.Addr().Zone() != "" {
			return "", false
		}
		return prefix.Masked().String(), true
	}
	address, err := netip.ParseAddr(line)
	if err != nil || address.Zone() != "" {
		return "", false
	}
	return address.String(), true
}

func collectExclusions(ctx context.Context, excludes []ListInput, options ListNormalizeOptions, manifest *ListManifest) ([]string, error) {
	var entries []string
	for _, exclude := range excludes {
		if exclude.Reader == nil {
			return nil, E.New("list-normalize: exclusion ", exclude.Path, " has no reader")
		}
		source, raw, err := readListSnapshot(ctx, exclude, options)
		if err != nil {
			return nil, err
		}
		parsed, stats, err := parseListSnapshot(ctx, raw, options)
		if err != nil {
			return nil, err
		}
		if len(entries)+len(parsed) > options.MaxExclusionEntries {
			return nil, E.New("list-normalize: exclusion entry count exceeds the aggregate limit of ", options.MaxExclusionEntries)
		}
		source.Lines = stats.lines
		source.Accepted = stats.accepted
		source.Invalid = stats.invalid
		source.Duplicates = stats.duplicates
		manifest.Excluded = append(manifest.Excluded, source)
		entries = append(entries, parsed...)
	}
	return entries, nil
}

func excludeDomains(entries []string, excluded []string) ([]string, int) {
	if len(excluded) == 0 {
		return entries, 0
	}
	set := make(map[string]struct{}, len(excluded))
	for _, entry := range excluded {
		set[entry] = struct{}{}
	}
	kept := entries[:0]
	removed := 0
	for _, entry := range entries {
		if _, found := set[entry]; found {
			removed++
			continue
		}
		kept = append(kept, entry)
	}
	return kept, removed
}

type ipExclusion struct {
	address netip.Addr
	bits    int
}

// exclusionPrefixLengths returns the distinct exclusion prefix lengths of one
// address family in ascending order.
func exclusionPrefixLengths(lengths []int) []int {
	unique := lengths[:0]
	for index, value := range lengths {
		if index == 0 || value != lengths[index-1] {
			unique = append(unique, value)
		}
	}
	return unique
}

// excludeIPs removes every entry contained in an exclusion prefix.
//
// The exclusions are indexed by (masked address, prefix length) once. An entry
// is contained when one of its ancestor prefixes is present, so the work is one
// map lookup per distinct exclusion prefix length (at most 129) per entry
// instead of a scan over every exclusion. The context is checked every
// listExclusionCancelInterval entries inside both loops, and maxWork caps the
// total number of prefix comparisons deterministically.
func excludeIPs(ctx context.Context, entries []string, excluded []string, maxWork int64) ([]string, int, error) {
	if len(excluded) == 0 {
		return entries, 0, nil
	}
	index := make(map[ipExclusion]struct{}, len(excluded))
	var lengths4 []int
	var lengths6 []int
	for position, entry := range excluded {
		if position%listExclusionCancelInterval == 0 {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
		}
		exclusion, ok := parseIPExclusion(entry)
		if !ok {
			continue
		}
		if _, found := index[exclusion]; found {
			continue
		}
		index[exclusion] = struct{}{}
		if exclusion.address.Is4() {
			lengths4 = append(lengths4, exclusion.bits)
		} else {
			lengths6 = append(lengths6, exclusion.bits)
		}
	}
	slices.Sort(lengths4)
	slices.Sort(lengths6)
	lengths4 = exclusionPrefixLengths(lengths4)
	lengths6 = exclusionPrefixLengths(lengths6)
	kept := entries[:0]
	removed := 0
	var work int64
	for position, entry := range entries {
		if position%listExclusionCancelInterval == 0 {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
		}
		target, ok := parseIPExclusion(entry)
		if !ok {
			kept = append(kept, entry)
			continue
		}
		lengths := lengths6
		if target.address.Is4() {
			lengths = lengths4
		}
		matched := false
		for _, bits := range lengths {
			if bits > target.bits {
				break
			}
			work++
			if work > maxWork {
				return nil, 0, E.New("list-normalize: IP exclusion work budget of ", maxWork, " prefix comparisons exceeded")
			}
			ancestor := target.address
			if bits < target.address.BitLen() {
				ancestor = netip.PrefixFrom(target.address, bits).Masked().Addr()
			}
			if _, found := index[ipExclusion{address: ancestor, bits: bits}]; found {
				matched = true
				break
			}
		}
		if matched {
			removed++
			continue
		}
		kept = append(kept, entry)
	}
	return kept, removed, nil
}

func parseIPExclusion(text string) (ipExclusion, bool) {
	if strings.ContainsRune(text, '/') {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return ipExclusion{}, false
		}
		return ipExclusion{address: prefix.Masked().Addr(), bits: prefix.Bits()}, true
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		return ipExclusion{}, false
	}
	return ipExclusion{address: address, bits: address.BitLen()}, true
}

func buildListOutput(entries []string, options ListNormalizeOptions) []byte {
	sorted := slices.Clone(entries)
	if options.Kind == ListKindIP {
		slices.SortFunc(sorted, compareIPEntries)
	} else {
		slices.Sort(sorted)
	}
	var builder bytes.Buffer
	for _, entry := range sorted {
		builder.WriteString(entry)
		builder.WriteByte('\n')
	}
	return builder.Bytes()
}

func compareIPEntries(a string, b string) int {
	left, leftOK := parseIPExclusion(a)
	right, rightOK := parseIPExclusion(b)
	switch {
	case leftOK && rightOK:
		if result := left.address.Compare(right.address); result != 0 {
			return result
		}
		return compareInt(left.bits, right.bits)
	case leftOK:
		return -1
	case rightOK:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func compareInt(a int, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// listProvenancePath keeps the operator supplied spelling, normalizing only the
// stdin placeholder.
func listProvenancePath(path string) string {
	if path == "" {
		return "-"
	}
	return path
}

package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// List bundle layout and publication.
//
// DIRECTORY/current.json is the only commit point of a provider list bundle.
// Every generation is an immutable directory below DIRECTORY/generations and is
// referenced exclusively through that single pointer file. This file owns the
// typed manifest, the strict decoders, shard naming and the atomic publication
// primitives. It never fetches, never dials and never invokes a shell.

const (
	// ListBundleFormat is the versioned provider list bundle manifest format.
	ListBundleFormat = "desync.list-bundle/v1"
	// ListRefreshResultFormat is the versioned refresh receipt format.
	ListRefreshResultFormat = "desync.list-refresh-result/v1"
	// ListRefreshRequestFormat is the versioned refresh request format.
	ListRefreshRequestFormat = "desync.list-refresh/v1"

	// ZapretRecipeRevision is the pinned bol-van/zapret revision of v72.9. The
	// provider data itself is mutable; this identifies the recipe source only.
	ZapretRecipeRevision = "c849e55ef0f1c244206f5a05ff7b1ab41a3824ee"

	listBundleManifestMaxBytes = 1 << 20
	listBundleMaxEntries       = 4 << 20
	listBundleMaxShardDecoded  = 3 << 20
	listBundleMaxShardWire     = 4 << 20
	listBundleMaxShards        = 1024
	listBundleMaxTotalBytes    = 512 << 20
	listBundleMaxNameBytes     = 128

	listBundleCurrentName  = "current.json"
	listBundleGenerations  = "generations"
	listBundleLockName     = ".refresh.lock"
	listBundleManifestName = "manifest.json"

	listBundleOriginGenerated   = "generated"
	listBundleOriginLocal       = "local"
	listBundleOriginNotProvided = "not_provided"
	listBundleOriginDisabled    = "disabled"
)

// ListBundleLimits are the effective limits recorded in the manifest. Runtime
// enforcement is independent: a manifest can only ever lower the hard bounds.
type ListBundleLimits struct {
	MaxEntries        int   `json:"max_entries"`
	MaxExcludeEntries int   `json:"max_exclude_entries"`
	MaxDecodedBytes   int64 `json:"max_decoded_bytes"`
	MaxTotalBytes     int64 `json:"max_total_bytes"`
	TimeoutSeconds    int   `json:"timeout_seconds"`
}

// ListBundleSource is the provenance of one acquired input. Remote sources
// carry the URL metadata, local sources carry a path. Both carry the raw body
// hash, which is computed before gzip decoding.
type ListBundleSource struct {
	ID               string `json:"id"`
	Path             string `json:"path,omitempty"`
	URL              string `json:"url,omitempty"`
	FinalURL         string `json:"final_url,omitempty"`
	FinalURLSHA256   string `json:"final_url_sha256,omitempty"`
	ETag             string `json:"etag,omitempty"`
	LastModified     string `json:"last_modified,omitempty"`
	FetchedAt        string `json:"fetched_at,omitempty"`
	SHA256           string `json:"sha256"`
	Size             int64  `json:"size"`
	Compression      string `json:"compression"`
	DecompressedSize int64  `json:"decompressed_size"`
	Lines            int    `json:"lines"`
	Accepted         int    `json:"accepted"`
	Invalid          int    `json:"invalid"`
	Duplicates       int    `json:"duplicates"`
	Excluded         int    `json:"excluded"`
}

// ListBundleAggregateFamily is one effective aggregation option set with the
// before/after entry counts of the source-derived feed.
type ListBundleAggregateFamily struct {
	Family       int    `json:"family"`
	PrefixLength string `json:"prefix_length"`
	Threshold    string `json:"threshold"`
	Before       int    `json:"before"`
	After        int    `json:"after"`
}

// ListBundleAggregation records the effective ip2net options of a run.
type ListBundleAggregation struct {
	Families []ListBundleAggregateFamily `json:"families"`
}

// ListBundleResolution records aggregate DNS accounting only. Host names are
// never part of the manifest or of an ordinary receipt.
type ListBundleResolution struct {
	Domains     int                    `json:"domains"`
	Success     int                    `json:"success"`
	Negative    int                    `json:"negative"`
	Temporary   int                    `json:"temporary"`
	Retries     int                    `json:"retries"`
	Addresses   int                    `json:"addresses"`
	Aggregation *ListBundleAggregation `json:"aggregation,omitempty"`
}

// ListBundleFile is one immutable ordered shard of a dataset.
type ListBundleFile struct {
	Name               string `json:"name"`
	SHA256             string `json:"sha256"`
	Size               int64  `json:"size"`
	DecompressedSHA256 string `json:"decompressed_sha256"`
	DecompressedSize   int64  `json:"decompressed_size"`
	Entries            int    `json:"entries"`
}

// ListBundleDataset is one typed dataset of a generation.
type ListBundleDataset struct {
	ID      string           `json:"id"`
	Kind    ListKind         `json:"kind"`
	Family  int              `json:"family,omitempty"`
	Origin  string           `json:"origin"`
	Entries int              `json:"entries"`
	SHA256  string           `json:"sha256"`
	Size    int64            `json:"size"`
	Files   []ListBundleFile `json:"files"`
}

// ListBundleManifest is the complete desync.list-bundle/v1 document.
type ListBundleManifest struct {
	Format         string               `json:"format"`
	Generation     string               `json:"generation"`
	CreatedAt      string               `json:"created_at"`
	RecipeRevision string               `json:"recipe_revision"`
	Provider       string               `json:"provider"`
	Acquisition    string               `json:"acquisition"`
	Families       []int                `json:"families"`
	RequestSHA256  string               `json:"request_sha256"`
	Limits         ListBundleLimits     `json:"limits"`
	Sources        []ListBundleSource   `json:"sources"`
	Resolution     ListBundleResolution `json:"resolution"`
	Datasets       []ListBundleDataset  `json:"datasets"`
}

// ListRefreshDatasetEntries is one dataset count of a refresh receipt.
type ListRefreshDatasetEntries struct {
	ID      string `json:"id"`
	Entries int    `json:"entries"`
}

// ListRefreshReceipt is the desync.list-refresh-result/v1 document. It carries
// no fetched data and no host names.
type ListRefreshReceipt struct {
	Format             string                      `json:"format"`
	Committed          bool                        `json:"committed"`
	Generation         string                      `json:"generation"`
	PreviousGeneration *string                     `json:"previous_generation"`
	Manifest           string                      `json:"manifest"`
	ManifestSHA256     string                      `json:"manifest_sha256"`
	DatasetEntries     []ListRefreshDatasetEntries `json:"dataset_entries"`
	Warnings           []string                    `json:"warnings"`
}

// listBundleDatasetSpec resolves the fixed dataset IDs of the contract.
func listBundleDatasetSpec(id string) (name string, kind ListKind, family int, ok bool) {
	switch id {
	case "hosts":
		return "zapret-hosts.txt", ListKindDomain, 0, true
	case "ip4":
		return "zapret-ip.txt", ListKindIP, 4, true
	case "ip6":
		return "zapret-ip6.txt", ListKindIP, 6, true
	case "user_hosts":
		return "zapret-hosts-user.txt", ListKindDomain, 0, true
	case "exclude_hosts":
		return "zapret-hosts-user-exclude.txt", ListKindDomain, 0, true
	case "ipban_hosts":
		return "zapret-hosts-user-ipban.txt", ListKindDomain, 0, true
	case "user_ip4":
		return "zapret-ip-user.txt", ListKindIP, 4, true
	case "user_ip6":
		return "zapret-ip-user6.txt", ListKindIP, 6, true
	case "exclude_ip4":
		return "zapret-ip-exclude.txt", ListKindIP, 4, true
	case "exclude_ip6":
		return "zapret-ip-exclude6.txt", ListKindIP, 6, true
	case "ipban_ip4":
		return "zapret-ip-user-ipban.txt", ListKindIP, 4, true
	case "ipban_ip6":
		return "zapret-ip-user-ipban6.txt", ListKindIP, 6, true
	}
	return "", "", 0, false
}

// ListBundleDatasetIDs returns the twelve fixed dataset IDs in layout order.
func ListBundleDatasetIDs() []string {
	return []string{
		"hosts", "ip4", "ip6",
		"user_hosts", "exclude_hosts", "ipban_hosts",
		"user_ip4", "user_ip6",
		"exclude_ip4", "exclude_ip6",
		"ipban_ip4", "ipban_ip6",
	}
}

// ListBundleDatasetBaseName returns the fixed base file name of a dataset ID.
func ListBundleDatasetBaseName(id string) (string, bool) {
	name, _, _, ok := listBundleDatasetSpec(id)
	return name, ok
}

// encodeListBundleManifest encodes a manifest deterministically with a trailing
// newline and enforces the manifest size limit.
func encodeListBundleManifest(manifest ListBundleManifest) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		return nil, E.Cause(err, "encode list bundle manifest")
	}
	if buffer.Len() > listBundleManifestMaxBytes {
		return nil, E.New("list bundle manifest exceeds ", listBundleManifestMaxBytes, " bytes")
	}
	return buffer.Bytes(), nil
}

// DecodeListBundleManifest strictly decodes and validates a bundle manifest.
// Unknown and duplicate keys, trailing documents, wrong types and inconsistent
// dataset metadata are rejected before any file is opened.
func DecodeListBundleManifest(data []byte) (ListBundleManifest, error) {
	var manifest ListBundleManifest
	if len(data) == 0 {
		return manifest, E.New("empty list bundle manifest")
	}
	if len(data) > listBundleManifestMaxBytes {
		return manifest, E.New("list bundle manifest exceeds ", listBundleManifestMaxBytes, " bytes")
	}
	if err := decodeStrictJSON(data, &manifest); err != nil {
		return manifest, E.Cause(err, "decode list bundle manifest")
	}
	if err := validateListBundleManifest(manifest); err != nil {
		return manifest, err
	}
	return manifest, nil
}

func validateListBundleManifest(manifest ListBundleManifest) error {
	if manifest.Format != ListBundleFormat {
		return E.New("unexpected list bundle format ", manifest.Format)
	}
	if !validGenerationID(manifest.Generation) {
		return E.New("invalid list bundle generation ", manifest.Generation)
	}
	if manifest.CreatedAt == "" || manifest.RecipeRevision == "" || manifest.Provider == "" || manifest.Acquisition == "" {
		return E.New("incomplete list bundle manifest header")
	}
	if !validSHA256Hex(manifest.RequestSHA256) {
		return E.New("invalid request_sha256 in list bundle manifest")
	}
	if len(manifest.Families) == 0 {
		return E.New("list bundle manifest has no families")
	}
	if manifest.Limits.MaxEntries <= 0 || manifest.Limits.MaxExcludeEntries <= 0 ||
		manifest.Limits.MaxDecodedBytes <= 0 || manifest.Limits.MaxTotalBytes <= 0 ||
		manifest.Limits.TimeoutSeconds <= 0 {
		return E.New("invalid list bundle manifest limits")
	}
	// Runtime hard caps are independent of the manifest: a manifest can only ever
	// lower them, never authorize a larger allocation.
	if manifest.Limits.MaxEntries > listBundleMaxEntries ||
		manifest.Limits.MaxExcludeEntries > listBundleMaxEntries ||
		manifest.Limits.MaxDecodedBytes > listBundleMaxTotalBytes ||
		manifest.Limits.MaxTotalBytes > listBundleMaxTotalBytes ||
		manifest.Limits.TimeoutSeconds > 3600 {
		return E.New("list bundle manifest limits exceed the hard caps")
	}
	seen := make(map[string]struct{}, len(manifest.Datasets))
	totalWire := int64(0)
	totalShards := 0
	for _, dataset := range manifest.Datasets {
		name, kind, family, ok := listBundleDatasetSpec(dataset.ID)
		if !ok {
			return E.New("unknown list bundle dataset ", dataset.ID)
		}
		if _, loaded := seen[dataset.ID]; loaded {
			return E.New("duplicate list bundle dataset ", dataset.ID)
		}
		seen[dataset.ID] = struct{}{}
		if dataset.Kind != kind || dataset.Family != family {
			return E.New("dataset ", dataset.ID, " has an inconsistent kind or family")
		}
		switch dataset.Origin {
		case listBundleOriginGenerated, listBundleOriginLocal, listBundleOriginNotProvided, listBundleOriginDisabled:
		default:
			return E.New("dataset ", dataset.ID, " has an unknown origin")
		}
		if dataset.Entries < 0 || dataset.Entries > listBundleMaxEntries {
			return E.New("dataset ", dataset.ID, " entry count out of range")
		}
		if dataset.Size < 0 || !validSHA256Hex(dataset.SHA256) {
			return E.New("dataset ", dataset.ID, " has invalid provenance")
		}
		if len(dataset.Files) == 0 {
			return E.New("dataset ", dataset.ID, " has no files")
		}
		entries := 0
		decoded := int64(0)
		for _, file := range dataset.Files {
			if err := validateShardName(name, file.Name); err != nil {
				return E.Cause(err, "dataset ", dataset.ID)
			}
			if !validSHA256Hex(file.SHA256) || !validSHA256Hex(file.DecompressedSHA256) {
				return E.Cause(E.New("invalid shard hash"), "dataset ", dataset.ID)
			}
			if file.Size < 0 || file.Size > listBundleMaxShardWire {
				return E.New("dataset ", dataset.ID, " shard exceeds the wire limit")
			}
			if file.DecompressedSize < 0 || file.DecompressedSize > listBundleMaxShardDecoded {
				return E.New("dataset ", dataset.ID, " shard exceeds the decoded limit")
			}
			if file.Entries < 0 || file.Entries > listBundleMaxEntries {
				return E.New("dataset ", dataset.ID, " shard entry count out of range")
			}
			entries += file.Entries
			decoded += file.DecompressedSize
			totalWire += file.Size
			totalShards++
		}
		if entries != dataset.Entries || decoded != dataset.Size {
			return E.New("dataset ", dataset.ID, " counts do not match its shards")
		}
		if dataset.Entries > manifest.Limits.MaxEntries && !isNegativeDataset(dataset.ID) {
			return E.New("dataset ", dataset.ID, " exceeds max_entries")
		}
		if dataset.Entries > manifest.Limits.MaxExcludeEntries && isNegativeDataset(dataset.ID) {
			return E.New("dataset ", dataset.ID, " exceeds max_exclude_entries")
		}
	}
	for _, id := range ListBundleDatasetIDs() {
		if _, loaded := seen[id]; !loaded {
			return E.New("list bundle manifest is missing dataset ", id)
		}
	}
	if totalShards > listBundleMaxShards {
		return E.New("list bundle exceeds the shard limit")
	}
	if totalWire > manifest.Limits.MaxTotalBytes || totalWire > listBundleMaxTotalBytes {
		return E.New("list bundle exceeds the total output byte limit")
	}
	for _, source := range manifest.Sources {
		if source.ID == "" || !validSHA256Hex(source.SHA256) || source.Size < 0 || source.DecompressedSize < 0 {
			return E.New("invalid list bundle source provenance")
		}
		remote := source.URL != ""
		local := source.Path != ""
		if remote == local {
			return E.New("list bundle source must be exactly one of url or path")
		}
		if remote && (!validSHA256Hex(source.FinalURLSHA256) || source.FinalURL == "") {
			return E.New("remote list bundle source is missing final URL provenance")
		}
	}
	return nil
}

func isNegativeDataset(id string) bool {
	return strings.HasPrefix(id, "exclude_") || strings.HasPrefix(id, "ipban_")
}

func validGenerationID(generation string) bool {
	if len(generation) != 32 {
		return false
	}
	for index := 0; index < len(generation); index++ {
		character := generation[index]
		if (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') {
			continue
		}
		return false
	}
	return true
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateShardName(base string, name string) error {
	if name == "" || len(name) > listBundleMaxNameBytes {
		return E.New("invalid shard name")
	}
	if name != path.Base(name) || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return E.New("shard name is not a plain basename: ", name)
	}
	suffix := name
	compressed := strings.HasSuffix(suffix, ".gz")
	if compressed {
		suffix = strings.TrimSuffix(suffix, ".gz")
	}
	prefix := base + "."
	if !strings.HasPrefix(suffix, prefix) {
		return E.New("shard name does not belong to the dataset: ", name)
	}
	index := strings.TrimPrefix(suffix, prefix)
	if len(index) != 5 {
		return E.New("invalid shard index in ", name)
	}
	for position := 0; position < len(index); position++ {
		if index[position] < '0' || index[position] > '9' {
			return E.New("invalid shard index in ", name)
		}
	}
	return nil
}

// shardName builds the fixed shard name of one dataset chunk.
func shardName(base string, index int, compressed bool) string {
	name := base + "." + leftPadIndex(index)
	if compressed {
		name += ".gz"
	}
	return name
}

func leftPadIndex(index int) string {
	digits := []byte{'0', '0', '0', '0', '0'}
	for position := 4; position >= 0 && index > 0; position-- {
		digits[position] = byte('0' + index%10)
		index /= 10
	}
	return string(digits)
}

// generationPath returns the immutable directory of one generation.
func generationPath(root string, generation string) (string, error) {
	if !validGenerationID(generation) {
		return "", E.New("invalid generation ", generation)
	}
	return filepath.Join(root, listBundleGenerations, generation), nil
}

// datasetChunks splits canonical entries into decoded shards of at most
// listBundleMaxShardDecoded bytes. Splitting happens on complete newline
// boundaries; no record is ever truncated.
func datasetChunks(entries []string) ([][]byte, error) {
	var chunks [][]byte
	var current bytes.Buffer
	flush := func() {
		chunks = append(chunks, current.Bytes())
		current = bytes.Buffer{}
	}
	for _, entry := range entries {
		if strings.ContainsAny(entry, "\r\n") {
			return nil, E.New("dataset entry contains a line break")
		}
		lineLength := len(entry) + 1
		if lineLength > listBundleMaxShardDecoded {
			return nil, E.New("dataset entry exceeds the shard limit")
		}
		if current.Len()+lineLength > listBundleMaxShardDecoded {
			flush()
		}
		current.WriteString(entry)
		current.WriteByte('\n')
	}
	flush()
	if len(chunks) == 0 {
		chunks = append(chunks, []byte{})
	}
	if len(chunks) > listBundleMaxShards {
		return nil, E.New("dataset exceeds the shard limit")
	}
	return chunks, nil
}

// gzipBytes produces a deterministic gzip member: zero modification time and no
// original file name or comment.
func gzipBytes(data []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		return nil, E.Cause(err, "compress shard")
	}
	if err := writer.Close(); err != nil {
		return nil, E.Cause(err, "compress shard")
	}
	return buffer.Bytes(), nil
}

// compressedMagic reports whether data starts with the gzip magic.
func gzipMagic(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

// decodeGzipOnce decodes exactly one gzip member and rejects trailing data and
// decompression beyond the limit.
func decodeGzipOnce(data []byte, maxDecoded int64) ([]byte, error) {
	source := bytes.NewReader(data)
	reader, err := gzip.NewReader(source)
	if err != nil {
		return nil, E.Cause(err, "invalid gzip stream")
	}
	defer reader.Close()
	// Exactly one member: a second concatenated member is trailing data, not a
	// second document to decode. bytes.Reader implements io.ByteReader, so the
	// gzip layer consumes exactly the member bytes and source.Len() is the
	// unconsumed remainder.
	reader.Multistream(false)
	var buffer bytes.Buffer
	limited := io.LimitReader(reader, maxDecoded+1)
	written, err := io.Copy(&buffer, limited)
	if err != nil {
		return nil, E.Cause(err, "decompress gzip stream")
	}
	if written > maxDecoded {
		return nil, E.New("decompressed stream exceeds the limit of ", maxDecoded, " bytes")
	}
	if source.Len() != 0 {
		return nil, E.New("gzip stream carries trailing data")
	}
	return buffer.Bytes(), nil
}

// decodeStrictJSON decodes exactly one JSON value, rejecting unknown and
// duplicate keys and trailing documents.
func decodeStrictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return E.New("trailing JSON document")
		}
		return E.Cause(err, "trailing JSON document")
	}
	return nil
}

// rejectDuplicateJSONKeys walks the token stream and rejects a repeated object
// key at any nesting level. encoding/json silently keeps the last value, which
// would make a request or manifest ambiguous.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	type jsonFrame struct {
		object    bool
		keys      map[string]struct{}
		expectKey bool
	}
	var stack []*jsonFrame
	completeValue := func() error {
		if len(stack) == 0 {
			return nil
		}
		parent := stack[len(stack)-1]
		if parent.object {
			parent.expectKey = true
		}
		return nil
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return E.New("truncated JSON document")
			}
			return nil
		}
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if isDelimiter {
			switch delimiter {
			case '{':
				if err = completeValue(); err != nil {
					return err
				}
				stack = append(stack, &jsonFrame{object: true, keys: make(map[string]struct{}), expectKey: true})
			case '[':
				if err = completeValue(); err != nil {
					return err
				}
				stack = append(stack, &jsonFrame{})
			case '}', ']':
				if len(stack) == 0 {
					return E.New("malformed JSON document")
				}
				frame := stack[len(stack)-1]
				if delimiter == '}' && !frame.object || delimiter == ']' && frame.object {
					return E.New("mismatched JSON delimiter")
				}
				stack = stack[:len(stack)-1]
				if err = completeValue(); err != nil {
					return err
				}
			}
			continue
		}
		if len(stack) == 0 {
			continue
		}
		frame := stack[len(stack)-1]
		if frame.object {
			if frame.expectKey {
				key, ok := token.(string)
				if !ok {
					return E.New("malformed JSON object key")
				}
				if _, duplicate := frame.keys[key]; duplicate {
					return E.New("duplicate JSON key ", key)
				}
				frame.keys[key] = struct{}{}
				frame.expectKey = false
				continue
			}
			frame.expectKey = true
		}
	}
}

// VerifyListBundle checks every referenced generation file against the manifest
// before it may be published or loaded. It never trusts manifest counts.
func VerifyListBundle(root string, manifest ListBundleManifest) error {
	if err := validateListBundleManifest(manifest); err != nil {
		return err
	}
	directory, err := generationPath(root, manifest.Generation)
	if err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return E.Cause(err, "inspect generation directory")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return E.New("generation path is not a plain directory")
	}
	for _, dataset := range manifest.Datasets {
		if _, err = readDatasetFiles(directory, dataset, manifest.Limits); err != nil {
			return err
		}
	}
	return nil
}

// ReadListBundleDataset reads one dataset of an already verified generation and
// returns its canonical entries. The reader hashes the bytes itself.
func ReadListBundleDataset(root string, manifest ListBundleManifest, id string) ([]string, error) {
	if err := validateListBundleManifest(manifest); err != nil {
		return nil, err
	}
	directory, err := generationPath(root, manifest.Generation)
	if err != nil {
		return nil, err
	}
	for _, dataset := range manifest.Datasets {
		if dataset.ID != id {
			continue
		}
		return readDatasetFiles(directory, dataset, manifest.Limits)
	}
	return nil, E.New("list bundle has no dataset ", id)
}

func readDatasetFiles(directory string, dataset ListBundleDataset, limits ListBundleLimits) ([]string, error) {
	var entries []string
	var decodedTotal int64
	decodedHash := sha256.New()
	for _, file := range dataset.Files {
		name, _, _, _ := listBundleDatasetSpec(dataset.ID)
		if err := validateShardName(name, file.Name); err != nil {
			return nil, err
		}
		data, err := readRegularFile(filepath.Join(directory, file.Name), listBundleMaxShardWire)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) != file.Size || sha256Hex(data) != file.SHA256 {
			return nil, E.New("shard ", file.Name, " does not match its manifest hash")
		}
		decoded := data
		if strings.HasSuffix(file.Name, ".gz") {
			decoded, err = decodeGzipOnce(data, listBundleMaxShardDecoded)
			if err != nil {
				return nil, E.Cause(err, "shard ", file.Name)
			}
		}
		if int64(len(decoded)) != file.DecompressedSize || sha256Hex(decoded) != file.DecompressedSHA256 {
			return nil, E.New("shard ", file.Name, " decoded bytes do not match the manifest")
		}
		decodedHash.Write(decoded)
		decodedTotal += int64(len(decoded))
		count := 0
		for _, line := range strings.Split(string(decoded), "\n") {
			if line == "" {
				continue
			}
			entries = append(entries, line)
			count++
			if len(entries) > listBundleMaxEntries {
				return nil, E.New("dataset exceeds the entry limit")
			}
		}
		if count != file.Entries {
			return nil, E.New("shard ", file.Name, " entry count does not match the manifest")
		}
	}
	if len(entries) != dataset.Entries || decodedTotal != dataset.Size {
		return nil, E.New("dataset ", dataset.ID, " does not match its manifest counts")
	}
	if dataset.Entries > limits.MaxEntries && !isNegativeDataset(dataset.ID) {
		return nil, E.New("dataset ", dataset.ID, " exceeds max_entries")
	}
	if dataset.Entries > limits.MaxExcludeEntries && isNegativeDataset(dataset.ID) {
		return nil, E.New("dataset ", dataset.ID, " exceeds max_exclude_entries")
	}
	return entries, nil
}

// readRegularFile opens path without following a final symlink and reads at most
// maxBytes+1 bytes.
func readRegularFile(filePath string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		return nil, E.Cause(err, "inspect ", filepath.Base(filePath))
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, E.New(filepath.Base(filePath), " is not a plain file")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, E.Cause(err, "open ", filepath.Base(filePath))
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, E.Cause(err, "stat ", filepath.Base(filePath))
	}
	if !os.SameFile(info, opened) {
		return nil, E.New(filepath.Base(filePath), " changed while being opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, E.Cause(err, "read ", filepath.Base(filePath))
	}
	if int64(len(data)) > maxBytes {
		return nil, E.New(filepath.Base(filePath), " exceeds the size limit of ", maxBytes, " bytes")
	}
	return data, nil
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// decodeListBundleManifestFile reads and strictly decodes a current.json or an
// archived generation manifest.
func decodeListBundleManifestFile(filePath string) (ListBundleManifest, []byte, error) {
	var manifest ListBundleManifest
	data, err := readRegularFile(filePath, listBundleManifestMaxBytes)
	if err != nil {
		return manifest, nil, err
	}
	manifest, err = DecodeListBundleManifest(data)
	if err != nil {
		return manifest, nil, err
	}
	return manifest, data, nil
}

// readCurrentManifest returns the published manifest and its exact bytes. A
// missing current.json is reported as os.ErrNotExist.
func readCurrentManifest(root string) (ListBundleManifest, []byte, error) {
	return decodeListBundleManifestFile(filepath.Join(root, listBundleCurrentName))
}

// verifyPathComponents rejects symbolic links and non-directory components of an
// existing output root. Missing trailing components are allowed: they are
// created by the publisher with the documented private mode.
func verifyPathComponents(directory string) error {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return E.Cause(err, "resolve output directory")
	}
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	remainder = strings.TrimPrefix(remainder, string(filepath.Separator))
	current := volume + string(filepath.Separator)
	missing := false
	for _, component := range strings.Split(remainder, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) {
				missing = true
				continue
			}
			return E.Cause(statErr, "inspect output directory component")
		}
		if missing {
			return E.New("output directory component ", filepath.Base(current), " is missing below an existing path")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return E.New("output directory component ", filepath.Base(current), " is a symbolic link")
		}
		if !info.IsDir() {
			return E.New("output directory component ", filepath.Base(current), " is not a directory")
		}
	}
	return nil
}

// ensureOutputRoot creates the operator output directory with private
// permissions after rejecting aliased components.
func ensureOutputRoot(directory string) error {
	if directory == "" {
		return E.New("output directory is required")
	}
	if err := verifyPathComponents(directory); err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return E.Cause(err, "create output directory")
	}
	return verifyPathComponents(directory)
}

// rejectAliasedLeaf rejects a symbolic link, a directory, an aliased hardlink or
// an unexpected device at a live publication path.
func rejectAliasedLeaf(filePath string) error {
	info, err := os.Lstat(filePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return E.Cause(err, "inspect ", filepath.Base(filePath))
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return E.New("refusing to replace the symbolic link ", filepath.Base(filePath))
	}
	if info.IsDir() {
		return E.New("refusing to replace the directory ", filepath.Base(filePath))
	}
	if !info.Mode().IsRegular() {
		return E.New("refusing to replace the non-regular file ", filepath.Base(filePath))
	}
	links, err := fileLinkCount(filePath)
	if err != nil {
		return err
	}
	if links > 1 {
		return E.New("refusing to replace the hardlinked file ", filepath.Base(filePath))
	}
	return nil
}

// writePrivateFile writes one new file with mode 0600 and synchronises it.
func writePrivateFile(filePath string, data []byte) error {
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return E.Cause(err, "create ", filepath.Base(filePath))
	}
	written, writeErr := file.Write(data)
	if writeErr == nil && written != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return E.Cause(writeErr, "write ", filepath.Base(filePath))
	}
	if closeErr != nil {
		return E.Cause(closeErr, "close ", filepath.Base(filePath))
	}
	return nil
}

// publishManifestBytes atomically replaces DIRECTORY/current.json with the given
// manifest bytes through a private same-directory temporary file.
func publishManifestBytes(root string, manifestBytes []byte) error {
	target := filepath.Join(root, listBundleCurrentName)
	if err := rejectAliasedLeaf(target); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(root, ".current-*.tmp")
	if err != nil {
		return E.Cause(err, "create current.json temporary file")
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return E.Cause(err, "set current.json temporary mode")
	}
	if _, err = temporary.Write(manifestBytes); err != nil {
		return E.Cause(err, "write current.json temporary file")
	}
	if err = temporary.Sync(); err != nil {
		return E.Cause(err, "sync current.json temporary file")
	}
	if err = temporary.Close(); err != nil {
		return E.Cause(err, "close current.json temporary file")
	}
	if err = bundleFault("publish-temp"); err != nil {
		return err
	}
	if err = replaceFileAtomically(temporaryPath, target); err != nil {
		return err
	}
	cleanup = false
	if err = bundleFault("post-replace"); err != nil {
		return &postCommitError{err: err}
	}
	if err = syncDirectory(root); err != nil {
		return &postCommitError{err: err}
	}
	return nil
}

// postCommitError marks a failure after the single commit point. The generation
// is published; only durability of the rename is uncertain.
type postCommitError struct {
	err error
}

func (e *postCommitError) Error() string { return e.err.Error() }
func (e *postCommitError) Unwrap() error { return e.err }

// bundleFaultHook is a test-only injection point for publication faults. It is
// nil in production builds and never changes a successful path.
var bundleFaultHook func(stage string) error

func bundleFault(stage string) error {
	if bundleFaultHook == nil {
		return nil
	}
	return bundleFaultHook(stage)
}

// bundleWriter stages one immutable generation directory.
type bundleWriter struct {
	root       string
	generation string
	directory  string
	committed  bool
}

// beginBundleGeneration creates the private generation directory. Staging files
// are created exclusively so a pre-existing or hardlinked leaf cannot be reused.
func beginBundleGeneration(root string, generation string) (*bundleWriter, error) {
	directory, err := generationPath(root, generation)
	if err != nil {
		return nil, err
	}
	generations := filepath.Join(root, listBundleGenerations)
	if err = os.Mkdir(generations, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, E.Cause(err, "create generations directory")
	}
	if err = verifyPathComponents(generations); err != nil {
		return nil, err
	}
	if err = os.Mkdir(directory, 0o700); err != nil {
		return nil, E.Cause(err, "create generation directory")
	}
	return &bundleWriter{root: root, generation: generation, directory: directory}, nil
}

// writeDataset shards one dataset into the staged generation and returns its
// manifest entry together with the canonical concatenation size.
func (w *bundleWriter) writeDataset(id string, entries []string, compression string) (ListBundleDataset, error) {
	base, kind, family, ok := listBundleDatasetSpec(id)
	if !ok {
		return ListBundleDataset{}, E.New("unknown dataset ", id)
	}
	chunks, err := datasetChunks(entries)
	if err != nil {
		return ListBundleDataset{}, E.Cause(err, "dataset ", id)
	}
	dataset := ListBundleDataset{
		ID:     id,
		Kind:   kind,
		Family: family,
		Files:  make([]ListBundleFile, 0, len(chunks)),
	}
	canonicalHash := sha256.New()
	for index, chunk := range chunks {
		wire := chunk
		compressed := compression == "gzip"
		if compressed {
			wire, err = gzipBytes(chunk)
			if err != nil {
				return ListBundleDataset{}, err
			}
		}
		if int64(len(wire)) > listBundleMaxShardWire {
			return ListBundleDataset{}, E.New("dataset ", id, " shard exceeds the wire limit")
		}
		name := shardName(base, index, compressed)
		if err = writePrivateFile(filepath.Join(w.directory, name), wire); err != nil {
			return ListBundleDataset{}, err
		}
		if err = bundleFault("write-shard"); err != nil {
			return ListBundleDataset{}, err
		}
		count := 0
		for _, line := range strings.Split(string(chunk), "\n") {
			if line != "" {
				count++
			}
		}
		dataset.Files = append(dataset.Files, ListBundleFile{
			Name:               name,
			SHA256:             sha256Hex(wire),
			Size:               int64(len(wire)),
			DecompressedSHA256: sha256Hex(chunk),
			DecompressedSize:   int64(len(chunk)),
			Entries:            count,
		})
		canonicalHash.Write(chunk)
		dataset.Size += int64(len(chunk))
		dataset.Entries += count
	}
	dataset.SHA256 = hex.EncodeToString(canonicalHash.Sum(nil))
	if dataset.Entries > listBundleMaxEntries {
		return ListBundleDataset{}, E.New("dataset ", id, " exceeds the entry limit")
	}
	return dataset, nil
}

// seal writes the archived manifest, synchronises the generation directory and
// then publishes the same bytes as the single current.json commit point.
func (w *bundleWriter) seal(manifest ListBundleManifest) (ListRefreshReceipt, error) {
	var receipt ListRefreshReceipt
	manifestBytes, err := encodeListBundleManifest(manifest)
	if err != nil {
		return receipt, err
	}
	if err = writePrivateFile(filepath.Join(w.directory, listBundleManifestName), manifestBytes); err != nil {
		return receipt, err
	}
	if err = bundleFault("seal-manifest"); err != nil {
		return receipt, err
	}
	if err = syncDirectory(w.directory); err != nil {
		return receipt, err
	}
	if err = bundleFault("sync-generation"); err != nil {
		return receipt, err
	}
	if err = publishManifestBytes(w.root, manifestBytes); err != nil {
		var postCommit *postCommitError
		if !errors.As(err, &postCommit) {
			return receipt, err
		}
		// The generation is published; only durability of the rename is
		// uncertain. Report the commit instead of claiming a rollback.
		receipt = buildReceipt(w.root, manifest, manifestBytes, true)
		receipt.Warnings = []string{"directory_sync_failed"}
		w.committed = true
		return receipt, nil
	}
	w.committed = true
	receipt = buildReceipt(w.root, manifest, manifestBytes, false)
	return receipt, nil
}

func buildReceipt(root string, manifest ListBundleManifest, manifestBytes []byte, durabilityUncertain bool) ListRefreshReceipt {
	receipt := ListRefreshReceipt{
		Format:         ListRefreshResultFormat,
		Committed:      true,
		Generation:     manifest.Generation,
		Manifest:       filepath.Join(root, listBundleCurrentName),
		ManifestSHA256: sha256Hex(manifestBytes),
		DatasetEntries: make([]ListRefreshDatasetEntries, 0, len(manifest.Datasets)),
		Warnings:       []string{},
	}
	_ = durabilityUncertain
	for _, dataset := range manifest.Datasets {
		receipt.DatasetEntries = append(receipt.DatasetEntries, ListRefreshDatasetEntries{ID: dataset.ID, Entries: dataset.Entries})
	}
	return receipt
}

// abort removes only this invocation's uncommitted staging directory.
func (w *bundleWriter) abort() {
	if w == nil || w.committed {
		return
	}
	_ = os.RemoveAll(w.directory)
}

// readPreviousGeneration reports the published generation before a refresh.
func readPreviousGeneration(root string) *string {
	manifest, _, err := readCurrentManifest(root)
	if err != nil {
		return nil
	}
	generation := manifest.Generation
	return &generation
}

// RollbackLists validates a previously published generation and republishes its
// archived manifest atomically. No network, generation mutation or reload occurs.
func RollbackLists(ctx context.Context, outputDir string, generation string) (ListRefreshReceipt, error) {
	var receipt ListRefreshReceipt
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	if !validGenerationID(generation) {
		return receipt, E.New("invalid generation ", generation)
	}
	if err := ensureOutputRoot(outputDir); err != nil {
		return receipt, err
	}
	release, err := acquireRefreshLock(ctx, outputDir, systemClock{})
	if err != nil {
		return receipt, err
	}
	defer release()
	if err = ctx.Err(); err != nil {
		return receipt, err
	}
	directory, err := generationPath(outputDir, generation)
	if err != nil {
		return receipt, err
	}
	manifest, manifestBytes, err := decodeListBundleManifestFile(filepath.Join(directory, listBundleManifestName))
	if err != nil {
		return receipt, E.Cause(err, "read archived generation manifest")
	}
	if manifest.Generation != generation {
		return receipt, E.New("archived manifest generation does not match the requested generation")
	}
	if err = VerifyListBundle(outputDir, manifest); err != nil {
		return receipt, E.Cause(err, "verify generation")
	}
	previous := readPreviousGeneration(outputDir)
	if err = publishManifestBytes(outputDir, manifestBytes); err != nil {
		return receipt, err
	}
	if previous != nil && *previous == generation {
		previous = nil
	}
	receipt = ListRefreshReceipt{
		Format:             ListRefreshResultFormat,
		Committed:          true,
		Generation:         generation,
		PreviousGeneration: previous,
		Manifest:           filepath.Join(outputDir, listBundleCurrentName),
		ManifestSHA256:     sha256Hex(manifestBytes),
		DatasetEntries:     make([]ListRefreshDatasetEntries, 0, len(manifest.Datasets)),
		Warnings:           []string{},
	}
	for _, dataset := range manifest.Datasets {
		receipt.DatasetEntries = append(receipt.DatasetEntries, ListRefreshDatasetEntries{ID: dataset.ID, Entries: dataset.Entries})
	}
	return receipt, nil
}

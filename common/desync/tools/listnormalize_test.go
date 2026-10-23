package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readTestData(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

const syntheticDomainList = `# Synthetic provider snapshot for parser tests, not captured from any network.
Example.COM.
example.com
sub.example.org
  duplicate.example.net  
*.wildcard.example
bad entry.example
exa_mple..org
.only-subdomains.example
`

const syntheticIPList = `# Synthetic provider snapshot for parser tests, not captured from any network.
10.1.2.0/24
10.1.2.5/24
192.0.2.1
2001:DB8::/32
10.1.2.0/24
invalid/99
300.1.1.1
`

type listTestCase struct {
	path    string
	content string
}

func runNormalize(t *testing.T, kind ListKind, input string, excludes []listTestCase, options ListNormalizeOptions) (string, ListManifest, error) {
	t.Helper()
	if options.Kind == "" {
		options.Kind = kind
	}
	var output strings.Builder
	excludeInputs := make([]ListInput, 0, len(excludes))
	for _, exclude := range excludes {
		excludeInputs = append(excludeInputs, ListInput{Path: exclude.path, Reader: strings.NewReader(exclude.content)})
	}
	manifest, err := NormalizeList(context.Background(), ListInput{Path: "provider-synthetic.txt", Reader: strings.NewReader(input)}, &output, excludeInputs, options)
	return output.String(), manifest, err
}

func TestNormalizeDomainList(t *testing.T) {
	t.Parallel()
	output, manifest, err := runNormalize(t, ListKindDomain, syntheticDomainList, nil, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const expected = ".only-subdomains.example\nduplicate.example.net\nexample.com\nsub.example.org\n"
	if output != expected {
		t.Fatalf("output mismatch\n got: %q\nwant: %q", output, expected)
	}
	if manifest.Format != ListManifestFormat || manifest.Kind != ListKindDomain {
		t.Fatalf("unexpected manifest header %+v", manifest)
	}
	if manifest.Source.Lines != 9 || manifest.Source.Accepted != 5 || manifest.Source.Invalid != 3 || manifest.Source.Duplicates != 1 || manifest.Source.Excluded != 0 {
		t.Fatalf("unexpected source counts %+v", manifest.Source)
	}
	digest := sha256.Sum256([]byte(expected))
	if manifest.Output.SHA256 != hex.EncodeToString(digest[:]) || manifest.Output.Entries != 4 || manifest.Output.Size != int64(len(expected)) {
		t.Fatalf("unexpected output provenance %+v", manifest.Output)
	}
	rawDigest := sha256.Sum256([]byte(syntheticDomainList))
	if manifest.Source.SHA256 != hex.EncodeToString(rawDigest[:]) || manifest.Source.Compression != "none" {
		t.Fatalf("unexpected source provenance %+v", manifest.Source)
	}
}

func TestNormalizeDomainExclusion(t *testing.T) {
	t.Parallel()
	output, manifest, err := runNormalize(t, ListKindDomain, syntheticDomainList, []listTestCase{
		{path: "exclude-synthetic.txt", content: "# excluded\nduplicate.example.net\n"},
	}, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const expected = ".only-subdomains.example\nexample.com\nsub.example.org\n"
	if output != expected {
		t.Fatalf("unexpected output %q", output)
	}
	if manifest.Source.Excluded != 1 || len(manifest.Excluded) != 1 || manifest.Excluded[0].Accepted != 1 {
		t.Fatalf("unexpected exclusion provenance %+v", manifest)
	}
}

func TestNormalizeIPList(t *testing.T) {
	t.Parallel()
	output, manifest, err := runNormalize(t, ListKindIP, syntheticIPList, nil, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "10.1.2.0/24\n192.0.2.1\n2001:db8::/32\n"
	if output != expected {
		t.Fatalf("output mismatch\n got: %q\nwant: %q", output, expected)
	}
	if manifest.Source.Accepted != 5 || manifest.Source.Duplicates != 2 || manifest.Source.Invalid != 2 {
		t.Fatalf("unexpected counts %+v", manifest.Source)
	}
}

func TestNormalizeIPExclusionByPrefix(t *testing.T) {
	t.Parallel()
	output, manifest, err := runNormalize(t, ListKindIP, syntheticIPList, []listTestCase{
		{path: "exclude-rfc1918.txt", content: "10.0.0.0/8\n"},
	}, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if output != "192.0.2.1\n2001:db8::/32\n" {
		t.Fatalf("unexpected output %q", output)
	}
	if manifest.Source.Excluded != 1 {
		t.Fatalf("unexpected exclusion count %+v", manifest.Source)
	}
	// A narrower exclusion must not remove a broader entry.
	output, _, err = runNormalize(t, ListKindIP, "10.0.0.0/8\n", []listTestCase{
		{path: "exclude-narrow.txt", content: "10.1.0.0/16\n"},
	}, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if output != "10.0.0.0/8\n" {
		t.Fatalf("a narrow exclusion removed a broad entry: %q", output)
	}
}

func TestNormalizeGzipInput(t *testing.T) {
	t.Parallel()
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	writer.Header.ModTime = time.Unix(0, 0)
	writer.Header.OS = 255
	if _, err = writer.Write([]byte(syntheticDomainList)); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, manifest, err := runNormalize(t, ListKindDomain, compressed.String(), nil, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output, ".only-subdomains.example\n") {
		t.Fatalf("unexpected output %q", output)
	}
	if manifest.Source.Compression != "gzip" || manifest.Source.Size != int64(compressed.Len()) || manifest.Source.Decompressed != int64(len(syntheticDomainList)) {
		t.Fatalf("unexpected gzip provenance %+v", manifest.Source)
	}
	rawDigest := sha256.Sum256(compressed.Bytes())
	if manifest.Source.SHA256 != hex.EncodeToString(rawDigest[:]) {
		t.Fatal("the source hash must cover the raw compressed bytes")
	}
}

func TestNormalizeGzipFixture(t *testing.T) {
	t.Parallel()
	data := readTestData(t, "testdata/provider/provider-synthetic.txt.gz")
	output, manifest, err := runNormalize(t, ListKindDomain, string(data), nil, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Source.Compression != "gzip" {
		t.Fatalf("fixture is not gzip: %+v", manifest.Source)
	}
	text := readTestData(t, "testdata/provider/provider-synthetic.txt")
	textOutput, textManifest, err := runNormalize(t, ListKindDomain, string(text), nil, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if output != textOutput || manifest.Output.SHA256 != textManifest.Output.SHA256 {
		t.Fatal("gzip and text fixtures must normalize to the same list")
	}
}

func TestNormalizeRejectsInvalidGzip(t *testing.T) {
	t.Parallel()
	_, _, err := runNormalize(t, ListKindDomain, "\x1f\x8bnot-a-gzip-stream", nil, ListNormalizeOptions{})
	if err == nil {
		t.Fatal("expected a gzip error")
	}
}

func TestNormalizeLimits(t *testing.T) {
	t.Parallel()
	if _, _, err := runNormalize(t, ListKindDomain, syntheticDomainList, nil, ListNormalizeOptions{MaxInputBytes: 8}); err == nil {
		t.Fatal("expected an input size error")
	}
	if _, _, err := runNormalize(t, ListKindDomain, syntheticDomainList, nil, ListNormalizeOptions{MaxEntries: 2}); err == nil {
		t.Fatal("expected an entry limit error")
	}
	if _, _, err := runNormalize(t, ListKindDomain, strings.Repeat("a", 64)+".example\n", nil, ListNormalizeOptions{MaxLineLength: 16}); err == nil {
		t.Fatal("expected a line length error")
	}
	// A decompression bomb must stop at the decompressed limit instead of
	// allocating the full expansion.
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(strings.Repeat("a.example\n", 100000))); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err := runNormalize(t, ListKindDomain, compressed.String(), nil, ListNormalizeOptions{MaxDecompressedBytes: 1024})
	if err == nil || !strings.Contains(err.Error(), "decompressed size limit") {
		t.Fatalf("expected a decompressed size error, got %v", err)
	}
}

func TestNormalizeCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output strings.Builder
	_, err := NormalizeList(ctx, ListInput{Path: "-", Reader: strings.NewReader(syntheticDomainList)}, &output, nil, ListNormalizeOptions{Kind: ListKindDomain})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestNormalizeShortWrite(t *testing.T) {
	t.Parallel()
	_, err := NormalizeList(context.Background(), ListInput{Path: "-", Reader: strings.NewReader("example.com\n")}, shortWriter{}, nil, ListNormalizeOptions{Kind: ListKindDomain})
	if err == nil {
		t.Fatal("expected a short write error")
	}
}

func TestNormalizeKindValidation(t *testing.T) {
	t.Parallel()
	var output strings.Builder
	_, err := NormalizeList(context.Background(), ListInput{Path: "-", Reader: strings.NewReader("x")}, &output, nil, ListNormalizeOptions{})
	if err == nil {
		t.Fatal("expected a kind error")
	}
	_, err = NormalizeList(context.Background(), ListInput{Path: "-", Reader: strings.NewReader("x")}, &output, nil, ListNormalizeOptions{Kind: "asn"})
	if err == nil {
		t.Fatal("expected an unsupported kind error")
	}
}

func TestNormalizeManifestDeterministic(t *testing.T) {
	t.Parallel()
	_, manifest, err := runNormalize(t, ListKindDomain, syntheticDomainList, []listTestCase{
		{path: "exclude-synthetic.txt", content: "example.com\n"},
	}, ListNormalizeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var first bytes.Buffer
	if err = WriteListManifest(&first, manifest); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	if err = WriteListManifest(&second, manifest); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("manifest encoding is not deterministic")
	}
	text := first.String()
	for _, key := range []string{`"format": "desync.list-manifest/v1"`, `"kind": "domain"`, `"source": {`, `"excluded": [`, `"output": {`, `"sha256": "`} {
		if !strings.Contains(text, key) {
			t.Fatalf("manifest misses %q: %s", key, text)
		}
	}
	if !strings.HasSuffix(text, "}\n") {
		t.Fatal("manifest must end with a newline")
	}
}

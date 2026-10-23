package main

// QA v2 command-surface tests (tester-max-3, task t_be788118): D3 CLI range,
// D4 boundary/atomicity, D5 Windows path identity and POSIX preservation.
// Persisted in the v3 artifact (task t_f7bf08bd); the behavioral assertions are
// unchanged from the independent QA run. No product binary, client, config or
// network is used.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func qaV2RunIP2Net(t *testing.T, input string, args ...string) (string, string, error) {
	t.Helper()
	return executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), []byte(input), args...)
}

// TestQAV2IP2NetCLIThresholdUint32 pins the D3 CLI repair: the full uint32
// range accepted by sscanf("%u") must be accepted by the flags, values above
// uint32 and a non-strict spelling must be rejected, and the arithmetic must be
// exact at the top of the range.
func TestQAV2IP2NetCLIThresholdUint32(t *testing.T) {
	t.Parallel()
	output, _, err := qaV2RunIP2Net(t, "10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.3\n",
		"--family", "4", "--prefix-length", "30-30",
		"--v4-threshold", "4294967294/4294967295")
	if err != nil {
		t.Fatalf("uint32 maximum threshold rejected: %v", err)
	}
	if output != "10.0.0.0/30\n" {
		t.Fatalf("unexpected output: %q", output)
	}
	output, _, err = qaV2RunIP2Net(t, "2001:db8::1\n2001:db8::2\n2001:db8::3\n",
		"--family", "6", "--v6-threshold", "4294967295")
	if err != nil {
		t.Fatalf("uint32 maximum v6 threshold rejected: %v", err)
	}
	if output != "2001:db8::1\n2001:db8::2\n2001:db8::3\n" {
		t.Fatalf("unexpected v6 output: %q", output)
	}
	rejections := [][]string{
		{"--v4-threshold", "4294967295/4294967295"},
		{"--v4-threshold", "4294967296/4294967297"},
		{"--v4-threshold", "4294967294/4294967295x"},
		{"--v4-threshold", "-1/2"},
		{"--v4-threshold", "+1/2"},
		{"--v6-threshold", "0"},
		{"--v6-threshold", "4294967296"},
		{"--v6-threshold", "-1"},
	}
	for _, args := range rejections {
		if _, _, err = qaV2RunIP2Net(t, "10.0.0.1\n", args...); err == nil {
			t.Fatalf("args %v must be rejected", args)
		}
	}
}

// TestQAV2IP2NetThresholdZeroPairRejected is the reproducer for QA defect
// Q1: `--v4-threshold 0/0` is accepted and silently replaced by the 3/4
// default, while the pinned C tool rejects a zero divisor and the documented
// range is 1 <= mul < div with div >= 2.
func TestQAV2IP2NetThresholdZeroPairRejected(t *testing.T) {
	t.Parallel()
	input := "192.0.2.0\n192.0.2.1\n192.0.2.2\n192.0.2.3\n"
	output, _, err := qaV2RunIP2Net(t, input, "--v4-threshold", "0/0")
	if err == nil {
		t.Fatalf("--v4-threshold 0/0 must be rejected, got output %q", output)
	}
}

func qaV2Response(answerCount int, payload ...[]byte) []byte {
	message := []byte{0x00, 0x01, 0x81, 0x80, 0x00, 0x00, byte(answerCount >> 8), byte(answerCount), 0x00, 0x00, 0x00, 0x00}
	for _, record := range payload {
		message = append(message, record...)
	}
	return message
}

// TestQAV2DNSParseQueryCommandBoundary pins the D4 command-level boundary and
// the structural-error atomicity: an oversized or invalid blob must produce an
// error and no stdout at all.
func TestQAV2DNSParseQueryCommandBoundary(t *testing.T) {
	t.Parallel()
	answerless := qaV2Response(0)
	padded := answerless
	if len(padded) < 12 {
		t.Fatal("bad fixture")
	}
	// A 8191-byte blob is accepted (structure is still answerless).
	accepted := append(append([]byte{}, answerless...), bytes.Repeat([]byte{0x00}, 8191-len(answerless))...)
	output, _, err := executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), accepted)
	if err != nil {
		t.Fatalf("8191 bytes must be accepted: %v", err)
	}
	if output != "" {
		t.Fatalf("answerless response must print nothing, got %q", output)
	}
	// Exactly 8192 bytes is rejected.
	oversized := append(append([]byte{}, answerless...), bytes.Repeat([]byte{0x00}, 8192-len(answerless))...)
	output, _, err = executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), oversized)
	if err == nil {
		t.Fatal("8192 bytes must be rejected")
	}
	if output != "" {
		t.Fatalf("rejected blob must not print anything, got %q", output)
	}
	// Structurally invalid second answer after a valid first one: the command
	// must fail atomically instead of printing the already-parsed address.
	validAnswer := []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0, 2, 1}
	brokenAnswer := []byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x10, 192, 0, 2}
	output, _, err = executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(),
		qaV2Response(2, validAnswer, brokenAnswer))
	if err == nil {
		t.Fatal("truncated answer must fail")
	}
	if output != "" {
		t.Fatalf("partial output on structural error: %q", output)
	}
}

// TestQAV2ListWindowsPathIdentity pins the D5 lexical Windows identity in the
// hermetic seam and proves POSIX stays byte exact.
func TestQAV2ListWindowsPathIdentity(t *testing.T) {
	t.Parallel()
	aliasPairs := [][2]string{
		{`C:\Lists\a.txt`, `c:\lists\A.TXT`},
		{`C:\Lists\a.txt`, `C:\Lists\a.txt.`},
		{`C:\Lists\a.txt`, `C:\Lists\a.txt `},
		{`C:\Lists\a.txt`, `C:/Lists/a.txt`},
		{`C:\a b\c.txt`, `c:\A B\C.TXT`},
	}
	for _, pair := range aliasPairs {
		err := validateListPathsPlatform(pair[1], "", "", []string{pair[0]}, true)
		if err == nil {
			t.Fatalf("windows=true must treat %q and %q as the same file", pair[0], pair[1])
		}
		if err = validateListPathsPlatform(pair[1], "", "", []string{pair[0]}, false); err != nil && strings.EqualFold(pair[0], pair[1]) {
			t.Fatalf("unexpected POSIX rejection for %q/%q: %v", pair[0], pair[1], err)
		}
	}
	// Distinct Windows paths must stay distinct.
	distinct := [][2]string{
		{`C:\Lists\a.txt`, `C:\Lists\b.txt`},
		{`C:\Lists\a.txt`, `D:\Lists\a.txt`},
		{`C:\Lists\a.txt`, `C:\Lists\a.txt.bak`},
		{`C:\a`, `C:\a\...`},
	}
	for _, pair := range distinct {
		if err := validateListPathsPlatform(pair[1], "", "", []string{pair[0]}, true); err != nil {
			t.Fatalf("windows=true must keep %q and %q distinct: %v", pair[0], pair[1], err)
		}
	}
	// POSIX semantics: byte-exact identity only.
	if err := validateListPathsPlatform("/tmp/a.txt", "", "", []string{"/tmp/a.txt"}, false); err == nil {
		t.Fatal("identical POSIX paths must collide")
	}
	if err := validateListPathsPlatform("/tmp/A.TXT", "", "", []string{"/tmp/a.txt"}, false); err != nil {
		t.Fatalf("POSIX paths are case sensitive: %v", err)
	}
	if err := validateListPathsPlatform("/tmp/a.txt", "", "", []string{"/tmp/a.txt "}, false); err != nil {
		t.Fatalf("POSIX must not trim trailing spaces: %v", err)
	}
	// The production guard on this host is the POSIX (byte-exact) form; the
	// Windows folding is selected through runtime.GOOS in validateListPaths.
	if err := validateListPaths("/tmp/A.TXT", "", "", []string{"/tmp/a.txt"}); err != nil {
		t.Fatalf("validateListPaths must not fold case on linux: %v", err)
	}
	if err := validateListPaths("/tmp/a.txt", "", "", []string{"/tmp/a.txt"}); err == nil {
		t.Fatal("validateListPaths must reject identical input and exclude paths")
	}
}

// TestQAV2ListOutputInputNontruncation proves the output/manifest guard runs
// before any file is opened or truncated, for plain paths and symlinks.
func TestQAV2ListOutputInputNontruncation(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	input := filepath.Join(directory, "provider.txt")
	if err := os.WriteFile(input, []byte("a.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(directory, "manifest.json")
	command := func(args ...string) (string, error) {
		stdout, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil, args...)
		return stdout, err
	}
	if _, err := command("--kind", "domain", "--input", input, "--output", input, "--manifest", manifest); err == nil {
		t.Fatal("output equal to input must be rejected")
	}
	content, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "a.example\n" {
		t.Fatalf("input was modified despite the guard: %q", content)
	}
	if _, err = os.Stat(manifest); !os.IsNotExist(err) {
		t.Fatalf("manifest must not be created on a rejected run: %v", err)
	}
	// Symlink output pointing at the input must be refused before truncation.
	link := filepath.Join(directory, "out-link.txt")
	if err = os.Symlink(input, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if _, err = command("--kind", "domain", "--input", input, "--output", link, "--manifest", manifest); err == nil {
		t.Fatal("symlink output must be refused")
	}
	content, err = os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "a.example\n" {
		t.Fatalf("input was modified through the symlink: %q", content)
	}
	// Directory output must be refused.
	if _, err = command("--kind", "domain", "--input", input, "--output", directory, "--manifest", manifest); err == nil {
		t.Fatal("directory output must be refused")
	}
	// A POSIX case-different output is a distinct file and must be accepted.
	upper := filepath.Join(directory, "PROVIDER.TXT")
	if _, err = command("--kind", "domain", "--input", input, "--output", upper, "--manifest", manifest); err != nil {
		t.Fatalf("case-different POSIX output must be accepted: %v", err)
	}
	upperContent, err := os.ReadFile(upper)
	if err != nil {
		t.Fatal(err)
	}
	if string(upperContent) != "a.example\n" {
		t.Fatalf("unexpected normalized output: %q", upperContent)
	}
	if content, err = os.ReadFile(input); err != nil || string(content) != "a.example\n" {
		t.Fatalf("input changed after a successful run: %q %v", content, err)
	}
}

// TestQAV2ListManifestAliasRefused covers the manifest side of the guard.
func TestQAV2ListManifestAliasRefused(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	input := filepath.Join(directory, "provider.txt")
	if err := os.WriteFile(input, []byte("a.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(directory, "out.txt")
	if _, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", input, "--output", output, "--manifest", input); err == nil {
		t.Fatal("manifest equal to input must be rejected")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("output must not be created when the guard rejects: %v", err)
	}
}

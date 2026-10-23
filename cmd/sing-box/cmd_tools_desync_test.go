package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/desync/tools"

	"github.com/spf13/cobra"
)

func executeDesyncCommand(t *testing.T, command *cobra.Command, stdin []byte, args ...string) (string, string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetArgs(args)
	command.SetIn(bytes.NewReader(stdin))
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	err := command.Execute()
	return stdout.String(), stderr.String(), err
}

func TestToolsDesyncRegistration(t *testing.T) {
	t.Parallel()
	var desync *cobra.Command
	for _, command := range commandTools.Commands() {
		if command.Name() == "desync" {
			desync = command
		}
	}
	if desync == nil {
		t.Fatal("the desync tool group is not registered under tools")
	}
	expected := map[string][]string{
		"ip2net":            {"family", "prefix-length", "v4-threshold", "v6-threshold", "input", "output"},
		"mdig":              {"family", "threads", "eagain", "eagain-delay", "verbose", "stats", "log-resolved", "log-failed", "input", "output"},
		"dns-make-query":    {"name", "family", "id"},
		"dns-parse-query":   {},
		"list-normalize":    {"kind", "input", "output", "exclude", "manifest"},
		"blockcheck-report": {"input", "output"},
		// D5 explicit provider/runtime commands. They stay children of the
		// existing offline group; no positional arguments or secret flags.
		"list-refresh": {"request", "rollback", "output-dir"},
		"reload":       {"server", "outbound"},
		"diagnostics":  {"server", "outbound", "kind", "limit", "include-sensitive", "all-networks", "output"},
		// U4 wait-only resolver. It shares the inbound binding schema and
		// never creates a listener, core instance or native driver.
		"bind-wait": {"input"},
	}
	registered := make(map[string]*cobra.Command)
	for _, command := range desync.Commands() {
		registered[command.Name()] = command
	}
	for name, flags := range expected {
		command, found := registered[name]
		if !found {
			t.Fatalf("subcommand %s is not registered", name)
		}
		for _, flag := range flags {
			if command.Flags().Lookup(flag) == nil {
				t.Fatalf("subcommand %s misses the --%s flag", name, flag)
			}
		}
	}
	if len(registered) != len(expected) {
		t.Fatalf("unexpected subcommand count: %v", registered)
	}
	// The group must not expose the client-owning tools flag handling; it is a
	// plain child of commandTools.
	if desync.Parent() != commandTools {
		t.Fatal("the desync group must be a child of the existing tools command")
	}
}

func TestToolsDesyncIP2NetStdin(t *testing.T) {
	t.Parallel()
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), []byte("0.0.0.0\n0.0.0.1\n0.0.0.2\n0.0.0.3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "0.0.0.0/30\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
}

func TestToolsDesyncIP2NetFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "input.txt")
	outputPath := filepath.Join(directory, "output.txt")
	if err := os.WriteFile(inputPath, []byte("2001:db8::5\n2001:db8::4\n2001:db8::3\n2001:db8::2\n2001:db8::1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), nil, "--family=6", "--input", inputPath, "--output", outputPath)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "2001:db8::/64\n" {
		t.Fatalf("unexpected file output %q", output)
	}
}

func TestToolsDesyncIP2NetFlagErrors(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{"--family=46"},
		{"--family=5"},
		{"--prefix-length=30-24"},
		{"--prefix-length=24-"},
		{"--prefix-length=-24"},
		{"--prefix-length=0-24"},
		{"--v4-threshold=3"},
		{"--v4-threshold=4/4"},
		{"--v4-threshold=0/4"},
		{"--v6-threshold=0"},
		{"--bogus"},
		{"extra-argument"},
	}
	for _, args := range cases {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			_, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), []byte("0.0.0.0\n"), args...)
			if err == nil {
				t.Fatalf("expected an error for %v", args)
			}
		})
	}
}

func TestToolsDesyncIP2NetThresholdUint32Range(t *testing.T) {
	t.Parallel()
	input := []byte("192.0.2.0\n192.0.2.1\n")
	// ip2net.c:286-301 parses both thresholds with sscanf("%u"), so any
	// uint32 pair with 1 <= mul < div and any v6 threshold >= 1 is valid.
	accepted := [][]string{
		{"--v4-threshold", "2000000/4000000"},
		{"--v4-threshold", "4294967294/4294967295"},
		{"--family", "6", "--v6-threshold", "4294967295"},
	}
	for _, args := range accepted {
		if _, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), input, args...); err != nil {
			t.Fatalf("upstream-valid threshold %v rejected: %v", args, err)
		}
	}
	rejected := [][]string{
		{"--v4-threshold", "4294967296/4294967297"},
		{"--v6-threshold", "4294967296"},
		{"--v6-threshold", "0"},
	}
	for _, args := range rejected {
		if _, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), input, args...); err == nil {
			t.Fatalf("unrepresentable threshold %v not rejected", args)
		}
	}
}

func TestToolsDesyncIP2NetMissingInput(t *testing.T) {
	t.Parallel()
	_, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), nil, "--input", filepath.Join(t.TempDir(), "missing.txt"))
	if err == nil {
		t.Fatal("expected an input open error")
	}
}

const expectedQueryHex = "123401000001000000000000076578616d706c6503636f6d0000010001"

func TestToolsDesyncDNSMakeQuery(t *testing.T) {
	t.Parallel()
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncDNSMakeQueryCommand(), nil, "--name", "example.com", "--family", "4", "--id", "4660")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString([]byte(stdout)) != expectedQueryHex {
		t.Fatalf("unexpected query %s", hex.EncodeToString([]byte(stdout)))
	}
	stdout, _, err = executeDesyncCommand(t, newToolsDesyncDNSMakeQueryCommand(), nil, "--name", "example.com", "--family", "6", "--id", "4660")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(hex.EncodeToString([]byte(stdout)), "001c0001") {
		t.Fatalf("expected an AAAA question: %s", hex.EncodeToString([]byte(stdout)))
	}
}

func TestToolsDesyncDNSMakeQueryErrors(t *testing.T) {
	t.Parallel()
	cases := [][]string{
		{"--family", "4"},
		{"--name", "example.com", "--family", "both"},
		{"--name", "example.com", "--id", "70000"},
		{"--name", "bad..name"},
		{"--name", strings.Repeat("a", 64) + ".com"},
	}
	for _, args := range cases {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			_, _, err := executeDesyncCommand(t, newToolsDesyncDNSMakeQueryCommand(), nil, args...)
			if err == nil {
				t.Fatalf("expected an error for %v", args)
			}
		})
	}
}

const testDNSResponseHex = "123481800001000200000000" +
	"076578616d706c6503636f6d0000010001" +
	"c00c000100010000003c00045db8d822" +
	"c00c001c00010000003c001026062800022000010248189325c81946"

func TestToolsDesyncDNSParseQuery(t *testing.T) {
	t.Parallel()
	message, err := hex.DecodeString(testDNSResponseHex)
	if err != nil {
		t.Fatal(err)
	}
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), message)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "93.184.216.34\n2606:2800:220:1:248:1893:25c8:1946\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	if _, _, err = executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), []byte("not-a-response")); err == nil {
		t.Fatal("expected a parse error")
	}
	if _, _, err = executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), nil); err == nil {
		t.Fatal("expected an empty input error")
	}
}

// TestToolsDesyncDNSParseQuerySizeBoundary is the command-level control for
// mdig.c:431-443: the pinned tool reads into an 8192 byte buffer and requires
// EOF, so a blob of 8192 bytes is an error while 8191 bytes still parse.
func TestToolsDesyncDNSParseQuerySizeBoundary(t *testing.T) {
	t.Parallel()
	boundary := make([]byte, 8191)
	boundary[2] = 0x80 // QR set, no questions or answers
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), boundary)
	if err != nil {
		t.Fatalf("8191-byte response must be accepted: %v", err)
	}
	if stdout != "" {
		t.Fatalf("unexpected output for an answerless response: %q", stdout)
	}
	oversized := make([]byte, 8192)
	oversized[2] = 0x80
	if _, _, err = executeDesyncCommand(t, newToolsDesyncDNSParseQueryCommand(), oversized); err == nil {
		t.Fatal("8192-byte response must be rejected like the pinned fread/feof check")
	}
}

type cliMockResolver struct {
	calls  atomic.Int32
	answer []netip.Addr
}

func (r *cliMockResolver) Lookup(_ context.Context, name string, _ tools.Family) ([]netip.Addr, error) {
	r.calls.Add(1)
	if name == "fail.example" {
		return nil, errors.New("EAI_NONAME")
	}
	return r.answer, nil
}

func TestToolsDesyncMDigMock(t *testing.T) {
	t.Parallel()
	resolver := &cliMockResolver{answer: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	stdout, stderr, err := executeDesyncCommand(t, newToolsDesyncMDigCommand(resolver), []byte("example.com\n1.2.3.4\n"), "--family", "both")
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "93.184.216.34\n1.2.3.4\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("unexpected diagnostics %q", stderr)
	}
	if resolver.calls.Load() != 1 {
		t.Fatalf("expected one resolver call, got %d", resolver.calls.Load())
	}
}

func TestToolsDesyncMDigStatsAndLogs(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	resolvedPath := filepath.Join(directory, "resolved.log")
	failedPath := filepath.Join(directory, "failed.log")
	resolver := &cliMockResolver{answer: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	stdout, stderr, err := executeDesyncCommand(t, newToolsDesyncMDigCommand(resolver),
		[]byte("ok.example\nfail.example\n"),
		"--family", "4", "--stats", "1", "--log-resolved", resolvedPath, "--log-failed", failedPath)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "10.0.0.1\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	if !strings.Contains(stderr, "mdig stats : 00:00:00 : domains=1 success=1 error=0") {
		t.Fatalf("unexpected statistics %q", stderr)
	}
	resolved, err := os.ReadFile(resolvedPath)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := os.ReadFile(failedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(resolved) != "ok.example\n" || string(failed) != "fail.example\n" {
		t.Fatalf("unexpected logs %q %q", resolved, failed)
	}
}

func TestToolsDesyncMDigNoLogFileByDefault(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	resolver := &cliMockResolver{answer: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	if _, _, err := executeDesyncCommand(t, newToolsDesyncMDigCommand(resolver), []byte("ok.example\n"), "--family", "4"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("unexpected files created: %v", entries)
	}
}

func TestToolsDesyncMDigFlagErrors(t *testing.T) {
	t.Parallel()
	resolver := &cliMockResolver{answer: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	cases := [][]string{
		{"--threads", "101"},
		{"--threads", "0"},
		{"--eagain", "0"},
		{"--eagain", "1001"},
		{"--eagain-delay", "-1"},
		{"--family", "5"},
		{"--stats", "-1"},
	}
	for _, args := range cases {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			_, _, err := executeDesyncCommand(t, newToolsDesyncMDigCommand(resolver), []byte("1.2.3.4\n"), args...)
			if err == nil {
				t.Fatalf("expected an error for %v", args)
			}
		})
	}
}

func TestToolsDesyncListNormalize(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "provider.txt")
	excludePath := filepath.Join(directory, "exclude.txt")
	outputPath := filepath.Join(directory, "list.txt")
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(inputPath, []byte("# synthetic\nExample.COM.\nsub.example.org\n*.invalid.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excludePath, []byte("sub.example.org\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", inputPath, "--output", outputPath, "--exclude", excludePath, "--manifest", manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "example.com\n" {
		t.Fatalf("unexpected output %q", output)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest tools.ListManifest
	if err = json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Format != tools.ListManifestFormat || manifest.Kind != tools.ListKindDomain {
		t.Fatalf("unexpected manifest %+v", manifest)
	}
	if manifest.Source.SHA256 == "" || manifest.Output.SHA256 == "" || manifest.Source.Excluded != 1 || manifest.Output.Entries != 1 {
		t.Fatalf("unexpected manifest provenance %+v", manifest)
	}
	if manifest.Excluded[0].Path != excludePath {
		t.Fatalf("unexpected exclusion provenance %+v", manifest.Excluded)
	}
}

func TestToolsDesyncListNormalizeStdio(t *testing.T) {
	t.Parallel()
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), []byte("192.0.2.1\n10.0.0.0/8\n"), "--kind", "ip", "--manifest", manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "10.0.0.0/8\n192.0.2.1\n" {
		t.Fatalf("unexpected stdout list %q", stdout)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestBytes), `"kind": "ip"`) {
		t.Fatalf("unexpected manifest %s", manifestBytes)
	}
	if !strings.Contains(string(manifestBytes), `"path": "-"`) {
		t.Fatalf("stdin must be recorded as the provenance path: %s", manifestBytes)
	}
}

func TestToolsDesyncListNormalizePathCollisions(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "provider.txt")
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(inputPath, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"--kind", "domain", "--input", inputPath, "--output", inputPath, "--manifest", manifestPath},
		{"--kind", "domain", "--input", inputPath, "--manifest", inputPath},
		{"--kind", "domain", "--input", inputPath, "--manifest", manifestPath, "--exclude", manifestPath, "--output", inputPath},
	}
	for _, args := range cases {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil, args...)
			if err == nil {
				t.Fatalf("expected a path collision error for %v", args)
			}
		})
	}
	if _, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil, "--kind", "domain", "--input", inputPath); err == nil {
		t.Fatal("expected a missing manifest error")
	}
	if _, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil, "--kind", "asn", "--manifest", manifestPath); err == nil {
		t.Fatal("expected an unsupported kind error")
	}
	if _, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil, "--kind", "domain", "--manifest", manifestPath, "--exclude", "-"); err == nil {
		t.Fatal("expected a stdin exclusion error")
	}
}

func TestToolsDesyncListWindowsPathAliases(t *testing.T) {
	t.Parallel()
	// The Windows identity key folds case and the trailing dots/spaces Win32
	// ignores. The same byte-distinct pair must not collide on POSIX.
	aliases := [][2]string{
		{`C:\lists\provider.txt`, `c:\lists\PROVIDER.TXT`},
		{`C:\lists\provider.txt`, `C:\lists\provider.txt.`},
		{`C:\lists\provider.txt`, `C:\lists\provider.txt `},
		{`C:\lists\provider.txt`, `C:/lists/provider.txt`},
	}
	for _, pair := range aliases {
		if err := validateListPathsPlatform(pair[0], pair[1], `C:\lists\manifest.json`, nil, true); err == nil {
			t.Fatalf("windows alias not rejected: %q vs %q", pair[0], pair[1])
		}
		if err := validateListPathsPlatform(pair[0], pair[1], `C:\lists\manifest.json`, nil, false); err != nil {
			t.Fatalf("POSIX paths must stay distinct: %q vs %q: %v", pair[0], pair[1], err)
		}
	}
	if err := validateListPathsPlatform(`C:\lists\provider.txt`, `C:\lists\out.txt`, `C:\lists\manifest.json`, []string{`C:\LISTS\PROVIDER.TXT`}, true); err == nil {
		t.Fatal("windows exclusion alias not rejected")
	}
	if err := validateListPathsPlatform("/tmp/lists/a.txt", "/tmp/lists/a.txt", "/tmp/lists/manifest.json", nil, false); err == nil {
		t.Fatal("identical POSIX paths must still collide")
	}
}

func TestToolsDesyncListNormalizeGzip(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "provider.txt.gz")
	outputPath := filepath.Join(directory, "list.txt")
	manifestPath := filepath.Join(directory, "manifest.json")
	fixture, err := os.ReadFile(filepath.Join("..", "..", "common", "desync", "tools", "testdata", "provider", "provider-synthetic.txt.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(inputPath, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", inputPath, "--output", outputPath, "--manifest", manifestPath); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), "example.com\n") || !strings.Contains(string(output), ".only-subdomains.example\n") {
		t.Fatalf("unexpected output %q", output)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifestBytes), `"compression": "gzip"`) {
		t.Fatalf("unexpected manifest %s", manifestBytes)
	}
}

func TestToolsDesyncBlockcheckReport(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "report.json")
	outputPath := filepath.Join(directory, "normalized.json")
	evidence := `{"artifact":"testdata/blockcheck/synthetic.pcap","sha256":"` + strings.Repeat("b", 64) + `"}`
	document := `{"format":"desync.blockcheck/v1",` +
		`"reference":{"zapret_revision":"` + tools.BlockcheckZapretRevision + `","flowseal_revision":"` + tools.BlockcheckFlowsealRevision + `"},` +
		`"cases":[` +
		`{"id":"b-case","platform":"windows","strategy":"split","status":"SKIP","evidence":null,"reason":"pending VM"},` +
		`{"id":"a-case","platform":"linux","strategy":"fake","status":"PASS","evidence":` + evidence + `,"reason":""}` +
		`]}`
	if err := os.WriteFile(inputPath, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeDesyncCommand(t, newToolsDesyncBlockcheckReportCommand(), nil, "--input", inputPath, "--output", outputPath); err != nil {
		t.Fatal(err)
	}
	output, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(output), `"a-case"`) {
		t.Fatalf("unexpected output %s", output)
	}
	if strings.Index(string(output), `"a-case"`) > strings.Index(string(output), `"b-case"`) {
		t.Fatal("cases are not normalized by platform and id")
	}
	// The normalized document must validate again.
	if _, err = tools.ValidateBlockcheckReport(output); err != nil {
		t.Fatal(err)
	}
	// A PASS without evidence must be rejected through the CLI as well.
	invalid := strings.Replace(document, `"evidence":`+evidence, `"evidence":null`, 1)
	if err = os.WriteFile(inputPath, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = executeDesyncCommand(t, newToolsDesyncBlockcheckReportCommand(), nil, "--input", inputPath); err == nil {
		t.Fatal("expected a PASS without evidence error")
	}
}

func TestToolsDesyncOutputSymlinkRefused(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := filepath.Join(directory, "target.txt")
	link := filepath.Join(directory, "link.txt")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	_, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), []byte("1.2.3.4\n"), "--output", link)
	if err == nil {
		t.Fatal("expected a symlink refusal")
	}
	content, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(content) != "keep\n" {
		t.Fatalf("the symlink target was modified: %q", content)
	}
}

func TestToolsDesyncRunsWithoutConfiguration(t *testing.T) {
	// Not parallel: it changes the process environment to prove the command
	// does not read a configuration or create client state.
	directory := t.TempDir()
	t.Setenv("HOME", directory)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(directory, "config"))
	t.Setenv("XDG_CACHE_HOME", filepath.Join(directory, "cache"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(directory, "data"))
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(directory, "runtime"))
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), []byte("1.2.3.4\n"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "1.2.3.4\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "config" && entry.Name() != "cache" && entry.Name() != "data" && entry.Name() != "runtime" {
			t.Fatalf("unexpected state created: %s", entry.Name())
		}
	}
}

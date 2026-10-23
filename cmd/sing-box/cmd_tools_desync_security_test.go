package main

// Security regressions for frozen v3 tree 09499e10, task t_cd90c243.
// Run only as hermetic Go tests in an isolated snapshot. No product or network.
// Imported permanently and formatted; every assertion is unchanged.
import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func secWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func secRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSecurityListAliasesPreserveInputs(t *testing.T) {
	for _, mode := range []string{"same-name-control", "hardlink-input-output", "symlink-input-output", "parent-symlink-input-output", "hardlink-exclude-output", "hardlink-output-manifest", "hardlink-input-manifest"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			input, output, manifest := filepath.Join(d, "provider.txt"), filepath.Join(d, "output.txt"), filepath.Join(d, "manifest.json")
			const provider = "blocked.example\nkeep.example\n"
			secWrite(t, input, provider)
			var extra []string
			switch mode {
			case "same-name-control":
				output = input
			case "hardlink-input-output":
				if err := os.Link(input, output); err != nil {
					t.Fatal(err)
				}
			case "symlink-input-output":
				secWrite(t, output, provider)
				input = filepath.Join(d, "provider-link.txt")
				if err := os.Symlink(output, input); err != nil {
					t.Fatal(err)
				}
			case "parent-symlink-input-output":
				alias := filepath.Join(d, "alias")
				if err := os.Symlink(d, alias); err != nil {
					t.Fatal(err)
				}
				output = filepath.Join(alias, "provider.txt")
			case "hardlink-exclude-output":
				exclude := filepath.Join(d, "exclude.txt")
				secWrite(t, exclude, "blocked.example\n")
				if err := os.Link(exclude, output); err != nil {
					t.Fatal(err)
				}
				extra = []string{"--exclude", exclude}
			case "hardlink-output-manifest":
				secWrite(t, output, "OLD-OUTPUT\n")
				if err := os.Link(output, manifest); err != nil {
					t.Fatal(err)
				}
			case "hardlink-input-manifest":
				if err := os.Link(input, manifest); err != nil {
					t.Fatal(err)
				}
			}
			beforeInput := secRead(t, input)
			var beforeOutput string
			if _, err := os.Stat(output); err == nil {
				beforeOutput = secRead(t, output)
			}
			args := []string{"--kind", "domain", "--input", input, "--output", output, "--manifest", manifest}
			args = append(args, extra...)
			_, _, runErr := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil, args...)
			afterInput := secRead(t, input)
			afterOutput := ""
			if _, err := os.Stat(output); err == nil {
				afterOutput = secRead(t, output)
			}
			t.Logf("security: mode=%s err=%v input_preserved=%t output_before=%q output_after=%q", mode, runErr, afterInput == beforeInput, beforeOutput, afterOutput)
			if runErr == nil {
				t.Error("colliding filesystem identities accepted")
			}
			if afterInput != beforeInput {
				t.Error("input was overwritten via an alias")
			}
			if afterOutput != beforeOutput {
				t.Error("colliding output was modified before rejection")
			}
			if len(extra) > 0 && secRead(t, extra[1]) != "blocked.example\n" {
				t.Error("exclusion input was overwritten and its filtering bypassed")
			}
		})
	}
}

func TestSecurityListRejectBeforeOutputMutation(t *testing.T) {
	for _, mode := range []string{"invalid-gzip", "bad-gzip-crc", "oversized-line", "manifest-symlink", "manifest-directory", "manifest-missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			output := filepath.Join(d, "out.txt")
			manifest := filepath.Join(d, "manifest.json")
			const keep = "last-good.example\n"
			secWrite(t, output, keep)
			input := []byte("new.example\n")
			switch mode {
			case "invalid-gzip":
				input = []byte{0x1f, 0x8b, 0, 0}
			case "bad-gzip-crc":
				var b bytes.Buffer
				gz := gzip.NewWriter(&b)
				_, err := gz.Write(input)
				if err != nil {
					t.Fatal(err)
				}
				if err = gz.Close(); err != nil {
					t.Fatal(err)
				}
				input = append([]byte(nil), b.Bytes()...)
				input[len(input)-8] ^= 1
			case "oversized-line":
				input = []byte(strings.Repeat("a", 8193) + "\n")
			case "manifest-symlink":
				target := filepath.Join(d, "target.json")
				secWrite(t, target, "keep-manifest\n")
				if err := os.Symlink(target, manifest); err != nil {
					t.Fatal(err)
				}
			case "manifest-directory":
				if err := os.Mkdir(manifest, 0700); err != nil {
					t.Fatal(err)
				}
			case "manifest-missing-parent":
				manifest = filepath.Join(d, "absent", "manifest.json")
			}
			_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), input, "--kind", "domain", "--output", output, "--manifest", manifest)
			got := secRead(t, output)
			t.Logf("security: mode=%s err=%v output_after=%q", mode, err, got)
			if err == nil {
				t.Error("expected rejection")
			}
			if got != keep {
				t.Error("rejected run modified the last-good operator output")
			}
		})
	}
}

func TestSecurityInvalidFlagsPreserveExistingOutput(t *testing.T) {
	for _, mode := range []string{"q1-control", "prefix-too-large", "mdig-delay-too-large", "mdig-negative-stats"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			output := filepath.Join(d, "out.txt")
			secWrite(t, output, "KEEP\n")
			cmd := newToolsDesyncIP2NetCommand()
			args := []string{"--v4-threshold", "0/0"}
			switch mode {
			case "prefix-too-large":
				args = []string{"--family", "4", "--prefix-length", "32"}
			case "mdig-delay-too-large":
				cmd = newToolsDesyncMDigCommand(&cliMockResolver{})
				args = []string{"--eagain-delay", "100001"}
			case "mdig-negative-stats":
				cmd = newToolsDesyncMDigCommand(&cliMockResolver{})
				args = []string{"--stats", "-1"}
			}
			args = append(args, "--output", output)
			_, _, err := executeDesyncCommand(t, cmd, []byte("192.0.2.1\n"), args...)
			got := secRead(t, output)
			t.Logf("security: mode=%s err=%v output_after=%q", mode, err, got)
			if err == nil {
				t.Error("invalid flags accepted")
			}
			if got != "KEEP\n" {
				t.Error("rejected flags truncated existing output")
			}
		})
	}
}

func TestSecurityStreamingPathCollisions(t *testing.T) {
	for _, mode := range []string{"ip2net-input-output", "mdig-input-output", "mdig-input-log", "mdig-output-log"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			input := filepath.Join(d, "in.txt")
			output := filepath.Join(d, "out.txt")
			secWrite(t, input, "192.0.2.1\n")
			cmd := newToolsDesyncIP2NetCommand()
			args := []string{"--input", input}
			switch mode {
			case "ip2net-input-output":
				args = append(args, "--output", input)
			case "mdig-input-output":
				cmd = newToolsDesyncMDigCommand(&cliMockResolver{})
				args = append(args, "--output", input)
			case "mdig-input-log":
				cmd = newToolsDesyncMDigCommand(&cliMockResolver{})
				args = append(args, "--log-resolved", input, "--output", output)
			case "mdig-output-log":
				cmd = newToolsDesyncMDigCommand(&cliMockResolver{})
				args = append(args, "--output", output, "--log-resolved", output)
			}
			_, _, err := executeDesyncCommand(t, cmd, nil, args...)
			got := secRead(t, input)
			t.Logf("security: mode=%s err=%v input_after=%q", mode, err, got)
			if err == nil {
				t.Error("colliding stream roles accepted")
			}
			if got != "192.0.2.1\n" {
				t.Error("input was truncated")
			}
		})
	}
}

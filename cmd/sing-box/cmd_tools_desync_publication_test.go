package main

// Publication regressions for the list-normalize staging path (security finding
// S2): rejected imports leave an existing last-good output and manifest alone,
// new output is not created, distinct successful outputs and manifests are
// published with matching hashes, and no staged temporary files remain.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/desync/tools"
)

func writePublicationFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readPublicationFile(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func assertNoStagedFiles(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".*.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("staged temporary files were left behind: %v", matches)
	}
}

// TestToolsDesyncListStagedPublication runs the real command twice: the second
// run must replace both files with the new content and a manifest whose output
// hash matches the published list.
func TestToolsDesyncListStagedPublication(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "provider.txt")
	output := filepath.Join(directory, "normalized.txt")
	manifestPath := filepath.Join(directory, "manifest.json")
	writePublicationFile(t, input, []byte("b.example\nA.example\n\n"))
	writePublicationFile(t, output, []byte("last-good.example\n"))
	writePublicationFile(t, manifestPath, []byte("{\"format\":\"old\"}\n"))
	_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", input, "--output", output, "--manifest", manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(readPublicationFile(t, output)); got != "a.example\nb.example\n" {
		t.Fatalf("unexpected normalized output %q", got)
	}
	var manifest tools.ListManifest
	if err = json.Unmarshal(readPublicationFile(t, manifestPath), &manifest); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(readPublicationFile(t, output))
	if manifest.Output.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("manifest output hash %q does not match the published file", manifest.Output.SHA256)
	}
	if manifest.Output.Entries != 2 || manifest.Output.Size != int64(len("a.example\nb.example\n")) {
		t.Fatalf("unexpected manifest output counts: %+v", manifest.Output)
	}
	if manifest.Kind != tools.ListKindDomain || manifest.Source.Accepted != 2 {
		t.Fatalf("unexpected manifest metadata: %+v", manifest)
	}
	assertNoStagedFiles(t, directory)
}

// TestToolsDesyncListRejectedImportCreatesNothing feeds an invalid gzip header
// and requires that neither the absent output nor the absent manifest is
// created.
func TestToolsDesyncListRejectedImportCreatesNothing(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "provider.txt")
	writePublicationFile(t, input, []byte{0x1f, 0x8b, 0x00, 0x00})
	output := filepath.Join(directory, "normalized.txt")
	manifestPath := filepath.Join(directory, "manifest.json")
	_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", input, "--output", output, "--manifest", manifestPath)
	if err == nil {
		t.Fatal("invalid gzip was accepted")
	}
	for _, path := range []string{output, manifestPath} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("rejected import created %s", path)
		}
	}
	assertNoStagedFiles(t, directory)
}

// TestToolsDesyncListStdoutBoundary documents the streaming boundary: stdout
// receives the normalized list, the manifest is still staged and published, and
// there is no rollback promise for a partial stdout write.
func TestToolsDesyncListStdoutBoundary(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "provider.txt")
	writePublicationFile(t, input, []byte("x.example\n"))
	manifestPath := filepath.Join(directory, "manifest.json")
	stdout, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", input, "--output", "-", "--manifest", manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "x.example\n" {
		t.Fatalf("unexpected stdout %q", stdout)
	}
	var manifest tools.ListManifest
	if err = json.Unmarshal(readPublicationFile(t, manifestPath), &manifest); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(stdout))
	if manifest.Output.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("stdout manifest hash mismatch: %q", manifest.Output.SHA256)
	}
	assertNoStagedFiles(t, directory)
}

// TestToolsDesyncListManifestDestinationGuarded requires both destination
// failures (a directory and a missing parent) to be rejected before the existing
// output or an existing manifest target is touched.
func TestToolsDesyncListManifestDestinationGuarded(t *testing.T) {
	for _, mode := range []string{"manifest-directory", "manifest-missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			input := filepath.Join(directory, "provider.txt")
			writePublicationFile(t, input, []byte("new.example\n"))
			output := filepath.Join(directory, "normalized.txt")
			writePublicationFile(t, output, []byte("last-good.example\n"))
			manifestPath := filepath.Join(directory, "manifest.json")
			writePublicationFile(t, manifestPath, []byte("keep-manifest\n"))
			switch mode {
			case "manifest-directory":
				if err := os.Remove(manifestPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(manifestPath, 0o700); err != nil {
					t.Fatal(err)
				}
			case "manifest-missing-parent":
				manifestPath = filepath.Join(directory, "absent", "manifest.json")
			}
			_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
				"--kind", "domain", "--input", input, "--output", output, "--manifest", manifestPath)
			if err == nil {
				t.Fatal("invalid manifest destination was accepted")
			}
			if got := string(readPublicationFile(t, output)); got != "last-good.example\n" {
				t.Fatalf("output changed before rejection: %q", got)
			}
			if mode == "manifest-directory" {
				info, statErr := os.Stat(manifestPath)
				if statErr != nil || !info.IsDir() {
					t.Fatalf("manifest directory was replaced: %v", statErr)
				}
			}
			assertNoStagedFiles(t, directory)
		})
	}
}

// TestToolsDesyncListOutputSymlinkRefused keeps the static output-symlink
// refusal of the previous contract while staging the replacement.
func TestToolsDesyncListOutputSymlinkRefused(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "provider.txt")
	target := filepath.Join(directory, "target.txt")
	writePublicationFile(t, input, []byte("a.example\n"))
	writePublicationFile(t, target, []byte("target-content\n"))
	output := filepath.Join(directory, "normalized.txt")
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), nil,
		"--kind", "domain", "--input", input, "--output", output, "--manifest", manifestPath)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("output symlink was not refused: %v", err)
	}
	if got := string(readPublicationFile(t, target)); got != "target-content\n" {
		t.Fatalf("symlink target changed: %q", got)
	}
	if _, statErr := os.Lstat(output); statErr != nil {
		t.Fatalf("output symlink disappeared: %v", statErr)
	}
	if _, statErr := os.Stat(manifestPath); !os.IsNotExist(statErr) {
		t.Fatal("manifest was created although the output was refused")
	}
	assertNoStagedFiles(t, directory)
}

//go:build !windows

package main

// Submission 5 security regressions for task t_fbff0c77.
//
// Provenance: the six symlink/".." cases and the distinct-publication control
// are imported from the independent security regression
// desync-artifacts/t_bd2c8f83-security_v4_cmd_test.go (t_bd2c8f83, evidence
// archive SHA256 e52e8f3fccb5a48db72e810c07a417c8ca5db4fd8cc5f58e47d8bd269c80cf18),
// which failed on the rejected v4 tree 10f18918. Assertions are strengthened to
// require the new explicit ambiguous-path refusal; no timing or scheduler
// coverage is used. The ordinary ".." control was added locally.
import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func securityV5RequireAmbiguousRejection(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Error("aliased output/manifest destination was accepted")
		return
	}
	if !strings.Contains(err.Error(), "ambiguous path") {
		t.Errorf("expected an explicit ambiguous-path refusal, got: %v", err)
	}
}

// TestSecurityV5SymlinkDotDotPublicationCollision covers the six independently
// reproduced cases: an output/manifest pair where one role uses raw
// "<dir>/link/../name" and the other the real target, with an absent and an
// existing destination and both role orderings. ".." after the symbolic link is
// resolved by the kernel to the real directory, while lexical cleaning names a
// different file, so the pair must be rejected before any destination changes.
func TestSecurityV5SymlinkDotDotPublicationCollision(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, rawRole := range []string{"manifest", "output"} {
			name := rawRole + "-absent"
			if existing {
				name = rawRole + "-existing"
			}
			t.Run(name, func(t *testing.T) {
				d := t.TempDir()
				logical := filepath.Join(d, "logical")
				real := filepath.Join(d, "real")
				child := filepath.Join(real, "child")
				for _, dir := range []string{logical, child} {
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(child, filepath.Join(logical, "link")); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(real, "published.txt")
				// Raw spelling, deliberately not filepath.Join.
				raw := logical + "/link/../published.txt"
				const keep = "LAST-GOOD\n"
				if existing {
					secWrite(t, target, keep)
					a, err := os.Stat(target)
					if err != nil {
						t.Fatal(err)
					}
					b, err := os.Stat(raw)
					if err != nil {
						t.Fatal(err)
					}
					if !os.SameFile(a, b) {
						t.Fatal("fixture does not alias")
					}
				}
				output, manifest := target, raw
				if rawRole == "output" {
					output, manifest = raw, target
				}
				_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), []byte("safe.example\n"),
					"--kind", "domain", "--output", output, "--manifest", manifest)
				t.Logf("raw_role=%s existing=%v err=%v", rawRole, existing, err)
				securityV5RequireAmbiguousRejection(t, err)
				if existing {
					if got := secRead(t, target); got != keep {
						t.Errorf("colliding publication overwrote last-good target: %q", got)
					}
				} else if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
					t.Error("rejected aliased output/manifest must not create the destination")
				}
			})
		}
	}
}

// TestSecurityV5DotDotStreamingLogCollision covers both role orderings of the
// mdig output/failed-log pair. v4 rejected the pair only after opening and
// truncating the first destination, so the last-good bytes were destroyed while
// an error was returned. The collision must now be refused before any mutation.
func TestSecurityV5DotDotStreamingLogCollision(t *testing.T) {
	for _, rawRole := range []string{"output", "failed-log"} {
		t.Run(rawRole, func(t *testing.T) {
			d := t.TempDir()
			logical := filepath.Join(d, "logical")
			child := filepath.Join(d, "real", "child")
			for _, dir := range []string{logical, child} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(child, filepath.Join(logical, "link")); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(d, "real", "result")
			raw := logical + "/link/../result"
			secWrite(t, target, "LAST-GOOD\n")
			output, log := target, raw
			if rawRole == "output" {
				output, log = raw, target
			}
			_, _, err := executeDesyncCommand(t, newToolsDesyncMDigCommand(&cliMockResolver{}), []byte("192.0.2.1\n"), "--output", output, "--log-failed", log)
			t.Logf("raw_role=%s err=%v last_good_preserved=%v", rawRole, err, secRead(t, target) == "LAST-GOOD\n")
			securityV5RequireAmbiguousRejection(t, err)
			if got := secRead(t, target); got != "LAST-GOOD\n" {
				t.Error("colliding output/log was truncated before rejection")
			}
		})
	}
}

// TestSecurityV5DistinctPublicationControl is the positive control for the R1
// matrix: two ordinary distinct destinations must still publish successfully.
func TestSecurityV5DistinctPublicationControl(t *testing.T) {
	d := t.TempDir()
	out := filepath.Join(d, "out")
	manifest := filepath.Join(d, "manifest")
	_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), []byte("Safe.Example\n"), "--kind", "domain", "--output", out, "--manifest", manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got := secRead(t, out); got != "safe.example\n" {
		t.Fatalf("output %q", got)
	}
	if !strings.Contains(secRead(t, manifest), "desync.list-manifest/v1") {
		t.Fatal("missing manifest")
	}
}

// TestSecurityV5OrdinaryDotDotControl proves the rejection is limited to ".."
// resolved through a symbolic link: an ordinary ".." behind a real directory
// keeps its usual meaning and must still publish.
func TestSecurityV5OrdinaryDotDotControl(t *testing.T) {
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(d, "out")
	manifest := d + "/sub/../manifest.json"
	_, _, err := executeDesyncCommand(t, newToolsDesyncListNormalizeCommand(), []byte("Safe.Example\n"), "--kind", "domain", "--output", out, "--manifest", manifest)
	if err != nil {
		t.Fatalf("ordinary '..' after a real directory must keep its OS meaning: %v", err)
	}
	if got := secRead(t, out); got != "safe.example\n" {
		t.Fatalf("output %q", got)
	}
	if !strings.Contains(secRead(t, filepath.Join(d, "manifest.json")), "desync.list-manifest/v1") {
		t.Fatal("manifest not published at the OS-resolved path")
	}
}

//go:build !windows

package main

// Submission 5 no-follow regressions for task t_fbff0c77, Unix side.
//
// The deterministic pre-open replacement window is exercised through the
// minimal production seam toolBeforeOutputOpen (no-op in production). The same
// seam is used by the independent security check from t_bd2c8f83; the native
// Windows reparse/handle behavior has a separate test file that must SKIP when
// the account cannot create links.
import (
	"os"
	"path/filepath"
	"testing"
)

// TestSecurityV5OutputOpenNormalControl keeps the ordinary path working: an
// existing regular file is opened and truncated only through the checked
// descriptor.
func TestSecurityV5OutputOpenNormalControl(t *testing.T) {
	d := t.TempDir()
	output := filepath.Join(d, "output")
	securityV5Write(t, output, "OLD\n")
	calls := 0
	toolBeforeOutputOpen = func(path string) {
		calls++
		if path != output {
			t.Errorf("unexpected seam path %q", path)
		}
	}
	t.Cleanup(func() { toolBeforeOutputOpen = func(string) {} })
	file, err := createToolFile(output, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteString("NEW\n"); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("seam calls=%d", calls)
	}
	if got := securityV5Read(t, output); got != "NEW\n" {
		t.Fatalf("output %q", got)
	}
}

// TestSecurityV5OutputOpenStaticSymlinkControl keeps the pre-existing refusal:
// a static final-component symlink is rejected before the acquisition seam and
// its target is never opened or truncated.
func TestSecurityV5OutputOpenStaticSymlinkControl(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "target")
	output := filepath.Join(d, "output")
	securityV5Write(t, target, "UNRELATED-TARGET\n")
	if err := os.Symlink(target, output); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	calls := 0
	toolBeforeOutputOpen = func(string) { calls++ }
	t.Cleanup(func() { toolBeforeOutputOpen = func(string) {} })
	file, err := createToolFile(output, nil)
	if file != nil {
		_ = file.Close()
	}
	if err == nil {
		t.Fatal("static symlink output was accepted")
	}
	if calls != 0 {
		t.Fatalf("static symlink must be refused before the acquisition seam, calls=%d", calls)
	}
	if got := securityV5Read(t, target); got != "UNRELATED-TARGET\n" {
		t.Fatalf("symlink target changed: %q", got)
	}
}

// TestSecurityV5OutputOpenHardlinkControl keeps the descriptor identity check:
// an output hard-linked to an open input is refused before truncation.
func TestSecurityV5OutputOpenHardlinkControl(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "input")
	output := filepath.Join(d, "output")
	securityV5Write(t, input, "INPUT\n")
	securityV5Write(t, output, "OLD\n")
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(input, output); err != nil {
		t.Skipf("hard links unsupported: %v", err)
	}
	file, err := createToolFile(output, securityV5OpenInput(t, input))
	if file != nil {
		_ = file.Close()
	}
	if err == nil {
		t.Fatal("hard link to the input was accepted")
	}
	if got := securityV5Read(t, input); got != "INPUT\n" {
		t.Fatalf("input changed: %q", got)
	}
}

// TestSecurityV5OutputOpenReplacement swaps the final entry for a symlink in
// the deterministic window between the cheap inspection and the open. The
// acquired object must be refused and the unrelated target preserved.
func TestSecurityV5OutputOpenReplacement(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "input")
	output := filepath.Join(d, "output")
	other := filepath.Join(d, "other")
	securityV5Write(t, input, "INPUT\n")
	securityV5Write(t, output, "OLD\n")
	securityV5Write(t, other, "UNRELATED-TARGET\n")
	calls := 0
	toolBeforeOutputOpen = func(path string) {
		calls++
		if path != output {
			t.Errorf("unexpected seam path %q", path)
		}
		if err := os.Rename(output, filepath.Join(d, "old-output")); err != nil {
			t.Errorf("park old output: %v", err)
			return
		}
		if err := os.Symlink(other, output); err != nil {
			t.Errorf("install replacement symlink: %v", err)
		}
	}
	t.Cleanup(func() { toolBeforeOutputOpen = func(string) {} })
	file, err := createToolFile(output, securityV5OpenInput(t, input))
	if file != nil {
		_ = file.Close()
	}
	if calls != 1 {
		t.Fatalf("seam calls=%d", calls)
	}
	if err == nil {
		t.Error("final-component symlink installed after Lstat was followed")
	}
	if got := securityV5Read(t, other); got != "UNRELATED-TARGET\n" {
		t.Errorf("unrelated target changed: %q", got)
	}
	if got := securityV5Read(t, input); got != "INPUT\n" {
		t.Errorf("input changed: %q", got)
	}
	if got := securityV5Read(t, filepath.Join(d, "old-output")); got != "OLD\n" {
		t.Errorf("parked output changed: %q", got)
	}
}

// TestSecurityV5OutputOpenHardlinkReplacement installs a hard link to the open
// input in the same window. O_NOFOLLOW does not help here, so the descriptor
// identity check must refuse the acquired object before any truncation.
func TestSecurityV5OutputOpenHardlinkReplacement(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "input")
	output := filepath.Join(d, "output")
	securityV5Write(t, input, "INPUT\n")
	securityV5Write(t, output, "OLD\n")
	calls := 0
	toolBeforeOutputOpen = func(path string) {
		calls++
		if path != output {
			t.Errorf("unexpected seam path %q", path)
		}
		if err := os.Remove(output); err != nil {
			t.Errorf("remove output: %v", err)
			return
		}
		if err := os.Link(input, output); err != nil {
			t.Errorf("install replacement hard link: %v", err)
		}
	}
	t.Cleanup(func() { toolBeforeOutputOpen = func(string) {} })
	file, err := createToolFile(output, securityV5OpenInput(t, input))
	if file != nil {
		_ = file.Close()
	}
	if calls != 1 {
		t.Fatalf("seam calls=%d", calls)
	}
	if err == nil {
		t.Error("input hard link installed after the descriptor check was accepted")
	}
	if got := securityV5Read(t, input); got != "INPUT\n" {
		t.Errorf("input changed: %q", got)
	}
}

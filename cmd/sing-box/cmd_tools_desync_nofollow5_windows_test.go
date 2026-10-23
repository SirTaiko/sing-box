//go:build windows

package main

// Native Windows controls for task t_fbff0c77 S1-R2.
//
// These tests are compiled on every Windows test build but are expected to
// SKIP when the account cannot create the link/reparse entry or is not running
// on NTFS. They do not infer native behavior from Linux or from a cross-build:
// a SKIP here is an explicit native evidence gap, never a PASS.
import (
	"os"
	"path/filepath"
	"testing"
)

func securityV5WindowsCanCreateLink(t *testing.T, target string, link string) bool {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Logf("native symlink creation unavailable: %v", err)
		return false
	}
	return true
}

func TestSecurityV5WindowsOutputOpenControls(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "input")
	expected := filepath.Join(d, "expected")
	output := filepath.Join(d, "output")
	secWrite(t, input, "INPUT\n")
	secWrite(t, expected, "UNRELATED-TARGET\n")

	// Ordinary regular output still opens and truncates through the acquired
	// handle.
	secWrite(t, output, "OLD\n")
	file, err := createToolFile(output, nil)
	if err != nil {
		t.Fatalf("ordinary regular output rejected: %v", err)
	}
	if _, err = file.WriteString("NEW\n"); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := secRead(t, output); got != "NEW\n" {
		t.Fatalf("ordinary output %q", got)
	}

	// A static final-component reparse point must be refused and its target
	// preserved.
	if err = os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if !securityV5WindowsCanCreateLink(t, expected, output) {
		t.Skip("native symlink creation unavailable; reparse-point controls SKIP")
	}
	file, err = createToolFile(output, nil)
	if file != nil {
		_ = file.Close()
	}
	if err == nil {
		t.Error("static reparse point output was accepted")
	}
	if got := secRead(t, expected); got != "UNRELATED-TARGET\n" {
		t.Errorf("reparse target changed: %q", got)
	}
}

func TestSecurityV5WindowsOutputOpenPreOpenReplacement(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "input")
	other := filepath.Join(d, "other")
	output := filepath.Join(d, "output")
	secWrite(t, input, "INPUT\n")
	secWrite(t, other, "UNRELATED-TARGET\n")
	secWrite(t, output, "OLD\n")
	replacement := filepath.Join(d, "replacement")
	if !securityV5WindowsCanCreateLink(t, other, replacement) {
		t.Skip("native symlink creation unavailable; pre-open reparse control SKIP")
	}
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
		if err := os.Rename(replacement, output); err != nil {
			t.Errorf("install replacement reparse point: %v", err)
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
		t.Error("reparse point installed after Lstat was followed")
	}
	if got := secRead(t, other); got != "UNRELATED-TARGET\n" {
		t.Errorf("unrelated target changed: %q", got)
	}
	if got := secRead(t, input); got != "INPUT\n" {
		t.Errorf("input changed: %q", got)
	}
}

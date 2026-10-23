package main

// Permanent regression for the QA v2 Q1 finding (tasks t_be788118 / t_f7bf08bd):
// an explicit --v4-threshold pair outside the documented range must be rejected
// by the flag parser instead of being silently replaced by the 3/4 default.
// The library zero value keeps meaning "use the default"; only the command
// flags require an explicit pair to be valid, before any file is opened.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolsDesyncIP2NetExplicitV4ThresholdValidation(t *testing.T) {
	t.Parallel()
	input := []byte("192.0.2.0\n192.0.2.1\n192.0.2.2\n192.0.2.3\n")
	// Every explicit pair outside 1 <= mul < div, div >= 2 must fail. The
	// zero spellings are the Q1 reproducer: the decimal parser accepts "00"
	// and "000", so the rejection must use the parsed value instead of the
	// textual spelling.
	invalid := [][]string{
		{"--v4-threshold", "0/0"},
		{"--v4-threshold", "00/000"},
		{"--v4-threshold", "0/000"},
		{"--v4-threshold", "0/2"},
		{"--v4-threshold", "1/0"},
		{"--v4-threshold", "1/1"},
		{"--v4-threshold", "3/3"},
		{"--v4-threshold", "4/3"},
		{"--v4-threshold", "2/1"},
		{"--v4-threshold", "4294967295/4294967295"},
		{"--v4-threshold", "4294967296/4294967297"},
		{"--v4-threshold", "-1/2"},
		{"--v4-threshold", "+1/2"},
		{"--v4-threshold", "3/4x"},
		{"--v4-threshold", "1/2/3"},
		{"--v4-threshold", " 0 / 0 "},
	}
	for _, args := range invalid {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			stdout, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), input, args...)
			if err == nil {
				t.Fatalf("explicit %v must be rejected, got output %q", args, stdout)
			}
			if stdout != "" {
				t.Fatalf("rejected threshold %v must produce no output, got %q", args, stdout)
			}
			if !strings.Contains(err.Error(), "1 <= mul < div") || !strings.Contains(err.Error(), "div >= 2") {
				t.Fatalf("error for %v is not actionable: %v", args, err)
			}
		})
	}
	// The rejection is a flag error: no output file may be created or
	// truncated before the validation fails.
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "out.txt")
	if _, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), input,
		"--v4-threshold", "0/0", "--output", outputPath); err == nil {
		t.Fatal("0/0 with an output path must be rejected")
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("rejected run must not create the output file: %v", err)
	}
	// Valid explicit pairs keep working across the documented range; the
	// omitted flag still applies the 3/4 default.
	valid := []struct {
		args   []string
		output string
	}{
		{nil, "192.0.2.0/30\n"},
		{[]string{"--v4-threshold", "3/4"}, "192.0.2.0/30\n"},
		{[]string{"--v4-threshold", "1/2"}, "192.0.2.0/30\n"},
		{[]string{"--v4-threshold", " 1 / 2 "}, "192.0.2.0/30\n"},
		{[]string{"--v4-threshold", "4294967294/4294967295"}, "192.0.2.0/30\n"},
	}
	for _, testCase := range valid {
		stdout, _, err := executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), input, testCase.args...)
		if err != nil {
			t.Fatalf("valid threshold %v rejected: %v", testCase.args, err)
		}
		if stdout != testCase.output {
			t.Fatalf("threshold %v: got %q want %q", testCase.args, stdout, testCase.output)
		}
	}
}

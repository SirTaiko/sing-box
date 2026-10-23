package main

// QA v3 independent command-surface tests (tester-max-3, task t_f340c660):
// Q1 repair verification with contrasts stronger than the writer's regression.
// Imported unchanged (formatting only) as a permanent regression for the
// explicit-threshold and existing-output acceptance criteria. No product binary,
// client, config or network is used.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func qaV3RunIP2Net(t *testing.T, input []byte, args ...string) (string, string, error) {
	t.Helper()
	return executeDesyncCommand(t, newToolsDesyncIP2NetCommand(), input, args...)
}

// TestQAV3IP2NetThresholdRejectedBeforeSideEffects pins the Q1 acceptance
// criterion: an explicit pair outside 1 <= mul < div, div >= 2 must be a flag
// error that happens before any input or output stream is opened, so nothing is
// written to stdout, no output file is created and an existing output file is
// not truncated.
func TestQAV3IP2NetThresholdRejectedBeforeSideEffects(t *testing.T) {
	t.Parallel()
	input := []byte("192.0.2.0\n192.0.2.1\n192.0.2.2\n192.0.2.3\n")
	invalid := []string{
		// zero spellings: rejection must use the parsed value, not the text
		"0/0", "00/000", "0/000", "000/0", " 0 / 0 ", "0 / 0", "\t0/0",
		// zero on one side
		"0/2", "0/1", "2/0", "1/0",
		// mul >= div
		"1/1", "2/2", "3/3", "4/3", "2/1", "4294967295/4294967295",
		// out of uint32 range
		"4294967296/1", "1/4294967296", "4294967296/4294967297",
		// spelling/format rejections
		"-1/2", "+1/2", "3/4x", "1/2/3", "0x0/0x1", "1.0/2",
		"", "/", "1/", "/2", "0", "3", "1", "1/ 2/",
	}
	for _, value := range invalid {
		value := value
		t.Run("reject_"+strings.ReplaceAll(value, "\t", "TAB"), func(t *testing.T) {
			t.Parallel()
			stdout, _, err := qaV3RunIP2Net(t, input, "--v4-threshold", value)
			if err == nil {
				t.Fatalf("--v4-threshold %q must be rejected, got stdout %q", value, stdout)
			}
			if stdout != "" {
				t.Fatalf("--v4-threshold %q must not write stdout, got %q", value, stdout)
			}
			if !strings.Contains(err.Error(), "--v4-threshold") {
				t.Fatalf("--v4-threshold %q: error does not name the flag: %v", value, err)
			}
		})
	}

	t.Run("no_truncate_of_existing_output", func(t *testing.T) {
		t.Parallel()
		directory := t.TempDir()
		outputPath := filepath.Join(directory, "existing.txt")
		const keep = "KEEP-ME\nsecond line\n"
		if err := os.WriteFile(outputPath, []byte(keep), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, runErr := qaV3RunIP2Net(t, input, "--v4-threshold", "0/0", "--output", outputPath)
		content, err := os.ReadFile(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != keep {
			t.Fatalf("rejected run truncated/overwrote the existing output: %q (flag error: %v)", content, runErr)
		}
		if runErr == nil {
			t.Fatal("0/0 with an existing output path must be rejected")
		}
	})

	t.Run("no_create_of_new_output", func(t *testing.T) {
		t.Parallel()
		directory := t.TempDir()
		outputPath := filepath.Join(directory, "absent.txt")
		if _, _, err := qaV3RunIP2Net(t, input, "--v4-threshold", "0/0", "--output", outputPath); err == nil {
			t.Fatal("0/0 with an output path must be rejected")
		}
		if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
			t.Fatalf("rejected run created the output file: %v", err)
		}
	})

	// The threshold must be validated before the input is opened: with a
	// missing input file the reported error is the threshold, not the input.
	t.Run("validated_before_input_open", func(t *testing.T) {
		t.Parallel()
		directory := t.TempDir()
		missingInput := filepath.Join(directory, "does-not-exist.txt")
		_, _, err := qaV3RunIP2Net(t, input, "--v4-threshold", "0/0", "--input", missingInput)
		if err == nil {
			t.Fatal("0/0 must be rejected")
		}
		if !strings.Contains(err.Error(), "--v4-threshold") {
			t.Fatalf("threshold error must precede the input open, got: %v", err)
		}
	})
}

// TestQAV3IP2NetOmittedFlagStillAppliesThreeQuarters proves behaviourally, not
// by reading the flag declaration, that an omitted --v4-threshold applies 3/4:
// the output must equal an explicit 3/4 run and differ from an explicit 1/2 run
// on an input whose density depends on that difference (two addresses in a /30,
// threshold floor(4*3/4)=3 versus floor(4*1/2)=2).
func TestQAV3IP2NetOmittedFlagStillAppliesThreeQuarters(t *testing.T) {
	t.Parallel()
	input := []byte("192.0.2.0\n192.0.2.1\n")
	omitted, _, err := qaV3RunIP2Net(t, input)
	if err != nil {
		t.Fatalf("omitted threshold: %v", err)
	}
	explicit34, _, err := qaV3RunIP2Net(t, input, "--v4-threshold", "3/4")
	if err != nil {
		t.Fatalf("explicit 3/4: %v", err)
	}
	explicit12, _, err := qaV3RunIP2Net(t, input, "--v4-threshold", "1/2")
	if err != nil {
		t.Fatalf("explicit 1/2: %v", err)
	}
	if omitted != explicit34 {
		t.Fatalf("omitted threshold output %q != explicit 3/4 output %q", omitted, explicit34)
	}
	if omitted == explicit12 {
		t.Fatalf("omitted threshold behaves like 1/2 (%q); the input does not distinguish the thresholds", omitted)
	}
	if explicit34 != "192.0.2.0\n192.0.2.1\n" {
		t.Fatalf("3/4 on two addresses in a /30 must stay bare, got %q", explicit34)
	}
	if explicit12 != "192.0.2.0/30\n" {
		t.Fatalf("1/2 on two addresses in a /30 must aggregate, got %q", explicit12)
	}
}

// TestQAV3IP2NetValidThresholdPairsAccepted checks that the new validation did
// not narrow the documented acceptance range, including the uint32 maximum.
func TestQAV3IP2NetValidThresholdPairsAccepted(t *testing.T) {
	t.Parallel()
	four := []byte("192.0.2.0\n192.0.2.1\n192.0.2.2\n192.0.2.3\n")
	pairs := []string{
		"1/2", "2/3", "3/4", "1/4294967295", "4294967294/4294967295",
		" 1 / 2 ", "1/2\n",
	}
	for _, value := range pairs {
		value := value
		t.Run("accept_"+strings.TrimSpace(value), func(t *testing.T) {
			t.Parallel()
			stdout, _, err := qaV3RunIP2Net(t, four, "--v4-threshold", value)
			if err != nil {
				t.Fatalf("valid --v4-threshold %q rejected: %v", value, err)
			}
			if stdout != "192.0.2.0/30\n" {
				t.Fatalf("--v4-threshold %q: unexpected output %q", value, stdout)
			}
		})
	}
}

// TestQAV3IP2NetThresholdErrorIsActionable pins the operator-facing message so
// the rejection is not a silent or opaque failure.
func TestQAV3IP2NetThresholdErrorIsActionable(t *testing.T) {
	t.Parallel()
	_, _, err := qaV3RunIP2Net(t, []byte("192.0.2.0\n"), "--v4-threshold", "0/0")
	if err == nil {
		t.Fatal("0/0 must be rejected")
	}
	message := err.Error()
	for _, want := range []string{"--v4-threshold", "0/0", "1 <= mul < div", "div >= 2"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not mention %q", message, want)
		}
	}
}

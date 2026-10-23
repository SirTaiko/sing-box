package tools

// QA v3 independent library-side tests (tester-max-3, task t_f340c660):
// the Q1 repair is a command-parser boundary only; the library zero-value API
// must keep meaning "use the built-in default" while nonzero invalid pairs stay
// rejected by the library itself. Scratch snapshot only.

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func qaV3RunIP2NetLibrary(t *testing.T, input string, options IP2NetOptions) (string, error) {
	t.Helper()
	var buffer bytes.Buffer
	_, err := IP2Net(context.Background(), strings.NewReader(input), &buffer, options)
	return buffer.String(), err
}

// TestQAV3IP2NetLibraryZeroValueIsDefault compares the zero-value library API
// with explicit thresholds on an input whose density depends on the threshold,
// so "zero means default" is proven behaviourally.
func TestQAV3IP2NetLibraryZeroValueIsDefault(t *testing.T) {
	t.Parallel()
	const input = "192.0.2.0\n192.0.2.1\n"
	zeroValue, err := qaV3RunIP2NetLibrary(t, input, IP2NetOptions{Family: FamilyIPv4})
	if err != nil {
		t.Fatalf("zero-value options must keep working: %v", err)
	}
	explicit34, err := qaV3RunIP2NetLibrary(t, input, IP2NetOptions{
		Family: FamilyIPv4, V4ThresholdMul: 3, V4ThresholdDiv: 4,
	})
	if err != nil {
		t.Fatalf("explicit 3/4: %v", err)
	}
	explicit12, err := qaV3RunIP2NetLibrary(t, input, IP2NetOptions{
		Family: FamilyIPv4, V4ThresholdMul: 1, V4ThresholdDiv: 2,
	})
	if err != nil {
		t.Fatalf("explicit 1/2: %v", err)
	}
	if zeroValue != explicit34 {
		t.Fatalf("zero-value output %q != explicit 3/4 output %q", zeroValue, explicit34)
	}
	if zeroValue == explicit12 {
		t.Fatalf("zero-value output %q equals the 1/2 output; input is not discriminating", zeroValue)
	}
	if zeroValue != "192.0.2.0\n192.0.2.1\n" {
		t.Fatalf("zero-value (default 3/4) output: %q", zeroValue)
	}
}

// TestQAV3IP2NetLibraryRejectsNonZeroInvalidPairs keeps the library's own
// contract: only the all-zero pair is the default sentinel.
func TestQAV3IP2NetLibraryRejectsNonZeroInvalidPairs(t *testing.T) {
	t.Parallel()
	const input = "192.0.2.0\n192.0.2.1\n"
	invalid := []IP2NetOptions{
		{Family: FamilyIPv4, V4ThresholdMul: 0, V4ThresholdDiv: 4},
		{Family: FamilyIPv4, V4ThresholdMul: 4, V4ThresholdDiv: 0},
		{Family: FamilyIPv4, V4ThresholdMul: 1, V4ThresholdDiv: 1},
		{Family: FamilyIPv4, V4ThresholdMul: 3, V4ThresholdDiv: 3},
		{Family: FamilyIPv4, V4ThresholdMul: 4, V4ThresholdDiv: 3},
		{Family: FamilyIPv4, V4ThresholdMul: 2, V4ThresholdDiv: 1},
	}
	for _, options := range invalid {
		options := options
		t.Run("library_reject", func(t *testing.T) {
			t.Parallel()
			output, err := qaV3RunIP2NetLibrary(t, input, options)
			if err == nil {
				t.Fatalf("%+v must be rejected, got output %q", options, output)
			}
			if output != "" {
				t.Fatalf("%+v must not write output, got %q", options, output)
			}
			if !strings.Contains(err.Error(), "--v4-threshold") {
				t.Fatalf("%+v: error does not name the flag: %v", options, err)
			}
		})
	}
}

// TestQAV3IP2NetLibraryFullUint32Range pins the documented 64-bit threshold
// arithmetic at the uint32 maximum (density floor(4*(2^32-2)/(2^32-1)) = 3).
func TestQAV3IP2NetLibraryFullUint32Range(t *testing.T) {
	t.Parallel()
	const input = "192.0.2.0\n192.0.2.1\n192.0.2.2\n192.0.2.3\n"
	output, err := qaV3RunIP2NetLibrary(t, input, IP2NetOptions{
		Family:         FamilyIPv4,
		V4ThresholdMul: 4294967294,
		V4ThresholdDiv: 4294967295,
	})
	if err != nil {
		t.Fatalf("uint32 maximum pair must be accepted: %v", err)
	}
	if output != "192.0.2.0/30\n" {
		t.Fatalf("uint32 maximum pair output: %q", output)
	}
	// Two addresses in the /30 must stay bare at that threshold (3).
	two, err := qaV3RunIP2NetLibrary(t, "192.0.2.0\n192.0.2.1\n", IP2NetOptions{
		Family:         FamilyIPv4,
		V4ThresholdMul: 4294967294,
		V4ThresholdDiv: 4294967295,
	})
	if err != nil {
		t.Fatal(err)
	}
	if two != "192.0.2.0\n192.0.2.1\n" {
		t.Fatalf("uint32 maximum pair threshold is not 3: %q", two)
	}
}

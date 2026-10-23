package tools

// Deterministic bounded-work and cancellation controls for the IP exclusion
// phase (security finding S3). No timing, benchmark or load test is used.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// stepCancelContext reports context.Canceled after limit Err calls. It lets a
// test observe that the implementation checks the context inside the expensive
// phase instead of only once around it.
type stepCancelContext struct {
	calls int
	limit int
}

func (c *stepCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *stepCancelContext) Done() <-chan struct{}       { return nil }
func (c *stepCancelContext) Value(any) any               { return nil }
func (c *stepCancelContext) Err() error {
	c.calls++
	if c.calls > c.limit {
		return context.Canceled
	}
	return nil
}

func exclusionEntries(prefix string, count int) []string {
	entries := make([]string, 0, count)
	for index := 0; index < count; index++ {
		entries = append(entries, fmt.Sprintf("%s.%d", prefix, index%256))
	}
	return entries
}

// TestIPExclusionPrefixSemantics pins the exact containment rule: an entry is
// excluded when one of its ancestor prefixes is excluded, never when it is a
// broader prefix than the exclusion or a different address family.
func TestIPExclusionPrefixSemantics(t *testing.T) {
	input := strings.Join([]string{
		"192.0.2.5",    // inside 192.0.2.0/24
		"192.0.2.0/25", // inside 192.0.2.0/24
		"192.0.3.5",    // outside the /24
		"192.0.2.0/23", // broader than the /24
		"198.51.100.7", // exact exclusion
		"198.51.100.8", // outside the /32
		"2001:db8::1",  // inside 2001:db8::/32
		"2001:db9::1",  // outside the /32
		"203.0.113.9",  // no exclusion of this family
	}, "\n") + "\n"
	excludes := strings.Join([]string{
		"192.0.2.0/24",
		"198.51.100.7",
		"2001:db8::/32",
	}, "\n") + "\n"
	var output bytes.Buffer
	manifest, err := NormalizeList(context.Background(),
		ListInput{Reader: strings.NewReader(input)}, &output,
		[]ListInput{{Reader: strings.NewReader(excludes)}},
		ListNormalizeOptions{Kind: ListKindIP})
	if err != nil {
		t.Fatal(err)
	}
	const expected = "192.0.2.0/23\n192.0.3.5\n198.51.100.8\n203.0.113.9\n2001:db9::1\n"
	if output.String() != expected {
		t.Fatalf("prefix containment changed:\n got %q\nwant %q", output.String(), expected)
	}
	if manifest.Output.Entries != 5 || manifest.Source.Excluded != 4 {
		t.Fatalf("unexpected counts: entries=%d excluded=%d", manifest.Output.Entries, manifest.Source.Excluded)
	}
}

// TestIPExclusionWorkIsNotRepeatedScan proves the deterministic work bound with
// 128 disjoint entries on each side. Each /32 exclusion contributes one prefix
// length, so the pass performs one prefix comparison per entry. A repeated
// N*M scan would exceed the 1024 budget (16384 comparisons) and fail here.
func TestIPExclusionWorkIsNotRepeatedScan(t *testing.T) {
	entries := exclusionEntries("192.0.2", 128)
	excluded := exclusionEntries("198.51.100", 128)
	kept, removed, err := excludeIPs(context.Background(), entries, excluded, 1024)
	if err != nil {
		t.Fatalf("sub-quadratic work exceeded the 1024 budget: %v", err)
	}
	if removed != 0 || len(kept) != 128 {
		t.Fatalf("disjoint lists changed: kept=%d removed=%d", len(kept), removed)
	}
	if _, _, err = excludeIPs(context.Background(), entries, excluded, 64); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Fatalf("work budget was not enforced: %v", err)
	}
}

// TestIPExclusionCancellationIsPeriodic cancels after two context checks and
// requires the failure to happen inside the filtering pass. Without the periodic
// check the call completes successfully and Err is never consulted.
func TestIPExclusionCancellationIsPeriodic(t *testing.T) {
	entries := exclusionEntries("192.0.2", 4096)
	excluded := exclusionEntries("198.51.100", 64)
	ctx := &stepCancelContext{limit: 2}
	kept, removed, err := excludeIPs(ctx, entries, excluded, 1<<30)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was not observed inside the exclusion pass: err=%v kept=%d removed=%d", err, len(kept), removed)
	}
	if ctx.calls != 3 {
		t.Fatalf("expected cancellation after the third periodic check, got %d checks", ctx.calls)
	}
}

// TestIGPExclusionAggregateEntryCap checks that the exclusion limit is shared by
// all exclusion files, not applied per file.
func TestIPExclusionAggregateEntryCap(t *testing.T) {
	input := strings.NewReader("203.0.113.1\n")
	excludes := []ListInput{
		{Reader: strings.NewReader("192.0.2.1\n192.0.2.2\n")},
		{Reader: strings.NewReader("198.51.100.1\n198.51.100.2\n")},
	}
	var output bytes.Buffer
	_, err := NormalizeList(context.Background(), ListInput{Reader: input}, &output, excludes,
		ListNormalizeOptions{Kind: ListKindIP, MaxEntries: 8, MaxExclusionEntries: 3})
	if err == nil || !strings.Contains(err.Error(), "aggregate limit") {
		t.Fatalf("aggregate exclusion cap was not enforced: %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("rejected run wrote %d bytes", output.Len())
	}
	output.Reset()
	if _, err = NormalizeList(context.Background(), ListInput{Reader: strings.NewReader("203.0.113.1\n")}, &output, excludes,
		ListNormalizeOptions{Kind: ListKindIP, MaxEntries: 8, MaxExclusionEntries: 4}); err != nil {
		t.Fatalf("exact aggregate limit was rejected: %v", err)
	}
	if output.String() != "203.0.113.1\n" {
		t.Fatalf("unexpected output %q", output.String())
	}
}

//go:build linux

package desync

import (
	"os"
	"path/filepath"
	"testing"
)

// TestQueueInUseReportParsing pins the read-only parsing of the kernel's
// bound-queue report used for collision avoidance. The real file is never
// touched here.
func TestQueueInUseReportParsing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nfnetlink_queue")
	content := "# queue  peer_pid  queue_total ...\n" +
		"2048   1234  0 0 0 0 0 0 0 0\n" +
		"2050   -1    0 0 0 0 0 0 0 0\n" +
		"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	for queue, want := range map[uint16]bool{2048: true, 2050: true, 2049: false, 1024: false} {
		if got := queueInUseReport(path, queue); got != want {
			t.Fatalf("queue %d in use = %v, want %v", queue, got, want)
		}
	}
	// A missing report must not claim a collision; the bind error path is the
	// remaining authority.
	if queueInUseReport(filepath.Join(t.TempDir(), "missing"), 2048) {
		t.Fatal("missing report must not report a queue in use")
	}
}

// TestNextFreeQueuesBounds verifies bounded managed allocation: used identities
// are skipped, only the managed range is returned, and an exhausted range
// yields fewer candidates instead of probing the host range.
func TestNextFreeQueuesBounds(t *testing.T) {
	used := map[uint16]bool{3000: true, 3001: true, 3003: true}
	inUse := func(queue uint16) bool { return used[queue] }
	candidates := nextFreeQueues(3000, 2, inUse)
	if len(candidates) != 2 || candidates[0] != 3002 || candidates[1] != 3004 {
		t.Fatalf("candidates = %v", candidates)
	}
	// Exhaust the window: 1024..1024+64 all in use.
	allUsed := func(queue uint16) bool { return true }
	if got := nextFreeQueues(managedQueueBase, 2, allUsed); len(got) != 0 {
		t.Fatalf("exhausted range returned %v", got)
	}
	// A start below the managed base never yields host-range numbers.
	belowBase := nextFreeQueues(10, 2, func(uint16) bool { return false })
	if len(belowBase) != 2 || belowBase[0] != managedQueueBase {
		t.Fatalf("below-base candidates = %v", belowBase)
	}
	// Never more than the search bound.
	many := nextFreeQueues(managedQueueBase, queueCandidates+10, func(uint16) bool { return false })
	if len(many) > queueCandidates {
		t.Fatalf("candidate count %d exceeds the search bound", len(many))
	}
}

// TestQueueAllocationIsDirectionallySeparate pins that the outbound and inbound
// observations use distinct queue identities, so a reply can never be mistaken
// for an outbound packet by the capture loop.
func TestQueueAllocationIsDirectionallySeparate(t *testing.T) {
	candidates := nextFreeQueues(4000, 2, func(uint16) bool { return false })
	if len(candidates) != 2 || candidates[0] == candidates[1] {
		t.Fatalf("candidates = %v", candidates)
	}
}

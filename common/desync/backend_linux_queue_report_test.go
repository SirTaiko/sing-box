//go:build linux

package desync

// Focused qualification of the deployed-kernel NFQUEUE report grammar used by
// the retirement receipts. The exact target producer is
// linux-v6.8 net/netfilter/nfnetlink_queue.c seq_show():
//
//	seq_printf(s, "%5u %6u %5u %1u %5u %5u %5u %8u %2d\n", ...)
//
// The authentic rows below are the bytes QA561 actually observed from the
// Ubuntu 6.8.0-146-generic target. Nothing here creates a kernel object.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The producer's enum values are spelled out independently of the production
// parser constants so a wrong constant cannot make a fixture agree with it.
const (
	deployedCopyNone   = 0
	deployedCopyPacket = 2
)

// deployedQueueReportRow renders one row with the exact deployed producer
// format string and column order, so a future producer change fails the
// fixture equality checks instead of silently passing an invented shape.
func deployedQueueReportRow(queue uint16, port, total, mode, copyRange, dropped, userDropped, idSequence uint32, trailing int) string {
	return fmt.Sprintf("%5d %6d %5d %1d %5d %5d %5d %8d %2d\n",
		queue, port, total, mode, copyRange, dropped, userDropped, idSequence, trailing)
}

func readQueueReportFixture(t *testing.T, content string) ([]queueRow, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nfnetlink_queue")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := namespaceQueueReportPath
	namespaceQueueReportPath = path
	t.Cleanup(func() { namespaceQueueReportPath = previous })
	return readQueueReportInNamespace()
}

// TestQueueReportParsesDeployedKernelRows drives the production parser with the
// exact nine-column bytes the target kernel emitted, and with a generated row
// of the same producer shape covering every unsigned column boundary.
func TestQueueReportParsesDeployedKernelRows(t *testing.T) {
	rows := []struct {
		name string
		row  string
		want queueRow
	}{
		{
			name: "authentic zero total",
			row:  "37879 2817580694     0 2 65531     0     0        0  1\n",
			want: queueRow{queue: 37879, port: 2817580694, total: 0, copyMode: deployedCopyPacket, copyRange: 65531},
		},
		{
			name: "authentic non-zero id sequence",
			row:  "46994 2998834639     0 2 65531     0     0        1  1\n",
			want: queueRow{queue: 46994, port: 2998834639, total: 0, copyMode: deployedCopyPacket, copyRange: 65531, idSequence: 1},
		},
		{
			name: "queue zero and copy none",
			row:  deployedQueueReportRow(0, 0, 0, deployedCopyNone, 0, 0, 0, 0, 1),
			want: queueRow{queue: 0, port: 0, total: 0, copyMode: deployedCopyNone, copyRange: 0},
		},
		{
			name: "full unsigned width",
			row:  deployedQueueReportRow(65535, ^uint32(0), ^uint32(0), deployedCopyPacket, ^uint32(0), ^uint32(0), ^uint32(0), ^uint32(0), 1),
			want: queueRow{queue: 65535, port: ^uint32(0), total: ^uint32(0), copyMode: deployedCopyPacket, copyRange: ^uint32(0), dropped: ^uint32(0), userDropped: ^uint32(0), idSequence: ^uint32(0)},
		},
	}
	for _, test := range rows {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := readQueueReportFixture(t, test.row)
			if err != nil {
				t.Fatalf("deployed kernel row rejected: %v", err)
			}
			if len(parsed) != 1 || parsed[0] != test.want {
				t.Fatalf("parsed rows = %#v, want %#v", parsed, test.want)
			}
		})
	}

	// The generator used by the fake kernel and the negative cases must
	// reproduce the authentic bytes exactly.
	generated := deployedQueueReportRow(37879, 2817580694, 0, deployedCopyPacket, 65531, 0, 0, 0, 1)
	if generated != "37879 2817580694     0 2 65531     0     0        0  1\n" {
		t.Fatalf("generated row = %q does not match the authentic kernel bytes", generated)
	}
}

// TestQueueReportRejectsUnknownProducerShapes proves that abbreviated,
// extended, non-numeric, overflowing, unknown-mode and inconsistent rows are
// rejected whole instead of truncated or partially adopted.
func TestQueueReportRejectsUnknownProducerShapes(t *testing.T) {
	cases := []struct{ name, content string }{
		{"abbreviated seven columns", "2048 4242 0 0 0 0 0\n"},
		{"eight columns", "2048 4242 0 2 65531 0 0 0\n"},
		{"ten columns", "2048 4242 0 2 65531 0 0 0 1 1\n"},
		{"missing trailing column", "2048 4242 0 2 65531 0 0 0\n"},
		{"queue above uint16", "65536 4242 0 2 65531 0 0 0 1\n"},
		{"port above uint32", "2048 4294967296 0 2 65531 0 0 0 1\n"},
		{"total above uint32", "2048 4242 4294967296 2 65531 0 0 0 1\n"},
		{"mode above enum", "2048 4242 0 3 65531 0 0 0 1\n"},
		{"mode above uint8", "2048 4242 0 256 65531 0 0 0 1\n"},
		{"copy range above uint32", "2048 4242 0 2 4294967296 0 0 0 1\n"},
		{"dropped above uint32", "2048 4242 0 2 65531 4294967296 0 0 1\n"},
		{"user dropped above uint32", "2048 4242 0 2 65531 0 4294967296 0 1\n"},
		{"id sequence above uint32", "2048 4242 0 2 65531 0 0 4294967296 1\n"},
		{"trailing zero", "2048 4242 0 2 65531 0 0 0 0\n"},
		{"trailing two", "2048 4242 0 2 65531 0 0 0 2\n"},
		{"negative port", "2048 -1 0 2 65531 0 0 0 1\n"},
		{"non-numeric total", "2048 4242 zero 2 65531 0 0 0 1\n"},
		{"non-numeric mode", "2048 4242 0 two 65531 0 0 0 1\n"},
		{"unknown line after valid row", deployedQueueReportRow(0, 4242, 0, deployedCopyPacket, 65531, 0, 0, 0, 1) + "garbage\n"},
		{"abbreviated row after valid row", deployedQueueReportRow(0, 4242, 0, deployedCopyPacket, 65531, 0, 0, 0, 1) + "2048 4242 0 0 0 0 0\n"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			rows, err := readQueueReportFixture(t, test.content)
			if err == nil || !strings.Contains(err.Error(), "malformed NFQUEUE report row") {
				t.Fatalf("unknown row accepted or wrong error: rows=%#v err=%v", rows, err)
			}
			if len(rows) != 0 {
				t.Fatalf("unknown row was partially adopted: %#v", rows)
			}
		})
	}
}

// TestQueueReportSelectionStaysStrict keeps the duplicate/inconsistent and
// foreign-port selection rules on real producer-shaped rows, including queue0.
func TestQueueReportSelectionStaysStrict(t *testing.T) {
	queueZero, err := readQueueReportFixture(t, deployedQueueReportRow(0, 4242, 0, deployedCopyPacket, 65531, 0, 0, 0, 1))
	if err != nil {
		t.Fatalf("queue0 row rejected: %v", err)
	}
	row, found := findQueueRow(queueZero, 0)
	if !found || row.port != 4242 {
		t.Fatalf("queue0 row = %#v found=%v", row, found)
	}
	if _, found := findQueueRowForPort(queueZero, 0, 4242); !found {
		t.Fatal("queue0 row with the exact port not found")
	}
	if _, found := findQueueRowForPort(queueZero, 0, 4243); found {
		t.Fatal("foreign port matched the own queue row")
	}

	highPort, err := readQueueReportFixture(t, deployedQueueReportRow(65535, ^uint32(0), 0, deployedCopyPacket, 65531, 0, 0, 0, 1))
	if err != nil {
		t.Fatalf("high-port row rejected: %v", err)
	}
	row, found = findQueueRowForPort(highPort, 65535, ^uint32(0))
	if !found || row.port != ^uint32(0) {
		t.Fatalf("high-port row = %#v found=%v", row, found)
	}

	duplicate := deployedQueueReportRow(0, 4242, 0, deployedCopyPacket, 65531, 0, 0, 0, 1) +
		deployedQueueReportRow(0, 4242, 1, deployedCopyPacket, 65531, 0, 0, 0, 1)
	rows, err := readQueueReportFixture(t, duplicate)
	if err != nil {
		t.Fatalf("duplicate rows did not parse: %v", err)
	}
	if _, found := findQueueRow(rows, 0); found {
		t.Fatal("inconsistent duplicate queue rows were accepted as unique")
	}
	if calls := queueRowCount(rows, 0); calls != 2 {
		t.Fatalf("queue row count = %d, want 2", calls)
	}

	replaced := deployedQueueReportRow(0, 4242, 0, deployedCopyPacket, 65531, 0, 0, 0, 1) +
		deployedQueueReportRow(0, 9001, 0, deployedCopyPacket, 65531, 0, 0, 0, 1)
	rows, err = readQueueReportFixture(t, replaced)
	if err != nil {
		t.Fatalf("replaced rows did not parse: %v", err)
	}
	if _, found := findQueueRow(rows, 0); found {
		t.Fatal("two rows for one queue were accepted as unique")
	}
	if _, found := findQueueRowForPort(rows, 0, 9001); !found {
		t.Fatal("the genuine replacement port was not found")
	}
}

// TestComposedCaptureRetirementUsesDeployedReportShape exercises the real
// composed first-open/close path over the deployed-shape report and requires
// the positive capture-retired receipt with zero active leases.
func TestComposedCaptureRetirementUsesDeployedReportShape(t *testing.T) {
	data := newFakeNFQueueConn("shape", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 16100)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := lease.capture.(*linuxCapture)

	rows, err := readQueueReportInNamespace()
	if err != nil {
		t.Fatalf("composed report read: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("composed report rows = %#v, want the two own queues", rows)
	}
	for _, row := range rows {
		if row.queue != linux.queue && row.queue != linux.inQueue {
			t.Fatalf("unexpected composed report row: %#v", row)
		}
		if row.port != data.portid || row.total != 0 {
			t.Fatalf("composed report row = %#v, want port %d and total 0", row, data.portid)
		}
		if row.copyMode != deployedCopyPacket || row.copyRange != fakeReportCopyRange {
			t.Fatalf("composed report row is not the deployed shape: %#v", row)
		}
	}

	if err := lease.Close(nil); err != nil {
		t.Fatalf("close over deployed-shape report: %v", err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatalf("positive capture-retired receipt: %v", err)
	}
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after retirement = %d, want 0", got)
	}
	if bound := seams.kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after retirement: %v", bound)
	}
}

// TestComposedRetirementRejectsAbbreviatedReport proves the negative control is
// non-vacuous: an abbreviated seven-column row, which the old fake kernel and
// the old parser used, fails the composed retirement with the parser error and
// publishes no positive receipt or lease release.
func TestComposedRetirementRejectsAbbreviatedReport(t *testing.T) {
	data := newFakeNFQueueConn("shape", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 16110)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := lease.capture.(*linuxCapture)
	abbreviated := fmt.Sprintf("%d %d 0 0 0 0 0", linux.queue, linux.outPort)
	writeQueueReport(t, seams.kernel, abbreviated)

	closeErr := lease.Close(nil)
	if closeErr == nil || !strings.Contains(closeErr.Error(), "malformed NFQUEUE report row") {
		t.Fatalf("abbreviated composed report Close = %v, want the parser rejection", closeErr)
	}
	if err := lease.WaitCaptureRetired(); err == nil {
		t.Fatal("positive capture-retired receipt published over an unknown report shape")
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after rejected retirement = %d, want the retained slot (1)", got)
	}
	content, err := os.ReadFile(namespaceQueueReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), abbreviated) {
		t.Fatalf("abbreviated row was altered instead of rejected: %q", string(content))
	}
}

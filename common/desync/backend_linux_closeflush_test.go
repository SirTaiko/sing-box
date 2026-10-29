//go:build linux

package desync

// Regressions for the kernel queue lifetime at capture teardown under the
// selected-A persistent anchors. Model tests: no kernel object is created, and
// every case says so.
//
// The capture no longer owns a table and never unregisters a hook: the fixed
// base chains and the a/t markers outlive it. Teardown must still answer every
// packet that is already queued, because nfqnl_recv_verdict() answers -ENOENT
// when find_dequeue_entry() no longer holds the id and the pinned netlink
// library surfaces that acknowledgement on the next Receive. The ordering the
// tests pin is therefore: terminal verdicts and the ordered drain first, then
// the non-witness UNBIND, then the owning socket close.

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// nativeDrainENOENT is the exact text of the teardown error the native QA
// observed, produced by this package wrapping the pinned library's OpError.
const nativeDrainENOENT = "desync: drain NFQUEUE receive queue: netlink receive: no such file or directory"

// assertDrainedBeforeUnbind checks that the queued packet's terminal verdict was
// applied while its kernel entry still existed, before the queue was unbound,
// and that the fixed anchors survived the capture close.
func assertDrainedBeforeUnbind(t *testing.T, kernel *fakeQueueKernel, seams *linuxCaptureSeams,
	conn *fakeNFQueueConn, queue uint16, id uint32, engine *Engine, closeErr error) {
	t.Helper()
	if closeErr != nil {
		t.Fatalf("close of an owned capture must not fail: %v", closeErr)
	}
	verdicts := kernel.verdictsFor(queue, id)
	if len(verdicts) != 1 {
		t.Fatalf("verdicts for the queued packet = %d, want exactly one", len(verdicts))
	}
	if verdicts[0].verdict != nfqueueVerdictAccept {
		t.Fatalf("queued packet verdict = %d, want NF_ACCEPT (%d)", verdicts[0].verdict, nfqueueVerdictAccept)
	}
	if got := countKernelEvents(kernel, "reject"); got != 0 {
		t.Fatalf("kernel rejected %d verdicts: the capture answered an id it no longer owned", got)
	}
	if got := countKernelEvents(kernel, "drop"); got != 0 {
		t.Fatalf("kernel dropped %d queued packets at teardown, want 0", got)
	}
	verdictIndex := kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "verdict" && event.id == id
	})
	unbindIndex := kernel.eventIndex(func(event fakeKernelEvent) bool {
		return event.kind == "unbind" && event.queue != queue
	})
	if verdictIndex < 0 || unbindIndex < 0 || verdictIndex > unbindIndex {
		t.Fatalf("event order verdict=%d unbind=%d, want the verdict before the non-witness unbind", verdictIndex, unbindIndex)
	}
	if bound := kernel.boundQueues(); len(bound) != 0 {
		t.Fatalf("queues still bound after Close: %v", bound)
	}
	if conn.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", conn.closings())
	}
	// The persistent anchors stay, exactly as created.
	if err := readFakeAnchors(t, seams, FamilyIPv4); err != nil {
		t.Fatalf("anchor validation after close: %v", err)
	}
	if got := fakeCaptureRecords(t, seams, FamilyIPv4); len(got) != 0 {
		t.Fatalf("capture records still present after close: %v", got)
	}
	if engine != nil {
		if got := engine.ActiveLeases(); got != 0 {
			t.Fatalf("active leases after close = %d, want 0", got)
		}
	}
}

// TestLinuxCaptureAnswersQueuedPacketBeforeUnbind is the permanent regression
// for the teardown ordering: a packet of the owned flow that is queued when the
// capture starts closing is answered while its kernel entry is still valid.
func TestLinuxCaptureAnswersQueuedPacketBeforeUnbind(t *testing.T) {
	t.Run("ordinary", func(t *testing.T) {
		data := newFakeNFQueueConn("closeflush", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		engine, lease := newLinuxCaptureLease(t, 15310)
		if err := lease.StartCapture(); err != nil {
			t.Fatalf("start capture: %v", err)
		}
		c := lease.capture.(*linuxCapture)
		select {
		case <-data.receiving:
		case <-time.After(5 * time.Second):
			t.Fatal("capture loop never entered Receive")
		}
		packet := buildIPv4TCP(t, []byte("owned-close-flush-payload"), 1000, tcpFlagACK|tcpFlagPSH)
		const id = 901
		if !seams.kernel.deliver(c.queue, fakePacketMessage(c.queue, id, packet.Raw), id) {
			t.Fatal("owned queue refused the packet")
		}
		waitForCondition(t, "terminal verdict of the queued packet", func() bool {
			return len(seams.kernel.verdictsFor(c.queue, id)) == 1
		})
		closeErr := lease.Close(nil)
		assertDrainedBeforeUnbind(t, seams.kernel, seams, data, c.queue, id, engine, closeErr)
	})

	t.Run("reader-parked-over-teardown-interrupt", func(t *testing.T) {
		data := newFakeNFQueueConn("closeflush-parked", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		gate := &drainReadGate{fakeNFQueueConn: data, entered: make(chan struct{}), resume: make(chan struct{})}
		openQueueTransport = func(port uint32) (nfqueueTransport, error) { return gate, nil }
		gate.portid = 0x51a00001
		engine, lease := newLinuxCaptureLease(t, 15311)
		if err := lease.StartCapture(); err != nil {
			t.Fatalf("start capture: %v", err)
		}
		c := lease.capture.(*linuxCapture)
		<-gate.entered

		packet := buildIPv4TCP(t, []byte("owned-close-flush-payload"), 1000, tcpFlagACK|tcpFlagPSH)
		const id = 902
		if !seams.kernel.deliver(c.queue, fakePacketMessage(c.queue, id, packet.Raw), id) {
			t.Fatal("owned queue refused the packet")
		}
		done := make(chan error, 1)
		go func() { done <- lease.Close(nil) }()
		waitForCondition(t, "teardown interrupt armed", func() bool { return data.deadlineCalls.Load() > 0 })
		time.Sleep(3 * queueStopDrain)
		close(gate.resume)
		closeErr := waitWithin(t, "lease close", done)
		assertDrainedBeforeUnbind(t, seams.kernel, seams, data, c.queue, id, engine, closeErr)
	})
}

// TestLinuxCaptureDrainReportsKernelRejectedVerdict is the error-preservation
// control: a kernel rejection that is NOT caused by this capture's teardown
// (here a foreign hook unregistration in the same network namespace, which
// flushes every queue instance) must still be reported, with the exact native
// text and the ENOENT cause preserved.
func TestLinuxCaptureDrainReportsKernelRejectedVerdict(t *testing.T) {
	data := newFakeNFQueueConn("closeflush-reject", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	gate := &drainReadGate{fakeNFQueueConn: data, entered: make(chan struct{}), resume: make(chan struct{})}
	gate.portid = 0x51a00001
	openQueueTransport = func(port uint32) (nfqueueTransport, error) { return gate, nil }
	_, lease := newLinuxCaptureLease(t, 15312)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("start capture: %v", err)
	}
	c := lease.capture.(*linuxCapture)
	<-gate.entered

	packet := buildIPv4TCP(t, []byte("foreign-flush-payload"), 1000, tcpFlagACK|tcpFlagPSH)
	const id = 903
	if !seams.kernel.deliver(c.queue, fakePacketMessage(c.queue, id, packet.Raw), id) {
		t.Fatal("owned queue refused the packet")
	}
	// A foreign hook unregistration flushes the instance, so the id is already
	// gone when the capture answers it.
	seams.kernel.hookDrop()
	if got := countKernelEvents(seams.kernel, "drop"); got != 1 {
		t.Fatalf("kernel flushed %d entries, want the queued packet (1)", got)
	}

	done := make(chan error, 1)
	go func() { done <- lease.Close(nil) }()
	waitForCondition(t, "teardown interrupt armed", func() bool { return data.deadlineCalls.Load() > 0 })
	time.Sleep(3 * queueStopDrain)
	close(gate.resume)
	closeErr := waitWithin(t, "lease close", done)
	if closeErr == nil {
		t.Fatalf("Close reported success although the kernel rejected the verdict: %q", nativeDrainENOENT)
	}
	if closeErr.Error() != nativeDrainENOENT {
		t.Fatalf("close error = %q, want %q", closeErr.Error(), nativeDrainENOENT)
	}
	if !errors.Is(closeErr, unix.ENOENT) {
		t.Fatalf("close error %v does not carry the kernel's ENOENT cause", closeErr)
	}
	if got := len(seams.kernel.verdictsFor(c.queue, id)); got != 0 {
		t.Fatalf("verdicts recorded for the flushed packet = %d, want 0", got)
	}
	if got := countKernelEvents(seams.kernel, "reject"); got != 1 {
		t.Fatalf("kernel rejections = %d, want exactly the one doomed verdict", got)
	}
}

// readFakeAnchors reads and validates the fixed anchors of the model family.
func readFakeAnchors(t *testing.T, seams *linuxCaptureSeams, family Family) error {
	t.Helper()
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000003}
	_, err := readAnchorFamilyState(session, family)
	return err
}

// fakeCaptureRecords returns every capture manifest currently visible.
func fakeCaptureRecords(t *testing.T, seams *linuxCaptureSeams, family Family) []anchorRecord {
	t.Helper()
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000003}
	state, err := readAnchorFamilyState(session, family)
	if err != nil {
		t.Fatalf("read anchor state: %v", err)
	}
	records := make([]anchorRecord, 0, len(state.captures))
	for _, manifest := range state.captures {
		records = append(records, manifest.record)
	}
	return records
}

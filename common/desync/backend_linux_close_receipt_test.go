//go:build linux

package desync

// Regressions for the receipts the Linux capture publishes when its receive
// lane cannot be stopped, and for the ordinary zero-payload FIN disposition.
// Model tests: production capture/lease/engine code runs unsandboxed, the
// netlink transport is the shipped deterministic fake. No kernel object is
// created and no packet is injected or sent.
//
// The native default lifecycle (task t_68efb1c5) closed a healthy capture over
// the real NFQUEUE adapter, the receive-interruption deadline failed, and the
// caller was left with active_leases=1. A repeated Engine.Close then returned
// nil because the engine itself was already closed. That is engine idempotence,
// not a positive retirement receipt: the endpoint owner must keep the native
// socket until WaitCaptureRetired proves the capture is gone. These tests pin
// exactly that distinction.

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// TestLinuxCaptureFailureRetentionIsNotRetirement pins the retained-error
// shape observed natively:
//   - the genuine deadline failure is preserved through Close/WaitClosed;
//   - the positive capture-retired receipt carries the same error, so no
//     caller may treat the closed lease as retired;
//   - the charged slot stays;
//   - a repeated Engine.Close returning nil does not change either fact.
func TestLinuxCaptureFailureRetentionIsNotRetirement(t *testing.T) {
	data := newFakeNFQueueConn("retention", 0, nil)
	data.deadlineDisabled = true
	installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 15320)

	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open capture: %v", err)
	}
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	closeErr := lease.Close(nil)
	if closeErr == nil {
		t.Fatal("Close reported success although the receive lane could not be interrupted")
	}
	if !errors.Is(closeErr, errFakeNoDeadline) {
		t.Fatalf("Close error = %v, want the genuine deadline failure", closeErr)
	}
	if err := lease.WaitClosed(); err == nil || !errors.Is(err, errFakeNoDeadline) {
		t.Fatalf("WaitClosed = %v, want the same genuine deadline failure", err)
	}
	receiptErr := lease.WaitCaptureRetired()
	if receiptErr == nil {
		t.Fatal("positive capture-retired receipt published for a failed retirement")
	}
	if !errors.Is(receiptErr, errFakeNoDeadline) {
		t.Fatalf("capture-retired receipt = %v, want the genuine deadline failure", receiptErr)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after a failed close = %d, want the retained slot (1)", got)
	}
	// A repeated Lease.Close is idempotent and must not turn the failure into a
	// nil success either.
	if err := lease.Close(nil); err == nil || !errors.Is(err, errFakeNoDeadline) {
		t.Fatalf("repeated Lease.Close = %v, want the same genuine deadline failure", err)
	}

	// The first Engine.Close reaches the retained lease and reports its
	// failure; the second only reports engine idempotence (nil). Neither is a
	// retirement receipt.
	if err := engine.Close(); err == nil {
		t.Fatal("first Engine.Close reported success over a retained lease")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second Engine.Close = %v, want engine idempotence nil", err)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after repeated Engine.Close = %d, want the retained slot (1)", got)
	}
	if err := lease.WaitCaptureRetired(); err == nil {
		t.Fatal("repeated Engine.Close was promoted to a positive retirement receipt")
	}
	if cl := data.closings(); cl != 1 {
		t.Fatalf("transport closes = %d, want exactly one owned-socket close", cl)
	}
}

// TestLinuxCapturePassesOrdinaryTCPFIN proves the capture seam itself does not
// withhold an ordinary zero-payload FIN of the owned flow: exactly one AF_ACCEPT
// verdict is issued and no drop/hold is invented. It is the bounded model half
// of the receiver-EOF attribution: missing EOF cannot be explained by this
// receive/verdict path.
func TestLinuxCapturePassesOrdinaryTCPFIN(t *testing.T) {
	data := newFakeNFQueueConn("fin", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 15321)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux := lease.capture.(*linuxCapture)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	fin := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagFIN)
	const id = 910
	if !seams.kernel.deliver(linux.queue, fakePacketMessage(linux.queue, id, fin.Raw), id) {
		t.Fatal("owned queue refused the FIN")
	}
	waitForCondition(t, "terminal FIN verdict", func() bool {
		return len(seams.kernel.verdictsFor(linux.queue, id)) == 1
	})
	verdicts := seams.kernel.verdictsFor(linux.queue, id)
	if verdicts[0].verdict != nfqueueVerdictAccept {
		t.Fatalf("FIN verdict = %d, want NF_ACCEPT (%d)", verdicts[0].verdict, nfqueueVerdictAccept)
	}
	if got := countKernelEvents(seams.kernel, "drop"); got != 0 {
		t.Fatalf("kernel drops = %d, want 0: the capture withheld a FIN", got)
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("close after FIN pass: %v", err)
	}
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after a clean close = %d, want 0", got)
	}
}

// TestLinuxCapturePassesFINWithSelectingRule is the same disposition with the
// default product rule shape (TCP port match plus multisplit). The rule is
// selected by the captured packet itself, and a zero-payload packet only runs
// the in-place and duplicate stages: a selecting split rule cannot turn an
// ordinary FIN into a hold or a drop, and injecting payload segments is never
// reached.
func TestLinuxCapturePassesFINWithSelectingRule(t *testing.T) {
	data := newFakeNFQueueConn("fin-rule", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	content := `{"enabled":true,"capture":{"linux":{"qnum":15322}},"rules":[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.1:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.7:443"),
	})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.1:40000"))
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux := lease.capture.(*linuxCapture)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}

	// The rule is selected by this very packet: a zero-payload FIN runs only
	// the in-place and duplicate stages, so the split method never plans a
	// payload segment and no injection is attempted.
	fin := buildIPv4TCP(t, nil, 932, tcpFlagACK|tcpFlagFIN)
	const finID = 912
	if !seams.kernel.deliver(linux.queue, fakePacketMessage(linux.queue, finID, fin.Raw), finID) {
		t.Fatal("owned queue refused the FIN")
	}
	waitForCondition(t, "terminal FIN verdict", func() bool {
		return len(seams.kernel.verdictsFor(linux.queue, finID)) == 1
	})
	if got := seams.kernel.verdictsFor(linux.queue, finID); got[0].verdict != nfqueueVerdictAccept {
		t.Fatalf("FIN verdict = %d, want NF_ACCEPT (%d)", got[0].verdict, nfqueueVerdictAccept)
	}
	if got := countKernelEvents(seams.kernel, "drop"); got != 0 {
		t.Fatalf("kernel drops = %d, want 0: a selecting rule withheld the FIN", got)
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("close after selecting-rule FIN pass: %v", err)
	}
}

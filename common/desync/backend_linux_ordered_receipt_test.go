//go:build linux

package desync

// Permanent regressions for the §3.3 ordered no-op CONFIG receipt of the Linux
// retirement protocol: after the receive/send users are joined, EVERY still
// bound own queue - including the outbound witness queue that is kept bound
// until the owning socket is closed - must answer one own no-attribute
// NFQNL_MSG_CONFIG REQUEST|ACK with its matching ACK0, before the fresh
// queue_total=0 observation, before the non-witness UNBIND and before the
// positive CaptureRetired receipt.
//
// The native attribution (task t_fd331082, F1-L3/NA1-Q3) found retire()
// enumerating only inQueue (plus the optional ICMP queue) for that receipt: the
// still-bound outq was omitted while the same enumeration already included it
// for the queue_total=0 observation. These tests pin the composed model, not an
// isolated helper: production open/capture/Close and the shipped deterministic
// netlink fake run unsandboxed, no kernel object is created and no packet is
// sent or injected.

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// noOpConfigQueue decodes one executed NFQNL_MSG_CONFIG message and reports its
// queue number and whether it is the §3.3 own no-attribute lookup: a REQUEST|
// ACK CONFIG message with zero attributes, which is neither the BIND command,
// nor an UNBIND command, nor the NFQA_CFG_PARAMS update of the binding.
func noOpConfigQueue(message netlink.Message) (uint16, bool) {
	if message.Header.Type != netlink.HeaderType(3<<8|nfqMessageConfig) {
		return 0, false
	}
	if len(message.Data) < 4 {
		return 0, false
	}
	attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
	if err != nil || len(attributes) != 0 {
		return 0, false
	}
	return binary.BigEndian.Uint16(message.Data[2:4]), true
}

// orderedOwnQueueReceipts returns the queue numbers of the ordered no-attribute
// CONFIG receipts in the exact order they were executed on the connection.
func orderedOwnQueueReceipts(t *testing.T, messages []netlink.Message) []uint16 {
	t.Helper()
	var queues []uint16
	for _, message := range messages {
		queue, ok := noOpConfigQueue(message)
		if !ok {
			continue
		}
		if message.Header.Flags&netlink.Request == 0 || message.Header.Flags&netlink.Acknowledge == 0 {
			t.Fatalf("ordered no-op CONFIG for queue %d was sent without REQUEST|ACK (flags %#x)",
				queue, message.Header.Flags)
		}
		queues = append(queues, queue)
	}
	return queues
}

// receiptBinding is the kernel binding state observed immediately before one
// ordered no-op receipt is processed: it proves which queues were still bound
// when that receipt was issued.
type receiptBinding struct {
	queue uint16
	bound map[uint16]bool
}

// expectEveryBoundQueueReceivedOnce asserts the ordered receipt list and the
// exactly-once property for one set of still-bound own queues.
func expectEveryBoundQueueReceivedOnce(t *testing.T, receipts []uint16, want []uint16) {
	t.Helper()
	if len(receipts) != len(want) {
		t.Fatalf("ordered no-op CONFIG receipts = %v, want exactly %v (one ACK0 per bound queue)", receipts, want)
	}
	for i, queue := range want {
		if receipts[i] != queue {
			t.Fatalf("ordered no-op CONFIG receipts = %v, want %v in that order", receipts, want)
		}
	}
}

// TestLinuxRetirementOrderedNoOpConfigCoversOutboundWitness is the permanent
// regression for the omitted witness receipt: the outq witness is enumerated
// for the ordered CONFIG/ACK0 loop exactly once, while it is still bound, and
// it stays bound until the owning socket is released.
func TestLinuxRetirementOrderedNoOpConfigCoversOutboundWitness(t *testing.T) {
	t.Run("outbound-witness-and-inbound", func(t *testing.T) {
		data := newFakeNFQueueConn("outq-receipt", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		engine, lease := newLinuxCaptureLease(t, 15330)
		if err := lease.StartCapture(); err != nil {
			t.Fatalf("start capture: %v", err)
		}
		c := lease.capture.(*linuxCapture)
		if c.queue == c.inQueue || c.queue == 0 || c.inQueue == 0 {
			t.Fatalf("owned queue identities out=%d in=%d", c.queue, c.inQueue)
		}
		if c.icmpQueue != 0 {
			t.Fatalf("ICMP queue %d bound without the filter being configured", c.icmpQueue)
		}
		select {
		case <-data.receiving:
		case <-time.After(5 * time.Second):
			t.Fatal("capture loop never entered Receive")
		}
		var bindings []receiptBinding
		data.setExecuteHook(func(_ int, message netlink.Message) error {
			if queue, ok := noOpConfigQueue(message); ok {
				bindings = append(bindings, receiptBinding{queue: queue, bound: seams.kernel.boundQueues()})
			}
			return nil
		})

		if err := lease.Close(nil); err != nil {
			t.Fatalf("close of an owned capture must not fail: %v", err)
		}
		if err := lease.WaitCaptureRetired(); err != nil {
			t.Fatalf("positive capture-retired receipt: %v", err)
		}
		if got := engine.ActiveLeases(); got != 0 {
			t.Fatalf("active leases after a clean close = %d, want 0", got)
		}
		if got := data.closings(); got != 1 {
			t.Fatalf("owning socket closes = %d, want exactly 1", got)
		}

		want := []uint16{c.queue, c.inQueue}
		expectEveryBoundQueueReceivedOnce(t, orderedOwnQueueReceipts(t, data.executedMessages()), want)

		// Every receipt was issued while every still-bound own queue was still
		// bound: the witness cannot be an UNBIND or a post-close lookup, and the
		// non-witness queue was not released before its receipt.
		if len(bindings) != len(want) {
			t.Fatalf("no-op receipts observed at the kernel = %d, want %d", len(bindings), len(want))
		}
		for _, observed := range bindings {
			for _, queue := range want {
				if !observed.bound[queue] {
					t.Fatalf("queue %d was already released when the no-op CONFIG for %d was issued (bound=%v)",
						queue, observed.queue, observed.bound)
				}
			}
		}

		// The witness is bound exactly once and is never UNBIND/rebound: the only
		// release of outq is the own socket close.
		if got := countQueueCommand(t, data.executedMessages(), c.queue, nfqCfgCmdBind); got != 1 {
			t.Fatalf("witness binds = %d, want exactly 1", got)
		}
		if got := countQueueCommand(t, data.executedMessages(), c.queue, nfqCfgCmdUnbind); got != 0 {
			t.Fatalf("witness UNBIND commands = %d, want 0: outq must stay bound until the socket closes", got)
		}
		if got := countKernelEvents(seams.kernel, "unbind"); got != 1 {
			t.Fatalf("kernel unbinds = %d, want only the non-witness inbound queue", got)
		}
		if idx := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
			return event.kind == "unbind" && event.queue == c.queue
		}); idx >= 0 {
			t.Fatal("the witness queue was unbound during retirement")
		}
		if got := seams.kernel.eventIndex(func(event fakeKernelEvent) bool {
			return event.kind == "release" && event.queue == c.queue
		}); got < 0 {
			t.Fatal("witness queue was not released by the owning socket close")
		}
		if bound := seams.kernel.boundQueues(); len(bound) != 0 {
			t.Fatalf("queues still bound after a clean close: %v", bound)
		}
	})

	t.Run("with-owned-icmp-queue", func(t *testing.T) {
		data := newFakeNFQueueConn("outq-receipt-icmp", 0, nil)
		seams := installLinuxCaptureSeams(t, data)
		lease := newFilteredICMPLease(t, 15331)
		engine := lease.engine
		if err := lease.StartCapture(); err != nil {
			t.Fatalf("start capture: %v", err)
		}
		c := lease.capture.(*linuxCapture)
		if c.icmpQueue == 0 || c.icmpQueue == c.queue || c.icmpQueue == c.inQueue {
			t.Fatalf("owned ICMP queue = %d (out %d in %d)", c.icmpQueue, c.queue, c.inQueue)
		}
		select {
		case <-data.receiving:
		case <-time.After(5 * time.Second):
			t.Fatal("capture loop never entered Receive")
		}
		var bindings []receiptBinding
		data.setExecuteHook(func(_ int, message netlink.Message) error {
			if queue, ok := noOpConfigQueue(message); ok {
				bindings = append(bindings, receiptBinding{queue: queue, bound: seams.kernel.boundQueues()})
			}
			return nil
		})

		if err := lease.Close(nil); err != nil {
			t.Fatalf("close of an owned ICMP capture must not fail: %v", err)
		}
		if err := lease.WaitCaptureRetired(); err != nil {
			t.Fatalf("positive capture-retired receipt: %v", err)
		}
		if got := engine.ActiveLeases(); got != 0 {
			t.Fatalf("active leases after a clean close = %d, want 0", got)
		}

		// The optional queue contributes exactly one extra receipt when it is
		// bound, and the witness receipt is present in both shapes.
		want := []uint16{c.queue, c.inQueue, c.icmpQueue}
		expectEveryBoundQueueReceivedOnce(t, orderedOwnQueueReceipts(t, data.executedMessages()), want)
		for _, observed := range bindings {
			for _, queue := range want {
				if !observed.bound[queue] {
					t.Fatalf("queue %d was already released when the no-op CONFIG for %d was issued", queue, observed.queue)
				}
			}
		}
		if got := countQueueCommand(t, data.executedMessages(), c.queue, nfqCfgCmdUnbind); got != 0 {
			t.Fatalf("witness UNBIND commands = %d, want 0: outq must stay bound until the socket closes", got)
		}
		if got := countKernelEvents(seams.kernel, "unbind"); got != 2 {
			t.Fatalf("kernel unbinds = %d, want the two non-witness queues", got)
		}
	})
}

// witnessReceiptFailure injects one failure for the own no-attribute CONFIG of
// the witness queue without mutating the modelled kernel state: either a
// transport error or the kernel's negative NLMSG_ERROR reply. Any other message
// reaches the shipped fake unchanged.
type witnessReceiptFailure struct {
	*fakeNFQueueConn
	queue    uint16
	reply    []netlink.Message
	err      error
	attempts []uint16
}

func (r *witnessReceiptFailure) Execute(message netlink.Message) ([]netlink.Message, error) {
	if queue, ok := noOpConfigQueue(message); ok {
		r.attempts = append(r.attempts, queue)
		if queue == r.queue {
			return r.reply, r.err
		}
	}
	return r.fakeNFQueueConn.Execute(message)
}

// TestLinuxRetirementWitnessReceiptFailureRetainsOwnership pins the negative
// path of the ordered receipt: a witness queue without its matching ACK0 keeps
// the native charge, the durable metadata and both queue bindings, issues no
// further receipt, and never closes or releases the owning socket early.
func TestLinuxRetirementWitnessReceiptFailureRetainsOwnership(t *testing.T) {
	negative := make([]byte, 4)
	rejected := -int32(unix.EPERM)
	binary.NativeEndian.PutUint32(negative, uint32(rejected))
	for _, tc := range []struct {
		name     string
		reply    []netlink.Message
		err      error
		wantText string
	}{
		{name: "rejected-negative-ack",
			reply:    []netlink.Message{{Header: netlink.Header{Type: netlink.Error, Sequence: 9}, Data: negative}},
			wantText: "ordered no-op CONFIG for NFQUEUE"},
		{name: "transport-error", err: errors.New("netlink: permission denied"),
			wantText: "netlink: permission denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := newFakeNFQueueConn("outq-receipt-fail", 0, nil)
			seams := installLinuxCaptureSeams(t, data)
			// The wrapper must be the connection the capture opens, so the seam is
			// replaced before StartCapture; the witness identity is known only
			// after the open and no exchange runs between the two.
			rejector := &witnessReceiptFailure{fakeNFQueueConn: data, reply: tc.reply, err: tc.err}
			dial := seams.dial
			openQueueTransport = func(port uint32) (nfqueueTransport, error) {
				// The seam's dial keeps the kernel/port bookkeeping and binds this
				// port to the wrapped connection; the returned transport is the
				// wrapper that fails exactly one witness receipt.
				if _, err := dial(port); err != nil {
					return nil, err
				}
				return rejector, nil
			}
			engine, lease := newLinuxCaptureLease(t, 15332)
			if err := lease.StartCapture(); err != nil {
				t.Fatalf("start capture: %v", err)
			}
			c := lease.capture.(*linuxCapture)
			rejector.queue = c.queue
			select {
			case <-data.receiving:
			case <-time.After(5 * time.Second):
				t.Fatal("capture loop never entered Receive")
			}

			closeErr := lease.Close(nil)
			if closeErr == nil {
				t.Fatal("Close reported success although the witness queue had no matching ACK0")
			}
			if !strings.Contains(closeErr.Error(), tc.wantText) {
				t.Fatalf("Close error = %v, want it to report %q", closeErr, tc.wantText)
			}
			receiptErr := lease.WaitCaptureRetired()
			if receiptErr == nil {
				t.Fatal("positive capture-retired receipt published for a failed witness receipt")
			}
			if !strings.Contains(receiptErr.Error(), tc.wantText) {
				t.Fatalf("capture-retired receipt = %v, want the same failure", receiptErr)
			}
			if got := engine.ActiveLeases(); got != 1 {
				t.Fatalf("active leases after a failed witness receipt = %d, want the charge retained (1)", got)
			}
			// Exactly one attempt: no retry, no second queue receipt.
			if len(rejector.attempts) != 1 || rejector.attempts[0] != c.queue {
				t.Fatalf("ordered receipts attempted = %v, want one attempt for the witness queue %d", rejector.attempts, c.queue)
			}
			// The owning socket is not closed, the witness is not released and the
			// non-witness queue is not unbound on an unproven order.
			if got := data.closings(); got != 0 {
				t.Fatalf("owning socket closes = %d, want 0 before the ordered receipts complete", got)
			}
			if got := countQueueCommand(t, data.executedMessages(), c.inQueue, nfqCfgCmdUnbind); got != 0 {
				t.Fatalf("non-witness UNBIND commands = %d, want 0 after a failed witness receipt", got)
			}
			if got := countKernelEvents(seams.kernel, "unbind"); got != 0 {
				t.Fatalf("kernel unbinds = %d, want 0 after a failed witness receipt", got)
			}
			if got := countKernelEvents(seams.kernel, "release"); got != 0 {
				t.Fatalf("kernel releases = %d, want 0 before the witness receipt is proven", got)
			}
			bound := seams.kernel.boundQueues()
			if !bound[c.queue] || !bound[c.inQueue] {
				t.Fatalf("queues after a failed witness receipt: %v, want outq and inq still bound", bound)
			}
			// The durable m+p record is retained for recovery.
			if got := fakeCaptureRecords(t, seams, FamilyIPv4); len(got) == 0 {
				t.Fatal("capture metadata was removed although the witness receipt failed")
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || strings.Contains(haystack, needle)
}

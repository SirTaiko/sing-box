//go:build windows

package windivert

// R1323 returned-count storage regressions. HOST INERT: no device, driver,
// filter, socket or native call is touched. Only the two existing native call
// variables of one submission are scripted; beginLane, submit, arm, the
// terminal classification, finishLane and the quarantine transition are the
// production lines.
//
// submit reuses one lane-owned count slot for DeviceIoControl's immediate
// output and GetOverlappedResult's completion output. The slot is zeroed under
// lane serialization before each submission, both calls receive that same slot,
// and the count is copied into ioResult before serialization is released.
// The regressions below pin that storage contract - exact counts
// and errors for inline success, waited completion, synchronous refusal and the
// UNKNOWN classification, the reset that hides the previous submission's count,
// successive reuse of one lane slot and the separation between lanes. The
// absence of the per-submission heap allocation itself is a compiler fact
// (gcflags=-m comparison), not something this test can assert.

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// returnedCountScript is one scripted submission at the two native call
// boundaries. A nil count means the scripted kernel wrote nothing, which is
// what makes a stale lane slot observable.
type returnedCountScript struct {
	pending     bool
	inlineErr   error
	inlineCount *uint32
	status      error
	count       *uint32

	calls     int
	waits     int
	inlinePtr *uint32
	waitPtr   *uint32
}

func installReturnedCountScript(t *testing.T, script *returnedCountScript) {
	t.Helper()
	previousControl := nativeDeviceIoControl
	previousResult := nativeGetOverlappedResult
	nativeDeviceIoControl = func(_ windows.Handle, _ uint32, _ *byte, _ uint32, _ *byte, _ uint32, returned *uint32, _ *windows.Overlapped) error {
		script.calls++
		script.inlinePtr = returned
		if script.inlineCount != nil {
			*returned = *script.inlineCount
		}
		if script.inlineErr != nil {
			return script.inlineErr
		}
		if script.pending {
			return windows.ERROR_IO_PENDING
		}
		return nil
	}
	nativeGetOverlappedResult = func(_ windows.Handle, _ *windows.Overlapped, returned *uint32, _ bool) error {
		script.waits++
		script.waitPtr = returned
		if script.count != nil {
			*returned = *script.count
		}
		return script.status
	}
	t.Cleanup(func() {
		nativeDeviceIoControl = previousControl
		nativeGetOverlappedResult = previousResult
	})
}

// newReturnedCountHandle builds a Handle whose lifecycle gate is real but whose
// lanes own no Win32 event, so no submission reaches a device.
func newReturnedCountHandle() *Handle {
	handle := &Handle{device: windows.Handle(1)}
	handle.gate = newIOLifecycle(nativeCompletionGrace, func(any) {}, func() error { return nil })
	return handle
}

func returnedCountPtr(value uint32) *uint32 {
	return &value
}

// TestSubmitUsesLaneOwnedReturnedSlot pins the storage contract: both native
// calls of one submission are handed the lane's own count slot rather than a
// per-submission local or caller memory; a later submission on the same lane
// reuses exactly that slot.
func TestSubmitUsesLaneOwnedReturnedSlot(t *testing.T) {
	handle := newReturnedCountHandle()
	address := Address{}
	address.SetOutbound(true)
	packet := []byte("count-slot")

	inline := &returnedCountScript{inlineCount: returnedCountPtr(11)}
	installReturnedCountScript(t, inline)
	count, err := handle.Send(packet, &address)
	if err != nil {
		t.Fatalf("inline send: %v", err)
	}
	if count != 11 {
		t.Fatalf("inline send count = %d, want 11", count)
	}
	if inline.inlinePtr != &handle.sendLane.returned {
		t.Fatalf("DeviceIoControl count slot = %p, want the send lane's own %p", inline.inlinePtr, &handle.sendLane.returned)
	}

	waited := &returnedCountScript{pending: true, count: returnedCountPtr(9)}
	installReturnedCountScript(t, waited)
	count, err = handle.Send(packet, &address)
	if err != nil || count != 9 {
		t.Fatalf("waited send = (%d, %v), want (9, nil)", count, err)
	}
	if waited.inlinePtr != &handle.sendLane.returned || waited.waitPtr != waited.inlinePtr {
		t.Fatalf("pending submission used %p and %p, want the single send lane slot %p",
			waited.inlinePtr, waited.waitPtr, &handle.sendLane.returned)
	}

	recv := &returnedCountScript{inlineCount: returnedCountPtr(5)}
	installReturnedCountScript(t, recv)
	recvCount, _, recvErr := handle.Recv(make([]byte, 64))
	if recvErr != nil || recvCount != 5 {
		t.Fatalf("recv = (%d, %v), want (5, nil)", recvCount, recvErr)
	}
	if recv.inlinePtr != &handle.recvLane.returned {
		t.Fatalf("recv count slot = %p, want the receive lane's own %p", recv.inlinePtr, &handle.recvLane.returned)
	}
	if recv.inlinePtr == waited.inlinePtr {
		t.Fatal("the receive and send lanes share one count slot")
	}
}

// TestSubmitResetsLaneReturnedCount pins the reset that makes one submission
// blind to its predecessor's count, including submissions where the driver
// writes nothing (a synchronous refusal and a cancelled wait). The submit seam
// poisons the slot after beginLane and before the zeroing, so the assertion
// proves the reset rather than passing on an accidentally clean slot.
func TestSubmitResetsLaneReturnedCount(t *testing.T) {
	handle := newReturnedCountHandle()
	address := Address{}
	address.SetOutbound(true)
	packet := []byte("reset-count")
	previousHook := handleTestBeforeSubmit
	handleTestBeforeSubmit = func() {
		handle.sendLane.returned = 0xDEADBEEF
	}
	t.Cleanup(func() {
		handleTestBeforeSubmit = previousHook
	})

	success := &returnedCountScript{inlineCount: returnedCountPtr(13)}
	installReturnedCountScript(t, success)
	count, err := handle.Send(packet, &address)
	if err != nil || count != 13 {
		t.Fatalf("first send = (%d, %v), want (13, nil)", count, err)
	}

	refused := &returnedCountScript{inlineErr: windows.ERROR_INVALID_PARAMETER}
	installReturnedCountScript(t, refused)
	count, err = handle.Send(packet, &address)
	if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("synchronous refusal = %v, want the operation status", err)
	}
	if count != 0 {
		t.Fatalf("synchronous refusal count = %d, want 0 (never the previous submission's 13)", count)
	}

	aborted := &returnedCountScript{pending: true, status: windows.ERROR_OPERATION_ABORTED}
	installReturnedCountScript(t, aborted)
	count, err = handle.Send(packet, &address)
	if !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		t.Fatalf("cancelled wait = %v, want the operation status", err)
	}
	if count != 0 {
		t.Fatalf("cancelled wait count = %d, want 0 (never the previous submission's count)", count)
	}
	// Every outcome above was terminal, so the lane is reusable rather than
	// quarantined: this distinguishes the branch each scripted submission took.
	if handle.sendLane.quarantined {
		t.Fatal("a terminal outcome quarantined the send lane")
	}

	reused := &returnedCountScript{pending: true, count: returnedCountPtr(7)}
	installReturnedCountScript(t, reused)
	count, err = handle.Send(packet, &address)
	if err != nil || count != 7 {
		t.Fatalf("reused send = (%d, %v), want (7, nil)", count, err)
	}
}

// TestSubmitUnprovenCompletionKeepsUnknownCountAndQuarantines pins the exact
// unproven classification through the real submit: a waited query that could
// not observe the completion publishes no count (the ioResult count is the
// reset zero, never the previous submission's value), marks the result
// non-terminal and leaves the lane quarantined.
func TestSubmitUnprovenCompletionKeepsUnknownCountAndQuarantines(t *testing.T) {
	handle := newReturnedCountHandle()
	address := Address{}
	address.SetOutbound(true)
	packet := []byte("unknown-count")

	success := &returnedCountScript{inlineCount: returnedCountPtr(21)}
	installReturnedCountScript(t, success)
	count, err := handle.Send(packet, &address)
	if err != nil || count != 21 {
		t.Fatalf("first send = (%d, %v), want (21, nil)", count, err)
	}

	unproven := &returnedCountScript{pending: true, status: windows.ERROR_IO_INCOMPLETE}
	installReturnedCountScript(t, unproven)
	lane := &handle.sendLane
	if err = handle.beginLane(lane); err != nil {
		t.Fatalf("registration: %v", err)
	}
	result := handle.submit(lane, ioctlSend, nil, nil)
	handle.finishLane(lane, result.terminal)
	if result.terminal {
		t.Fatal("an unobserved completion was reported as terminal")
	}
	if result.err == nil {
		t.Fatal("an unobserved completion reported no error")
	}
	if result.count != 0 {
		t.Fatalf("unproven count = %d, want 0 (the reset slot, not the previous 21)", result.count)
	}
	if !lane.quarantined {
		t.Fatal("an unproven completion left the lane reusable")
	}
	if count, err = handle.Send(packet, &address); err == nil || count != 0 {
		t.Fatalf("send on a quarantined lane = (%d, %v), want (0, non-nil)", count, err)
	}
}

// TestControlLaneCountPreservesFullWidth pins that the lane slot carries the
// complete uint32 the native call reported, and that successive control
// submissions on one lane each observe only their own count.
func TestControlLaneCountPreservesFullWidth(t *testing.T) {
	handle := newReturnedCountHandle()
	first := &returnedCountScript{inlineCount: returnedCountPtr(^uint32(0))}
	installReturnedCountScript(t, first)
	count, err := handle.laneIoctl(&handle.ctrlLane, ioctlInitialize, nil, nil)
	if err != nil || count != ^uint32(0) {
		t.Fatalf("control ioctl = (%d, %v), want (%d, nil)", count, err, ^uint32(0))
	}
	if first.inlinePtr != &handle.ctrlLane.returned {
		t.Fatalf("control count slot = %p, want the control lane's own %p", first.inlinePtr, &handle.ctrlLane.returned)
	}

	second := &returnedCountScript{pending: true, count: returnedCountPtr(0x01020304)}
	installReturnedCountScript(t, second)
	count, err = handle.laneIoctl(&handle.ctrlLane, ioctlShutdown, nil, nil)
	if err != nil || count != 0x01020304 {
		t.Fatalf("second control ioctl = (%d, %v), want (16909060, nil)", count, err)
	}
	if second.inlinePtr != &handle.ctrlLane.returned || second.waitPtr != second.inlinePtr {
		t.Fatalf("pending control ioctl used %p and %p, want the single control lane slot %p",
			second.inlinePtr, second.waitPtr, &handle.ctrlLane.returned)
	}
}

//go:build windows

package windivert

// HOST INERT regressions for the synchronous terminal batch view. Only the two
// Win32 calls of one submission are scripted; beginLane, arm, the lane-owned
// storage, the terminal/dimension classification and the single deferred
// terminal cleanup are the production lines. Nothing here is a native
// WinDivert/Windows execution result.

import (
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// batchRecvIoctlUnion is the 16-byte WINDIVERT_IOCTL union buildIoctlRecvBatch
// packs: the address-array pointer and the address-byte-length pointer.
type batchRecvIoctlUnion struct {
	addrs    *Address
	addrsLen *uint32
}

type batchReceipt struct {
	payload      []byte
	addressCount int
	// pending scripts a submission that returns ERROR_IO_PENDING and completes
	// through GetOverlappedResult with status/count.
	pending bool
	status  error
}

// batchFakeNativeIO scripts the driver side of batch submits. It follows the
// ioctl input union exactly as the real driver does, so a view can only alias
// storage the lane itself handed to the kernel.
type batchFakeNativeIO struct {
	mu       sync.Mutex
	receipts []batchReceipt
	next     int
	submits  int
	views    int
	sends    int

	pendingStatus error
	pendingCount  uint32
	// sendPending scripts a send submission that returns ERROR_IO_PENDING and
	// completes through the waited query with sendStatus/sendCount. sendErr is
	// a synchronous send failure. sendReturned is the successful count.
	sendPending  bool
	sendStatus   error
	sendCount    uint32
	sendErr      error
	sendReturned uint32
	// lastPayloadPtr/lastAddrPtr are the exact lane storages the driver wrote.
	lastPayloadPtr unsafe.Pointer
	lastAddrPtr    unsafe.Pointer
	// Observations of the direct-original send submission: which ranges the
	// kernel was handed, and which lane's count slot and OVERLAPPED it used.
	sentPayloadPtr  unsafe.Pointer
	sentAddrsPtr    unsafe.Pointer
	sentAddrsLen    uint64
	sentOutLen      uint32
	sentReturnedPtr unsafe.Pointer
	sentOverlapped  unsafe.Pointer
}

func installBatchFake(t *testing.T, fake *batchFakeNativeIO) {
	t.Helper()
	previousControl := nativeDeviceIoControl
	previousResult := nativeGetOverlappedResult
	nativeDeviceIoControl = func(_ windows.Handle, code uint32, in *byte, inLen uint32, out *byte, outLen uint32, returned *uint32, overlapped *windows.Overlapped) error {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		switch code {
		case ioctlRecv:
			fake.submits++
			if fake.next >= len(fake.receipts) {
				return windows.ERROR_INVALID_FUNCTION
			}
			receipt := fake.receipts[fake.next]
			fake.next++
			if in == nil || inLen < ioctlSize {
				return windows.ERROR_INVALID_PARAMETER
			}
			union := (*batchRecvIoctlUnion)(unsafe.Pointer(in))
			if union.addrs == nil || union.addrsLen == nil {
				return windows.ERROR_INVALID_PARAMETER
			}
			if receipt.addressCount > 0 {
				targets := unsafe.Slice(union.addrs, receipt.addressCount)
				for index := range targets {
					targets[index] = Address{Timestamp: int64(0xA000 + index)}
					targets[index].SetOutbound(index%2 == 1)
				}
				*union.addrsLen = uint32(receipt.addressCount) * uint32(unsafe.Sizeof(Address{}))
			} else {
				*union.addrsLen = 0
			}
			if outLen > 0 && out != nil && len(receipt.payload) > 0 {
				copy(unsafe.Slice(out, outLen), receipt.payload)
			}
			fake.views++
			fake.lastPayloadPtr = unsafe.Pointer(out)
			fake.lastAddrPtr = unsafe.Pointer(union.addrs)
			if receipt.pending {
				fake.pendingStatus = receipt.status
				fake.pendingCount = uint32(len(receipt.payload))
				return windows.ERROR_IO_PENDING
			}
			*returned = uint32(len(receipt.payload))
			return nil
		case ioctlSend:
			fake.sends++
			if in == nil || inLen < ioctlSize || out == nil || outLen == 0 || returned == nil {
				return windows.ERROR_INVALID_PARAMETER
			}
			fake.sentAddrsPtr = *(*unsafe.Pointer)(unsafe.Pointer(in))
			fake.sentAddrsLen = *(*uint64)(unsafe.Add(unsafe.Pointer(in), 8))
			fake.sentPayloadPtr = unsafe.Pointer(out)
			fake.sentOutLen = outLen
			fake.sentReturnedPtr = unsafe.Pointer(returned)
			fake.sentOverlapped = unsafe.Pointer(overlapped)
			if fake.sendErr != nil {
				return fake.sendErr
			}
			if fake.sendPending {
				fake.pendingStatus = fake.sendStatus
				fake.pendingCount = fake.sendCount
				return windows.ERROR_IO_PENDING
			}
			*returned = fake.sendReturned
			if *returned == 0 {
				*returned = outLen
			}
			return nil
		default:
			return windows.ERROR_INVALID_FUNCTION
		}
	}
	nativeGetOverlappedResult = func(_ windows.Handle, _ *windows.Overlapped, returned *uint32, _ bool) error {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		*returned = fake.pendingCount
		return fake.pendingStatus
	}
	t.Cleanup(func() {
		nativeDeviceIoControl = previousControl
		nativeGetOverlappedResult = previousResult
	})
}

// V01: the terminal view is delivered once, under the real lifecycle
// registration and receive-lane serialization, aliases the lane's exact
// receipt with capped slices, and a separate send lane completes while the
// consumer runs. No call is made for unknown progress.
func TestRecvBatchViewSynchronousTerminalDelivery(t *testing.T) {
	handle := newOwnershipTestHandle()
	payload := []byte("terminal-view-batch")
	fake := &batchFakeNativeIO{receipts: []batchReceipt{{payload: payload, addressCount: 2}}}
	installBatchFake(t, fake)

	var (
		calls       int
		raw         []byte
		addrs       []Address
		rawCap      int
		addrCap     int
		pendingKeys int
		recvKey     bool
		sendErr     error
	)
	count, err := handle.RecvBatchView(MTUMax, func(viewRaw []byte, viewAddrs []Address) {
		calls++
		raw, addrs = viewRaw, viewAddrs
		rawCap, addrCap = cap(viewRaw), cap(viewAddrs)
		handle.gate.mu.Lock()
		pendingKeys = len(handle.gate.pending)
		_, recvKey = handle.gate.pending[&handle.recvLane]
		handle.gate.mu.Unlock()
		// The send lane is independent: it registers and completes while the
		// receive lane and its registration are still held by this consumer.
		_, sendErr = handle.SendBatch([]byte("separate-send"), []Address{{}})
	})
	if err != nil {
		t.Fatalf("RecvBatchView: %v", err)
	}
	if count != len(payload) {
		t.Fatalf("RecvBatchView count = %d, want the native byte count %d", count, len(payload))
	}
	if calls != 1 {
		t.Fatalf("consumer calls = %d, want 1", calls)
	}
	if pendingKeys != 1 || !recvKey {
		t.Fatalf("consumer ran with %d registrations (recv registered=%v), want exactly the receive", pendingKeys, recvKey)
	}
	if sendErr != nil {
		t.Fatalf("separate send lane failed while the receive consumer ran: %v", sendErr)
	}
	if !fake.lastPayloadPtrEqual(&handle.recvLane.dataBuf[0]) {
		t.Fatal("driver was not handed the receive lane's payload storage")
	}
	if len(raw) != len(payload) || rawCap != len(payload) || cap(raw) != len(payload) {
		t.Fatalf("payload view len/cap = %d/%d, want %d/%d", len(raw), cap(raw), len(payload), len(payload))
	}
	if unsafe.Pointer(&raw[0]) != unsafe.Pointer(&handle.recvLane.dataBuf[0]) {
		t.Fatal("payload view does not alias the receive lane")
	}
	if len(addrs) != 2 || addrCap != 2 || cap(addrs) != 2 {
		t.Fatalf("address view len/cap = %d/%d, want 2/2", len(addrs), cap(addrs))
	}
	if unsafe.Pointer(&addrs[0]) != unsafe.Pointer(&handle.recvLane.addrs[0]) {
		t.Fatal("address view does not alias the receive lane")
	}
	if addrs[0].Timestamp != 0xA000 || !addrs[1].Outbound() {
		t.Fatal("address view lost the driver-written receipt")
	}
	if handle.recvLane.quarantined {
		t.Fatal("a terminal view left the receive lane quarantined")
	}
	handle.gate.mu.Lock()
	after := len(handle.gate.pending)
	handle.gate.mu.Unlock()
	if after != 0 {
		t.Fatalf("%d registrations remained after the consumer returned", after)
	}
	// The terminal cleanup unlocked the lane: the next receive is accepted.
	fake.receipts = append(fake.receipts, batchReceipt{payload: []byte("second"), addressCount: 1})
	calls = 0
	if count, err = handle.RecvBatchView(MTUMax, func([]byte, []Address) { calls++ }); err != nil || count != len("second") || calls != 1 {
		t.Fatalf("second receive after terminal consumer: count=%d calls=%d err=%v", count, calls, err)
	}
}

// V02: the old allocating and caller-owned APIs keep their exact contracts on
// the shared terminal path: the allocating receipt is detached, the Into
// receipt aliases caller storage, variable counts and raw80 addresses survive.
func TestRecvBatchViewOldAPICompatibility(t *testing.T) {
	handle := newOwnershipTestHandle()
	storage := make([]Address, BatchMax)
	oldReceipts := make([][]Address, 0, 5)
	var expected [][][80]byte
	var fake *batchFakeNativeIO
	for index, count := range []int{3, 1, 5, 2, 4} {
		payload := make([]byte, 20*count)
		for packet := 0; packet < count; packet++ {
			payload[packet*20] = 0x45
			payload[packet*20+2] = 0
			payload[packet*20+3] = 20
		}
		fake = &batchFakeNativeIO{receipts: []batchReceipt{{payload: payload, addressCount: count}}}
		installBatchFake(t, fake)
		buffer := make([]byte, MTUMax)
		n, receipt, err := handle.RecvBatch(buffer)
		if err != nil || n != len(payload) || len(receipt) != count {
			t.Fatalf("batch %d RecvBatch: n=%d addrs=%d err=%v", index, n, len(receipt), err)
		}
		if unsafe.Pointer(&receipt[0]) == unsafe.Pointer(&handle.recvLane.addrs[0]) {
			t.Fatalf("batch %d allocating receipt aliases the lane", index)
		}
		raw := make([][80]byte, count)
		for address := range receipt {
			raw[address] = *(*[80]byte)(unsafe.Pointer(&receipt[address]))
		}
		expected = append(expected, raw)
		oldReceipts = append(oldReceipts, receipt)
		fake.receipts = append(fake.receipts, batchReceipt{payload: payload, addressCount: count})
		n, into, err := handle.RecvBatchInto(buffer, storage)
		if err != nil || n != len(payload) || len(into) != count {
			t.Fatalf("batch %d RecvBatchInto: n=%d addrs=%d err=%v", index, n, len(into), err)
		}
		if unsafe.Pointer(&into[0]) != unsafe.Pointer(&storage[0]) {
			t.Fatalf("batch %d Into receipt does not alias caller storage", index)
		}
		for address := range into {
			if *(*[80]byte)(unsafe.Pointer(&into[address])) != raw[address] {
				t.Fatalf("batch %d Into address %d differs from the allocating receipt", index, address)
			}
		}
	}
	// The earlier allocating receipts stayed detached across later receives.
	for index, receipt := range oldReceipts {
		for address := range receipt {
			if *(*[80]byte)(unsafe.Pointer(&receipt[address])) != expected[index][address] {
				t.Fatalf("allocating receipt %d address %d was overwritten by a later receive", index, address)
			}
		}
	}
	// Preflight rejections allocate no submission and publish no view.
	before := fake.submits
	if _, err := handle.RecvBatchView(MTUMax, nil); err == nil {
		t.Fatal("nil consumer was accepted")
	}
	if _, err := handle.RecvBatchView(MTUMax-1, func([]byte, []Address) {}); err == nil {
		t.Fatal("short view buffer was accepted")
	}
	if _, _, err := handle.RecvBatchInto(make([]byte, MTUMax), make([]Address, BatchMax-1)); err == nil {
		t.Fatal("short Into storage was accepted")
	}
	if _, _, err := handle.RecvBatch(make([]byte, MTUMax-1)); err == nil {
		t.Fatal("short RecvBatch buffer was accepted")
	}
	if fake.submits != before {
		t.Fatalf("preflight rejections reached the driver: %d submits", fake.submits-before)
	}
}

// V01 negative: an unproven completion publishes no view, keeps the lane
// quarantined and reports unknown progress.
func TestRecvBatchViewUnknownCompletionHasNoConsumer(t *testing.T) {
	handle := newOwnershipTestHandle()
	fake := &batchFakeNativeIO{receipts: []batchReceipt{{
		payload: []byte("unproven"), addressCount: 1, pending: true, status: windows.ERROR_IO_INCOMPLETE,
	}}}
	installBatchFake(t, fake)
	calls := 0
	count, err := handle.RecvBatchView(MTUMax, func([]byte, []Address) { calls++ })
	if err == nil || count != unknownProgress || calls != 0 {
		t.Fatalf("unproven completion: count=%d calls=%d err=%v", count, calls, err)
	}
	if !handle.recvLane.quarantined {
		t.Fatal("an unproven view receive left the lane reusable")
	}
	handle.gate.mu.Lock()
	pending := len(handle.gate.pending)
	handle.gate.mu.Unlock()
	if pending != 1 {
		t.Fatalf("unproven completion left %d registrations, want the quarantined receive", pending)
	}
}

// V06: the ordinary empty native drain returns its terminal error without a
// consumer view.
func TestRecvBatchViewEmptyDrainHasNoConsumer(t *testing.T) {
	handle := newOwnershipTestHandle()
	fake := &batchFakeNativeIO{receipts: []batchReceipt{{
		addressCount: 0, pending: true, status: windows.ERROR_NO_DATA,
	}}}
	installBatchFake(t, fake)
	calls := 0
	count, err := handle.RecvBatchView(MTUMax, func([]byte, []Address) { calls++ })
	if count != 0 || calls != 0 || !IsDrained(err) {
		t.Fatalf("empty drain: count=%d calls=%d err=%v drained=%v", count, calls, err, IsDrained(err))
	}
	if handle.recvLane.quarantined {
		t.Fatal("a terminal drain error quarantined the lane")
	}
}

// The single deferred terminal cleanup also runs when the consumer panics: the
// lane is unlocked and the registration is released, and the panic propagates
// (it is never converted into a receive error or a replay).
func TestRecvBatchViewPanicRunsTerminalCleanup(t *testing.T) {
	handle := newOwnershipTestHandle()
	fake := &batchFakeNativeIO{receipts: []batchReceipt{
		{payload: []byte("panic"), addressCount: 1},
		{payload: []byte("after"), addressCount: 1},
	}}
	installBatchFake(t, fake)
	func() {
		defer func() {
			if recovered := recover(); recovered == nil {
				t.Fatal("consumer panic was swallowed")
			}
		}()
		_, _ = handle.RecvBatchView(MTUMax, func([]byte, []Address) { panic("consumer panic") })
	}()
	if handle.recvLane.quarantined {
		t.Fatal("a terminal receipt was quarantined by a consumer panic")
	}
	handle.gate.mu.Lock()
	pending := len(handle.gate.pending)
	handle.gate.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d registrations remained after the panicking consumer", pending)
	}
	calls := 0
	if count, err := handle.RecvBatchView(MTUMax, func([]byte, []Address) { calls++ }); err != nil || count != len("after") || calls != 1 {
		t.Fatalf("lane was not reusable after a panicking consumer: count=%d calls=%d err=%v", count, calls, err)
	}
}

func (f *batchFakeNativeIO) lastPayloadPtrEqual(target *byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastPayloadPtr == unsafe.Pointer(target)
}

// V07: the forwarding companion hands the send lane the exact terminal receive
// payload and raw80 array. It uses the send lane's own returned slot and
// OVERLAPPED, never copies into the send lane's staging buffers, submits once,
// and invalidates the capability when the consumer returns.
func TestRecvBatchViewForwardUsesOriginalBatch(t *testing.T) {
	handle := newOwnershipTestHandle()
	payload := []byte("original-batch-bytes")
	fake := &batchFakeNativeIO{receipts: []batchReceipt{{payload: payload, addressCount: 3}}}
	installBatchFake(t, fake)

	var (
		calls         int
		forwardCount  int
		secondErr     error
		forwardN      int
		forwardErr    error
		duringPending int
		duringRecvKey bool
	)
	count, err := handle.RecvBatchViewForward(MTUMax, func(raw []byte, addrs []Address, forwardOriginal func() (int, error)) {
		calls++
		forwardN, forwardErr = forwardOriginal()
		handle.gate.mu.Lock()
		duringPending = len(handle.gate.pending)
		_, duringRecvKey = handle.gate.pending[&handle.recvLane]
		handle.gate.mu.Unlock()
		forwardCount++
		// A second invocation must not reach the driver.
		_, secondErr = forwardOriginal()
	})
	if err != nil {
		t.Fatalf("RecvBatchViewForward: %v", err)
	}
	if count != len(payload) {
		t.Fatalf("receive count = %d, want %d", count, len(payload))
	}
	if calls != 1 || forwardCount != 1 {
		t.Fatalf("consumer calls=%d forward calls=%d, want 1/1", calls, forwardCount)
	}
	if forwardN != len(payload) || forwardErr != nil {
		t.Fatalf("forward result = %d, %v", forwardN, forwardErr)
	}
	if secondErr == nil {
		t.Fatal("a second capability invocation was accepted")
	}
	if fake.sends != 1 {
		t.Fatalf("native send submissions = %d, want exactly 1", fake.sends)
	}
	if duringPending != 1 || !duringRecvKey {
		t.Fatalf("after direct send: %d registrations (recv=%v), want only the receive", duringPending, duringRecvKey)
	}
	// Payload and addresses are the receive lane's terminal view, not a copy.
	if fake.sentPayloadPtr != unsafe.Pointer(&handle.recvLane.dataBuf[0]) {
		t.Fatal("direct send was not handed the receive payload storage")
	}
	if fake.sentAddrsPtr != unsafe.Pointer(&handle.recvLane.addrs[0]) {
		t.Fatal("direct send was not handed the receive raw80 array")
	}
	if fake.sentAddrsLen != 3*uint64(addressSize) {
		t.Fatalf("direct send address bytes = %d, want %d", fake.sentAddrsLen, 3*uint64(addressSize))
	}
	if fake.sentOutLen != uint32(len(payload)) {
		t.Fatalf("direct send payload length = %d, want %d", fake.sentOutLen, len(payload))
	}
	// The send lane owns the submission metadata.
	if fake.sentReturnedPtr != unsafe.Pointer(&handle.sendLane.returned) {
		t.Fatal("direct send used a returned-count slot other than the send lane's")
	}
	if fake.sentOverlapped != unsafe.Pointer(&handle.sendLane.overlapped) {
		t.Fatal("direct send reused an OVERLAPPED other than the send lane's")
	}
	// No send-lane payload or address staging was allocated or copied.
	if handle.sendLane.dataBuf != nil {
		t.Fatal("direct send copied the payload into the send lane")
	}
	if handle.sendLane.addrs != nil {
		t.Fatal("direct send copied the address array into the send lane")
	}
	if handle.sendLane.quarantined || handle.recvLane.quarantined {
		t.Fatal("a terminal forward quarantined a lane")
	}
	handle.gate.mu.Lock()
	after := len(handle.gate.pending)
	handle.gate.mu.Unlock()
	if after != 0 {
		t.Fatalf("%d registrations remained after the consumer returned", after)
	}
}

// V08: an ordinary pending direct send completes through the unchanged
// submit/arm/wait protocol and keeps the exact completion count.
func TestRecvBatchViewForwardPendingSuccess(t *testing.T) {
	handle := newOwnershipTestHandle()
	payload := []byte("pending-forward")
	fake := &batchFakeNativeIO{
		receipts:    []batchReceipt{{payload: payload, addressCount: 1}},
		sendPending: true,
		sendCount:   uint32(len(payload)),
	}
	installBatchFake(t, fake)
	var n int
	var sendErr error
	count, err := handle.RecvBatchViewForward(MTUMax, func(_ []byte, _ []Address, forwardOriginal func() (int, error)) {
		n, sendErr = forwardOriginal()
	})
	if err != nil || count != len(payload) || sendErr != nil || n != len(payload) {
		t.Fatalf("pending forward: receive=%d/%v send=%d/%v", count, err, n, sendErr)
	}
	if handle.sendLane.quarantined || handle.recvLane.quarantined {
		t.Fatal("pending-success forward quarantined a lane")
	}
	handle.gate.mu.Lock()
	pending := len(handle.gate.pending)
	handle.gate.mu.Unlock()
	if pending != 0 {
		t.Fatalf("%d registrations remained after pending success", pending)
	}
}

// V09: a proven terminal send failure (synchronous error or short count) is a
// visible diagnostic and must not quarantine either lane; the receive lane stays
// reusable for the next batch.
func TestRecvBatchViewForwardTerminalSendFailureReleasesLanes(t *testing.T) {
	for _, test := range []struct {
		name  string
		err   error
		count uint32
	}{
		{name: "error", err: windows.ERROR_ACCESS_DENIED},
		{name: "short", count: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle := newOwnershipTestHandle()
			payload := []byte("terminal-forward")
			fake := &batchFakeNativeIO{
				receipts:     []batchReceipt{{payload: payload, addressCount: 1}},
				sendErr:      test.err,
				sendReturned: test.count,
			}
			installBatchFake(t, fake)
			var sendN int
			var sendErr error
			if _, err := handle.RecvBatchViewForward(MTUMax, func(_ []byte, _ []Address, forwardOriginal func() (int, error)) {
				sendN, sendErr = forwardOriginal()
			}); err != nil {
				t.Fatalf("receive reported the send diagnostic: %v", err)
			}
			if test.err != nil && sendErr == nil {
				t.Fatal("terminal send error was not reported by the capability")
			}
			if test.err == nil && (sendErr != nil || sendN != int(test.count)) {
				t.Fatalf("short terminal completion = %d/%v, want %d/nil", sendN, sendErr, test.count)
			}
			if handle.sendLane.quarantined || handle.recvLane.quarantined {
				t.Fatal("proven terminal send failure quarantined a lane")
			}
			fake.sendErr = nil
			fake.sendReturned = uint32(len("next"))
			fake.receipts = append(fake.receipts, batchReceipt{payload: []byte("next"), addressCount: 1})
			calls := 0
			if count, err := handle.RecvBatchViewForward(MTUMax, func(_ []byte, _ []Address, forwardOriginal func() (int, error)) {
				calls++
				if n, err := forwardOriginal(); err != nil || n != len("next") {
					t.Fatalf("next forward = %d, %v", n, err)
				}
			}); err != nil || count != len("next") || calls != 1 {
				t.Fatalf("receive after terminal send failure: count=%d calls=%d err=%v", count, calls, err)
			}
		})
	}
}

// V10: an unproven direct send keeps BOTH existing lane registrations and
// quarantines BOTH lanes before the consumer's return is cleaned up. The
// capability reports unknown progress, and the receive call keeps its own
// terminal success.
func TestRecvBatchViewForwardUnknownRetainsBothLanes(t *testing.T) {
	handle := newOwnershipTestHandle()
	payload := []byte("unknown-forward")
	fake := &batchFakeNativeIO{
		receipts:    []batchReceipt{{payload: payload, addressCount: 1}},
		sendPending: true,
		sendStatus:  windows.ERROR_IO_INCOMPLETE,
	}
	installBatchFake(t, fake)
	var n int
	var sendErr error
	count, err := handle.RecvBatchViewForward(MTUMax, func(_ []byte, _ []Address, forwardOriginal func() (int, error)) {
		n, sendErr = forwardOriginal()
	})
	if err != nil || count != len(payload) {
		t.Fatalf("receive result = %d/%v, want its own terminal success", count, err)
	}
	if n != unknownProgress || sendErr == nil {
		t.Fatalf("capability result = %d/%v, want unknown progress", n, sendErr)
	}
	if !handle.sendLane.quarantined || !handle.recvLane.quarantined {
		t.Fatalf("unknown forward quarantine: send=%v recv=%v, want both",
			handle.sendLane.quarantined, handle.recvLane.quarantined)
	}
	handle.gate.mu.Lock()
	pending := len(handle.gate.pending)
	_, sendKey := handle.gate.pending[&handle.sendLane]
	_, recvKey := handle.gate.pending[&handle.recvLane]
	handle.gate.mu.Unlock()
	if pending != 2 || !sendKey || !recvKey {
		t.Fatalf("unknown forward registrations = %d (send=%v recv=%v), want both lanes", pending, sendKey, recvKey)
	}
	// The retained receive lane refuses a new receive without touching the
	// driver: the kernel may still read the storage the send was given.
	before := fake.submits
	if _, err := handle.RecvBatchView(MTUMax, func([]byte, []Address) {}); err == nil {
		t.Fatal("a quarantined receive lane accepted a new receive")
	}
	if fake.submits != before {
		t.Fatal("quarantined receive lane reached the driver")
	}
}

// V11: the capability does not outlive its consumer invocation and a nil
// consumer is rejected before any submission.
func TestRecvBatchViewForwardScopeAndPreflight(t *testing.T) {
	handle := newOwnershipTestHandle()
	payload := []byte("scope")
	fake := &batchFakeNativeIO{receipts: []batchReceipt{{payload: payload, addressCount: 1}}}
	installBatchFake(t, fake)
	var escaped func() (int, error)
	_, _ = handle.RecvBatchViewForward(MTUMax, func(_ []byte, _ []Address, forwardOriginal func() (int, error)) {
		escaped = forwardOriginal
	})
	if escaped == nil {
		t.Fatal("capability was not published")
	}
	if n, err := escaped(); err == nil || n != 0 {
		t.Fatalf("out-of-scope capability = %d/%v, want a local rejection", n, err)
	}
	if fake.sends != 0 {
		t.Fatalf("out-of-scope capability reached the driver: %d sends", fake.sends)
	}
	beforeViews := fake.submits
	if _, err := handle.RecvBatchViewForward(MTUMax, nil); err == nil {
		t.Fatal("nil consumer was accepted")
	}
	if fake.submits != beforeViews {
		t.Fatal("nil consumer reached the driver")
	}
}

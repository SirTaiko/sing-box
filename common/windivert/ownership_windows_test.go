//go:build windows

package windivert

// ARCH-04 regressions: a public Recv/Send may return while the kernel still owns
// the submitted operation. The native-accessed storage must therefore be
// operation-owned (never the caller's slice), the address may only be read after
// a terminal receipt, an unproven completion must not report zero progress, and
// the quarantined lane must refuse reuse. Only the two Win32 calls of one
// submission are replaced here; beginLane/arm/finishLane/quarantine/count
// handling are the production lines.

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fakeNativeIO is one scripted submission. It stands in for the driver at the
// two native-call boundaries: it records the exact storage the kernel was
// handed and, on a receive, writes the receipt - payload and WINDIVERT_ADDRESS -
// into the lane-owned buffers the ioctl input union names, exactly as the
// driver does.
type fakeNativeIO struct {
	pending   bool
	status    error // GetOverlappedResult status
	returned  uint32
	onSubmit  func(out []byte)
	submitRan bool
	// driverAddr is the WINDIVERT_ADDRESS this scripted driver writes on a
	// receive. The real driver dereferences the address pointer packed into the
	// ioctl input union and fills that storage, so the fixture cannot publish an
	// address the lane did not itself hand to the driver.
	driverAddr *Address
	// addrTarget is the lane-owned address storage the receive ioctl union must
	// carry. A mismatch is reported: the fixture then refuses to invent a
	// receipt the source never asked for.
	addrTarget *Address

	mu sync.Mutex
	// driverView is the exact payload storage the "kernel" was handed.
	driverView []byte
	// dataPtr is that same storage as a pointer, so a test can prove the driver
	// was handed lane-owned memory and not the caller's slice.
	dataPtr unsafe.Pointer
	// addrWritten records that the scripted driver followed the ioctl input
	// union's address pointer.
	addrWritten bool
}

// recvIoctlUnion is the first word of the 16-byte WINDIVERT_IOCTL union
// buildIoctlRecv packs for a receive: the driver writes the received packet's
// WINDIVERT_ADDRESS through this pointer.
type recvIoctlUnion struct {
	address *Address
}

func installFakeNativeIO(t *testing.T, fake *fakeNativeIO) {
	t.Helper()
	previousControl := nativeDeviceIoControl
	previousResult := nativeGetOverlappedResult
	nativeDeviceIoControl = func(_ windows.Handle, code uint32, in *byte, inLen uint32, out *byte, outLen uint32, returned *uint32, _ *windows.Overlapped) error {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		fake.submitRan = true
		if code == ioctlRecv && fake.addrTarget != nil {
			if in == nil || inLen < ioctlSize {
				t.Errorf("receive ioctl union = %d bytes, want %d carrying the address pointer", inLen, ioctlSize)
				return windows.ERROR_INVALID_PARAMETER
			}
			target := (*recvIoctlUnion)(unsafe.Pointer(in)).address
			if target != fake.addrTarget {
				t.Errorf("receive ioctl address pointer = %p, want the lane-owned storage %p", target, fake.addrTarget)
				return windows.ERROR_INVALID_PARAMETER
			}
			if fake.driverAddr != nil {
				*target = *fake.driverAddr
				fake.addrWritten = true
			}
		}
		if outLen > 0 && out != nil {
			view := unsafe.Slice(out, outLen)
			fake.dataPtr = unsafe.Pointer(out)
			fake.driverView = append([]byte(nil), view...)
			if fake.onSubmit != nil {
				fake.onSubmit(view)
			}
		}
		if fake.pending {
			return windows.ERROR_IO_PENDING
		}
		*returned = fake.returned
		return nil
	}
	nativeGetOverlappedResult = func(_ windows.Handle, _ *windows.Overlapped, returned *uint32, _ bool) error {
		fake.mu.Lock()
		defer fake.mu.Unlock()
		if fake.status == nil {
			*returned = fake.returned
		}
		return fake.status
	}
	t.Cleanup(func() {
		nativeDeviceIoControl = previousControl
		nativeGetOverlappedResult = previousResult
	})
}

// newOwnershipTestHandle builds a Handle whose lifecycle gate is real but whose
// lanes own no Win32 event: beginLane only publishes the lane registration.
func newOwnershipTestHandle() *Handle {
	handle := &Handle{device: windows.Handle(1)}
	handle.gate = newIOLifecycle(nativeCompletionGrace, func(any) {}, func() error { return nil })
	return handle
}

// TestRecvKeepsCallerBufferOutOfNativeIO proves the received bytes land in
// lane-owned storage: the driver view is independent of the caller's buffer, the
// address is only reported for a terminal receipt, and an unproven completion
// reports unknown progress instead of a zero-byte read.
func TestRecvKeepsCallerBufferOutOfNativeIO(t *testing.T) {
	payload := []byte("received-packet-bytes")
	driverAddr := Address{Timestamp: 0x1122334455667788}
	driverAddr.SetOutbound(true)
	handle := newOwnershipTestHandle()
	// The scripted driver writes both lane-owned buffers the ioctl names before
	// its outcome is known, so "nothing was published" cannot pass merely
	// because nothing was written: withholding the receipt is what the
	// completion query has to prove. A waited query that reports
	// ERROR_IO_INCOMPLETE did not observe the completion, which is exactly the
	// status the production classifier treats as unproven.
	fake := &fakeNativeIO{
		pending:    true,
		status:     windows.ERROR_IO_INCOMPLETE,
		driverAddr: &driverAddr,
	}
	fake.onSubmit = func(view []byte) { copy(view, payload) }
	fake.addrTarget = &handle.recvLane.addr
	installFakeNativeIO(t, fake)

	callerBuffer := make([]byte, 64)
	for index := range callerBuffer {
		callerBuffer[index] = 0xEE
	}
	count, address, err := handle.Recv(callerBuffer)
	if err == nil {
		t.Fatal("an unproven completion reported success")
	}
	if count != unknownProgress {
		t.Fatalf("unproven recv count = %d, want %d (unknown progress)", count, unknownProgress)
	}
	if address != (Address{}) {
		t.Fatal("an unproven completion published a driver address")
	}
	for index, value := range callerBuffer {
		if value != 0xEE {
			t.Fatalf("caller buffer byte %d changed on an unproven completion", index)
		}
	}
	if !handle.recvLane.quarantined {
		t.Fatal("an unproven receive left the lane reusable")
	}
	if _, _, err = handle.Recv(callerBuffer); err == nil {
		t.Fatal("a quarantined receive lane accepted a second submission")
	}
	// The fixture only ran if the scripted driver really followed the ioctl
	// input union's address pointer and wrote the payload into the lane's
	// storage; otherwise the assertions above would be vacuous.
	if !fake.addrWritten {
		t.Fatal("the driver never wrote the address through the receive ioctl input")
	}
	if len(fake.driverView) != len(callerBuffer) {
		t.Fatalf("driver view = %d bytes, want %d", len(fake.driverView), len(callerBuffer))
	}
	// The driver never saw the caller's slice.
	if fake.dataPtr == unsafe.Pointer(&callerBuffer[0]) {
		t.Fatal("the driver was handed the caller's slice")
	}
	if lanePtr := unsafe.Pointer(&handle.recvLane.dataBuf[0]); fake.dataPtr != lanePtr {
		t.Fatalf("driver data view at %p, want the lane-owned buffer %p", fake.dataPtr, lanePtr)
	}
}

// TestRecvCopiesOutOnlyAfterTerminalReceipt proves a successful completion
// delivers the bytes and the address, and that a short/terminal failure keeps
// the authoritative status without copying driver bytes into the caller buffer.
func TestRecvCopiesOutOnlyAfterTerminalReceipt(t *testing.T) {
	payload := []byte("packet")
	// Recv zeroes the lane's address at submission, so this receipt can only
	// reach the caller if the driver itself wrote it through the ioctl input
	// union the production code packed for it.
	driverAddr := Address{Timestamp: 0x0102030405060708}
	driverAddr.SetOutbound(true)
	handle := newOwnershipTestHandle()
	fake := &fakeNativeIO{returned: uint32(len(payload)), driverAddr: &driverAddr}
	fake.onSubmit = func(view []byte) { copy(view, payload) }
	fake.addrTarget = &handle.recvLane.addr
	installFakeNativeIO(t, fake)

	buffer := make([]byte, 32)
	count, address, err := handle.Recv(buffer)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if count != len(payload) || string(buffer[:count]) != string(payload) {
		t.Fatalf("recv delivered %d bytes %q, want %q", count, buffer[:count], payload)
	}
	if !address.Outbound() {
		t.Fatal("recv did not report the driver-written address after a terminal receipt")
	}
	if address.Timestamp != driverAddr.Timestamp {
		t.Fatalf("recv address timestamp = %#x, want the driver-written %#x", address.Timestamp, driverAddr.Timestamp)
	}
	if !fake.addrWritten {
		t.Fatal("the driver never wrote the address through the receive ioctl input")
	}
	if handle.recvLane.quarantined {
		t.Fatal("a terminal receive quarantined the lane")
	}

	// A cancelled receive is a terminal operation error: its status is the
	// authoritative result even when the driver already wrote a payload and an
	// address into the lane's storage, and nothing reaches the caller.
	terminalFailure := &fakeNativeIO{
		pending:    true,
		status:     windows.ERROR_OPERATION_ABORTED,
		driverAddr: &driverAddr,
	}
	terminalFailure.onSubmit = func(view []byte) { copy(view, payload) }
	handle = newOwnershipTestHandle()
	terminalFailure.addrTarget = &handle.recvLane.addr
	installFakeNativeIO(t, terminalFailure)
	failedBuffer := make([]byte, 32)
	for index := range failedBuffer {
		failedBuffer[index] = 0xAB
	}
	count, address, err = handle.Recv(failedBuffer)
	if !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
		t.Fatalf("terminal failure = %v, want the operation status", err)
	}
	if count != 0 {
		t.Fatalf("terminal failure count = %d, want the authoritative zero", count)
	}
	if address != (Address{}) {
		t.Fatal("a terminal failure published a driver address")
	}
	for index, value := range failedBuffer {
		if value != 0xAB {
			t.Fatalf("caller buffer byte %d changed on a terminal failure", index)
		}
	}
	// The completion was terminal, so the lane is reusable rather than
	// quarantined: this distinguishes the branch the fixture reached from the
	// unproven one.
	if handle.recvLane.quarantined {
		t.Fatal("a terminal receive failure quarantined the lane")
	}
}

// TestSendSubmitsOperationOwnedBytes proves the kernel is handed a copy: mutating
// the caller's packet after submission cannot change what native I/O reads, and
// an unproven send reports unknown progress and quarantines the lane.
func TestSendSubmitsOperationOwnedBytes(t *testing.T) {
	packet := []byte("client-hello-first-flight")
	fake := &fakeNativeIO{pending: true, status: windows.ERROR_INVALID_HANDLE}
	installFakeNativeIO(t, fake)
	handle := newOwnershipTestHandle()
	address := Address{}
	address.SetOutbound(true)

	count, err := handle.Send(packet, &address)
	if err == nil {
		t.Fatal("an unproven completion reported success")
	}
	if count != unknownProgress {
		t.Fatalf("unproven send count = %d, want %d (unknown progress)", count, unknownProgress)
	}
	if !handle.sendLane.quarantined {
		t.Fatal("an unproven send left the lane reusable")
	}
	if _, err = handle.Send(packet, &address); err == nil {
		t.Fatal("a quarantined send lane accepted a second submission")
	}
	if !fake.submitRan {
		t.Fatal("the submission never reached the native call")
	}
	if string(fake.driverView) != string(packet) {
		t.Fatalf("driver view = %q, want the submitted packet %q", fake.driverView, packet)
	}

	// A successful send keeps its exact authoritative count, including a short
	// write, and the lane stays reusable.
	short := &fakeNativeIO{returned: 7}
	installFakeNativeIO(t, short)
	handle = newOwnershipTestHandle()
	if count, err = handle.Send(packet, &address); err != nil || count != 7 {
		t.Fatalf("short send = (%d, %v), want (7, nil)", count, err)
	}
	if handle.sendLane.quarantined {
		t.Fatal("a proven short send quarantined the lane")
	}
	if _, err = handle.Send(packet, &address); err != nil {
		t.Fatalf("proven terminal send did not release the lane: %v", err)
	}
}

// TestSendCopiesCallerBytesBeforeNativeAccess proves a caller that reuses its
// packet storage while the completion is outstanding cannot change the bytes the
// kernel reads: the native view is still the submitted packet after the caller
// overwrote its own slice.
func TestSendCopiesCallerBytesBeforeNativeAccess(t *testing.T) {
	const submitted = "original-first-flight"
	var nativeViewAfterCallerMutation string
	callerPacket := []byte(submitted)
	fake := &fakeNativeIO{pending: true, status: windows.ERROR_IO_INCOMPLETE}
	fake.onSubmit = func(view []byte) {
		// The caller is free to reuse its slice as soon as the public call
		// returns; emulate that while the "kernel" still holds its view.
		for index := range callerPacket {
			callerPacket[index] = 'X'
		}
		nativeViewAfterCallerMutation = string(view)
	}
	installFakeNativeIO(t, fake)
	handle := newOwnershipTestHandle()
	address := Address{}
	if _, err := handle.Send(callerPacket, &address); err == nil {
		t.Fatal("unproven send reported success")
	}
	if nativeViewAfterCallerMutation != submitted {
		t.Fatalf("native view = %q after the caller reused its buffer, want %q", nativeViewAfterCallerMutation, submitted)
	}
	if want := strings.Repeat("X", len(submitted)); string(callerPacket) != want {
		t.Fatalf("caller slice = %q, want the caller-owned mutation %q", callerPacket, want)
	}
}

//go:build windows

package windivert

// QA470 control-ioctl request-buffer regressions.
//
// A control ioctl carries its request data in the same lane-owned buffer the
// driver answers into: initialize submits the caller-built WINDIVERT_VERSION
// handshake and startup submits the compiled filter program. A lane-owned
// buffer that is not primed with those bytes hands the driver a zeroed request,
// which the authentic driver rejects with STATUS_INVALID_PARAMETER
// (ERROR_INVALID_PARAMETER) and no capture can open. The regressions below
// record the exact bytes at the native DeviceIoControl boundary, so they fail on
// that source and pass only when the caller's request reached the driver
// unchanged. They also pin the ownership half: the boundary buffer is the lane's
// own copy (a caller that reuses its slice cannot change what the driver reads),
// the caller's buffer is written only after a terminal receipt, and an unproven
// completion neither copies out nor recycles the lane.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// controlBoundary scripts one control submission and records what the kernel
// would have read at the native call boundary.
type controlBoundary struct {
	// pending makes DeviceIoControl report ERROR_IO_PENDING; the outcome then
	// comes from status.
	pending bool
	// status is the GetOverlappedResult result on the pending path.
	status error
	// terminal is a synchronous, non-pending DeviceIoControl failure.
	terminal error
	// returned is the reported completion count.
	returned uint32
	// onSubmit runs at the boundary with the exact lane-owned buffer handed to
	// the kernel, before the scripted outcome is produced.
	onSubmit func(request []byte)

	mu       sync.Mutex
	calls    int
	code     uint32
	inBytes  []byte
	outBytes []byte
	outLen   uint32
}

func installControlBoundary(t *testing.T, boundary *controlBoundary) {
	t.Helper()
	previousControl := nativeDeviceIoControl
	previousResult := nativeGetOverlappedResult
	nativeDeviceIoControl = func(_ windows.Handle, code uint32, in *byte, inLen uint32, out *byte, outLen uint32, returned *uint32, _ *windows.Overlapped) error {
		boundary.mu.Lock()
		defer boundary.mu.Unlock()
		boundary.calls++
		boundary.code = code
		boundary.outLen = outLen
		if inLen > 0 {
			boundary.inBytes = append([]byte(nil), unsafe.Slice(in, inLen)...)
		}
		if outLen > 0 {
			if out == nil {
				t.Error("control submission reported an output length without a buffer")
				return windows.ERROR_INVALID_PARAMETER
			}
			view := unsafe.Slice(out, outLen)
			boundary.outBytes = append([]byte(nil), view...)
			if boundary.onSubmit != nil {
				boundary.onSubmit(view)
			}
		}
		if boundary.terminal != nil {
			return boundary.terminal
		}
		if boundary.pending {
			return windows.ERROR_IO_PENDING
		}
		*returned = boundary.returned
		return nil
	}
	nativeGetOverlappedResult = func(_ windows.Handle, _ *windows.Overlapped, returned *uint32, _ bool) error {
		boundary.mu.Lock()
		defer boundary.mu.Unlock()
		if boundary.status != nil {
			return boundary.status
		}
		*returned = boundary.returned
		return nil
	}
	t.Cleanup(func() {
		nativeDeviceIoControl = previousControl
		nativeGetOverlappedResult = previousResult
	})
}

// newControlTestHandle builds a Handle whose lifecycle gate is real but whose
// lanes own no Win32 event: the control submissions below never reach a real
// driver.
func newControlTestHandle() *Handle {
	handle := &Handle{device: windows.Handle(1)}
	handle.gate = newIOLifecycle(nativeCompletionGrace, func(any) {}, func() error { return nil })
	return handle
}

func controlTestRequest(length int) []byte {
	request := make([]byte, length)
	for index := range request {
		request[index] = byte(0xA0 + index%16)
	}
	return request
}

func snapshotControlBoundary(t *testing.T, boundary *controlBoundary) (calls int, code uint32, inBytes, outBytes []byte, outLen uint32) {
	t.Helper()
	boundary.mu.Lock()
	defer boundary.mu.Unlock()
	return boundary.calls, boundary.code, append([]byte(nil), boundary.inBytes...), append([]byte(nil), boundary.outBytes...), boundary.outLen
}

// TestInitializeSendsVersionHandshakeToDriver is the QA470 RED: open failed
// because the driver received an all-zero WINDIVERT_VERSION request instead of
// the caller-built handshake, and answered STATUS_INVALID_PARAMETER.
func TestInitializeSendsVersionHandshakeToDriver(t *testing.T) {
	const priority int16 = 0
	flags := FlagSendOnly
	boundary := &controlBoundary{returned: versionStructSize}
	boundary.onSubmit = func(request []byte) {
		// The driver answers the handshake through the same buffer.
		binary.LittleEndian.PutUint64(request[0:8], magicSYS)
		binary.LittleEndian.PutUint32(request[8:12], versionMajor)
		binary.LittleEndian.PutUint32(request[12:16], versionMinor)
	}
	installControlBoundary(t, boundary)
	handle := newControlTestHandle()

	if err := handle.initialize(LayerNetwork, priority, flags); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	calls, code, inBytes, outBytes, outLen := snapshotControlBoundary(t, boundary)
	if calls != 1 {
		t.Fatalf("initialize submissions = %d, want 1", calls)
	}
	if code != ioctlInitialize {
		t.Fatalf("initialize ioctl code = %#x, want %#x", code, ioctlInitialize)
	}
	if outLen != versionStructSize {
		t.Fatalf("initialize request length at the native boundary = %d, want %d", outLen, versionStructSize)
	}
	wantRequest := make([]byte, versionStructSize)
	binary.LittleEndian.PutUint64(wantRequest[0:8], magicDLL)
	binary.LittleEndian.PutUint32(wantRequest[8:12], versionMajor)
	binary.LittleEndian.PutUint32(wantRequest[12:16], versionMinor)
	binary.LittleEndian.PutUint32(wantRequest[16:20], uint32(unsafe.Sizeof(uintptr(0))*8))
	if !bytes.Equal(outBytes, wantRequest) {
		t.Fatalf("initialize request at the native boundary = % x, want the caller-built WINDIVERT_VERSION % x", outBytes, wantRequest)
	}
	wantIn := buildIoctlInitialize(LayerNetwork, priority, flags)
	if !bytes.Equal(inBytes, wantIn[:]) {
		t.Fatalf("initialize ioctl union = % x, want % x", inBytes, wantIn)
	}
	// The driver's answer must reach the caller only through the terminal
	// copy out; initialize validates that magic, so a nil error above already
	// proves it, and the lane stays reusable.
	if handle.ctrlLane.quarantined {
		t.Fatal("a terminal initialize quarantined the control lane")
	}
}

// TestStartupSendsCompiledFilterToDriver is the second half of the QA470 RED:
// with the handshake fixed, startup still failed because the driver received a
// zeroed buffer instead of the compiled filter program.
func TestStartupSendsCompiledFilterToDriver(t *testing.T) {
	filterBin := make([]byte, 0, 768)
	for index := range cap(filterBin) {
		filterBin = append(filterBin, byte(index*7+3))
	}
	filterFlags := filterFlagOutbound | filterFlagIP
	submitted := append([]byte(nil), filterBin...)
	boundary := &controlBoundary{}
	installControlBoundary(t, boundary)
	handle := newControlTestHandle()

	if err := handle.startup(filterBin, filterFlags); err != nil {
		t.Fatalf("startup: %v", err)
	}

	calls, code, inBytes, outBytes, outLen := snapshotControlBoundary(t, boundary)
	if calls != 1 {
		t.Fatalf("startup submissions = %d, want 1", calls)
	}
	if code != ioctlStartup {
		t.Fatalf("startup ioctl code = %#x, want %#x", code, ioctlStartup)
	}
	if outLen != uint32(len(filterBin)) {
		t.Fatalf("startup request length at the native boundary = %d, want %d", outLen, len(filterBin))
	}
	if !bytes.Equal(outBytes, submitted) {
		t.Fatalf("startup request at the native boundary = % x, want the compiled filter program % x", outBytes, submitted)
	}
	wantIn := buildIoctlStartup(filterFlags)
	if !bytes.Equal(inBytes, wantIn[:]) {
		t.Fatalf("startup ioctl union = % x, want % x", inBytes, wantIn)
	}
}

// TestControlIoctlCopiesRequestOutOfCallerMemory proves the request reaches the
// driver as a lane-owned copy: a caller that reuses its slice while the request
// is visible to the kernel cannot alter what the driver reads, and the driver's
// answer is written back only after the call returns.
func TestControlIoctlCopiesRequestOutOfCallerMemory(t *testing.T) {
	request := controlTestRequest(versionStructSize)
	submitted := append([]byte(nil), request...)
	response := make([]byte, versionStructSize)
	for index := range response {
		response[index] = byte(index ^ 0x5A)
	}
	var driverView string
	boundary := &controlBoundary{returned: versionStructSize}
	boundary.onSubmit = func(view []byte) {
		// The caller is free to reuse its own storage as soon as it stops
		// waiting; emulate that while the kernel's request is outstanding.
		for index := range request {
			request[index] = 0xEE
		}
		driverView = string(view)
		copy(view, response)
	}
	installControlBoundary(t, boundary)
	handle := newControlTestHandle()
	in := buildIoctlStartup(0)

	count, err := handle.laneIoctl(&handle.ctrlLane, ioctlStartup, in[:], request)
	if err != nil {
		t.Fatalf("control ioctl: %v", err)
	}
	if driverView != string(submitted) {
		t.Fatalf("native request view = % x after the caller reused its buffer, want the submitted copy % x", driverView, submitted)
	}
	if string(request) != string(response) {
		t.Fatalf("caller buffer = % x, want the driver's terminal response % x", request, response)
	}
	if count != versionStructSize {
		t.Fatalf("control ioctl count = %d, want %d", count, versionStructSize)
	}
	if handle.ctrlLane.quarantined {
		t.Fatal("a terminal control ioctl quarantined the lane")
	}
	// A proven terminal receipt releases the lane for the next request.
	next := controlTestRequest(ioctlSize)
	nextSubmitted := append([]byte(nil), next...)
	nextIn := buildIoctlShutdown(shutdownBoth)
	if _, err = handle.laneIoctl(&handle.ctrlLane, ioctlShutdown, nextIn[:], next); err != nil {
		t.Fatalf("control lane was not reusable after a terminal receipt: %v", err)
	}
	if _, _, _, outBytes, _ := snapshotControlBoundary(t, boundary); !bytes.Equal(outBytes, nextSubmitted) {
		t.Fatalf("second request at the native boundary = % x, want % x", outBytes, nextSubmitted)
	}
}

// TestControlIoctlWithholdsCopyOutUntilTerminalReceipt proves an unproven
// completion keeps the caller's buffer untouched and quarantines the lane while
// the request itself still reached the driver unchanged.
func TestControlIoctlWithholdsCopyOutUntilTerminalReceipt(t *testing.T) {
	request := controlTestRequest(versionStructSize)
	submitted := append([]byte(nil), request...)
	boundary := &controlBoundary{
		pending:  true,
		status:   windows.ERROR_INVALID_PARAMETER,
		returned: versionStructSize,
	}
	installControlBoundary(t, boundary)
	handle := newControlTestHandle()
	in := buildIoctlInitialize(LayerNetwork, 0, 0)

	if _, err := handle.laneIoctl(&handle.ctrlLane, ioctlInitialize, in[:], request); err == nil {
		t.Fatal("an unproven control completion reported success")
	}
	if !bytes.Equal(request, submitted) {
		t.Fatalf("caller buffer = % x after an unproven completion, want it untouched % x", request, submitted)
	}
	if !handle.ctrlLane.quarantined {
		t.Fatal("an unproven control completion left the lane reusable")
	}
	if _, _, _, outBytes, _ := snapshotControlBoundary(t, boundary); !bytes.Equal(outBytes, submitted) {
		t.Fatalf("request at the native boundary = % x, want % x", outBytes, submitted)
	}
	_, err := handle.laneIoctl(&handle.ctrlLane, ioctlInitialize, in[:], request)
	if err == nil || !strings.Contains(err.Error(), "quarantined") {
		t.Fatalf("quarantined control lane accepted a second submission: %v", err)
	}
}

// TestControlIoctlTerminalFailureKeepsLaneReusable proves a synchronous
// terminal driver status is reported as itself, is not treated as progress and
// still releases the lane for the next request.
func TestControlIoctlTerminalFailureKeepsLaneReusable(t *testing.T) {
	request := controlTestRequest(versionStructSize)
	submitted := append([]byte(nil), request...)
	boundary := &controlBoundary{terminal: windows.ERROR_INVALID_PARAMETER}
	installControlBoundary(t, boundary)
	handle := newControlTestHandle()
	in := buildIoctlInitialize(LayerNetwork, 0, 0)

	_, err := handle.laneIoctl(&handle.ctrlLane, ioctlInitialize, in[:], request)
	if !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("terminal control failure = %v, want the driver status", err)
	}
	if !bytes.Equal(request, submitted) {
		t.Fatalf("caller buffer = % x after a terminal failure, want it untouched % x", request, submitted)
	}
	if handle.ctrlLane.quarantined {
		t.Fatal("a terminal control failure quarantined the lane")
	}

	retry := &controlBoundary{returned: versionStructSize}
	installControlBoundary(t, retry)
	if _, err = handle.laneIoctl(&handle.ctrlLane, ioctlInitialize, in[:], request); err != nil {
		t.Fatalf("control lane was not reusable after a terminal failure: %v", err)
	}
}

// TestShutdownControlIoctlSubmitsNoRequestBuffer pins that the shutdown control
// ioctl, which carries no request payload, still submits its ioctl union and no
// buffer at all.
func TestShutdownControlIoctlSubmitsNoRequestBuffer(t *testing.T) {
	boundary := &controlBoundary{}
	installControlBoundary(t, boundary)
	handle := newControlTestHandle()

	if err := handle.ShutdownRecv(); err != nil {
		t.Fatalf("shutdown recv: %v", err)
	}
	calls, code, inBytes, outBytes, outLen := snapshotControlBoundary(t, boundary)
	if calls != 1 || code != ioctlShutdown {
		t.Fatalf("shutdown submission = (%d, %#x), want (1, %#x)", calls, code, ioctlShutdown)
	}
	if outLen != 0 || len(outBytes) != 0 {
		t.Fatalf("shutdown request buffer = %d bytes % x, want none", outLen, outBytes)
	}
	wantIn := buildIoctlShutdown(shutdownRecv)
	if !bytes.Equal(inBytes, wantIn[:]) {
		t.Fatalf("shutdown ioctl union = % x, want % x", inBytes, wantIn)
	}
}

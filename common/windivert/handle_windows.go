//go:build windows

package windivert

import (
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

// nativeCompletionGrace bounds how long Close waits for canceled native
// operations to produce a terminal receipt before it hands the remaining
// retirement to a background owner. It follows the project's existing bounded
// completion convention (dialer.connectCancelGrace): the caller gets an answer
// quickly, and the native owner stays alive - still charged to its existing
// admission reference - until the kernel proves completion.
const nativeCompletionGrace = 100 * time.Millisecond

// ioLane is one serialized native I/O direction of a handle. It owns its own
// manual-reset event, OVERLAPPED and native packet/address storage, so a pending
// receive can never share a wakeup or native memory with a send or a control
// operation. Lanes are serialized independently: one receive and one send may be
// in flight on the same handle at the same time, and a blocked receive never
// prevents a held-packet send, a receive shutdown or a close from progressing.
type ioLane struct {
	mu         sync.Mutex
	event      windows.Handle
	overlapped windows.Overlapped
	// quarantined marks a lane whose last submission could not be proven
	// terminal. The OVERLAPPED, its event and the native packet/address
	// storage may still be referenced by the kernel, so the lane is never
	// reused and its lifecycle registration stays charged.
	quarantined bool
	// addr is the single-packet WINDIVERT_ADDRESS the driver writes to on
	// receive and reads from on send. It stays reachable until completion.
	addr Address
	// addrs and addrsLen are the batch address array and its byte capacity;
	// on receive the driver replaces addrsLen with the bytes it wrote.
	addrs    []Address
	addrsLen uint32
	// inBuf is the lane-owned control input of the current submission
	// (the 16-byte WINDIVERT_IOCTL union). It is copied out of the caller's
	// stack array before the kernel sees it and is only reused after a proven
	// terminal completion.
	inBuf []byte
	// dataBuf is the lane-owned data buffer of the current submission. Receives
	// are delivered into it and copied to the caller only after a terminal
	// receipt; sends are copied into it before submission, so the kernel never
	// references caller memory that may be reused as soon as the public call
	// returns. The control lane stages its ioctl request and response in the
	// same buffer. A quarantine keeps it reachable with the lane.
	dataBuf []byte
}

// ownedInput returns the lane-owned control input of one submission. A public
// call may return before the kernel produced a terminal receipt, so the ioctl
// union cannot live on the caller's stack across that return.
func (l *ioLane) ownedInput(in []byte) []byte {
	if cap(l.inBuf) < len(in) {
		l.inBuf = make([]byte, len(in))
	}
	l.inBuf = l.inBuf[:len(in)]
	copy(l.inBuf, in)
	return l.inBuf
}

// ownedData returns the lane-owned data buffer of exactly length bytes. Receive
// payloads, send payloads and the control lane's request/response buffer are all
// staged here. The lane is serialized, and the buffer is only recycled after a
// proven terminal completion (an unproven one quarantines the lane), so it can
// never alias an operation the kernel may still reference.
func (l *ioLane) ownedData(length int) []byte {
	if cap(l.dataBuf) < length {
		l.dataBuf = make([]byte, length)
	}
	l.dataBuf = l.dataBuf[:length]
	return l.dataBuf
}

func (l *ioLane) init() error {
	event, err := windows.CreateEvent(nil, 1, 0, nil) // manual reset, unsignaled
	if err != nil {
		return E.Cause(err, "windivert: create io lane event")
	}
	l.event = event
	return nil
}

func (l *ioLane) close() error {
	if l.event == 0 {
		return nil
	}
	if err := windows.CloseHandle(l.event); err != nil {
		// A failed release is not a release. Keep the value for diagnosis and
		// do not retry it blindly: a later handle number may already denote a
		// different object. Done stays open because retirement is unproven.
		return err
	}
	l.event = 0
	return nil
}

// Handle is one WinDivert device handle.
//
// Lifetime invariant: a native operation registers on its lane under the handle
// lifecycle lock before the kernel can see it, and deregisters only after a
// terminal receipt. Closing wins the lifecycle lock, refuses every later
// registration, cancels the registered operations and retires the device and
// events only after their terminal receipts - or, when the kernel does not
// produce one inside the bounded grace, reports a non-success Close and defers
// retirement to the owner that observes the receipts, still reachable through
// Done.
type Handle struct {
	device   windows.Handle
	recvLane ioLane
	sendLane ioLane
	ctrlLane ioLane
	gate     *ioLifecycle
}

func Open(filter *Filter, layer Layer, priority int16, flags Flag) (*Handle, error) {
	err := validateOpenArgs(layer, priority, flags)
	if err != nil {
		return nil, err
	}
	if filter == nil {
		filter = reject()
	}
	filterBin, filterFlags, err := filter.encode()
	if err != nil {
		return nil, err
	}
	device, err := acquireDevice()
	if err != nil {
		return nil, err
	}
	h := &Handle{device: device}
	h.gate = newIOLifecycle(nativeCompletionGrace,
		func(key any) {
			// CancelIoEx addresses one OVERLAPPED, so it cancels exactly the
			// registered operation of that lane and never a neighbor's.
			lane := key.(*ioLane)
			_ = windows.CancelIoEx(h.device, &lane.overlapped)
		},
		func() error { return h.retire() },
	)
	for _, lane := range []*ioLane{&h.recvLane, &h.sendLane, &h.ctrlLane} {
		if err = lane.init(); err != nil {
			// The rollback error is joined, not swallowed: a retirement that
			// could not be proven must stay visible to the caller.
			return nil, h.failedOpen(err)
		}
	}
	if err = h.initialize(layer, priority, flags); err != nil {
		// Rollback completes here unless the kernel refuses to produce a
		// terminal receipt inside the bounded grace; that case is surfaced
		// instead of being hidden behind the open error.
		return nil, h.failedOpen(err)
	}
	if err = h.startup(filterBin, filterFlags); err != nil {
		return nil, h.failedOpen(err)
	}
	return h, nil
}

// failedOpen completes the rollback of an activation that never returned a
// handle. A close that proves retirement leaves only the activation error: the
// caller's admission charge can be discharged immediately because no native
// resource is left. A close that cannot prove retirement returns a
// RetainedOpenError carrying the handle's Done receipt, so the caller can keep
// that charge until the kernel actually releases the device and events instead
// of losing the cleanup owner behind a nil handle.
func (h *Handle) failedOpen(cause error) error {
	closeErr := h.Close()
	if closeErr == nil {
		return cause
	}
	return &RetainedOpenError{err: E.Errors(cause, closeErr), done: h.Done()}
}

func openDevice() (windows.Handle, error) {
	return windows.CreateFile(
		driverDevName,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
}

func validateOpenArgs(layer Layer, priority int16, flags Flag) error {
	if layer != LayerNetwork {
		return E.New("windivert: invalid layer ", uint32(layer))
	}
	if priority < PriorityLowest || priority > PriorityHighest {
		return E.New("windivert: priority out of range")
	}
	const supportedFlags = FlagSniff | FlagSendOnly
	if flags&^supportedFlags != 0 {
		return E.New("windivert: unknown flag bits")
	}
	if flags&FlagSniff != 0 && flags&FlagSendOnly != 0 {
		return E.New("windivert: FlagSniff and FlagSendOnly are mutually exclusive")
	}
	return nil
}

func (h *Handle) initialize(layer Layer, priority int16, flags Flag) error {
	in := buildIoctlInitialize(layer, priority, flags)
	var outBuf [versionStructSize]byte
	binary.LittleEndian.PutUint64(outBuf[0:8], magicDLL)
	binary.LittleEndian.PutUint32(outBuf[8:12], versionMajor)
	binary.LittleEndian.PutUint32(outBuf[12:16], versionMinor)
	binary.LittleEndian.PutUint32(outBuf[16:20], uint32(unsafe.Sizeof(uintptr(0))*8))
	_, err := h.controlIoctl(ioctlInitialize, in[:], outBuf[:])
	if err != nil {
		return E.Cause(err, "windivert: initialize ioctl")
	}
	gotMagic := binary.LittleEndian.Uint64(outBuf[0:8])
	if gotMagic != magicSYS {
		return E.New("windivert: driver magic mismatch (got ", gotMagic, ")")
	}
	gotMajor := binary.LittleEndian.Uint32(outBuf[8:12])
	if gotMajor < versionMajor {
		gotMinor := binary.LittleEndian.Uint32(outBuf[12:16])
		return E.New("windivert: driver version too old: ", gotMajor, ".", gotMinor)
	}
	return nil
}

func (h *Handle) startup(filterBin []byte, filterFlags uint64) error {
	in := buildIoctlStartup(filterFlags)
	_, err := h.controlIoctl(ioctlStartup, in[:], filterBin)
	if err != nil {
		return E.Cause(err, "windivert: startup ioctl")
	}
	return nil
}

// ShutdownRecv stops new driver receive enqueues while preserving the packets
// already queued and the handle's send capability. The queue is drained by
// continuing to receive until Recv returns ERROR_NO_DATA (IsDrained), which is
// the documented end-of-drained-queue status. Every other receive error is a
// real failure, never a silent end of stream.
//
// The ioctl code is pinned against the authentic WinDivert v2.2.2 driver this
// package embeds (assets/WinDivert64.sys, SHA-256 8da08533...): its control
// dispatch accepts 0x12E486 initialize, 0x12E489 startup, 0x12648E recv,
// 0x12E491 send, 0x12649A get-parameter, 0x12E495 set-parameter and 0x12E49D
// shutdown, and rejects everything else with STATUS_INVALID_DEVICE_REQUEST. The
// input is the same 16-byte WINDIVERT_IOCTL union every other control call
// uses, whose first 32-bit word carries WINDIVERT_SHUTDOWN (RECV=1, SEND=2,
// BOTH=3 in the public windivert.h).
func (h *Handle) ShutdownRecv() error {
	in := buildIoctlShutdown(shutdownRecv)
	_, err := h.laneIoctl(&h.ctrlLane, ioctlShutdown, in[:], nil)
	if err != nil {
		return E.Cause(err, "windivert: shutdown recv ioctl")
	}
	return nil
}

// Recv receives one packet into buf. The returned Address is that packet's
// receipt. The kernel writes into lane-owned storage, never into buf: buf is
// filled only after the completion was proven terminal, so a public return can
// never leave the caller's slice referenced by a still-running receive. An
// unproven completion keeps the lane (and that storage) quarantined and reports
// unknownProgress, not a zero-byte read.
func (h *Handle) Recv(buf []byte) (int, Address, error) {
	if len(buf) == 0 {
		return 0, Address{}, E.New("windivert: recv: zero-length buffer")
	}
	lane := &h.recvLane
	if err := h.beginLane(lane); err != nil {
		return 0, Address{}, err
	}
	lane.addr = Address{}
	in := buildIoctlRecv(&lane.addr)
	owned := lane.ownedData(len(buf))
	result := h.submit(lane, ioctlRecv, in[:], owned)
	if !result.terminal {
		h.finishLane(lane, false)
		runtime.KeepAlive(h)
		return unknownProgress, Address{}, result.err
	}
	h.finishLane(lane, true)
	runtime.KeepAlive(h)
	if result.err != nil {
		return 0, Address{}, result.err
	}
	count := int(result.count)
	if count > len(owned) {
		return 0, Address{}, E.New("windivert: recv: driver reported ", count, " bytes for a ", len(owned), "-byte buffer")
	}
	copy(buf, owned[:count])
	return count, lane.addr, nil
}

// BatchMax is WINDIVERT_BATCH_MAX: the driver caps both directions at 255
// packets per ioctl.
const BatchMax = 255

const addressSize = uint32(unsafe.Sizeof(Address{}))

// The driver packs packets back-to-back into buf with no padding and copies
// exactly each packet's IP total length, and returns as soon as at least one
// packet is available.
//
// The returned address slice is a copy: the lane's native array becomes
// reusable as soon as this call returns. The received bytes are written into
// lane-owned storage and copied to buf only after a terminal receipt, so buf is
// never referenced by native I/O after this call returns.
func (h *Handle) RecvBatch(buf []byte) (int, []Address, error) {
	if len(buf) < MTUMax {
		return 0, nil, E.New("windivert: recv batch: buffer smaller than MTUMax")
	}
	lane := &h.recvLane
	if err := h.beginLane(lane); err != nil {
		return 0, nil, err
	}
	if lane.addrs == nil {
		lane.addrs = make([]Address, BatchMax)
	}
	lane.addrsLen = uint32(len(lane.addrs)) * addressSize
	in := buildIoctlRecvBatch(&lane.addrs[0], &lane.addrsLen)
	owned := lane.ownedData(len(buf))
	result := h.submit(lane, ioctlRecv, in[:], owned)
	if !result.terminal {
		h.finishLane(lane, false)
		runtime.KeepAlive(h)
		return unknownProgress, nil, result.err
	}
	// Copy the driver-written addresses while the lane still owns the array,
	// and only when the kernel proved the completion.
	var addrs []Address
	if result.err == nil {
		count := int(lane.addrsLen / addressSize)
		if count > len(lane.addrs) {
			h.finishLane(lane, true)
			runtime.KeepAlive(h)
			return 0, nil, E.New("windivert: recv batch: driver returned ", count, " addresses")
		}
		addrs = make([]Address, count)
		copy(addrs, lane.addrs[:count])
	}
	h.finishLane(lane, true)
	runtime.KeepAlive(h)
	if result.err != nil {
		return 0, nil, result.err
	}
	count := int(result.count)
	if count > len(owned) {
		return 0, nil, E.New("windivert: recv batch: driver reported ", count, " bytes for a ", len(owned), "-byte buffer")
	}
	copy(buf, owned[:count])
	return count, addrs, nil
}

// The driver recovers packet boundaries from the IP total-length fields and
// rejects the whole batch if they do not add up to len(buf). buf is copied into
// lane-owned storage before submission, so the caller may reuse it as soon as
// this call returns even if the completion could not be proven.
func (h *Handle) SendBatch(buf []byte, addrs []Address) (int, error) {
	if len(addrs) == 0 || len(addrs) > BatchMax {
		return 0, E.New("windivert: send batch: invalid packet count ", len(addrs))
	}
	if len(buf) == 0 {
		return 0, E.New("windivert: send batch: empty buffer")
	}
	lane := &h.sendLane
	if err := h.beginLane(lane); err != nil {
		return 0, err
	}
	if lane.addrs == nil {
		lane.addrs = make([]Address, BatchMax)
	}
	copy(lane.addrs, addrs)
	in := buildIoctlSend(&lane.addrs[0], uint32(len(addrs))*addressSize)
	owned := lane.ownedData(len(buf))
	copy(owned, buf)
	result := h.submit(lane, ioctlSend, in[:], owned)
	h.finishLane(lane, result.terminal)
	runtime.KeepAlive(h)
	if !result.terminal {
		// The completion was not observed: neither the count nor the absence
		// of a count describes progress, so it is reported as unknown.
		return unknownProgress, result.err
	}
	if result.err != nil {
		// The reported count belongs to the completion attempt, not to proven
		// progress: the caller must keep the error and never treat this as a
		// successful short write.
		return int(result.count), result.err
	}
	return int(result.count), nil
}

// The address's Outbound flag controls whether the packet is sent toward
// the wire (outbound=true) or delivered up the stack (outbound=false). The
// packet bytes are copied into lane-owned storage before submission.
func (h *Handle) Send(packet []byte, addr *Address) (int, error) {
	if len(packet) == 0 {
		return 0, E.New("windivert: send: empty packet")
	}
	if addr == nil {
		return 0, E.New("windivert: send: nil address")
	}
	lane := &h.sendLane
	if err := h.beginLane(lane); err != nil {
		return 0, err
	}
	lane.addr = *addr
	in := buildIoctlSend(&lane.addr, addressSize)
	owned := lane.ownedData(len(packet))
	copy(owned, packet)
	result := h.submit(lane, ioctlSend, in[:], owned)
	h.finishLane(lane, result.terminal)
	runtime.KeepAlive(h)
	if !result.terminal {
		// See SendBatch: an unproven completion is not zero progress.
		return unknownProgress, result.err
	}
	if result.err != nil {
		// See SendBatch: a failed completion is an error even when it reports a
		// nonzero count, and a successful completion keeps its exact count.
		return int(result.count), result.err
	}
	return int(result.count), nil
}

// controlIoctl runs one control operation on the control lane. It uses the same
// registration and lifetime rules as every other call, so an initialization or
// shutdown operation can never outlive the handle unnoticed.
func (h *Handle) controlIoctl(code uint32, in []byte, out []byte) (uint32, error) {
	return h.laneIoctl(&h.ctrlLane, code, in, out)
}

// laneIoctl serializes one lane, registers the operation against the handle
// lifetime, runs it to a terminal receipt and deregisters it. The control buffer
// is lane-owned in both directions: the caller's request bytes are copied into
// it before submission and the driver's response is copied out only after a
// terminal receipt, so a pending control operation never reads or writes caller
// stack storage.
func (h *Handle) laneIoctl(lane *ioLane, code uint32, in []byte, out []byte) (uint32, error) {
	if err := h.beginLane(lane); err != nil {
		return 0, err
	}
	owned := lane.ownedData(len(out))
	if len(out) > 0 {
		// Two control ioctls carry a caller-built request in this buffer:
		// initialize submits the prefilled WINDIVERT_VERSION handshake and
		// startup submits the compiled filter program. The driver rejects a
		// zeroed request with STATUS_INVALID_PARAMETER, so those request bytes
		// must reach the kernel - but as the lane's own copy, never as caller
		// memory that stays reachable and writable after this call returns.
		copy(owned, out)
	}
	result := h.submit(lane, code, in, owned)
	if !result.terminal {
		h.finishLane(lane, false)
		runtime.KeepAlive(h)
		return 0, result.err
	}
	h.finishLane(lane, true)
	runtime.KeepAlive(h)
	if result.err != nil {
		return result.count, result.err
	}
	if len(out) > 0 {
		copy(out, owned)
	}
	return result.count, nil
}

// beginLane takes the lane's serialization lock and registers the operation
// under the handle lifecycle gate. After closing won the gate no new operation
// may register; a lane waiter queued behind another operation rechecks the gate
// here. A quarantined lane whose completion could not be proven terminal is
// never reused.
func (h *Handle) beginLane(lane *ioLane) error {
	lane.mu.Lock()
	if lane.quarantined {
		lane.mu.Unlock()
		return E.New("windivert: lane is quarantined after an unproven native completion")
	}
	if err := h.gate.begin(lane); err != nil {
		lane.mu.Unlock()
		return err
	}
	// The I/O manager resets the event when the operation starts; the
	// OVERLAPPED itself is lane storage and is never shared between lanes.
	lane.overlapped.HEvent = lane.event
	return nil
}

// finishLane releases a lane after one submission. Only a proven terminal
// status makes the OVERLAPPED and its buffers reusable; an unproven completion
// keeps the lifecycle registration charged and quarantines the lane, so native
// memory the kernel may still reference is never recycled and Close cannot
// certify retirement.
func (h *Handle) finishLane(lane *ioLane, terminal bool) {
	if terminal {
		h.gate.end(lane)
		lane.mu.Unlock()
		return
	}
	lane.quarantined = true
	lane.mu.Unlock()
}

// Done is closed only after every native reference of this handle is retired:
// all registered operations reached a terminal receipt, the device handle and
// all lane events are closed. A Close that had to defer retirement returns a
// non-success error and closes Done later; once Done is closed, a repeated
// Close reports the completed retirement instead of that earlier deferral.
func (h *Handle) Done() <-chan struct{} {
	return h.gate.Done()
}

// Close is idempotent and safe from any goroutine, including while a receive or
// send is blocked. It refuses new native operations, cancels the registered
// ones and retires the device and events only after their terminal receipts.
func (h *Handle) Close() error {
	return h.gate.Close()
}

// retire releases the device and the lane events. It runs only after every
// registered operation is terminal.
func (h *Handle) retire() error {
	var errs []error
	for _, lane := range []*ioLane{&h.recvLane, &h.sendLane, &h.ctrlLane} {
		if err := lane.close(); err != nil {
			errs = append(errs, err)
		}
	}
	if h.device != 0 {
		if err := windows.CloseHandle(h.device); err != nil {
			// Keep the value: a failed release means the device is not retired,
			// so Done must not close and no blind retry is attempted.
			errs = append(errs, err)
		} else {
			h.device = 0
		}
	}
	return E.Errors(errs...)
}

// IsDrained reports whether err is the documented end-of-drained-queue status a
// receive returns after ShutdownRecv delivered every queued packet.
func IsDrained(err error) bool {
	return errors.Is(err, windows.ERROR_NO_DATA)
}

// IOCTL codes from windivert_device.h. CTL_CODE macro layout:
//
//	(DeviceType << 16) | (Access << 14) | (Function << 2) | Method
const (
	fileDeviceNetwork uint32 = 0x12
	accessReadWrite   uint32 = 3 // FILE_READ_DATA | FILE_WRITE_DATA
	accessRead        uint32 = 1

	methodInDirect  uint32 = 1
	methodOutDirect uint32 = 2
)

func ctlCode(deviceType, access, function, method uint32) uint32 {
	return (deviceType << 16) | (access << 14) | (function << 2) | method
}

var (
	ioctlInitialize = ctlCode(fileDeviceNetwork, accessReadWrite, 0x921, methodOutDirect)
	ioctlStartup    = ctlCode(fileDeviceNetwork, accessReadWrite, 0x922, methodInDirect)
	ioctlRecv       = ctlCode(fileDeviceNetwork, accessRead, 0x923, methodOutDirect)
	ioctlSend       = ctlCode(fileDeviceNetwork, accessReadWrite, 0x924, methodInDirect)
	// ioctlShutdown is the ninth control entry of the embedded v2.2.2 driver's
	// dispatch: function 0x927, METHOD_IN_DIRECT, FILE_READ_DATA|FILE_WRITE_DATA.
	ioctlShutdown = ctlCode(fileDeviceNetwork, accessReadWrite, 0x927, methodInDirect)
)

// WINDIVERT_SHUTDOWN from windivert.h.
const (
	shutdownRecv uint32 = 1
	shutdownSend uint32 = 2
	shutdownBoth uint32 = 3
)

// Magic numbers exchanged during INITIALIZE. DLL sends magicDLL in the
// version struct; driver returns magicSYS on success.
const (
	magicDLL uint64 = 0x4C4C447669645724 // "$WdivDLL" in LE bytes
	magicSYS uint64 = 0x5359537669645723 // "#WdivSYS" in LE bytes
)

const (
	versionMajor uint32 = 2
	versionMinor uint32 = 2
)

// Size of the WINDIVERT_IOCTL union on wire (packed).
const ioctlSize = 16

// Size of WINDIVERT_VERSION on wire (packed). Only the first 20 bytes
// carry data; the rest is reserved zero padding.
const versionStructSize = 64

// ioResult carries one submission's outcome. terminal reports that the kernel
// produced a terminal status for this exact request (synchronously or through
// the completion), which is the only condition under which the lane's memory
// may be reused or retired.
type ioResult struct {
	count    uint32
	terminal bool
	err      error
}

// unknownProgress is the count a public call reports when its submission could
// not be observed to completion. It is deliberately not zero: an unproven
// completion says nothing about how much of the data the kernel/target already
// consumed, and a zero would invite a caller to treat it as "nothing happened"
// and replay work whose ownership is still with the kernel. The matching error
// is always non-nil.
const unknownProgress = -1

// handleTestBeforeSubmit is a test seam and is nil in production. The Windows
// regression uses it to hold the exact registration/submission window open, so
// the close-versus-submission barrier is deterministic instead of relying on a
// sleep that merely favors the kernel entry.
var handleTestBeforeSubmit func()

// nativeDeviceIoControl and nativeGetOverlappedResult are the two native calls
// of one submission. They are variables only so the submission protocol - lane
// storage ownership, quarantine, terminal classification, counts and the
// close-versus-submission barrier - can be exercised deterministically without
// the driver; production always calls the Win32 functions below. Replacing them
// does not change any other production line: beginLane, arm, the cancellation
// decision and finishLane all still run for real.
var (
	nativeDeviceIoControl     = windows.DeviceIoControl
	nativeGetOverlappedResult = windows.GetOverlappedResult
)

// submit runs one overlapped device control to a terminal receipt or reports
// that the query could not prove one.
//
// Registration happened in beginLane, before the kernel saw the call. The
// remaining half of the protocol is here: when the submission reports pending,
// arm() publishes that the request is now visible, and if Close won meanwhile
// this call cancels its own request. This closes the window in which a
// Close-time CancelIoEx ran before the request existed.
//
// The ioctl union is copied into lane-owned storage first: out is already
// lane-owned by the caller (received payload/version output or the copied send
// bytes), so no caller-provided memory is handed to the driver. Once this
// function returns an unproven completion, the caller keeps the lane charged
// and quarantined, which keeps that storage reachable.
//
// A pending submission is not a terminal receipt. The wait below distinguishes:
//   - a successful completion (count is authoritative, including short counts);
//   - a terminal operation error, which completes the request and frees the
//     lane memory;
//   - a failed completion query, which leaves ownership unproven: the caller
//     must keep the lane and lifecycle registration charged.
func (h *Handle) submit(lane *ioLane, code uint32, in []byte, out []byte) ioResult {
	if handleTestBeforeSubmit != nil {
		handleTestBeforeSubmit()
	}
	var inPtr *byte
	var inLen uint32
	if len(in) > 0 {
		ownedIn := lane.ownedInput(in)
		inPtr = &ownedIn[0]
		inLen = uint32(len(ownedIn))
	}
	var outPtr *byte
	var outLen uint32
	if len(out) > 0 {
		outPtr = &out[0]
		outLen = uint32(len(out))
	}
	var returned uint32
	overlapped := &lane.overlapped
	err := nativeDeviceIoControl(h.device, code, inPtr, inLen, outPtr, outLen, &returned, overlapped)
	if err == nil {
		return ioResult{count: returned, terminal: true}
	}
	if !errors.Is(err, windows.ERROR_IO_PENDING) {
		// The request never became pending: the kernel reported this
		// operation's terminal failure synchronously and holds no reference to
		// the lane.
		return ioResult{count: returned, terminal: true, err: err}
	}
	// The request is now visible to the kernel. Publish that and re-check the
	// gate: a Close whose cancellation missed this submission is compensated
	// here by a cancellation of exactly this OVERLAPPED.
	if h.gate.arm(lane) {
		_ = windows.CancelIoEx(h.device, overlapped)
	}
	// Waiting for the completion is not the same as shortcutting the wait. A
	// canceled operation completes with ERROR_OPERATION_ABORTED; a successful
	// completion that raced the cancellation keeps its authoritative count.
	err = nativeGetOverlappedResult(h.device, overlapped, &returned, true)
	if err == nil {
		return ioResult{count: returned, terminal: true}
	}
	if unprovenCompletionStatus(err) {
		return ioResult{count: returned, terminal: false, err: E.Cause(err,
			"windivert: native completion could not be observed; ownership retained")}
	}
	return ioResult{count: returned, terminal: true, err: err}
}

// unprovenCompletionStatus reports whether a failed GetOverlappedResult means
// the request's terminal status was not observed, as opposed to a terminal
// operation result.
//
// With bWait=TRUE the documented behavior is to wait until the operation
// completes and report its status, so ERROR_IO_INCOMPLETE cannot be returned on
// that path; it is classified conservatively anyway because treating a
// still-pending request as reusable memory is the hazard this distinction
// exists to prevent. ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER and
// ERROR_NOT_FOUND mean the API could not consult the request itself (the
// operation may still be running), so ownership stays unproven rather than
// being concluded from a query failure. Every other status returned by the
// waited query is the request's own terminal completion status
// (ERROR_OPERATION_ABORTED for cancellation, driver statuses for refused
// control operations).
func unprovenCompletionStatus(err error) bool {
	return errors.Is(err, windows.ERROR_IO_INCOMPLETE) ||
		errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
		errors.Is(err, windows.ERROR_INVALID_PARAMETER) ||
		errors.Is(err, windows.ERROR_NOT_FOUND)
}

func buildIoctlInitialize(layer Layer, priority int16, flags Flag) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint32(buf[0:4], uint32(layer))
	// The driver expects priority + WINDIVERT_PRIORITY_HIGHEST (30000) so
	// the low range maps to non-negative integers.
	binary.LittleEndian.PutUint32(buf[4:8], uint32(int32(priority)+int32(PriorityHighest)))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(flags))
	return buf
}

func buildIoctlStartup(filterFlags uint64) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], filterFlags)
	return buf
}

// The driver dereferences the packed pointer to write the received packet's
// WINDIVERT_ADDRESS.
func buildIoctlRecv(addr *Address) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(uintptr(unsafe.Pointer(addr))))
	binary.LittleEndian.PutUint64(buf[8:16], 0)
	return buf
}

// addr_len_ptr carries the Address array capacity in bytes; the driver
// overwrites it with the bytes actually written (packet count × 80).
func buildIoctlRecvBatch(addrs *Address, addrsLen *uint32) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(uintptr(unsafe.Pointer(addrs))))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(uintptr(unsafe.Pointer(addrsLen))))
	return buf
}

func buildIoctlSend(addrs *Address, addrsLen uint32) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint64(buf[0:8], uint64(uintptr(unsafe.Pointer(addrs))))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(addrsLen))
	return buf
}

// buildIoctlShutdown carries WINDIVERT_SHUTDOWN in the first 32-bit word of the
// same 16-byte WINDIVERT_IOCTL union the other control calls use.
func buildIoctlShutdown(how uint32) [ioctlSize]byte {
	var buf [ioctlSize]byte
	binary.LittleEndian.PutUint32(buf[0:4], how)
	return buf
}

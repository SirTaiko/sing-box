//go:build windows

package desync

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/windows"
)

type windowsBackend struct{}

func NewNativeBackend() Backend { return windowsBackend{} }

func (windowsBackend) Name() string { return "windows-windivert" }

func (windowsBackend) Open(lease *Lease) (Capture, error) {
	capture, err := openWindowsCapture(lease)
	if capture == nil {
		return nil, err // never return a typed-nil retained owner
	}
	return capture, err
}

// openWindowsCapture composes one capture's whole native lifetime: the admitted
// lease is charged before the first native resource exists, every opened
// handle is released only after the kernel proved device/event retirement, and
// a partial open tears down exactly what it created.
func openWindowsCapture(lease *Lease) (*windowsCapture, error) {
	endpoint := lease.Endpoint()
	// The existing admission budget is the owner of this capture. Acquiring the
	// native hold before the first handle means a delayed retirement keeps the
	// charged slot (MaxLeases=1 cannot admit a replacement) until the real
	// terminal receipt, instead of a live Go reference being mistaken for
	// admission.
	release, err := lease.AcquireNativeHold()
	if err != nil {
		return nil, err
	}
	capture := &windowsCapture{
		lease:       lease,
		done:        make(chan struct{}),
		dispatch:    newCaptureDispatchGate(),
		releaseHold: release,
	}
	if err = capture.open(endpoint); err != nil {
		// teardown closes every handle that was opened, joins nothing that was
		// never started, and releases the hold only when retirement is proven.
		// Preserve the same rollback owner for Lease.Close as well as its
		// activation diagnostic. A late native receipt must reach the Lease.
		return capture, E.Errors(err, capture.abortOpen())
	}
	return capture, nil
}

// open acquires every native resource before any receive loop starts. A
// failure at any position therefore has no loop to join and no unowned
// receiver; the unified teardown still handles every position identically.
func (c *windowsCapture) open(endpoint Endpoint) error {
	outFilter, err := openCaptureFilter(c.lease, true)
	if err != nil {
		return err
	}
	// The filter dump is the explicit --wf-save equivalent: it happens when
	// the capture is actually activated, only for a configured path, and its
	// failure is a real activation error (the operator asked for it).
	if config := c.lease.Engine().Config().Capture; config.windows != nil {
		if err = config.windows.writeFilterDump(endpoint); err != nil {
			return err
		}
	}
	outbound, err := windivert.Open(outFilter, windivert.LayerNetwork, 0, captureDivertFlags)
	if err != nil {
		return c.recordRetainedOpen(err)
	}
	c.outbound = outbound
	// The reply side is a second, explicitly inbound handle scoped to the
	// reverse of the owned tuple. Direction is carried by the handle/filter and
	// by each captured address; it is never inferred from payload shape.
	if endpoint.Destination.IsValid() {
		inFilter, filterErr := openCaptureFilter(c.lease, false)
		if filterErr != nil {
			return filterErr
		}
		inbound, openErr := windivert.Open(inFilter, windivert.LayerNetwork, 0, captureDivertFlags)
		if openErr != nil {
			return c.recordRetainedOpen(openErr)
		}
		c.inbound = inbound
	}
	if c.lease.Engine().Config().Capture.filterTTLExpiredICMP {
		icmpFilter, filterErr := icmpErrorFilter(c.lease)
		if filterErr != nil {
			return filterErr
		}
		icmpHandle, openErr := windivert.Open(icmpFilter, windivert.LayerNetwork, 0, captureDivertFlags)
		if openErr != nil {
			return c.recordRetainedOpen(openErr)
		}
		c.icmp = icmpHandle
	}
	// Only now, with every handle the loops observe already owned, may a receive
	// user start. No partial-open position can leave a loop running behind a
	// failed activation.
	c.startUsers()
	return nil
}

// captureDivertFlags selects normal diverting handles: the driver hands the
// packet to this capture and waits for exactly one terminal disposition from it.
// FlagSniff is observation-only (the original is copied and always forwarded),
// so it can neither hold, replace nor drop a packet and must never be used by a
// capture that decides dispositions. FlagDrop/FlagSendOnly are equally wrong
// here: the interceptor must decide, not the driver.
const captureDivertFlags = windivert.Flag(0)

// icmpErrorFilter builds the owned time-exceeded filter. The address narrowing
// is used whenever the attempt's local address is concrete; otherwise the
// filter is narrowed by the owned interface index and every packet is still
// validated against the owned tuple before a drop, so it is never a host-wide
// capture. Parameter-problem messages are not matched.
func icmpErrorFilter(lease *Lease) (*windivert.Filter, error) {
	endpoint := lease.Endpoint()
	ipv6 := endpoint.Family == FamilyIPv6
	local := lease.LocalAddress()
	address := local.Addr()
	var filter *windivert.Filter
	var err error
	if address.IsValid() && !address.IsUnspecified() && address.Is6() == ipv6 {
		filter, err = windivert.InboundICMPTimeExceeded([]netip.Addr{address})
	} else if endpoint.InterfaceIndex != 0 {
		filter, err = windivert.InboundICMPTimeExceededFamily(ipv6)
	} else {
		return nil, fmt.Errorf("desync: capture.filter_ttl_expired_icmp needs an actual local address or owned interface: the owned attempt has neither, so no bounded ICMP capture can be installed")
	}
	if err != nil {
		return nil, err
	}
	if endpoint.InterfaceIndex != 0 {
		interfaceFilter, interfaceErr := windivert.InterfaceIndex(endpoint.InterfaceIndex, 0)
		if interfaceErr != nil {
			return nil, interfaceErr
		}
		filter, err = windivert.And(filter, interfaceFilter)
		if err != nil {
			return nil, err
		}
	}
	if count := filter.InstructionCount(); count < 0 {
		return nil, fmt.Errorf("desync: capture.filter_ttl_expired_icmp filter does not compile")
	}
	return filter, nil
}

// openCaptureFilter builds the kernel filter for one direction. When
// capture.windows is configured the filter is the composed envelope AND user
// expression AND non-LAN exclusion; otherwise the plain owned envelope is
// used. Both directions come from the single owned envelope builder.
func openCaptureFilter(lease *Lease, outbound bool) (*windivert.Filter, error) {
	endpoint := lease.Endpoint()
	config := lease.Engine().Config().Capture
	if config.windows != nil {
		return config.windows.captureFilter(endpoint, outbound)
	}
	return windowsFilter(endpoint, outbound)
}

// windowsFilter is the plain (unconfigured) capture path's filter builder. It is
// deliberately a thin alias of the shared owned envelope so the plain and
// configured paths cannot diverge. It lives with the shared builder (not in the
// Windows-only backend file) so the shared-builder property is testable on every
// platform.

type windowsCapture struct {
	lease    *Lease
	outbound *windivert.Handle
	inbound  *windivert.Handle
	// icmp is the owned time-exceeded handle. It exists only when
	// capture.filter_ttl_expired_icmp is enabled and an actual ownership fact
	// (local address or interface index) can bound it.
	icmp        *windivert.Handle
	done        chan struct{}
	wg          sync.WaitGroup
	startOnce   sync.Once
	receiveOnce sync.Once
	// Outbound storage is one capture-owned bounded ledger, not one per peer.
	// A slot stays charged across dequeue and semantic Hold until both worker
	// nonuse and a known terminal disposition. Publication is NOT dispatch.
	rxMu                                sync.Mutex
	rxCond                              *sync.Cond
	records                             [windowsReceiveRecords]windowsReceiveRecord
	queue                               [windowsReceiveRecords]uint16
	queueHead, queueCount               int
	usedRecords, usedRawBytes           int
	sequence                            uint64
	readerDone, receiveHalt, sendUnsafe bool
	capacityErr                         error
	scratch                             windowsReceiveRecord
	receiveBuffer                       []byte

	// dispatch is the ordered close gate: it fences new semantic dispatch,
	// waits for the records already being handled, and holds records captured
	// after the fence until the lease released the older held originals.
	dispatch *captureDispatchGate

	// stopOnce records the single receive-shutdown attempt and its result. The
	// shutdown is issued by StopReceive only after the lease paused the endpoint
	// producers, never by the semantic quiesce.
	stopOnce sync.Once
	stopErr  error

	// drainMu guards the receive errors that made the queue non-drained. They
	// are diagnostics of a failed drain, never a successful end of stream.
	drainMu     sync.Mutex
	drainErrors [3]windowsErrorSummary
	drained     [3]bool
	// A terminal send error is a delivery diagnostic, not a missing safe
	// receipt. Unknown completion still owns native buffers and forbids Close.
	sendErrors     [2]windowsErrorSummary
	sendIncomplete bool
	// Optional lanes have no new FIFO; on unknown progress retain their one
	// existing buffer/address instead of losing it when the receive user exits.
	optionalRetained [2]windowsReceiveRecord

	closeOnce sync.Once
	closeErr  error
	retired   bool // read only after Close's once has joined teardown

	// releaseHold discharges this capture's native admission reference exactly
	// once, only after the receive users joined and every handle's Done proved
	// that its device and events retired.
	releaseHold func()
	releaseOnce sync.Once

	// retainedReceipts are the retirement receipts of failed inner Opens whose
	// native resources could not be proven released when Open returned. They
	// are not opened handles of this capture (no receive loop, no disposition
	// path uses them), but their device/events still exist, so this capture's
	// admission reference must stay charged until each receipt closes.
	retainedReceipts []<-chan struct{}
}

// captureDrainGrace bounds the caller of a failed activation rollback. The
// Lease supplies the ordinary Close bound; neither bound grants permission to
// cancel a retained original or retire a handle before the receive users join.
const captureDrainGrace = 2 * time.Second

const (
	windowsReceiveRecords  = 256
	windowsReceiveRawBytes = 8 << 20
)

var (
	errWindowsReceiveCapacity = errors.New("desync: Windows receive staging capacity exhausted")
	errWindowsReceiveUnproven = errors.New("desync: Windows received storage/disposition unproven")
)

// Fixed descriptors/ring: no per-record channel, goroutine or error history.
// Full address bytes include the blank union which struct comparison ignores.
type windowsReceiveRecord struct {
	raw                                        []byte
	address                                    [80]byte
	sequence                                   uint64
	occupied, worker, claimed, terminal, ready bool
}

type windowsErrorSummary struct {
	first error
	count uint64
}

func (s *windowsErrorSummary) add(err error) bool {
	first := s.first == nil
	if first {
		s.first = err
	}
	if s.count != ^uint64(0) {
		s.count++
	}
	return first
}

func (s windowsErrorSummary) err() error {
	if s.first == nil {
		return nil
	}
	return fmt.Errorf("%w (occurrences: %d)", s.first, s.count)
}

func copyWindowsAddress(dst, src *windivert.Address) {
	*(*[80]byte)(unsafe.Pointer(dst)) = *(*[80]byte)(unsafe.Pointer(src))
}

func (c *windowsCapture) initReceive() {
	c.receiveOnce.Do(func() {
		c.rxCond = sync.NewCond(&c.rxMu)
		c.receiveBuffer = make([]byte, windivert.MTUMax)
	})
}

// Normal start and partial-open rollback use exactly the same users. Register
// every user before launching any; nothing fallible occurs between launches.
func (c *windowsCapture) startUsers() {
	c.startOnce.Do(func() {
		c.initReceive()
		users := 0
		if c.outbound != nil {
			users += 2
		}
		if c.inbound != nil {
			users++
		}
		if c.icmp != nil {
			users++
		}
		c.wg.Add(users)
		if c.outbound != nil {
			go c.outboundWorker()
			go c.loop()
		}
		if c.inbound != nil {
			go c.inboundLoop()
		}
		if c.icmp != nil {
			go c.icmpLoop()
		}
	})
}

// Never wait for producers/callbacks here, including the public Close's bound.
func (c *windowsCapture) failCapture(err error) {
	if c.lease == nil {
		return
	}
	c.lease.producers.fail(err)
	c.FenceDispatch() // also covers an Open not yet attached to its Lease
	c.lease.startClose(err)
}

// Charge copy-in-progress before allocation. Subtraction avoids overflow;
// invalid counters cannot admit another record. Dequeue/Hold return no credit.
func (c *windowsCapture) reserveRecordLocked(n int) *windowsReceiveRecord {
	if n <= 0 || n > windivert.MTUMax || c.usedRecords < 0 || c.usedRecords >= windowsReceiveRecords || c.usedRawBytes < 0 || c.usedRawBytes > windowsReceiveRawBytes || n > windowsReceiveRawBytes-c.usedRawBytes {
		return nil
	}
	for i := range c.records {
		r := &c.records[i]
		if !r.occupied {
			*r = windowsReceiveRecord{occupied: true, worker: true, sequence: c.sequence}
			c.usedRecords++
			c.usedRawBytes += n
			return r
		}
	}
	return nil
}

// In-budget this reader only receives, validates, reserves, copies and publishes.
// Failed-mode scratch rendezvous is the explicit saturation boundary, NOT a
// claim of losslessness for packets still below native receive.
func (c *windowsCapture) loop() {
	defer c.wg.Done()
	defer close(c.done)
	c.initReceive()
	defer func() { c.rxMu.Lock(); c.readerDone = true; c.rxCond.Broadcast(); c.rxMu.Unlock() }()
	buffer := c.receiveBuffer
	for {
		c.rxMu.Lock()
		halt := c.receiveHalt
		exhausted := c.sequence == ^uint64(0)
		c.rxMu.Unlock()
		if halt {
			return
		}
		if exhausted {
			c.recordDrainError("outbound", errors.New("desync: Windows receive sequence exhausted"))
			return
		}
		length, address, err := c.outbound.Recv(buffer)
		if err != nil && windivert.IsDrained(err) {
			c.markDrained(0)
			return
		}
		if err != nil || length <= 0 || length > len(buffer) {
			// Invalid/unknown lengths never index a slice. Keep the one scratch.
			c.rxMu.Lock()
			c.scratch = windowsReceiveRecord{raw: buffer, occupied: true, address: *(*[80]byte)(unsafe.Pointer(&address))}
			c.rxMu.Unlock()
			if err == nil {
				err = fmt.Errorf("desync: invalid Windows receive length %d", length)
			}
			c.recordDrainError("outbound", err)
			return
		}
		c.rxMu.Lock()
		c.sequence++ // checked before receive; only this reader advances it
		if c.sendUnsafe {
			c.scratch = windowsReceiveRecord{raw: buffer[:length], occupied: true, sequence: c.sequence, address: *(*[80]byte)(unsafe.Pointer(&address))}
			c.rxMu.Unlock()
			return
		}
		var record *windowsReceiveRecord
		if c.capacityErr == nil {
			record = c.reserveRecordLocked(length)
		}
		if record == nil {
			c.scratch = windowsReceiveRecord{raw: buffer[:length], occupied: true, worker: true, ready: true, sequence: c.sequence, address: *(*[80]byte)(unsafe.Pointer(&address))}
			first := c.capacityErr == nil
			if first {
				c.capacityErr = errWindowsReceiveCapacity
				// Staging -> producer leaf is the only extra lock edge. This is
				// admission linearization, NOT a retrospective packet credit.
				c.lease.producers.fail(c.capacityErr)
			}
			c.rxCond.Broadcast()
			c.rxMu.Unlock()
			if first {
				c.failCapture(errWindowsReceiveCapacity)
			}
			c.rxMu.Lock()
			for c.scratch.occupied && !c.sendUnsafe {
				c.rxCond.Wait()
			}
			halt = c.receiveHalt
			c.rxMu.Unlock()
			if halt {
				return
			}
			continue
		}
		c.rxMu.Unlock()
		packet := make([]byte, length) // exact backing capacity, never append
		copy(packet, buffer[:length])
		addressBytes := *(*[80]byte)(unsafe.Pointer(&address))
		c.rxMu.Lock()
		record.raw, record.address = packet, addressBytes
		index := uint16(0)
		for &c.records[index] != record {
			index++
		}
		c.queue[(c.queueHead+c.queueCount)%windowsReceiveRecords] = index
		c.queueCount++
		c.rxCond.Broadcast()
		c.rxMu.Unlock()
	}
}

// This worker alone owns dispatch and the immediate outbound modified slot.
// Queued publication has no dispatch count: Quiesce cannot join a tail that
// needs AllowPassThrough, which is released only after the held drain.
func (c *windowsCapture) outboundWorker() {
	defer c.wg.Done()
	for {
		c.rxMu.Lock()
		for c.queueCount == 0 && !c.scratch.ready && !c.readerDone && !c.sendUnsafe {
			c.rxCond.Wait()
		}
		if c.sendUnsafe {
			c.rxMu.Unlock()
			return
		}
		var r *windowsReceiveRecord
		scratch := false
		if c.queueCount != 0 {
			r = &c.records[c.queue[c.queueHead]]
			c.queueHead = (c.queueHead + 1) % windowsReceiveRecords
			c.queueCount-- // dequeue is NOT a credit
		} else if c.scratch.ready {
			r = &c.scratch
			r.ready = false
			scratch = true
		} else {
			c.rxMu.Unlock()
			return
		}
		sequence := r.sequence
		c.rxMu.Unlock()
		if scratch || !c.dispatch.beginDispatch() {
			c.dispatch.awaitPassThrough()
			c.disposeRecord(r, sequence, VerdictPass, nil)
		} else {
			verdict, modified, held := c.handleOutboundRecord(r, sequence)
			c.dispatch.endDispatch()
			if !held {
				preFence := c.dispatch.beginSend()
				if !preFence {
					c.dispatch.awaitPassThrough()
				}
				c.disposeRecord(r, sequence, verdict, modified)
				if preFence {
					c.dispatch.endSend()
				}
			}
		}
		c.finishRecord(r, sequence, false, true)
	}
}

// A worker pin covers synchronous completion-before-Hold-return. Sequence
// validation rejects stale callbacks after reuse; both transitions are idempotent.
func (c *windowsCapture) finishRecord(r *windowsReceiveRecord, sequence uint64, terminal, workerDone bool) {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	if !r.occupied || r.sequence != sequence {
		return
	}
	r.terminal = r.terminal || terminal
	if workerDone {
		r.worker = false
	}
	if !r.terminal || r.worker {
		return
	}
	if r != &c.scratch {
		c.usedRecords--
		c.usedRawBytes -= cap(r.raw)
	}
	*r = windowsReceiveRecord{}
	c.rxCond.Broadcast()
}

func (c *windowsCapture) disposeRecord(r *windowsReceiveRecord, sequence uint64, verdict Verdict, modified []byte) {
	c.rxMu.Lock()
	if !r.occupied || r.sequence != sequence || r.claimed || c.sendUnsafe {
		c.rxMu.Unlock()
		return
	}
	r.claimed = true
	c.rxMu.Unlock()
	var address windivert.Address
	*(*[80]byte)(unsafe.Pointer(&address)) = r.address
	err := c.sendDisposition(c.outbound, r.raw, &address, verdict, modified)
	if err != nil {
		c.recordSendError(err)
	}
	c.finishRecord(r, sequence, !errors.Is(err, errCaptureSendIncomplete), false)
}

func (c *windowsCapture) handleOutboundRecord(r *windowsReceiveRecord, sequence uint64) (verdict Verdict, modified []byte, held bool) {
	complete := func(verdict Verdict, _ string, modified []byte) { c.disposeRecord(r, sequence, verdict, modified) }
	verdict = c.lease.HandlePacket(r.raw, DirectionOutbound, func(replacement []byte) error {
		c.rxMu.Lock()
		usable := r.occupied && r.sequence == sequence && !c.sendUnsafe
		c.rxMu.Unlock()
		if !usable {
			return errCaptureSendIncomplete
		}
		var address windivert.Address
		*(*[80]byte)(unsafe.Pointer(&address)) = r.address
		suppliedChecksums(&address)
		err := sendCaptured(c.outbound, replacement, &address)
		if err != nil {
			c.recordSendError(err)
		}
		return err
	}, complete)
	if verdict == VerdictHold {
		return verdict, nil, true
	}
	if verdict == VerdictModify {
		modified = c.lease.TakeModified(DirectionOutbound)
	}
	return verdict, modified, false
}

// inboundLoop observes replies. Inbound records never reach the outbound
// planner: a reply is re-injected once on the inbound handle, with its captured
// direction, interface and offload metadata preserved. In-place reply
// transformations (window rewrite) replace the bytes and are therefore
// re-checksummed.
func (c *windowsCapture) inboundLoop() {
	defer c.wg.Done()
	buffer := make([]byte, windivert.MTUMax)
	for {
		if c.receivesHalted() {
			return
		}
		length, address, err := c.inbound.Recv(buffer)
		if err != nil && windivert.IsDrained(err) {
			c.markDrained(1)
			return
		}
		if err != nil || length <= 0 || length > len(buffer) {
			c.retainOptional(0, buffer, &address)
			if err == nil {
				err = fmt.Errorf("desync: invalid inbound receive length %d", length)
			}
			c.recordDrainError("inbound", err)
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		var sendAddress windivert.Address
		copyWindowsAddress(&sendAddress, &address)
		if c.sendsUnsafe() {
			c.retainOptional(0, packet, &address)
			return
		}
		if c.dispatch.beginDispatch() {
			// Inbound verdicts are Pass/Modify only; a reply is never replanned
			// on the outbound path.
			_ = c.lease.HandlePacket(packet, DirectionInbound, nil, nil)
			c.dispatch.endDispatch()
		} else {
			// A quiesced capture only forwards already-captured traffic, and
			// only after the lease released the held originals of earlier
			// captures.
			c.dispatch.awaitPassThrough()
		}
		sendPacket := packet
		if replacement := c.lease.TakeModified(DirectionInbound); replacement != nil {
			sendPacket = replacement
			recomputeChecksums(&sendAddress)
		}
		if err = sendCaptured(c.inbound, sendPacket, &sendAddress); err != nil {
			c.recordSendError(err)
			if errors.Is(err, errCaptureSendIncomplete) {
				c.retainOptional(0, packet, &address)
				return
			}
		}
	}
}

// sendDisposition applies the one terminal disposition of a captured outbound
// record. A pass re-injects the original exactly once; a modify re-injects
// exactly one modified packet and never the unmodified original; a drop sends
// nothing. Hold is not a disposition here: the stored completer performs the
// terminal send later.
func (c *windowsCapture) sendDisposition(handle *windivert.Handle, packet []byte, address *windivert.Address, verdict Verdict, modified []byte) error {
	switch verdict {
	case VerdictDrop, VerdictHold:
		return nil
	case VerdictModify:
		if len(modified) > 0 {
			var sendAddress windivert.Address
			copyWindowsAddress(&sendAddress, address)
			recomputeChecksums(&sendAddress)
			return sendCaptured(handle, modified, &sendAddress)
		}
	}
	return sendCaptured(handle, packet, address)
}

var errCaptureSendIncomplete = errors.New("desync: capture send completion unproven")

// sendCaptured submits one packet and requires a complete native receipt. A
// short write is not a stream prefix to retry; it is a visible failure.
func sendCaptured(handle *windivert.Handle, packet []byte, address *windivert.Address) error {
	n, err := handle.Send(packet, address)
	if n < 0 {
		// The wrapper's unknown-progress result is not a terminal failed send.
		return E.Errors(errCaptureSendIncomplete, err)
	}
	if err != nil {
		return fmt.Errorf("desync: windivert reinjection of %d bytes failed: %w", len(packet), err)
	}
	if n != len(packet) {
		return fmt.Errorf("desync: windivert reinjection wrote %d of %d bytes", n, len(packet))
	}
	return nil
}

// icmpLoop observes the owned time-exceeded capture. A validated owned low-hop
// error is dropped (never re-injected); every other error - foreign tuple,
// malformed/truncated quote, reply-side quote, parameter-problem - is passed
// unchanged exactly once. It never reaches the packet planner.
func (c *windowsCapture) icmpLoop() {
	defer c.wg.Done()
	buffer := make([]byte, windivert.MTUMax)
	for {
		if c.receivesHalted() {
			return
		}
		length, address, err := c.icmp.Recv(buffer)
		if err != nil && windivert.IsDrained(err) {
			c.markDrained(2)
			return
		}
		if err != nil || length <= 0 || length > len(buffer) {
			c.retainOptional(1, buffer, &address)
			if err == nil {
				err = fmt.Errorf("desync: invalid ICMP receive length %d", length)
			}
			c.recordDrainError("icmp", err)
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		if c.sendsUnsafe() {
			c.retainOptional(1, packet, &address)
			return
		}
		preFence := false
		if c.dispatch.beginDispatch() {
			suppressed := c.lease.HandleICMPTimeExceeded(packet)
			c.dispatch.endDispatch()
			if suppressed {
				// Suppressing the validated owned error is its terminal
				// disposition.
				continue
			}
			preFence = c.dispatch.beginSend()
			if !preFence {
				c.dispatch.awaitPassThrough()
			}
		} else {
			c.dispatch.awaitPassThrough()
		}
		var sendAddress windivert.Address
		copyWindowsAddress(&sendAddress, &address)
		if err = sendCaptured(c.icmp, packet, &sendAddress); err != nil {
			c.recordSendError(err)
		}
		if preFence {
			c.dispatch.endSend()
		}
		if errors.Is(err, errCaptureSendIncomplete) {
			c.retainOptional(1, packet, &address)
			return
		}
	}
}

func (c *windowsCapture) receivesHalted() bool {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	return c.receiveHalt
}

func (c *windowsCapture) sendsUnsafe() bool {
	c.rxMu.Lock()
	defer c.rxMu.Unlock()
	return c.sendUnsafe
}

func (c *windowsCapture) retainOptional(index int, raw []byte, address *windivert.Address) {
	c.drainMu.Lock()
	c.optionalRetained[index] = windowsReceiveRecord{raw: raw, occupied: true, address: *(*[80]byte)(unsafe.Pointer(address))}
	c.drainMu.Unlock()
}

// FenceDispatch publishes the ordered-close fence without waiting for the
// records already inside the engine or shutting the driver receives down. The
// lease calls it while publishing its own closed flag, so no record can take the
// closed-lease fast-pass and still be sent before the held originals are
// flushed. Quiesce performs the same publication plus the ordered wait, so the
// two can be called in either order.
func (c *windowsCapture) FenceDispatch() {
	c.dispatch.fence()
}

// Quiesce fences new dispositions and waits for the records already inside the
// engine. It deliberately performs NO driver call: the carried D§4.2 order puts
// semantic quiesce before the held drain, and the receive shutdown
// (ShutdownRecv) only after the producers are paused. A quiesce that stopped
// receives here would let a post-fence caller write overtake the older held
// original - the demonstrated F2 failure.
func (c *windowsCapture) Quiesce() error {
	c.dispatch.quiesce()
	return nil
}

// StopReceive performs the once-only receive shutdown on every opened handle.
// It is called after the producer pause, so no new covered socket operation can
// exploit the bypass it enables. The inbound reply handle and the TTL-expired
// ICMP handle are optional: they are opened only when the owned endpoint and
// the configuration require them, so their slots are legitimately nil and own
// neither a receive user nor a device. Every handle that was actually opened is
// still shut down and its error still reported. The call is idempotent - a
// second call (Close runs it again) neither re-issues the shutdown ioctl nor
// changes the recorded result.
func (c *windowsCapture) StopReceive() error {
	c.stopOnce.Do(func() {
		var errs []error
		for _, handle := range c.handles() {
			if handle == nil {
				continue
			}
			if err := handle.ShutdownRecv(); err != nil {
				errs = append(errs, err)
			}
		}
		c.stopErr = E.Errors(errs...)
		c.lease.ReportNativeFailure(c.stopErr)
		if c.stopErr != nil {
			c.failCapture(c.stopErr)
		}
	})
	return c.stopErr
}

// AllowPassThrough releases records captured after the fence. The lease calls it
// after it flushed the held originals of earlier captures, so those records can
// no longer overtake held data on the wire. It is idempotent.
func (c *windowsCapture) AllowPassThrough() {
	c.dispatch.allowPassThrough()
}

func (c *windowsCapture) handles() []*windivert.Handle {
	return []*windivert.Handle{c.outbound, c.inbound, c.icmp}
}

// recordDrainError keeps a receive failure visible even after the fence: it
// means the queue was not proven drained, so Close must not report a successful
// lossless shutdown.
func (c *windowsCapture) recordDrainError(direction string, err error) {
	index := 0
	if direction == "inbound" {
		index = 1
	} else if direction == "icmp" {
		index = 2
	}
	wrapped := fmt.Errorf("desync: windows %s capture receive: %w", direction, err)
	c.drainMu.Lock()
	first := c.drainErrors[index].add(wrapped)
	c.drainMu.Unlock()
	c.rxMu.Lock()
	c.receiveHalt = true
	if c.rxCond != nil {
		c.rxCond.Broadcast()
	}
	c.rxMu.Unlock()
	if first {
		c.lease.ReportNativeFailure(wrapped)
		c.failCapture(wrapped)
	}
}

func (c *windowsCapture) markDrained(index int) {
	c.drainMu.Lock()
	c.drained[index] = true
	c.drainMu.Unlock()
}

func (c *windowsCapture) recordSendError(err error) {
	unknown := errors.Is(err, errCaptureSendIncomplete)
	index := 0
	if unknown {
		index = 1
	}
	c.drainMu.Lock()
	first := c.sendErrors[index].add(err)
	c.sendIncomplete = c.sendIncomplete || unknown
	c.drainMu.Unlock()
	if unknown {
		c.rxMu.Lock()
		c.sendUnsafe, c.receiveHalt = true, true
		if c.rxCond != nil {
			c.rxCond.Broadcast()
		}
		c.rxMu.Unlock()
	}
	// One report per fixed category, never an ever-growing per-send error list.
	if first {
		c.lease.ReportNativeFailure(err)
	}
	if unknown {
		c.failCapture(err)
	}
}

// captureRetirementError separates the safety receipt from delivery/Close
// diagnostics. Called only after Close joined the one teardown owner.
func (c *windowsCapture) captureRetirementError() error {
	if c.retired {
		return nil
	}
	return c.closeErr
}

// releaseNative discharges the capture's admission reference exactly once.
func (c *windowsCapture) releaseNative() {
	c.releaseOnce.Do(func() {
		if c.releaseHold != nil {
			c.releaseHold()
		}
	})
}

// recordRetainedOpen keeps the cleanup ownership of a failed inner Open. When
// windivert.Open could not prove that the resources it acquired were released,
// its error carries the handle's retirement receipt; storing it here is what
// makes the original admission charge stay charged, because teardown discharges
// that charge only after every receipt closed. An ordinary activation failure
// (no receipt) changes nothing: its rollback already completed.
func (c *windowsCapture) recordRetainedOpen(err error) error {
	if receipt, retained := windivert.RetainedRetirement(err); retained {
		c.retainedReceipts = append(c.retainedReceipts, receipt)
	}
	return err
}

// retirementReceipts returns every receipt this capture must await before its
// admission reference may be discharged: the opened handles' Done channels plus
// the retained receipts of failed inner Opens.
func (c *windowsCapture) retirementReceipts() []<-chan struct{} {
	receipts := make([]<-chan struct{}, 0, 3+len(c.retainedReceipts))
	for _, handle := range c.handles() {
		if handle == nil {
			continue
		}
		receipts = append(receipts, handle.Done())
	}
	receipts = append(receipts, c.retainedReceipts...)
	return receipts
}

// releaseWhenRetired keeps the native ownership charged until the kernel proves
// that the receive users stopped and every device/event retired. It is the
// late-retirement bridge for a caller that hit its bound before that proof; it
// never frees anything and never reuses a handle number.
func (c *windowsCapture) releaseWhenRetired(loopsDone <-chan struct{}) {
	<-loopsDone
	for _, receipt := range c.retirementReceipts() {
		<-receipt
	}
	c.releaseNative()
}

// teardown is the one capture destruction path, used both by Close and by a
// failed open. It fences dispatch, stops receives, forwards queued records,
// joins every started receive user, closes each opened handle and releases the
// admission reference only when loops and the handles' Done both prove
// retirement.
func (c *windowsCapture) teardown() error {
	var errs []error
	if err := c.Quiesce(); err != nil {
		errs = append(errs, err)
	}
	// No semantic users exist in a partial-open rollback. Opened diverting
	// handles nevertheless need real readers and ERROR_NO_DATA, not wg==0.
	c.AllowPassThrough()
	c.startUsers()
	if err := c.StopReceive(); err != nil {
		errs = append(errs, err)
	}
	// A direct capture close has no lease-ordered held flush to wait for; the
	// lease path has already released the gate before calling Close.
	c.AllowPassThrough()
	// Lease.Close already bounds its caller. This single teardown owner keeps
	// the copied tail and its native hold alive for however long actual drain
	// takes. Handle.Close cancels I/O: it is not a drain timeout fallback.
	c.wg.Wait()
	loopsDone := make(chan struct{})
	close(loopsDone)
	c.drainMu.Lock()
	incomplete := c.sendIncomplete
	for index, summary := range c.drainErrors {
		errs = append(errs, summary.err())
		if summary.first != nil || (c.handles()[index] != nil && !c.drained[index]) {
			incomplete = true
		}
	}
	for _, summary := range c.sendErrors {
		errs = append(errs, summary.err())
	}
	c.drainMu.Unlock()
	c.rxMu.Lock()
	errs = append(errs, c.capacityErr)
	incomplete = incomplete || c.usedRecords != 0 || c.usedRawBytes != 0 || c.scratch.occupied
	c.rxMu.Unlock()
	if c.stopErr != nil || incomplete {
		// Receive-user exit is not ERROR_NO_DATA, and a failed completion query
		// is not terminal disposition. Closing here could discard originals.
		// No retry or fabricated late success: keep the same capture charge.
		return E.Errors(append(errs, errWindowsReceiveUnproven)...)
	}
	for _, handle := range c.handles() {
		if handle == nil {
			continue
		}
		if err := handle.Close(); err != nil {
			errs = append(errs, err)
			c.lease.ReportNativeFailure(err)
		}
	}
	// Done, not Close's return/error, is the native retirement receipt. Keep
	// this same owner waiting for late retirement; the Lease caller is bounded
	// independently and no second cleanup service or retry is needed.
	c.releaseWhenRetired(loopsDone)
	c.retired = true
	return E.Errors(errs...)
}

// handlesRetired waits inside one bound for every opened handle's Done. Done is
// closed only after the device and events were actually released, so a failed
// CloseHandle attempt leaves it open and this reports false. A failed inner Open
// that retained its cleanup keeps the same charge: its receipt is part of the
// same proof, so an invisible hidden device can no longer be discharged early.
func (c *windowsCapture) handlesRetired(grace time.Duration) bool {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	for _, receipt := range c.retirementReceipts() {
		select {
		case <-receipt:
		case <-timer.C:
			return false
		}
	}
	return true
}

// abortOpen destroys the resources of an activation that never became visible
// to the lease. It uses the same teardown path, so a partially opened capture
// joins whatever loops started (none in the current open order), closes each
// opened handle and releases the admission reference only after retirement.
func (c *windowsCapture) abortOpen() error {
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	timer := time.NewTimer(captureDrainGrace)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return fmt.Errorf("desync: windows activation rollback still owns native resources: %w", ErrLeaseCloseIncomplete)
	}
}

// Close runs the capture phase order: fence and stop new receive enqueues, let
// the receive loops deliver every already-queued record as pass-through, join
// them, then retire the handles only after their proven terminal retirement. A
// caller is bounded by Lease.Close (abortOpen bounds failed activation). This
// teardown itself keeps waiting for actual drain/retirement; elapsed time is
// never permission to cancel an original. Diagnostics and the safe receipt
// remain separate, and the native reference stays charged until proven safe.
func (c *windowsCapture) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.teardown()
	})
	return c.closeErr
}

// prepareSocket establishes the owned endpoint and registers capture on the
// native Winsock handle.
//
// A TCP packet attempt reaches this hook after the native ConnectEx helper has
// already bound the exclusive local port. A UDP packet attempt reaches it from
// the dialer's last-chance Control hook, which runs before net.Dialer's own
// bind, and the dialer clears its local address for packet leases so the lease
// is the single bind owner: the exclusive port therefore has to be established
// here, exactly like the Linux hook. Without that bind the socket is still
// unbound and getsockname fails with WSAEINVAL ("An invalid argument was
// supplied."), which used to abort every Windows packet-enabled connected UDP
// dial before capture or tracking.
func prepareSocket(lease *Lease, fd uintptr) error {
	if lease.Intent().Transport == TransportUDP {
		if err := bindExclusiveUDPAddress(lease, fd); err != nil {
			return err
		}
	}
	if lease.LocalAddress().Port() == 0 {
		address, err := sockaddrForHandle(fd)
		if err != nil {
			return err
		}
		lease.SetLocalAddress(address)
	}
	// The actual interface the native attempt is bound to is queried from the
	// socket itself (IP_UNICAST_IF/IPV6_UNICAST_IF), never inferred from
	// configuration. The index is what a WinDivert ifIdx comparison uses; the
	// resolved adapter name feeds the state/ipcache interface dimension.
	if index, name := querySocketInterface(fd); index != 0 {
		lease.setSocketInterface(index, name)
	}
	return lease.StartCapture()
}

// bindExclusiveUDPAddress binds the attempt's requested local address on the
// unbound Winsock UDP socket. The port stays kernel-assigned, so the owned
// capture envelope is scoped to the actual port the kernel handed out, read
// back from the socket immediately after this bind. The requested source
// address, its IPv6 zone and the interface control that already ran are
// honored; an address the host cannot bind fails the attempt closed.
func bindExclusiveUDPAddress(lease *Lease, fd uintptr) error {
	intent := lease.Intent()
	handle := windows.Handle(fd)
	// The endpoint this attempt is about to receive must be exclusively owned
	// before the kernel assigns it: a second Winsock socket that sets
	// SO_REUSEADDR can otherwise share the same local endpoint, and tuple
	// capture cannot tell the two sockets apart. Winsock honours the option
	// only before bind, so it is applied to the still-unbound handle.
	if err := setExclusiveUDPBind(handle); err != nil {
		return err
	}
	switch intent.Family {
	case FamilyIPv4:
		bind := &windows.SockaddrInet4{}
		if intent.Source.IsValid() {
			address := intent.Source.Addr().Unmap()
			if !address.Is4() {
				return fmt.Errorf("desync: IPv6 bind address for an IPv4 destination")
			}
			bind.Addr = address.As4()
		}
		if err := windows.Bind(handle, bind); err != nil {
			return fmt.Errorf("desync: bind exclusive local port: %w", err)
		}
	case FamilyIPv6:
		bind := &windows.SockaddrInet6{}
		if intent.Source.IsValid() {
			address := intent.Source.Addr().Unmap()
			if address.Is4() {
				return fmt.Errorf("desync: IPv4 bind address for an IPv6 destination")
			}
			bind.Addr = address.As16()
			if zone := intent.Source.Addr().Zone(); zone != "" {
				iface, err := net.InterfaceByName(zone)
				if err != nil {
					return fmt.Errorf("desync: resolve zone %s: %w", zone, err)
				}
				bind.ZoneId = uint32(iface.Index)
			}
		}
		if err := windows.Bind(handle, bind); err != nil {
			return fmt.Errorf("desync: bind exclusive local port: %w", err)
		}
	default:
		return fmt.Errorf("desync: unsupported address family")
	}
	return nil
}

// Winsock unicast interface options. Both families use option 31 at their own
// level (ws2ipdef.h: IP_UNICAST_IF / IPV6_UNICAST_IF); x/sys/windows does not
// export them.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// querySocketInterface returns the interface index the socket was bound to and
// the adapter name for that index, or (0, "") when the socket is not
// interface-bound.
func querySocketInterface(fd uintptr) (uint32, string) {
	handle := windows.Handle(fd)
	for _, level := range []int{windows.IPPROTO_IP, windows.IPPROTO_IPV6} {
		option := ipUnicastIf
		if level == windows.IPPROTO_IPV6 {
			option = ipv6UnicastIf
		}
		index, err := windows.GetsockoptInt(handle, level, option)
		if err != nil || index <= 0 {
			continue
		}
		return uint32(index), adapterNameByIndex(uint32(index))
	}
	return 0, ""
}

func adapterNameByIndex(index uint32) string {
	adapters, err := queryAdapters()
	if err != nil {
		return ""
	}
	for _, adapter := range adapters {
		if adapter.Index == index {
			return adapter.Name
		}
	}
	return ""
}

func sockaddrForHandle(fd uintptr) (netip.AddrPort, error) {
	sockaddr, err := windows.Getsockname(windows.Handle(fd))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("desync: getsockname: %w", err)
	}
	switch value := sockaddr.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(value.Addr), uint16(value.Port)), nil
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(value.Addr), uint16(value.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("desync: unexpected sockaddr family")
	}
}

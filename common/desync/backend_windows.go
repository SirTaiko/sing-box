//go:build windows

package desync

import (
	"encoding/binary"
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
	// pendingBatch is the single capture-owned view of the last native
	// outbound batch receipt. raw aliases receiveBuffer and addrs aliases the
	// returned address array; neither is copied into a second queue. next is
	// the first packet whose ownership has not been transferred yet, and only
	// the outbound reader mutates this descriptor under rxMu. An occupied
	// descriptor keeps the whole receipt rooted and forbids the next receive.
	pendingBatch  windowsOutboundPendingBatch
	receiveBuffer []byte

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
	// The inbound slot also records the packed batch that was actually
	// submitted, because a batched native send completion owns both copies.
	optionalRetained [2]windowsOptionalRetention
	// prepareErrors are local batch-preparation failures (for example a
	// length-changing inbound replacement). They are not receive errors, but
	// they own a retained batch and must keep teardown from claiming success.
	prepareErrors windowsErrorSummary

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
	// windowsReceiveInlinePayload is the one private per-slot payload backing of
	// a reserved detached record. It is not an accepted packet size or a
	// capture strategy limit: a longer span keeps the exact previous
	// make([]byte, n) copy. The fixed extra backing is
	// windowsReceiveRecords*windowsReceiveInlinePayload = 32768 B for the ring
	// plus one more slot for the scratch rendezvous; it sits outside the
	// windowsReceiveRawBytes packet ledger, which still charges every record
	// its logical length exactly as before.
	windowsReceiveInlinePayload = 128
)

var (
	errWindowsReceiveCapacity = errors.New("desync: Windows receive staging capacity exhausted")
	errWindowsReceiveUnproven = errors.New("desync: Windows received storage/disposition unproven")
)

// Fixed descriptors/ring: no per-record channel, goroutine or error history.
// Full address bytes include the blank union which struct comparison ignores.
type windowsReceiveRecord struct {
	raw     []byte
	address [80]byte
	// inline is this slot's own payload backing for a reserved detached record
	// of at most windowsReceiveInlinePayload bytes. raw aliases it with
	// len==cap==n while the slot is occupied, so the payload lifetime is
	// exactly the record lifetime and the ledger releases exactly the charged
	// n. The array is inside the slot (never shared with another record) and
	// the wholesale reset in reserveRecordLocked/finishRecord zeroes it, so a
	// reused slot cannot expose a previous, longer payload. The only other
	// cost is that reset: 128 more zeroed bytes per record transition, with no
	// heap object and no change to 8MiB admission.
	inline                                     [windowsReceiveInlinePayload]byte
	sequence                                   uint64
	occupied, worker, claimed, terminal, ready bool
}

// windowsOutboundPendingBatch is the one packed-tail descriptor of the
// outbound receive path. raw/addrs borrow the synchronous terminal view only
// while the reader callback that acquired them runs; before a descriptor may
// outlive that callback, the reader materializes the complete receipt into
// receiveBuffer and its own address backing and rebinds these slices to those
// capture-owned targets (the ordinary path never copies into them at all).
// count/next preserve the original ordinal order, validated records that the
// whole batch passed framing/family checks, and occupied keeps the receipt
// rooted across saturation, unsafe or a refused view. A pre-native occupied
// marker has nil views: it roots one possible acquire, never received bytes.
// Only the reader mutates this value, always under rxMu.
type windowsOutboundPendingBatch struct {
	raw       []byte
	addrs     []windivert.Address
	count     int
	next      int
	occupied  bool
	validated bool
}

// windowsOptionalRetention is the single retained unit of an optional lane.
// The old single-packet fields are kept for the ICMP lane; the inbound slot
// additionally owns the captured addresses of its batch and the exact
// bytes/addresses handed to SendBatch, because an unknown native completion
// retains both the caller copy and the driver-visible copy.
type windowsOptionalRetention struct {
	raw       []byte
	address   [80]byte
	addrs     []windivert.Address
	submitted []byte
	sendAddrs []windivert.Address
	occupied  bool
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
// The reservation carries the exact slot index it found: publication uses that
// index directly instead of scanning the ring a second time. The index is only
// valid together with a non-nil record; a refused reservation publishes nothing.
func (c *windowsCapture) reserveRecordLocked(n int) (*windowsReceiveRecord, uint16) {
	if n <= 0 || n > windivert.MTUMax || c.usedRecords < 0 || c.usedRecords >= windowsReceiveRecords || c.usedRawBytes < 0 || c.usedRawBytes > windowsReceiveRawBytes || n > windowsReceiveRawBytes-c.usedRawBytes {
		return nil, 0
	}
	for i := range c.records {
		r := &c.records[i]
		if !r.occupied {
			*r = windowsReceiveRecord{occupied: true, worker: true, sequence: c.sequence}
			c.usedRecords++
			c.usedRawBytes += n
			return r, uint16(i)
		}
	}
	return nil, 0
}

// detachPayload copies one framed span out of the packed receive buffer into
// storage that outlives the native receive. A span that fits this slot's
// private backing uses it with exact len==cap, so no heap object is created
// and the ledger releases exactly the charged n; a longer span keeps the exact
// previous make/copy. The copy happens before publication and outside rxMu: an
// occupied slot is unreachable to any other goroutine until the reader
// publishes it, so filling it needs no lock, exactly like the previous heap
// copy.
func (r *windowsReceiveRecord) detachPayload(span []byte) []byte {
	n := len(span)
	if n <= windowsReceiveInlinePayload {
		packet := r.inline[:n:n]
		copy(packet, span)
		return packet
	}
	packet := make([]byte, n) // exact backing capacity, never append
	copy(packet, span)
	return packet
}

// In-budget this reader only receives, validates, reserves, copies and publishes.
// One native RecvBatchView lends every already-available packet back-to-back for
// exactly one synchronous callback. The whole packed stream is framed and
// family-checked before any packet is published, then each packet keeps its own
// sequence and its own detached record in the unchanged FIFO. A failed
// reservation latches the existing sticky capacity failure and moves the
// remaining packed tail through the one scratch rendezvous. Failed-mode scratch
// rendezvous is the explicit saturation boundary, NOT a claim of losslessness
// for packets still below native receive. The next native receive is issued only
// after the whole receipt was transferred and the shared scratch is terminal and
// worker-free.
//
// Ownership: the borrowed view ends when the callback returns, so every path
// that keeps the receipt - a malformed/family/sequence receipt, the first failed
// reservation of a sticky batch, or a concurrent unsafe - materializes the
// complete receipt into the capture-owned receive buffer and this reader's
// address backing before the callback returns. The ordinary prefix is detached
// directly from the view, so it is never written into that fallback backing.
func (c *windowsCapture) loop() {
	defer c.wg.Done()
	defer close(c.done)
	c.initReceive()
	defer func() { c.rxMu.Lock(); c.readerDone = true; c.rxCond.Broadcast(); c.rxMu.Unlock() }()
	// This reader-local address backing is the fallback snapshot target, never
	// native receive storage: a pending descriptor may borrow the view only
	// inside the callback that materializes or clears it.
	addresses := make([]windivert.Address, windivert.BatchMax)
	var spans [windivert.BatchMax + 1]uint32
	for {
		c.rxMu.Lock()
		halt := c.receiveHalt
		exhausted := c.sequence == ^uint64(0)
		owned := c.pendingBatch.occupied || c.scratch.occupied
		if !halt && !exhausted && !owned {
			// Pre-native occupied marker: nil views only root one possible
			// acquire; they never claim received bytes. Only the exact empty
			// drained receipt, or a callback that cleared its descriptor,
			// releases this marker.
			c.pendingBatch = windowsOutboundPendingBatch{occupied: true}
		}
		c.rxMu.Unlock()
		if halt {
			return
		}
		if exhausted {
			c.recordDrainError("outbound", errors.New("desync: Windows receive sequence exhausted"))
			return
		}
		if owned {
			// The previous receipt must be transferred completely and the one
			// shared scratch terminal before this reader may receive again.
			c.recordDrainError("outbound", errors.New("desync: Windows outbound receive buffer still owned"))
			return
		}
		consumed := false
		stop := false
		length, err := c.outbound.RecvBatchView(windivert.MTUMax, func(raw []byte, addrs []windivert.Address) {
			consumed = true
			stop = c.consumeOutboundBatch(raw, addrs, &spans, addresses)
		})
		if err != nil {
			// Only the exact empty terminal receipt proves the queue drained. A
			// negative count or a callback that already ran is not proof, and a
			// callback's local stop/diagnostics never become the receive error.
			// A receipt the wrapper refused to publish keeps the nil marker:
			// the native bytes/addresses stay in the quarantined lane and this
			// reader never reads lane memory to invent them.
			if windivert.IsDrained(err) && length == 0 && !consumed {
				c.rxMu.Lock()
				c.pendingBatch = windowsOutboundPendingBatch{}
				c.rxMu.Unlock()
				c.markDrained(0)
				return
			}
			c.recordDrainError("outbound", err)
			return
		}
		if !consumed {
			// The wrapper publishes success only through the callback. Refuse
			// to spin on a receipt nobody consumed; the marker still roots it.
			c.recordDrainError("outbound", fmt.Errorf("desync: outbound view success without a consumed batch (%d bytes)", length))
			return
		}
		if stop {
			return
		}
	}
}

// consumeOutboundBatch runs the whole reader cycle for one terminal view. The
// borrowed raw/addrs are valid only inside this call: any path that returns
// while the descriptor is still occupied first materializes the complete
// receipt into capture-owned storage, and each already-reserved record owns its
// exact detached copy before publication. stop reports that the receive owner
// must not issue another receive.
func (c *windowsCapture) consumeOutboundBatch(raw []byte, addrs []windivert.Address, spans *[windivert.BatchMax + 1]uint32, addresses []windivert.Address) (stop bool) {
	length := len(raw)
	materialized := false
	// Record the acquisition under rxMu. Both receipt dimensions were already
	// validated by the wrapper, so this never publishes anything.
	c.rxMu.Lock()
	c.pendingBatch.raw, c.pendingBatch.addrs = raw, addrs
	c.rxMu.Unlock()
	retain := func() {
		c.rxMu.Lock()
		c.materializeOutboundReceipt(&raw, &addrs, addresses, &materialized)
		c.rxMu.Unlock()
	}
	if length <= 0 || length > len(c.receiveBuffer) || len(addrs) == 0 || len(addrs) > windivert.BatchMax {
		// Zero bytes with captured addresses is an invalid backend batch, not
		// the ordinary empty native drain (which never reaches a callback).
		retain()
		c.recordDrainError("outbound", fmt.Errorf("desync: invalid outbound batch view (%d bytes, %d addresses)", length, len(addrs)))
		return true
	}
	// The whole packed stream is validated before ANY prefix publication: a
	// malformed suffix forbids delivering an otherwise valid prefix.
	count, frameErr := frameWindowsBatch(raw, spans)
	if frameErr == nil {
		frameErr = validateWindowsBatchFamilies(raw, spans, count, addrs)
	}
	if frameErr != nil {
		// The complete visible receipt is retained as unvalidated (count/next 0).
		retain()
		c.recordDrainError("outbound", frameErr)
		return true
	}
	c.rxMu.Lock()
	// Sequence range is checked for the whole batch before the first record.
	// Only this reader advances the sequence, exactly once per packet that is
	// actually transferred to a record or to the scratch rendezvous.
	if uint64(count) > ^uint64(0)-c.sequence {
		c.rxMu.Unlock()
		retain()
		c.recordDrainError("outbound", errors.New("desync: Windows receive sequence exhausted"))
		return true
	}
	c.pendingBatch.count, c.pendingBatch.next, c.pendingBatch.validated = count, 0, true
	c.rxMu.Unlock()
	for index := 0; index < count; index++ {
		start, end := int(spans[index]), int(spans[index+1])
		c.rxMu.Lock()
		if c.sendUnsafe {
			// Concurrent unsafe stops new receive but never discards the
			// already-received tail: materialize it and keep the descriptor.
			c.materializeOutboundReceipt(&raw, &addrs, addresses, &materialized)
			c.rxMu.Unlock()
			return true
		}
		c.sequence++
		var record *windowsReceiveRecord
		var queueIndex uint16
		if c.capacityErr == nil {
			record, queueIndex = c.reserveRecordLocked(end - start)
		}
		if record == nil {
			// First failed reservation: one complete snapshot into the existing
			// capture backing, once, before the scratch aliases it. Subsequent
			// spans of this sticky batch reuse the same backing without a second
			// copy or a cursor change.
			c.materializeOutboundReceipt(&raw, &addrs, addresses, &materialized)
			// Sticky mid-batch exhaustion: one span at a time through the
			// existing single-record scratch rendezvous, with its own
			// sequence and the full 80-byte captured address. The scratch is
			// capture-owned; it is not a record credit and never enters the
			// ledger.
			c.scratch = windowsReceiveRecord{
				raw:      raw[start:end:end],
				address:  *(*[80]byte)(unsafe.Pointer(&addrs[index])),
				sequence: c.sequence,
				occupied: true, worker: true, ready: true,
			}
			c.pendingBatch.next = index + 1
			first := c.capacityErr == nil
			if first {
				c.capacityErr = errWindowsReceiveCapacity
				// Staging -> producer leaf is the only extra lock edge. This
				// is admission linearization, NOT a retrospective credit.
				c.lease.producers.fail(c.capacityErr)
			}
			c.rxCond.Broadcast()
			c.rxMu.Unlock()
			if first {
				c.failCapture(errWindowsReceiveCapacity)
			}
			// Wait only for the scratch completion protocol. A halt stops
			// new native receive, not the preservation of the acquired tail.
			c.rxMu.Lock()
			for c.scratch.occupied && !c.sendUnsafe {
				c.rxCond.Wait()
			}
			unsafe := c.sendUnsafe
			c.rxMu.Unlock()
			if unsafe {
				return true
			}
			continue
		}
		c.rxMu.Unlock()
		// The charged record is filled directly from the terminal view: one
		// exact detached copy and one raw80 pointer copy of the captured
		// address (including the blank union). Neither borrow is retained.
		packet := record.detachPayload(raw[start:end])
		addressBytes := *(*[80]byte)(unsafe.Pointer(&addrs[index]))
		c.rxMu.Lock()
		// A concurrent unsafe does not cancel this already-charged copy:
		// the exact detached record is published, then the reader stops.
		record.raw, record.address = packet, addressBytes
		c.queue[(c.queueHead+c.queueCount)%windowsReceiveRecords] = queueIndex
		c.queueCount++
		c.pendingBatch.next = index + 1
		c.rxCond.Broadcast()
		c.rxMu.Unlock()
	}
	c.rxMu.Lock()
	for c.scratch.occupied && !c.sendUnsafe {
		c.rxCond.Wait()
	}
	if c.sendUnsafe {
		// Retain the complete descriptor; the cursor is the only owner state of
		// the remaining originals. A sticky batch is already capture-owned.
		c.materializeOutboundReceipt(&raw, &addrs, addresses, &materialized)
		c.rxMu.Unlock()
		return true
	}
	// Whole batch transferred and the shared scratch terminal and worker-free:
	// the descriptor may be received into again. Dropping it returns no ledger
	// credit because it never held one.
	c.pendingBatch = windowsOutboundPendingBatch{}
	c.rxMu.Unlock()
	return false
}

// materializeOutboundReceipt copies the complete borrowed receipt into the
// capture-owned packed buffer and this reader's address backing exactly once,
// then rebinds only the pending descriptor and the callback-local views. It
// runs under rxMu before the first scratch alias is published or an occupied
// descriptor escapes the callback. count/next/validated, the original spans and
// the sequence stay untouched, so the existing cursor still addresses the same
// bytes; no suffix is compacted, reframed or re-reserved.
func (c *windowsCapture) materializeOutboundReceipt(raw *[]byte, addrs *[]windivert.Address, addresses []windivert.Address, materialized *bool) {
	if *materialized {
		return
	}
	n := len(*raw)
	// The wrapper already bounds both views to MTUMax and BatchMax. These
	// clamps only keep an out-of-contract wrapper from writing past the fixed
	// capture backings; a valid receipt is never truncated.
	if n > len(c.receiveBuffer) {
		n = len(c.receiveBuffer)
	}
	copy(c.receiveBuffer[:n], *raw)
	addressCount := len(*addrs)
	if addressCount > len(addresses) {
		addressCount = len(addresses)
	}
	for index := 0; index < addressCount; index++ {
		copyWindowsAddress(&addresses[index], &(*addrs)[index])
	}
	*raw = c.receiveBuffer[:n:n]
	*addrs = addresses[:addressCount:addressCount]
	c.pendingBatch.raw, c.pendingBatch.addrs = *raw, *addrs
	*materialized = true
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
	// The synchronous per-packet sender of this captured record is unchanged: it
	// re-checks ownership under rxMu, clones the full captured address, marks
	// only the supplied checksum bits and requires a complete native receipt.
	single := func(replacement []byte) error {
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
	}
	// The captured address is written before publication and never rewritten
	// while the slot remains occupied, so one snapshot is the exact per-packet
	// metadata of this record.
	var captured windivert.Address
	*(*[80]byte)(unsafe.Pointer(&captured)) = r.address
	batch := func(packets [][]byte) (int, error) {
		return sendPlanBatches(c.outbound, packets, captured, func() bool {
			c.rxMu.Lock()
			defer c.rxMu.Unlock()
			return r.occupied && r.sequence == sequence && !c.sendUnsafe
		}, single, c.recordSendError)
	}
	verdict = c.lease.handlePacket(r.raw, DirectionOutbound, packetInjection{single: single, batch: batch}, complete)
	if verdict == VerdictHold {
		return verdict, nil, true
	}
	if verdict == VerdictModify {
		modified = c.lease.TakeModified(DirectionOutbound)
	}
	return verdict, modified, false
}

// sendPlanBatches submits the already-built replacement plan of exactly one
// captured record. Consecutive elements that each frame as exactly one outer
// IPv4/IPv6 packet of the captured address family are concatenated unchanged
// into bounded SendBatch chunks (windivert.BatchMax packets / windivert.MTUMax
// bytes per native call); an element that is not eligible keeps the previous
// single-packet sender and is submitted on its own after the pending chunk.
// Framing only decides batch eligibility: bytes, checksums, order and captured
// metadata are never repaired, truncated or rewritten. A whole plan of zero or
// one packet keeps the existing single path.
//
// A chunk is confirmed only by a nil batch result. Any error, short count or
// unknown completion confirms no additional packet of that chunk, keeps the
// previously confirmed prefix and stops this plan; a submitted chunk is never
// retried, split back into single sends or followed by a later chunk. usable is
// re-checked under the record lock before every submission, never held across
// native I/O. recordError publishes a real batch failure once through the
// existing send-error path.
func sendPlanBatches(handle *windivert.Handle, packets [][]byte, address windivert.Address, usable func() bool, single Injector, recordError func(error)) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	if len(packets) == 1 {
		if err := single(packets[0]); err != nil {
			return 0, err
		}
		return 1, nil
	}
	ipv6 := address.IPv6()
	packed := make([]byte, 0, windivert.MTUMax)
	addrs := make([]windivert.Address, 0, windivert.BatchMax)
	confirmed := 0
	flush := func() error {
		switch len(addrs) {
		case 0:
			return nil
		case 1:
			// One packed packet is exactly the old single submission; packing it
			// into a batch would add no native saving.
			if err := single(packed); err != nil {
				return err
			}
			confirmed++
		default:
			if !usable() {
				return errCaptureSendIncomplete
			}
			if err := sendCapturedBatch(handle, packed, addrs); err != nil {
				recordError(err)
				return err
			}
			confirmed += len(addrs)
		}
		packed, addrs = packed[:0], addrs[:0]
		return nil
	}
	for _, packet := range packets {
		eligible := planBatchEligible(packet, ipv6)
		if eligible && len(addrs) != 0 && (len(addrs) == windivert.BatchMax || len(packed)+len(packet) > windivert.MTUMax) {
			// The work quantum is a chunk boundary, not a rejection: flush the
			// previous segment and start the next one with this element.
			if err := flush(); err != nil {
				return confirmed, err
			}
		}
		if !eligible {
			// An element that is not yet submitted always keeps its real single
			// sender: the preceding segment is flushed first, and only that
			// element's real result decides whether the remaining tail continues.
			if err := flush(); err != nil {
				return confirmed, err
			}
			if err := single(packet); err != nil {
				return confirmed, err
			}
			confirmed++
			continue
		}
		packed = append(packed, packet...)
		var sendAddress windivert.Address
		copyWindowsAddress(&sendAddress, &address)
		suppliedChecksums(&sendAddress)
		addrs = append(addrs, sendAddress)
	}
	if err := flush(); err != nil {
		return confirmed, err
	}
	return confirmed, nil
}

// planBatchEligible reports whether one planned replacement is exactly one
// outer IPv4/IPv6 packet matching the captured address family and fitting one
// batch quantum. It is a framing/family predicate only: transport parsing and
// checksum validity are deliberately not consulted and the bytes are never
// truncated, padded or repaired.
func planBatchEligible(packet []byte, ipv6 bool) bool {
	if len(packet) == 0 || len(packet) > windivert.MTUMax {
		return false
	}
	var spans [windivert.BatchMax + 1]uint32
	count, err := frameWindowsBatch(packet, &spans)
	if err != nil || count != 1 || int(spans[1]) != len(packet) {
		return false
	}
	return (packet[0]>>4 == 6) == ipv6
}

// inboundLoop observes replies. Inbound records never reach the outbound
// planner: a reply is re-injected once on the inbound handle, with its captured
// direction, interface and offload metadata preserved. In-place reply
// transformations (window rewrite) replace the bytes and are therefore
// re-checksummed.
//
// One native batch receive returns the packets already queued by the driver,
// packed back-to-back, with one captured address per packet. The whole packed
// stream is framed before anything is dispatched, each packet keeps its own
// dispatch admission and immediate modified-slot consumption, and the batch is
// re-sent once. An all-Pass batch is forwarded through the receive-bound
// one-shot capability, which submits the terminal view itself; the first Modify
// lazily stages the batch in a capture-loop-owned copy and keeps the ordinary
// SendBatch path.
//
// Ownership: the native view is borrowed for exactly one synchronous iteration.
// RecvBatchViewForward keeps the receive lane serialized and the operation
// registered until the consumer returns. The all-Pass capability submits the
// exact receive payload and raw80 array through the separate send lane, so no
// capture-owned staging copy stands between the terminal receipt and the
// kernel read. SendBatch still copies what it submits into its own lane for a
// modified batch. Every retention path detaches the whole original batch and
// its raw80 addresses before the view ends, then the loop returns instead of
// receiving again; the retained copies keep the receipt alive without aliasing
// lane storage.
func (c *windowsCapture) inboundLoop() {
	defer c.wg.Done()
	var spans [windivert.BatchMax + 1]uint32
	// Modified staging is allocated only after the first Modify and then
	// reused by this single inbound owner. All-Pass never touches it.
	var sendBuffer []byte
	var sendAddresses []windivert.Address
	for {
		if c.receivesHalted() {
			return
		}
		consumed := false
		stop := false
		length, err := c.inbound.RecvBatchViewForward(windivert.MTUMax, func(raw []byte, addrs []windivert.Address, forwardOriginal func() (int, error)) {
			consumed = true
			stop = c.consumeInboundBatch(raw, addrs, &spans, &sendBuffer, &sendAddresses, forwardOriginal)
		})
		if err != nil {
			// A drain receipt is only the ordinary terminal empty receive. A
			// negative count or a consumer that already ran is not proof that
			// the queue was empty.
			if windivert.IsDrained(err) && length == 0 && !consumed {
				c.markDrained(1)
				return
			}
			if !consumed {
				// No validated view was published: keep the occupied marker so
				// teardown cannot claim a lossless drain, and never read the
				// lane's pending memory. The native bytes stay in the lane.
				c.retainInboundMarker()
				c.recordDrainError("inbound", err)
			}
			return
		}
		if !consumed {
			// The wrapper publishes success only through the consumer. Refuse
			// to spin on a receipt nobody consumed.
			c.retainInboundMarker()
			c.recordDrainError("inbound", fmt.Errorf("desync: inbound view success without a consumed batch (%d bytes)", length))
			return
		}
		if stop {
			return
		}
	}
}

// consumeInboundBatch processes one batch acquired through the synchronous
// terminal view. It returns true when the receive owner must stop. The raw and
// addrs views are only valid inside this call: every retention detaches a
// complete copy before returning, and no path asks for another receive.
//
// forwardOriginal is the receive-bound one-shot capability of this exact
// batch. It is used only after every existing gate admitted the unchanged
// all-Pass disposition; a batch with any Modify keeps the detached staging and
// the ordinary SendBatch path.
func (c *windowsCapture) consumeInboundBatch(raw []byte, addrs []windivert.Address, spans *[windivert.BatchMax + 1]uint32, sendBuffer *[]byte, sendAddresses *[]windivert.Address, forwardOriginal func() (int, error)) bool {
	length := len(raw)
	if length <= 0 || len(addrs) == 0 || len(addrs) > windivert.BatchMax {
		// Zero bytes with valid addresses is an invalid backend batch, not the
		// ordinary empty native drain (which never reaches a consumer).
		c.retainInboundOriginal(raw, addrs)
		c.recordDrainError("inbound", fmt.Errorf("desync: invalid inbound batch receive (%d bytes, %d addresses)", length, len(addrs)))
		return true
	}
	count, frameErr := frameWindowsBatch(raw, spans)
	if frameErr == nil {
		frameErr = validateWindowsBatchFamilies(raw, spans, count, addrs)
	}
	if frameErr != nil {
		c.retainInboundOriginal(raw, addrs)
		c.recordDrainError("inbound", frameErr)
		return true
	}
	if c.sendsUnsafe() {
		c.retainInboundOriginal(raw, addrs)
		return true
	}
	sendBatch := raw
	sendBatchAddrs := addrs
	modifiedAny := false
	var prepareErr error
	for index := 0; index < count; index++ {
		start, end := int(spans[index]), int(spans[index+1])
		if !c.dispatch.beginDispatch() {
			// The fence won between packets: the remaining tail is
			// pass-through only. Wait for the held-original release without
			// holding a dispatch/send count, lease/flow lock or capture rxMu.
			// The terminal view still holds recvLane.mu and its lifecycle
			// registration; the pass-through release does not need that lane.
			c.dispatch.awaitPassThrough()
			break
		}
		_ = c.lease.HandlePacket(raw[start:end:end], DirectionInbound, nil, nil)
		// The modified slot is one per direction: it must be consumed before
		// the next packet can overwrite it.
		modified := c.lease.TakeModified(DirectionInbound)
		c.dispatch.endDispatch()
		if modified == nil {
			continue
		}
		if len(modified) != end-start {
			// PlanReply is length-preserving; anything else is a local
			// preparation failure, never a truncation or silent Pass.
			prepareErr = fmt.Errorf("desync: inbound reply replacement has %d bytes for a %d-byte packet", len(modified), end-start)
			break
		}
		if *sendBuffer == nil {
			*sendBuffer = make([]byte, windivert.MTUMax)
			*sendAddresses = make([]windivert.Address, windivert.BatchMax)
		}
		if !modifiedAny {
			copy((*sendBuffer)[:length], raw)
			sendBatch = (*sendBuffer)[:length]
			sendBatchAddrs = (*sendAddresses)[:len(addrs)]
			for i := range addrs {
				copyWindowsAddress(&sendBatchAddrs[i], &addrs[i])
			}
			modifiedAny = true
		}
		copy(sendBatch[start:end], modified)
		recomputeChecksums(&sendBatchAddrs[index])
	}
	if prepareErr != nil {
		c.retainInboundSubmitted(raw, addrs, sendBatch, sendBatchAddrs, modifiedAny)
		c.recordPrepareError(prepareErr)
		return true
	}
	if c.sendsUnsafe() {
		c.retainInboundSubmitted(raw, addrs, sendBatch, sendBatchAddrs, modifiedAny)
		return true
	}
	preFence := c.dispatch.beginSend()
	if !preFence {
		// Never hold a pre-fence send token while waiting for the release:
		// Quiesce itself waits for that token.
		c.dispatch.awaitPassThrough()
	}
	// Re-check after the wait: an unrelated lane may have reported an unknown
	// completion in the meantime.
	if c.sendsUnsafe() {
		if preFence {
			c.dispatch.endSend()
		}
		c.retainInboundSubmitted(raw, addrs, sendBatch, sendBatchAddrs, modifiedAny)
		return true
	}
	var err error
	if modifiedAny {
		err = sendCapturedBatch(c.inbound, sendBatch, sendBatchAddrs)
	} else {
		// The unchanged all-Pass batch is submitted from the terminal
		// receive view itself, so the exact payload and raw80 array reach
		// the send lane without a capture-owned staging copy.
		err = forwardCapturedBatch(forwardOriginal, raw, addrs)
	}
	if preFence {
		c.dispatch.endSend()
	}
	if err != nil {
		c.recordSendError(err)
		if errors.Is(err, errCaptureSendIncomplete) {
			// Unknown progress owns both the received original and the
			// submitted batch; do not retry and do not receive again.
			c.retainInboundSubmitted(raw, addrs, sendBatch, sendBatchAddrs, modifiedAny)
			return true
		}
	}
	return false
}

// frameWindowsBatch validates the whole packed stream before any packet
// reaches a semantic user. This helper is direction-neutral; inbound dispatch
// and outbound record publication both require the same exact boundaries. WinDivert's batch receive appends the IPv4/IPv6
// packets back-to-back without padding, so each outer IP total length is the
// only boundary fact. ParsePacket is deliberately not used for framing: it may
// shorten a transport payload, while fragments, unsupported protocols and
// semantic-invalid packets must still pass unchanged. spans receives
// BatchMax+1 boundaries for a stream of at most BatchMax packets; IPv6 payload
// length zero means exactly a 40-byte header, never a guessed jumbogram.
func frameWindowsBatch(raw []byte, spans *[windivert.BatchMax + 1]uint32) (int, error) {
	n := len(raw)
	spans[0] = 0
	if n == 0 {
		return 0, errors.New("desync: empty batch")
	}
	offset, count := 0, 0
	for offset < n {
		if count >= windivert.BatchMax {
			return 0, fmt.Errorf("desync: batch exceeds %d packets", windivert.BatchMax)
		}
		remaining := n - offset
		switch raw[offset] >> 4 {
		case 4:
			if remaining < 20 {
				return 0, fmt.Errorf("desync: IPv4 packet truncated at offset %d", offset)
			}
			length := int(binary.BigEndian.Uint16(raw[offset+2 : offset+4]))
			if length < 20 || length > remaining {
				return 0, fmt.Errorf("desync: invalid IPv4 length %d at offset %d", length, offset)
			}
			offset += length
		case 6:
			if remaining < 40 {
				return 0, fmt.Errorf("desync: IPv6 packet truncated at offset %d", offset)
			}
			length := 40 + int(binary.BigEndian.Uint16(raw[offset+4:offset+6]))
			if length > remaining {
				return 0, fmt.Errorf("desync: invalid IPv6 length %d at offset %d", length, offset)
			}
			offset += length
		default:
			return 0, fmt.Errorf("desync: unsupported IP version %d at offset %d", raw[offset]>>4, offset)
		}
		spans[count+1] = uint32(offset)
		count++
	}
	return count, nil
}

// validateWindowsBatchFamilies requires one captured address per framed
// packet and an exact IP-version/address-family match. Remaining captured
// metadata is preserved, never normalized.
func validateWindowsBatchFamilies(raw []byte, spans *[windivert.BatchMax + 1]uint32, count int, addrs []windivert.Address) error {
	if count != len(addrs) {
		return fmt.Errorf("desync: batch has %d packets for %d captured addresses", count, len(addrs))
	}
	for index := 0; index < count; index++ {
		ipv6 := raw[spans[index]]>>4 == 6
		if ipv6 != addrs[index].IPv6() {
			return fmt.Errorf("desync: packet %d family does not match its captured address", index)
		}
	}
	return nil
}

// capturedBatchSendDisposition applies the one terminal disposition shared by
// the copied SendBatch path and the direct original forward. A negative count
// is the wrapper's unknown-progress result and owns the whole batch; any other
// terminal error is a visible failure (a count on it is the completion attempt,
// not progress); a short successful count is equally a visible failure and
// never a prefix to retry.
func capturedBatchSendDisposition(n int, err error, byteCount int, packetCount int) error {
	if n < 0 {
		return E.Errors(errCaptureSendIncomplete, err)
	}
	if err != nil {
		return fmt.Errorf("desync: windivert batch reinjection of %d bytes in %d packets failed: %w", byteCount, packetCount, err)
	}
	if n != byteCount {
		return fmt.Errorf("desync: windivert batch reinjection wrote %d of %d bytes", n, byteCount)
	}
	return nil
}

// sendCapturedBatch submits one captured batch and requires a complete native
// receipt. A short/error write is a visible terminal failure, not a prefix to
// retry; an unknown count keeps the whole-batch ownership with the caller.
func sendCapturedBatch(handle *windivert.Handle, batch []byte, addrs []windivert.Address) error {
	n, err := handle.SendBatch(batch, addrs)
	return capturedBatchSendDisposition(n, err, len(batch), len(addrs))
}

// forwardCapturedBatch forwards the exact terminal original batch through the
// receive-bound capability and applies the same terminal disposition as the
// copied batch send. The receive result itself is returned by the receive call,
// never replaced by this send diagnostic.
func forwardCapturedBatch(forwardOriginal func() (int, error), batch []byte, addrs []windivert.Address) error {
	n, err := forwardOriginal()
	return capturedBatchSendDisposition(n, err, len(batch), len(addrs))
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
	c.optionalRetained[index] = windowsOptionalRetention{raw: raw, occupied: true, address: *(*[80]byte)(unsafe.Pointer(address))}
	c.drainMu.Unlock()
}

// detachOriginalBytes copies the whole original batch into storage that
// outlives the terminal view. The capacity is exact, so a retained receipt is a
// detached copy and never an alias of lane storage.
func detachOriginalBytes(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	detached := make([]byte, len(raw))
	copy(detached, raw)
	return detached
}

func detachOriginalAddrs(addrs []windivert.Address) []windivert.Address {
	if len(addrs) == 0 {
		return nil
	}
	detached := make([]windivert.Address, len(addrs))
	for i := range addrs {
		copyWindowsAddress(&detached[i], &addrs[i])
	}
	return detached
}

// retainInboundMarker records an occupied optional slot without a published
// view: a receive that never reached a validated terminal consumer owns no
// readable batch, and the lane's pending memory is never read to invent one.
func (c *windowsCapture) retainInboundMarker() {
	c.drainMu.Lock()
	c.optionalRetained[0] = windowsOptionalRetention{occupied: true}
	c.drainMu.Unlock()
}

// retainInbound detaches the complete original batch (all bytes and every raw80
// address) from the terminal view before the consumer returns and keeps it in
// the existing optional slot. The old aliasing-only retention is deliberately
// gone: a lane view cannot outlive the consumer.
//
// When a send batch was already chosen, detached reports whether it is
// capture-owned staging (kept as-is) or the all-pass terminal view (retained as
// the same detached original copies).
func (c *windowsCapture) retainInbound(raw []byte, addrs []windivert.Address, chosen bool, submitted []byte, sendAddrs []windivert.Address, detached bool) {
	retained := windowsOptionalRetention{
		raw:      detachOriginalBytes(raw),
		addrs:    detachOriginalAddrs(addrs),
		occupied: true,
	}
	if chosen {
		if detached {
			retained.submitted = submitted
			retained.sendAddrs = sendAddrs
		} else {
			retained.submitted = retained.raw
			retained.sendAddrs = retained.addrs
		}
	}
	c.drainMu.Lock()
	c.optionalRetained[0] = retained
	c.drainMu.Unlock()
}

// retainInboundOriginal retains a batch before any send batch was chosen.
func (c *windowsCapture) retainInboundOriginal(raw []byte, addrs []windivert.Address) {
	c.retainInbound(raw, addrs, false, nil, nil, false)
}

// retainInboundSubmitted retains the original batch and the exact send-batch
// forms of a batch whose submission had already been prepared.
func (c *windowsCapture) retainInboundSubmitted(raw []byte, addrs []windivert.Address, submitted []byte, sendAddrs []windivert.Address, detached bool) {
	c.retainInbound(raw, addrs, true, submitted, sendAddrs, detached)
}

// recordPrepareError publishes a local batch-preparation failure: the whole
// batch is retained by the caller and no native disposition was issued.
func (c *windowsCapture) recordPrepareError(err error) {
	c.drainMu.Lock()
	first := c.prepareErrors.add(err)
	c.drainMu.Unlock()
	c.rxMu.Lock()
	c.receiveHalt = true
	if c.rxCond != nil {
		c.rxCond.Broadcast()
	}
	c.rxMu.Unlock()
	if first {
		c.lease.ReportNativeFailure(err)
		c.failCapture(err)
	}
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
	errs = append(errs, c.prepareErrors.err())
	if c.prepareErrors.first != nil {
		incomplete = true
	}
	// An occupied optional retention owns the only received unit of that lane;
	// it is never cleared to manufacture a successful Close.
	for index := range c.optionalRetained {
		if c.optionalRetained[index].occupied {
			incomplete = true
		}
	}
	c.drainMu.Unlock()
	c.rxMu.Lock()
	errs = append(errs, c.capacityErr)
	incomplete = incomplete || c.usedRecords != 0 || c.usedRawBytes != 0 || c.scratch.occupied || c.pendingBatch.occupied
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

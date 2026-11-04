//go:build desync_windows_model && !windows

package desync

// Offline model checks for the narrow outbound receive-only RecvBatch path.
// This is a source-shaped model over the reversible Windows overlay, never a
// native WinDivert/Windows execution result.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

type outboundBatchInput struct {
	raw   []byte
	addrs [][80]byte
	n     int
	err   error
}

type outboundBatchCall struct {
	raw   []byte
	addrs [][80]byte
	ptr   uintptr
	live  []byte
	// rawCap records the capacity of the terminal view handed to the
	// consumer. The view is capped to its exact receipt length.
	rawCap int
	// addrPtr/addrCap record the model lane's address backing and the exact
	// capacity of the address view handed to the consumer. The outbound reader
	// must use the view seam; it no longer shares a caller-owned backing.
	addrPtr uintptr
	addrCap int
}

type outboundBatchHarness struct {
	t          *testing.T
	e          *Engine
	l          *Lease
	c          *windowsCapture
	input      chan outboundBatchInput
	stop       chan struct{}
	stopOnce   sync.Once
	nativeDone chan struct{}
	mu         sync.Mutex
	recvCalls  []outboundBatchCall
	sendCalls  []outboundBatchCall
	sendResult func([]byte, *windivert.Address) (int, error)
	// One reusable model lane backing, written only by the serialized receive
	// owner, exactly like the wrapper's lane-owned payload/address storage.
	laneBuf   []byte
	laneAddrs []windivert.Address
	// The old caller-owned Into path and the terminal view are counted
	// separately: the outbound owner must use the view seam exclusively.
	viewCalls    int
	viewConsumes int
	intoCalls    int
	// recvIssued counts receive attempts as soon as they block, so "the next
	// receive was issued" is observable before its scripted receipt arrives.
	recvIssued int
	shutdowns  atomic.Int32
	closes     atomic.Int32
}

func outboundModelAddress(seed byte, ipv6 bool) [80]byte {
	var address [80]byte
	for i := range address {
		address[i] = seed + byte(i)
	}
	// Keep the packed flags word deterministic; the WINDIVERT_ADDRESS IPv6
	// flag is bit 20 of that word.
	binary.LittleEndian.PutUint32(address[8:12], 0)
	if ipv6 {
		binary.LittleEndian.PutUint32(address[8:12], 1<<20)
	}
	return address
}

func outboundAddressFromBytes(raw [80]byte) windivert.Address {
	var address windivert.Address
	*(*[80]byte)(unsafe.Pointer(&address)) = raw
	return address
}

func outboundAddressBytes(address *windivert.Address) [80]byte {
	return *(*[80]byte)(unsafe.Pointer(address))
}

func newOutboundBatchModel(t *testing.T) *outboundBatchHarness {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},"rules":[{"network":["tcp"],"port":[1]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &producerOrderBackend{})
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	h := &outboundBatchHarness{
		t: t, e: engine, l: lease,
		input:      make(chan outboundBatchInput, 16),
		stop:       make(chan struct{}),
		nativeDone: make(chan struct{}),
	}
	capture := &windowsCapture{lease: lease, dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	h.c = capture
	capture.releaseHold, err = lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	capture.outbound = &windivert.Handle{
		RecvFunc: func([]byte) (int, windivert.Address, error) {
			// The outbound reader must use the batch receipt; a single Recv is
			// a modeled failure, not a silent fallback.
			return 0, windivert.Address{}, fmt.Errorf("model outbound reader used single Recv")
		},
		RecvBatchFunc:     h.recvBatch,
		RecvBatchIntoFunc: h.recvBatchInto,
		RecvBatchViewFunc: h.recvBatchView,
		SendFunc:          h.send,
		SendBatchFunc: func([]byte, []windivert.Address) (int, error) {
			panic("outbound send batching is not part of this change")
		},
		ShutdownFunc: func() error {
			h.shutdowns.Add(1)
			h.stopOnce.Do(func() { close(h.stop) })
			return nil
		},
		CloseFunc: func() error {
			h.closes.Add(1)
			close(h.nativeDone)
			return nil
		},
		DoneChan: h.nativeDone,
	}
	lease.capture = capture
	t.Cleanup(func() { _ = engine.Close() })
	return h
}

func (h *outboundBatchHarness) recvBatch(p []byte) (int, []windivert.Address, error) {
	// Record the issued receive before blocking: an outstanding next batch is
	// itself the observable fact that the reader did not wait for terminal
	// detached records.
	h.mu.Lock()
	index := len(h.recvCalls)
	h.recvCalls = append(h.recvCalls, outboundBatchCall{ptr: uintptr(unsafe.Pointer(&p[0])), live: p})
	h.recvIssued++
	h.mu.Unlock()
	var input outboundBatchInput
	select {
	case input = <-h.input:
	case <-h.stop:
		return 0, nil, windivert.ReplayDrained
	}
	n := input.n
	if n == 0 && input.err == nil {
		n = len(input.raw)
	}
	copy(p, input.raw)
	addrs := make([]windivert.Address, len(input.addrs))
	for i := range input.addrs {
		addrs[i] = outboundAddressFromBytes(input.addrs[i])
	}
	h.mu.Lock()
	h.recvCalls[index].raw = bytes.Clone(input.raw)
	h.recvCalls[index].addrs = append([][80]byte(nil), input.addrs...)
	h.mu.Unlock()
	return n, addrs, input.err
}

func (h *outboundBatchHarness) recvBatchInto(p []byte, dst []windivert.Address) (int, []windivert.Address, error) {
	if len(dst) < windivert.BatchMax {
		panic("model outbound RecvBatchInto short caller storage")
	}
	n, addrs, err := h.recvBatch(p)
	h.mu.Lock()
	h.intoCalls++
	if len(h.recvCalls) > 0 {
		last := &h.recvCalls[len(h.recvCalls)-1]
		last.addrPtr = uintptr(unsafe.Pointer(&dst[0]))
		last.addrCap = cap(dst)
	}
	h.mu.Unlock()
	if err != nil {
		return n, nil, err
	}
	copy(dst, addrs)
	return n, dst[:len(addrs)], nil
}

// recvBatchView models the wrapper's synchronous terminal view: one reusable
// model lane is filled by the scripted driver, and only a terminal receipt with
// validated dimensions reaches the consumer. The views end when the consumer
// returns, exactly like the production borrow interval, so retaining either of
// them past the callback is an observable aliasing bug.
func (h *outboundBatchHarness) recvBatchView(bufferSize int, consume func([]byte, []windivert.Address)) (int, error) {
	if bufferSize < windivert.MTUMax {
		panic("model outbound RecvBatchView short buffer")
	}
	if h.laneBuf == nil {
		h.laneBuf = make([]byte, bufferSize)
		h.laneAddrs = make([]windivert.Address, windivert.BatchMax)
	}
	// Record the issued receive before blocking: an outstanding next batch is
	// itself the observable fact that the reader did not wait for terminal
	// detached records or the scripted receipt.
	h.mu.Lock()
	index := len(h.recvCalls)
	h.recvCalls = append(h.recvCalls, outboundBatchCall{
		ptr: uintptr(unsafe.Pointer(&h.laneBuf[0])), live: h.laneBuf,
		addrPtr: uintptr(unsafe.Pointer(&h.laneAddrs[0])),
	})
	h.recvIssued++
	h.mu.Unlock()
	var input outboundBatchInput
	select {
	case input = <-h.input:
	case <-h.stop:
		return 0, windivert.ReplayDrained
	}
	n := input.n
	if n == 0 && input.err == nil {
		n = len(input.raw)
	}
	copy(h.laneBuf, input.raw)
	for i := range input.addrs {
		h.laneAddrs[i] = outboundAddressFromBytes(input.addrs[i])
	}
	h.mu.Lock()
	call := &h.recvCalls[index]
	call.raw = bytes.Clone(input.raw)
	call.addrs = append([][80]byte(nil), input.addrs...)
	h.mu.Unlock()
	if input.err != nil {
		// A terminal native failure publishes no view; the count is the raw
		// completion value and is never treated as a successful receipt.
		h.mu.Lock()
		h.viewCalls++
		h.mu.Unlock()
		return n, input.err
	}
	raw := h.laneBuf[:n:n]
	addrs := h.laneAddrs[:len(input.addrs):len(input.addrs)]
	h.mu.Lock()
	call = &h.recvCalls[index]
	call.rawCap = cap(raw)
	call.addrCap = cap(addrs)
	h.viewCalls++
	h.viewConsumes++
	h.mu.Unlock()
	consume(raw, addrs)
	return n, nil
}

func (h *outboundBatchHarness) send(p []byte, address *windivert.Address) (int, error) {
	call := outboundBatchCall{raw: bytes.Clone(p), ptr: uintptr(unsafe.Pointer(&p[0])), addrs: [][80]byte{outboundAddressBytes(address)}}
	h.mu.Lock()
	h.sendCalls = append(h.sendCalls, call)
	h.mu.Unlock()
	if h.sendResult != nil {
		return h.sendResult(p, address)
	}
	return len(p), nil
}

func (h *outboundBatchHarness) deliver(raw []byte, addrs [][80]byte) {
	h.input <- outboundBatchInput{raw: bytes.Clone(raw), addrs: addrs}
}

func (h *outboundBatchHarness) start() { h.c.startUsers() }

func (h *outboundBatchHarness) counts() (recv, send int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.recvIssued, len(h.sendCalls)
}

func (h *outboundBatchHarness) calls() (recv, send []outboundBatchCall) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]outboundBatchCall(nil), h.recvCalls...), append([]outboundBatchCall(nil), h.sendCalls...)
}

func (h *outboundBatchHarness) viewStats() (views, consumes, into int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.viewCalls, h.viewConsumes, h.intoCalls
}

func (h *outboundBatchHarness) waitSends(t *testing.T, want int) []outboundBatchCall {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		recv, send := h.counts()
		if send >= want {
			_, sends := h.calls()
			return sends
		}
		if time.Now().After(deadline) {
			h.c.drainMu.Lock()
			receiveErr := h.c.drainErrors[0].err()
			h.c.drainMu.Unlock()
			t.Fatalf("outbound sends absent: recv=%d send=%d want=%d receive=%v", recv, send, want, receiveErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *outboundBatchHarness) delivered() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	delivered := 0
	for _, call := range h.recvCalls {
		if call.addrs != nil || len(call.raw) != 0 {
			delivered++
		}
	}
	return delivered
}

func (h *outboundBatchHarness) waitRecv(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		recv, _ := h.counts()
		if recv >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("next outbound receive absent: recv=%d want=%d", recv, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *outboundBatchHarness) close(t *testing.T) {
	t.Helper()
	if err := h.l.Close(nil); err != nil {
		t.Fatal(err)
	}
	if err := h.l.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	if h.e.ActiveLeases() != 0 {
		t.Fatal("native charge retained")
	}
}

func TestWindowsOutboundBatchOrdinaryFIFO(t *testing.T) {
	h := newOutboundBatchModel(t)
	h.start()
	// Variable, decreasing IPv4/IPv6 packets. The ordinary path must hand each
	// packet to its own detached record straight from the terminal view.
	packets := [][]byte{
		buildIPv4UDP(t, []byte("first-ordinary-batch-payload"), 443).Raw,
		buildIPv6UDP(t, []byte("v2")).Raw,
		buildIPv4UDP(t, []byte("third"), 443).Raw,
	}
	addrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, true), outboundModelAddress(3, false)}
	// Poison the capture fallback backing. The ordinary path detaches from the
	// terminal view directly, so it must never write a second copy here.
	poison := bytes.Repeat([]byte{0xe7}, len(h.c.receiveBuffer))
	copy(h.c.receiveBuffer, poison)
	h.deliver(concatPackets(packets...), addrs)
	sends := h.waitSends(t, len(packets))
	if delivered := h.delivered(); delivered != 1 {
		t.Fatalf("delivered receive batches = %d, want 1 for one packed receive", delivered)
	}
	recv, _ := h.calls()
	for index, packet := range packets {
		if !bytes.Equal(sends[index].raw, packet) {
			t.Fatalf("send %d does not carry exactly that packet", index)
		}
		if sends[index].ptr == recv[0].ptr {
			t.Fatalf("record %d aliases the terminal view instead of a detached copy", index)
		}
		if sends[index].ptr == uintptr(unsafe.Pointer(&h.c.receiveBuffer[0])) {
			t.Fatalf("record %d aliases the capture fallback backing", index)
		}
		if sends[index].addrs[0] != addrs[index] {
			t.Fatalf("send %d lost the full 80-byte captured address", index)
		}
	}
	if views, consumes, into := h.viewStats(); views != 1 || consumes != 1 || into != 0 {
		t.Fatalf("ordinary receive seam: view=%d consume=%d old-into=%d, want 1/1/0", views, consumes, into)
	}
	if !bytes.Equal(h.c.receiveBuffer, poison) {
		t.Fatal("ordinary batch wrote into the capture fallback backing")
	}
	// The next native receive is issued once the batch has been transferred,
	// without waiting for the detached records to reach their terminal send.
	h.waitRecv(t, 2)
	if delivered := h.delivered(); delivered != 1 {
		t.Fatalf("delivered receive batches = %d, want 1", delivered)
	}
	rxWait(t, "detached records were not released", func() bool {
		h.c.rxMu.Lock()
		defer h.c.rxMu.Unlock()
		return h.c.usedRecords == 0 && h.c.usedRawBytes == 0 && !h.c.scratch.occupied
	})
	// The same packets delivered one per native batch keep the same detached
	// copies, addresses and FIFO order.
	for index, packet := range packets {
		h.deliver(packet, [][80]byte{addrs[index]})
	}
	sends = h.waitSends(t, len(packets)*2)
	for index, packet := range packets {
		got := sends[len(packets)+index]
		if !bytes.Equal(got.raw, packet) {
			t.Fatalf("single-batch send %d differs from the packed batch", index)
		}
		if got.addrs[0] != addrs[index] {
			t.Fatalf("single-batch address %d differs from the packed batch", index)
		}
	}
	h.waitRecv(t, 1+len(packets)+1)
	if delivered := h.delivered(); delivered != 1+len(packets) {
		t.Fatalf("delivered receive batches = %d, want %d", delivered, 1+len(packets))
	}
	if views, consumes, into := h.viewStats(); views != 1+len(packets) || consumes != 1+len(packets) || into != 0 {
		t.Fatalf("receive seam: view=%d consume=%d old-into=%d, want %d/%d/0", views, consumes, into, 1+len(packets), 1+len(packets))
	}
	if !bytes.Equal(h.c.receiveBuffer, poison) {
		t.Fatal("ordinary batches wrote into the capture fallback backing")
	}
	recv, _ = h.calls()
	for _, call := range recv[1:] {
		if call.ptr != recv[0].ptr || call.addrPtr != recv[0].addrPtr {
			t.Fatal("reader replaced the one receive lane backing")
		}
	}
	if recv[0].rawCap != len(packets[0])+len(packets[1])+len(packets[2]) || recv[0].addrCap != len(addrs) {
		t.Fatalf("terminal view caps = %d/%d, want %d/%d", recv[0].rawCap, recv[0].addrCap, len(packets[0])+len(packets[1])+len(packets[2]), len(addrs))
	}
	h.close(t)
}

// A whole-batch sequence-range shortage is retained without publishing any
// prefix and without manufacturing record tokens for untransferred packets.
func TestWindowsOutboundBatchSequenceRange(t *testing.T) {
	h := newOutboundBatchModel(t)
	h.c.rxMu.Lock()
	h.c.sequence = ^uint64(0) - 1
	before := h.c.sequence
	h.c.rxMu.Unlock()
	packets := [][]byte{
		buildIPv4UDP(t, []byte("first"), 443).Raw,
		buildIPv4UDP(t, []byte("second"), 443).Raw,
	}
	addrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, false)}
	h.start()
	h.deliver(concatPackets(packets...), addrs)
	rxChannel(t, h.c.done, "outbound reader kept receiving after a sequence-range failure")
	recv, sends := h.calls()
	if len(recv) != 1 || len(sends) != 0 {
		t.Fatalf("sequence shortage published a prefix: recv=%d send=%d", len(recv), len(sends))
	}
	h.c.rxMu.Lock()
	pending := h.c.pendingBatch
	sequence := h.c.sequence
	h.c.rxMu.Unlock()
	if sequence != before {
		t.Fatalf("sequence advanced to %d on an untransferred batch", sequence)
	}
	if !pending.occupied || pending.validated || pending.count != 0 || pending.next != 0 {
		t.Fatalf("sequence shortage did not retain the untransferred receipt: %+v", pending)
	}
	if len(pending.raw) != len(packets[0])+len(packets[1]) || len(pending.addrs) != 2 {
		t.Fatalf("retained receipt shape = %d bytes, %d addresses", len(pending.raw), len(pending.addrs))
	}
	// The retained receipt is the complete capture-owned snapshot, not the
	// borrowed terminal lane.
	if uintptr(unsafe.Pointer(&pending.raw[0])) != uintptr(unsafe.Pointer(&h.c.receiveBuffer[0])) {
		t.Fatal("sequence shortage retained the borrowed terminal view")
	}
	if !bytes.Equal(pending.raw, concatPackets(packets...)) {
		t.Fatal("sequence shortage snapshot differs from the terminal receipt")
	}
	if outboundAddressBytes(&pending.addrs[1]) != addrs[1] {
		t.Fatal("sequence shortage lost the raw80 captured address")
	}
	if err := h.l.Close(nil); err == nil {
		t.Fatal("sequence shortage closed successfully")
	}
	if err := h.l.WaitCaptureRetired(); err == nil {
		t.Fatal("sequence shortage retired the native owner")
	}
	if h.e.ActiveLeases() != 1 {
		t.Fatal("sequence shortage released the native charge")
	}
}

func TestWindowsOutboundBatchReceiptRetention(t *testing.T) {
	valid := buildIPv4UDP(t, []byte("valid"), 443).Raw
	t.Run("malformed-suffix", func(t *testing.T) {
		h := newOutboundBatchModel(t)
		h.start()
		truncated := buildIPv4UDP(t, []byte("suffix"), 443).Raw
		raw := append(append([]byte(nil), valid...), truncated[:len(truncated)-1]...)
		addrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, false)}
		h.deliver(raw, addrs)
		rxChannel(t, h.c.done, "malformed suffix was not a terminal receipt")
		recv, sends := h.calls()
		if len(recv) != 1 || len(sends) != 0 {
			t.Fatalf("malformed suffix published a prefix: recv=%d send=%d", len(recv), len(sends))
		}
		h.c.rxMu.Lock()
		pending := h.c.pendingBatch
		records, bytesUsed := h.c.usedRecords, h.c.usedRawBytes
		h.c.rxMu.Unlock()
		if !pending.occupied || pending.validated {
			t.Fatal("malformed suffix descriptor is not retained/unvalidated")
		}
		if len(pending.raw) != len(raw) || !bytes.Equal(pending.raw, raw) || len(pending.addrs) != 2 {
			t.Fatalf("malformed receipt not preserved: %d bytes, %d addresses", len(pending.raw), len(pending.addrs))
		}
		// The complete visible receipt was materialized into capture-owned
		// storage before the callback returned.
		if uintptr(unsafe.Pointer(&pending.raw[0])) != uintptr(unsafe.Pointer(&h.c.receiveBuffer[0])) {
			t.Fatal("malformed receipt still aliases the borrowed terminal view")
		}
		if outboundAddressBytes(&pending.addrs[1]) != addrs[1] {
			t.Fatal("captured address of the malformed suffix was lost")
		}
		if records != 0 || bytesUsed != 0 {
			t.Fatalf("malformed suffix charged the ledger: %d records %d bytes", records, bytesUsed)
		}
		if err := h.l.Close(nil); err == nil {
			t.Fatal("malformed suffix closed successfully")
		}
		if err := h.l.WaitCaptureRetired(); err == nil || h.e.ActiveLeases() != 1 {
			t.Fatal("malformed suffix retired a retained receipt")
		}
	})
	t.Run("unknown", func(t *testing.T) {
		h := newOutboundBatchModel(t)
		h.start()
		failure := errors.New("modeled unknown receipt")
		h.input <- outboundBatchInput{raw: valid, n: -1, err: failure, addrs: [][80]byte{outboundModelAddress(9, false)}}
		rxChannel(t, h.c.done, "unknown receipt was not terminal")
		recv, sends := h.calls()
		if len(recv) != 1 || len(sends) != 0 {
			t.Fatalf("unknown receipt produced work: recv=%d send=%d", len(recv), len(sends))
		}
		h.c.rxMu.Lock()
		pending := h.c.pendingBatch
		h.c.rxMu.Unlock()
		// The pre-native occupied marker has nil views: no callback ran, so the
		// native payload/addresses stay in the quarantined lane and the caller
		// buffer is never presented as a receipt. This is source-shaped
		// bookkeeping, not a native UNKNOWN PASS.
		if !pending.occupied || len(pending.raw) != 0 || len(pending.addrs) != 0 || pending.count != 0 || pending.next != 0 || pending.validated {
			t.Fatalf("unknown receipt retention = %+v", pending)
		}
		if err := h.l.Close(nil); err == nil || h.l.WaitCaptureRetired() == nil || h.e.ActiveLeases() != 1 {
			t.Fatal("unknown receipt manufactured a safe retirement")
		}
	})
}

// Sticky mid-batch exhaustion keeps the already-received tail in the same
// single scratch rendezvous: each remaining span is aliased, addressed and sent
// once, and never consumes or returns a record/byte credit.
func TestWindowsOutboundBatchStickyMidBatch(t *testing.T) {
	h := newOutboundBatchModel(t)
	h.c.rxMu.Lock()
	for i := 0; i < windowsReceiveRecords; i++ {
		record, _ := h.c.reserveRecordLocked(1)
		if record == nil {
			h.c.rxMu.Unlock()
			t.Fatalf("prefill reserve %d failed", i)
		}
		record.raw = make([]byte, 1) // exact copy of the charged span
	}
	h.c.rxMu.Unlock()
	h.start()
	packets := [][]byte{buildIPv4UDP(t, []byte("first"), 443).Raw, buildIPv4UDP(t, []byte("second"), 443).Raw}
	packed := concatPackets(packets...)
	addrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, false)}
	h.deliver(packed, addrs)
	sends := h.waitSends(t, 2)
	if delivered := h.delivered(); delivered != 1 {
		t.Fatalf("delivered receive batches = %d", delivered)
	}
	recv, _ := h.calls()
	offset := 0
	for index := range packets {
		if !bytes.Equal(sends[index].raw, packets[index]) || sends[index].addrs[0] != addrs[index] {
			t.Fatalf("scratch span %d differs from the received original", index)
		}
		if sends[index].ptr == recv[0].ptr {
			t.Fatalf("scratch span %d still aliases the terminal view", index)
		}
		if sends[index].ptr != uintptr(unsafe.Pointer(&h.c.receiveBuffer[0]))+uintptr(offset) {
			t.Fatalf("scratch span %d does not alias the capture snapshot", index)
		}
		offset += len(packets[index])
	}
	// One complete snapshot of the whole terminal receipt, taken before the
	// first scratch publication, with the original cursor/sequence intact.
	if !bytes.Equal(h.c.receiveBuffer[:len(packed)], packed) {
		t.Fatal("sticky batch did not snapshot the complete terminal receipt")
	}
	h.c.rxMu.Lock()
	latched := h.c.capacityErr
	sequence := h.c.sequence
	records, bytesUsed := h.c.usedRecords, h.c.usedRawBytes
	scratch, pending := h.c.scratch.occupied, h.c.pendingBatch.occupied
	h.c.rxMu.Unlock()
	if sequence != uint64(len(packets)) {
		t.Fatalf("sticky batch sequence = %d, want %d", sequence, len(packets))
	}
	if latched != errWindowsReceiveCapacity {
		t.Fatal("sticky capacity failure was not latched")
	}
	if records != windowsReceiveRecords || bytesUsed != windowsReceiveRecords {
		t.Fatalf("scratch spans changed the ledger: %d records %d bytes", records, bytesUsed)
	}
	if scratch || pending {
		t.Fatal("completed sticky batch kept owned views")
	}
	// The pre-filled credits are deliberately not freed: the close path must
	// report the unproven retention instead of retiring the native owner.
	if err := h.l.WaitClosed(); !errors.Is(err, errWindowsReceiveCapacity) {
		t.Fatalf("WaitClosed = %v", err)
	}
	if err := h.l.WaitCaptureRetired(); err == nil || h.e.ActiveLeases() != 1 {
		t.Fatal("unfreed ledger was manufactured into a safe retirement")
	}
}

// Freed ledger credits do not resume detached records: once the sticky failure
// exists, every later batch stays on the one scratch rendezvous.
func TestWindowsOutboundBatchStickyAfterFreedCredits(t *testing.T) {
	h := newOutboundBatchModel(t)
	h.c.rxMu.Lock()
	h.c.capacityErr = errWindowsReceiveCapacity
	h.c.rxMu.Unlock()
	h.c.AllowPassThrough() // the scratch path of a latched failure is pass-through
	h.start()
	for round := 0; round < 2; round++ {
		packets := [][]byte{
			buildIPv4UDP(t, []byte{byte('a' + round)}, 443).Raw,
			buildIPv4UDP(t, []byte{byte('b' + round), 2}, 443).Raw,
		}
		packed := concatPackets(packets...)
		addrs := [][80]byte{outboundModelAddress(byte(round*2+1), false), outboundModelAddress(byte(round*2+2), false)}
		h.deliver(packed, addrs)
		sends := h.waitSends(t, (round+1)*2)
		recv, _ := h.calls()
		offset := 0
		for index := range packets {
			got := sends[round*2+index]
			if !bytes.Equal(got.raw, packets[index]) || got.addrs[0] != addrs[index] {
				t.Fatalf("round %d scratch span %d differs from the received original", round, index)
			}
			if got.ptr == recv[0].ptr {
				t.Fatalf("round %d scratch span %d still aliases the terminal view", round, index)
			}
			if got.ptr != uintptr(unsafe.Pointer(&h.c.receiveBuffer[0]))+uintptr(offset) {
				t.Fatalf("round %d scratch span %d does not alias the capture snapshot", round, index)
			}
			offset += len(packets[index])
		}
		if !bytes.Equal(h.c.receiveBuffer[:len(packed)], packed) {
			t.Fatalf("round %d sticky batch did not snapshot the complete terminal receipt", round)
		}
		h.c.rxMu.Lock()
		records, bytesUsed, scratch := h.c.usedRecords, h.c.usedRawBytes, h.c.scratch.occupied
		sticky := h.c.capacityErr
		h.c.rxMu.Unlock()
		if records != 0 || bytesUsed != 0 || scratch {
			t.Fatalf("round %d charged the ledger: %d %d %v", round, records, bytesUsed, scratch)
		}
		if sticky != errWindowsReceiveCapacity {
			t.Fatalf("round %d cleared the sticky failure", round)
		}
	}
	if err := h.l.Close(nil); !errors.Is(err, errWindowsReceiveCapacity) {
		t.Fatalf("Close = %v, want the sticky capacity failure", err)
	}
	if err := h.l.WaitCaptureRetired(); err != nil {
		t.Fatalf("drained sticky failure did not retire: %v", err)
	}
	if h.shutdowns.Load() != 1 || h.closes.Load() != 1 || h.e.ActiveLeases() != 0 {
		t.Fatal("native owners not exactly once")
	}
}

// Local bookkeeping only: the pending descriptor survives scratch completion
// and halts, and the teardown predicate treats its occupancy as unproven.
func TestWindowsOutboundBatchRetentionState(t *testing.T) {
	t.Run("scratch-terminal-keeps-pending", func(t *testing.T) {
		c := &windowsCapture{}
		c.initReceive()
		addrs := []windivert.Address{outboundAddressFromBytes(outboundModelAddress(1, false)), outboundAddressFromBytes(outboundModelAddress(2, false))}
		c.pendingBatch = windowsOutboundPendingBatch{raw: c.receiveBuffer[:40:40], addrs: addrs, count: 2, next: 1, occupied: true, validated: true}
		c.sequence = 7
		c.receiveHalt, c.scratch = true, windowsReceiveRecord{raw: c.receiveBuffer[10:20:20], sequence: 7, occupied: true, worker: true}
		c.finishRecord(&c.scratch, 7, true, true)
		if c.scratch.occupied {
			t.Fatal("terminal scratch was not released")
		}
		if !c.pendingBatch.occupied || c.pendingBatch.count != 2 || c.pendingBatch.next != 1 || c.pendingBatch.raw[0] != c.receiveBuffer[0] || len(c.pendingBatch.addrs) != 2 {
			t.Fatal("scratch completion/halt cleared or mutated the pending descriptor")
		}
		if c.usedRecords != 0 || c.usedRawBytes != 0 {
			t.Fatal("scratch completion returned a ledger credit")
		}
	})
	teardownPredicate := func(t *testing.T, occupied bool) error {
		t.Helper()
		c := &windowsCapture{dispatch: newCaptureDispatchGate()}
		c.initReceive()
		c.readerDone = true
		if occupied {
			c.pendingBatch = windowsOutboundPendingBatch{raw: c.receiveBuffer[:20:20], addrs: make([]windivert.Address, 1), count: 1, occupied: true, validated: true}
		}
		return c.teardown()
	}
	t.Run("teardown-retains-pending", func(t *testing.T) {
		err := teardownPredicate(t, true)
		if !errors.Is(err, errWindowsReceiveUnproven) {
			t.Fatalf("teardown with a pending receipt = %v, want unproven retention", err)
		}
	})
	t.Run("teardown-safe-without-pending", func(t *testing.T) {
		if err := teardownPredicate(t, false); err != nil {
			t.Fatalf("empty teardown = %v", err)
		}
	})
}

// Whole-batch validation happens before any prefix publication. Every malformed
// frame/family receipt and a zero-byte terminal view keeps the complete receipt
// as a capture-owned snapshot, publishes no prefix and stops the reader; none of
// them is the ordinary empty drain.
func TestWindowsOutboundBatchValidationTables(t *testing.T) {
	valid4 := buildIPv4UDP(t, []byte("prefix"), 443).Raw
	valid6 := buildIPv6UDP(t, []byte("v6")).Raw
	truncated4 := buildIPv4UDP(t, []byte("suffix"), 443).Raw
	badLength := make([]byte, 20)
	badLength[0] = 0x45
	binary.BigEndian.PutUint16(badLength[2:4], 10)
	tests := []struct {
		name  string
		raw   []byte
		addrs [][80]byte
	}{
		{"frame/bad-version", []byte{0x75, 0, 0, 0}, [][80]byte{outboundModelAddress(1, false)}},
		{"frame/ipv4-truncated", valid4[:12], [][80]byte{outboundModelAddress(1, false)}},
		{"frame/ipv4-bad-length", badLength, [][80]byte{outboundModelAddress(1, false)}},
		{"frame/ipv6-truncated", valid6[:24], [][80]byte{outboundModelAddress(1, true)}},
		{"frame/malformed-suffix", append(append([]byte(nil), valid4...), truncated4[:len(truncated4)-1]...), [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, false)}},
		{"family/mismatch", valid4, [][80]byte{outboundModelAddress(1, true)}},
		{"view/zero-bytes", nil, [][80]byte{outboundModelAddress(4, false)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h := newOutboundBatchModel(t)
			h.start()
			h.deliver(test.raw, test.addrs)
			rxChannel(t, h.c.done, "invalid outbound view did not stop the reader")
			if _, sends := h.calls(); len(sends) != 0 {
				t.Fatalf("invalid view published %d packets before validation", len(sends))
			}
			h.c.rxMu.Lock()
			pending := h.c.pendingBatch
			h.c.rxMu.Unlock()
			if !pending.occupied || pending.validated || pending.count != 0 || pending.next != 0 {
				t.Fatalf("invalid view did not retain an unvalidated descriptor: %+v", pending)
			}
			if len(pending.raw) != len(test.raw) || len(pending.addrs) != len(test.addrs) {
				t.Fatalf("retained receipt shape = %d/%d, want %d/%d", len(pending.raw), len(pending.addrs), len(test.raw), len(test.addrs))
			}
			if len(test.raw) > 0 {
				if !bytes.Equal(pending.raw, test.raw) {
					t.Fatal("retained snapshot differs from the terminal receipt")
				}
				if uintptr(unsafe.Pointer(&pending.raw[0])) != uintptr(unsafe.Pointer(&h.c.receiveBuffer[0])) {
					t.Fatal("retained snapshot still aliases the borrowed terminal view")
				}
			}
			if outboundAddressBytes(&pending.addrs[0]) != test.addrs[0] {
				t.Fatal("retained raw80 captured address differs")
			}
			h.c.drainMu.Lock()
			drained := h.c.drained[0]
			h.c.drainMu.Unlock()
			if drained {
				t.Fatal("invalid view marked the outbound queue drained")
			}
			if err := h.l.Close(nil); err == nil {
				t.Fatal("invalid view closed successfully")
			}
			if err := h.l.WaitCaptureRetired(); err == nil || h.e.ActiveLeases() != 1 {
				t.Fatal("invalid view manufactured a safe retirement")
			}
		})
	}
}

// Literal mid-batch record/byte boundaries: the first packet of the batch is an
// ordinary detached record, the next reservation fails, and the complete
// terminal receipt is snapshotted exactly once before the sticky scratch
// publication. The original cursor/spans/sequence are unchanged and no held or
// artificially delayed send is involved.
func TestWindowsOutboundBatchMidBatchBoundarySnapshot(t *testing.T) {
	packets := [][]byte{
		buildIPv4UDP(t, []byte("mid-batch-boundary-first"), 443).Raw,
		buildIPv4UDP(t, []byte("second"), 443).Raw,
	}
	packed := concatPackets(packets...)
	addrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, false)}
	type boundaryState struct {
		occupied, validated bool
		count, next         int
		sequence            uint64
		rawOwned            bool
		scratchOwned        bool
		fullSnapshot        bool
		allRaw80            bool
	}
	for _, kind := range []string{"records", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			h := newOutboundBatchModel(t)
			h.c.rxMu.Lock()
			switch kind {
			case "records":
				for i := 0; i < windowsReceiveRecords-1; i++ {
					record, _ := h.c.reserveRecordLocked(1)
					if record == nil {
						h.c.rxMu.Unlock()
						t.Fatalf("prefill reserve %d failed", i)
					}
					record.raw = make([]byte, 1)
				}
			case "bytes":
				h.c.usedRawBytes = windowsReceiveRawBytes - len(packets[0])
			}
			h.c.rxMu.Unlock()
			checked := make(chan boundaryState, 1)
			var once sync.Once
			h.sendResult = func(p []byte, _ *windivert.Address) (int, error) {
				h.mu.Lock()
				n := len(h.sendCalls)
				h.mu.Unlock()
				if n == 2 {
					h.c.rxMu.Lock()
					pending := h.c.pendingBatch
					scratch := h.c.scratch
					state := boundaryState{
						occupied: pending.occupied, validated: pending.validated,
						count: pending.count, next: pending.next, sequence: h.c.sequence,
					}
					state.fullSnapshot = bytes.Equal(pending.raw, packed)
					state.allRaw80 = len(pending.addrs) == len(addrs)
					for i := range pending.addrs {
						state.allRaw80 = state.allRaw80 && outboundAddressBytes(&pending.addrs[i]) == addrs[i]
					}
					h.c.rxMu.Unlock()
					state.rawOwned = len(pending.raw) == len(packed) && uintptr(unsafe.Pointer(&pending.raw[0])) == uintptr(unsafe.Pointer(&h.c.receiveBuffer[0]))
					state.scratchOwned = len(scratch.raw) == len(packets[1]) && uintptr(unsafe.Pointer(&scratch.raw[0])) == uintptr(unsafe.Pointer(&h.c.receiveBuffer[len(packets[0])]))
					once.Do(func() { checked <- state })
				}
				return len(p), nil
			}
			h.start()
			h.deliver(packed, addrs)
			sends := h.waitSends(t, 2)
			var state boundaryState
			select {
			case state = <-checked:
			case <-time.After(time.Second):
				t.Fatal("scratch boundary state was not observed")
			}
			if !state.occupied || !state.validated || state.count != len(packets) || state.next != len(packets) || state.sequence != uint64(len(packets)) {
				t.Fatalf("mid-batch cursor state = %+v", state)
			}
			if !state.fullSnapshot || !state.allRaw80 {
				t.Fatalf("first scratch send lacks complete original snapshot/raw80: %+v", state)
			}
			if !state.rawOwned || !state.scratchOwned {
				t.Fatalf("mid-batch snapshot is not capture-owned: raw=%v scratch=%v", state.rawOwned, state.scratchOwned)
			}
			recv, _ := h.calls()
			if sends[0].ptr == recv[0].ptr || sends[0].ptr == uintptr(unsafe.Pointer(&h.c.receiveBuffer[0])) {
				t.Fatal("first packet was not detached from both the view and the fallback backing")
			}
			if sends[1].ptr != uintptr(unsafe.Pointer(&h.c.receiveBuffer[0]))+uintptr(len(packets[0])) {
				t.Fatal("sticky scratch does not alias the complete capture snapshot")
			}
			if !bytes.Equal(h.c.receiveBuffer[:len(packed)], packed) {
				t.Fatal("mid-batch snapshot did not copy the complete terminal receipt")
			}
			h.c.rxMu.Lock()
			scratch, pending := h.c.scratch.occupied, h.c.pendingBatch.occupied
			h.c.rxMu.Unlock()
			if scratch || pending {
				t.Fatal("completed mid-batch boundary kept owned views")
			}
			// The deliberate record/byte residue is not invented into a safe
			// retirement; the sticky capacity failure is still reported.
			if err := h.l.Close(nil); !errors.Is(err, errWindowsReceiveCapacity) {
				t.Fatalf("Close = %v, want the sticky capacity failure", err)
			}
			if err := h.l.WaitCaptureRetired(); err == nil || h.e.ActiveLeases() != 1 {
				t.Fatal("unfreed boundary residue was manufactured into a safe retirement")
			}
		})
	}
}

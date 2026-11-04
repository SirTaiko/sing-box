//go:build desync_windows_model && !windows

package desync

// Offline model checks for the narrow inbound RecvBatch/SendBatch path. This is
// a source-shaped model over the reversible Windows overlay, never a native
// WinDivert/Windows execution result.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

type inboundBatchInput struct {
	raw   []byte
	addrs [][80]byte
	n     int
	err   error
}

type inboundBatchCall struct {
	raw   []byte
	addrs [][80]byte
	ptr   uintptr
	live  []byte
	// rawCap records the capacity of the payload view handed to the terminal
	// consumer. The terminal view is capped to its exact receipt length.
	rawCap int
	// addrPtr/addrCap record the address backing and the capacity of the view
	// this receive handed to its consumer, so a model test can prove
	// successive batches shared one lane backing with an exact-count cap.
	addrPtr uintptr
	addrCap int
}

type inboundBatchHarness struct {
	t          *testing.T
	e          *Engine
	l          *Lease
	c          *windowsCapture
	input      chan inboundBatchInput
	stop       chan struct{}
	stopOnce   sync.Once
	nativeDone chan struct{}
	mu         sync.Mutex
	recvCalls  []inboundBatchCall
	sendCalls  []inboundBatchCall
	// One reusable model lane backing, written only by the serialized receive
	// owner, exactly like the wrapper's lane-owned payload/address storage.
	laneBuf   []byte
	laneAddrs []windivert.Address
	// The old caller-owned Into path and the new terminal view are counted
	// separately: the inbound owner must use the view seam exclusively.
	viewCalls    int
	viewConsumes int
	intoCalls    int
	// forwardCalls counts identical-batch direct forwards through the
	// receive-bound capability; copiedCalls counts the ordinary detached
	// SendBatch path. They distinguish the copy-elision seam from a merely
	// pointer-equal stub call.
	forwardCalls int
	copiedCalls  int
	// sendResult overrides the modeled native SendBatch result.
	sendResult func([]byte, []windivert.Address) (int, error)
	closes     atomic.Int32
	shutdowns  atomic.Int32
}

func inboundModelAddress(seed byte, ipv6 bool) [80]byte {
	var address [80]byte
	for i := range address {
		address[i] = seed + byte(i)
	}
	// The packed flags word must contain only the explicitly modeled bits;
	// otherwise the seed pattern could accidentally set IPv6/Outbound/checksum.
	binary.LittleEndian.PutUint32(address[8:12], 0)
	if ipv6 {
		// WINDIVERT_ADDRESS IPv6 flag is bit 20 of the packed bits word.
		binary.LittleEndian.PutUint32(address[8:12], 1<<20)
	}
	return address
}

func inboundAddressBytes(address *windivert.Address) [80]byte {
	return *(*[80]byte)(unsafe.Pointer(address))
}

func inboundAddressFromBytes(raw [80]byte) windivert.Address {
	var address windivert.Address
	*(*[80]byte)(unsafe.Pointer(&address)) = raw
	return address
}

func newInboundBatchModel(t *testing.T, rules string, primeSYN bool) *inboundBatchHarness {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &producerOrderBackend{})
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	h := &inboundBatchHarness{
		t: t, e: engine, l: lease,
		input:      make(chan inboundBatchInput, 8),
		stop:       make(chan struct{}),
		nativeDone: make(chan struct{}),
	}
	capture := &windowsCapture{lease: lease, dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	h.c = capture
	capture.releaseHold, err = lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	capture.inbound = &windivert.Handle{
		RecvFunc:                 func([]byte) (int, windivert.Address, error) { panic("single Recv used by the inbound owner") },
		SendFunc:                 func([]byte, *windivert.Address) (int, error) { panic("single Send used by the inbound owner") },
		RecvBatchFunc:            h.recvBatch,
		RecvBatchIntoFunc:        h.recvBatchInto,
		RecvBatchViewFunc:        h.recvBatchView,
		RecvBatchViewForwardFunc: h.recvBatchViewForward,
		SendBatchFunc:            h.sendBatch,
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
	lease.tcpFlow.primeSemanticTrack()
	t.Cleanup(func() { _ = engine.Close() })
	if primeSYN {
		syn := buildIPv4TCP(t, nil, 14000, tcpFlagSYN)
		if verdict := lease.HandlePacket(syn.Raw, DirectionOutbound, nil, nil); verdict != VerdictModify {
			t.Fatalf("priming SYN verdict = %d, want modify", verdict)
		}
		if modified := lease.TakeModified(DirectionOutbound); modified == nil {
			t.Fatal("priming SYN rewrite missing")
		}
	}
	return h
}

func (h *inboundBatchHarness) dequeue() (inboundBatchInput, bool) {
	var input inboundBatchInput
	select {
	case input = <-h.input:
		return input, true
	case <-h.stop:
		return inboundBatchInput{}, false
	}
}

func (h *inboundBatchHarness) recvBatch(p []byte) (int, []windivert.Address, error) {
	input, ok := h.dequeue()
	if !ok {
		return 0, nil, windivert.ReplayDrained
	}
	n := input.n
	if n == 0 && input.err == nil {
		n = len(input.raw)
	}
	copy(p, input.raw)
	addrs := make([]windivert.Address, len(input.addrs))
	for i := range input.addrs {
		addrs[i] = inboundAddressFromBytes(input.addrs[i])
	}
	h.mu.Lock()
	h.recvCalls = append(h.recvCalls, inboundBatchCall{
		raw: bytes.Clone(input.raw), addrs: append([][80]byte(nil), input.addrs...),
		ptr: uintptr(unsafe.Pointer(&p[0])), live: p,
	})
	h.mu.Unlock()
	return n, addrs, input.err
}

// recvBatchView models the wrapper's synchronous terminal view: one reusable
// model lane is filled by the scripted driver, and only a terminal receipt with
// valid dimensions reaches the consumer. The views end when the consumer
// returns, exactly like the production borrow interval.
func (h *inboundBatchHarness) recvBatchView(bufferSize int, consume func([]byte, []windivert.Address)) (int, error) {
	if bufferSize < windivert.MTUMax {
		panic("model RecvBatchView short buffer")
	}
	input, ok := h.dequeue()
	if !ok {
		return 0, windivert.ReplayDrained
	}
	n := input.n
	if n == 0 && input.err == nil {
		n = len(input.raw)
	}
	if h.laneBuf == nil {
		h.laneBuf = make([]byte, bufferSize)
		h.laneAddrs = make([]windivert.Address, windivert.BatchMax)
	}
	copy(h.laneBuf, input.raw)
	for i := range input.addrs {
		h.laneAddrs[i] = inboundAddressFromBytes(input.addrs[i])
	}
	call := inboundBatchCall{
		raw: bytes.Clone(input.raw), addrs: append([][80]byte(nil), input.addrs...),
		ptr: uintptr(unsafe.Pointer(&h.laneBuf[0])), live: h.laneBuf,
		addrPtr: uintptr(unsafe.Pointer(&h.laneAddrs[0])),
	}
	if input.err != nil {
		// A terminal native failure publishes no view; the count is the raw
		// completion value and is never treated as a successful receipt.
		h.mu.Lock()
		h.viewCalls++
		h.recvCalls = append(h.recvCalls, call)
		h.mu.Unlock()
		return n, input.err
	}
	raw := h.laneBuf[:n:n]
	addrs := h.laneAddrs[:len(input.addrs):len(input.addrs)]
	call.rawCap = cap(raw)
	call.addrCap = cap(addrs)
	h.mu.Lock()
	h.viewCalls++
	h.viewConsumes++
	h.recvCalls = append(h.recvCalls, call)
	h.mu.Unlock()
	consume(raw, addrs)
	return n, nil
}

// recvBatchViewForward models the wrapper's receive-bound forwarding companion:
// the same modeled lane fills with the scripted batch, and the consumer gets a
// one-shot capability that submits exactly that view through the modeled send
// lane. The model cannot quarantine a lane (it does not own one); the wrapper's
// dual-lane retention is asserted by the Windows host-inert regression instead.
func (h *inboundBatchHarness) recvBatchViewForward(bufferSize int, consume func(raw []byte, addrs []windivert.Address, forwardOriginal func() (int, error))) (int, error) {
	if bufferSize < windivert.MTUMax {
		panic("model RecvBatchViewForward short buffer")
	}
	input, ok := h.dequeue()
	if !ok {
		return 0, windivert.ReplayDrained
	}
	n := input.n
	if n == 0 && input.err == nil {
		n = len(input.raw)
	}
	if h.laneBuf == nil {
		h.laneBuf = make([]byte, bufferSize)
		h.laneAddrs = make([]windivert.Address, windivert.BatchMax)
	}
	copy(h.laneBuf, input.raw)
	for i := range input.addrs {
		h.laneAddrs[i] = inboundAddressFromBytes(input.addrs[i])
	}
	call := inboundBatchCall{
		raw: bytes.Clone(input.raw), addrs: append([][80]byte(nil), input.addrs...),
		ptr: uintptr(unsafe.Pointer(&h.laneBuf[0])), live: h.laneBuf,
		addrPtr: uintptr(unsafe.Pointer(&h.laneAddrs[0])),
	}
	if input.err != nil {
		h.mu.Lock()
		h.viewCalls++
		h.recvCalls = append(h.recvCalls, call)
		h.mu.Unlock()
		return n, input.err
	}
	raw := h.laneBuf[:n:n]
	addrs := h.laneAddrs[:len(input.addrs):len(input.addrs)]
	call.rawCap = cap(raw)
	call.addrCap = cap(addrs)
	h.mu.Lock()
	h.viewCalls++
	h.viewConsumes++
	h.recvCalls = append(h.recvCalls, call)
	h.mu.Unlock()
	attempted := false
	forwardOriginal := func() (int, error) {
		if attempted {
			return 0, errors.New("model forward capability reused")
		}
		attempted = true
		return h.forwardSend(raw, addrs)
	}
	consume(raw, addrs, forwardOriginal)
	return n, nil
}

// forwardSend models the wrapper's direct-original send submission. It records
// the exact same lane pointers SendBatch would receive, but under the capability
// counter so a test can prove the copy-elision seam is the one in use.
func (h *inboundBatchHarness) forwardSend(p []byte, addrs []windivert.Address) (int, error) {
	call := inboundBatchCall{raw: bytes.Clone(p), ptr: uintptr(unsafe.Pointer(&p[0]))}
	for i := range addrs {
		call.addrs = append(call.addrs, inboundAddressBytes(&addrs[i]))
	}
	h.mu.Lock()
	h.forwardCalls++
	h.sendCalls = append(h.sendCalls, call)
	h.mu.Unlock()
	if h.sendResult != nil {
		return h.sendResult(p, addrs)
	}
	return len(p), nil
}

func (h *inboundBatchHarness) recvBatchInto(p []byte, dst []windivert.Address) (int, []windivert.Address, error) {
	if len(dst) < windivert.BatchMax {
		panic("model inbound RecvBatchInto short caller storage")
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

func (h *inboundBatchHarness) sendBatch(p []byte, addrs []windivert.Address) (int, error) {
	call := inboundBatchCall{raw: bytes.Clone(p), ptr: uintptr(unsafe.Pointer(&p[0]))}
	for i := range addrs {
		call.addrs = append(call.addrs, inboundAddressBytes(&addrs[i]))
	}
	h.mu.Lock()
	h.copiedCalls++
	h.sendCalls = append(h.sendCalls, call)
	h.mu.Unlock()
	if h.sendResult != nil {
		return h.sendResult(p, addrs)
	}
	return len(p), nil
}

func (h *inboundBatchHarness) deliver(raw []byte, addrs [][80]byte) {
	h.input <- inboundBatchInput{raw: bytes.Clone(raw), addrs: addrs}
}

func (h *inboundBatchHarness) start() { h.c.startUsers() }

func (h *inboundBatchHarness) counts() (recv, send int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.recvCalls), len(h.sendCalls)
}

func (h *inboundBatchHarness) calls() (recv, send []inboundBatchCall) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]inboundBatchCall(nil), h.recvCalls...), append([]inboundBatchCall(nil), h.sendCalls...)
}

func (h *inboundBatchHarness) viewStats() (views, consumes, into int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.viewCalls, h.viewConsumes, h.intoCalls
}

// submitStats reports how the inbound owner chose its send path: direct
// original forwards through the receive-bound capability versus copied
// SendBatch submissions.
func (h *inboundBatchHarness) submitStats() (forwarded, copied int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.forwardCalls, h.copiedCalls
}

func (h *inboundBatchHarness) waitSends(t *testing.T, want int) inboundBatchCall {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		recv, send := h.counts()
		if send == want {
			_, sends := h.calls()
			return sends[want-1]
		}
		if time.Now().After(deadline) {
			h.c.drainMu.Lock()
			receiveErr, prepareErr := h.c.drainErrors[1].err(), h.c.prepareErrors.err()
			sendErr := h.c.sendErrors[0].err()
			h.c.drainMu.Unlock()
			t.Fatalf("batch send absent: recv=%d send=%d receive=%v prepare=%v send=%v", recv, send, receiveErr, prepareErr, sendErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func (h *inboundBatchHarness) close(t *testing.T) {
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

func inboundIPv4Packet(length int) []byte {
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	return packet
}

func inboundIPv6Packet(length int) []byte {
	packet := make([]byte, length)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(length-40))
	return packet
}

func concatPackets(packets ...[]byte) []byte {
	var raw []byte
	for _, packet := range packets {
		raw = append(raw, packet...)
	}
	return raw
}

func TestWindowsInboundBatchFraming(t *testing.T) {
	valid := []struct {
		name  string
		raw   []byte
		spans []uint32
	}{
		{"ipv4", inboundIPv4Packet(20), []uint32{0, 20}},
		{"ipv4-options", inboundIPv4Packet(24), []uint32{0, 24}},
		{"ipv6", inboundIPv6Packet(40), []uint32{0, 40}},
		{"ipv6-payload", inboundIPv6Packet(64), []uint32{0, 64}},
		{"mixed", concatPackets(inboundIPv4Packet(20), inboundIPv6Packet(48), inboundIPv4Packet(32)), []uint32{0, 20, 68, 100}},
		{"ipv4-max", inboundIPv4Packet(65535), []uint32{0, 65535}},
		{"ipv6-max", inboundIPv6Packet(windivert.MTUMax), []uint32{0, windivert.MTUMax}},
	}
	for _, test := range valid {
		t.Run(test.name, func(t *testing.T) {
			var spans [windivert.BatchMax + 1]uint32
			count, err := frameWindowsBatch(test.raw, &spans)
			if err != nil {
				t.Fatal(err)
			}
			if count != len(test.spans)-1 {
				t.Fatalf("count = %d", count)
			}
			for index, want := range test.spans {
				if spans[index] != want {
					t.Fatalf("span %d = %d, want %d", index, spans[index], want)
				}
			}
		})
	}
	t.Run("255-packets", func(t *testing.T) {
		packets := make([][]byte, windivert.BatchMax)
		for i := range packets {
			packets[i] = inboundIPv4Packet(20)
		}
		var spans [windivert.BatchMax + 1]uint32
		count, err := frameWindowsBatch(concatPackets(packets...), &spans)
		if err != nil || count != windivert.BatchMax {
			t.Fatalf("count=%d err=%v", count, err)
		}
		if spans[0] != 0 || spans[windivert.BatchMax] != uint32(windivert.BatchMax*20) {
			t.Fatal("boundary span mismatch")
		}
	})
	bad := []struct {
		name string
		raw  []byte
	}{
		{"empty", nil},
		{"ipv4-truncated", inboundIPv4Packet(20)[:19]},
		{"ipv6-truncated", inboundIPv6Packet(40)[:39]},
		{"version", append([]byte{0x55}, make([]byte, 19)...)},
		{"ipv4-length-short", func() []byte {
			packet := inboundIPv4Packet(20)
			binary.BigEndian.PutUint16(packet[2:4], 19)
			return packet
		}()},
		{"ipv4-length-beyond", func() []byte {
			packet := inboundIPv4Packet(20)
			binary.BigEndian.PutUint16(packet[2:4], 21)
			return packet
		}()},
		{"ipv6-length-beyond", func() []byte {
			packet := inboundIPv6Packet(40)
			binary.BigEndian.PutUint16(packet[4:6], 1)
			return packet
		}()},
		{"trailing-byte", append(inboundIPv4Packet(20), 0x00)},
		{"256-packets", concatPackets(func() [][]byte {
			packets := make([][]byte, windivert.BatchMax+1)
			for i := range packets {
				packets[i] = inboundIPv4Packet(20)
			}
			return packets
		}()...)},
	}
	for _, test := range bad {
		t.Run(test.name, func(t *testing.T) {
			var spans [windivert.BatchMax + 1]uint32
			if count, err := frameWindowsBatch(test.raw, &spans); err == nil {
				t.Fatalf("accepted count=%d", count)
			}
		})
	}
	t.Run("families", func(t *testing.T) {
		ipv4, ipv6 := inboundIPv4Packet(20), inboundIPv6Packet(40)
		var spans [windivert.BatchMax + 1]uint32
		raw := concatPackets(ipv4, ipv6)
		count, err := frameWindowsBatch(raw, &spans)
		if err != nil || count != 2 {
			t.Fatalf("count=%d err=%v", count, err)
		}
		good := []windivert.Address{inboundAddressFromBytes(inboundModelAddress(1, false)), inboundAddressFromBytes(inboundModelAddress(2, true))}
		if err = validateWindowsBatchFamilies(raw, &spans, count, good); err != nil {
			t.Fatalf("valid families rejected: %v", err)
		}
		if err = validateWindowsBatchFamilies(raw, &spans, count, good[:1]); err == nil {
			t.Fatal("address count mismatch accepted")
		}
		swapped := []windivert.Address{inboundAddressFromBytes(inboundModelAddress(1, true)), inboundAddressFromBytes(inboundModelAddress(2, false))}
		if err = validateWindowsBatchFamilies(raw, &spans, count, swapped); err == nil {
			t.Fatal("family mismatch accepted")
		}
	})
}

func TestWindowsInboundBatchModifiedAndPass(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[443],"wsize":{"size":1000},"orig":{"ttl":9}}]`, true)
	h.start()
	synack := func(sequence uint32) []byte {
		packet := buildIPv4TCP(t, nil, sequence, tcpFlagSYN|tcpFlagACK)
		packet.TCPAck = 14001
		binary.BigEndian.PutUint32(packet.Raw[packet.IPHeaderLen+8:packet.IPHeaderLen+12], 14001)
		if err := refreshChecksums(packet.Raw, packet); err != nil {
			t.Fatal(err)
		}
		return packet.Raw
	}
	first, second := synack(15000), synack(16000)
	pass := buildIPv4UDP(t, []byte("payload"), 443).Raw
	raw := concatPackets(first, pass, second)
	addrs := [][80]byte{inboundModelAddress(1, false), inboundModelAddress(2, false), inboundModelAddress(3, false)}
	h.deliver(raw, addrs)
	sent := h.waitSends(t, 1)
	recv, _ := h.calls()
	if len(recv) != 1 {
		t.Fatalf("receive batches = %d", len(recv))
	}
	if sent.ptr == recv[0].ptr {
		t.Fatal("modified batch reused the receive buffer instead of staging")
	}
	if !bytes.Equal(recv[0].live[:len(raw)], raw) {
		t.Fatal("original receive buffer was mutated in place")
	}
	if len(sent.raw) != len(raw) || len(sent.addrs) != 3 {
		t.Fatalf("sent batch shape = %d bytes, %d addresses", len(sent.raw), len(sent.addrs))
	}
	firstEnd, secondStart := len(first), len(first)+len(pass)
	if !bytes.Equal(sent.raw[firstEnd:secondStart], pass) {
		t.Fatal("pass span changed")
	}
	for index, span := range [][2]int{{0, firstEnd}, {secondStart, len(raw)}} {
		packet, err := ParsePacket(sent.raw[span[0]:span[1]])
		if err != nil || packet.TCPWindow != 1000 {
			t.Fatalf("modified span %d window = %v %v", index, packet, err)
		}
	}
	// Captured 80-byte metadata is preserved except for checksum flags of the
	// spans whose bytes were rewritten.
	modifiedAddress := func(captured [80]byte) [80]byte {
		expected := captured
		bits := binary.LittleEndian.Uint32(expected[8:12]) &^ (7 << 21)
		binary.LittleEndian.PutUint32(expected[8:12], bits)
		return expected
	}
	if sent.addrs[0] != modifiedAddress(addrs[0]) {
		t.Fatal("modified address metadata/flags mismatch")
	}
	if sent.addrs[1] != addrs[1] {
		t.Fatal("pass address was normalized")
	}
	if sent.addrs[2] != modifiedAddress(addrs[2]) {
		t.Fatal("second modified address mismatch")
	}
	h.l.mu.Lock()
	stale := h.l.modifiedInbound
	h.l.mu.Unlock()
	if stale != nil {
		t.Fatal("modified slot was not consumed immediately")
	}
	// All-Pass keeps the borrowed receive buffer: no staging copy.
	one := buildIPv4UDP(t, []byte("second"), 443).Raw
	h.deliver(one, [][80]byte{inboundModelAddress(4, false)})
	secondSend := h.waitSends(t, 2)
	recv, _ = h.calls()
	if secondSend.ptr != recv[1].ptr {
		t.Fatal("all-pass batch was copied instead of borrowed")
	}
	if forwarded, copied := h.submitStats(); forwarded != 1 || copied != 1 {
		t.Fatalf("send seam after mixed+all-pass batches: forwarded=%d copied=%d, want 1/1", forwarded, copied)
	}
	if len(secondSend.raw) != len(one) || !bytes.Equal(secondSend.raw, one) {
		t.Fatal("second batch stale tail/bytes")
	}
	if secondSend.addrs[0] != inboundModelAddress(4, false) {
		t.Fatal("second batch address mismatch")
	}
	h.close(t)
	if h.shutdowns.Load() != 1 || h.closes.Load() != 1 {
		t.Fatalf("native owners stop=%d close=%d", h.shutdowns.Load(), h.closes.Load())
	}
}

func TestWindowsInboundBatchSemanticParity(t *testing.T) {
	const rules = `[{"network":["tcp"],"port":[443],"wsize":{"size":1000},"orig":{"ttl":9}}]`
	batched := newInboundBatchModel(t, rules, true)
	manual := newInboundBatchModel(t, rules, true)
	synack := func(sequence uint32) []byte {
		packet := buildIPv4TCP(t, nil, sequence, tcpFlagSYN|tcpFlagACK)
		packet.TCPAck = 14001
		binary.BigEndian.PutUint32(packet.Raw[packet.IPHeaderLen+8:packet.IPHeaderLen+12], 14001)
		if err := refreshChecksums(packet.Raw, packet); err != nil {
			t.Fatal(err)
		}
		return packet.Raw
	}
	packets := [][]byte{synack(17000), buildIPv4TCP(t, nil, 17001, tcpFlagACK).Raw, synack(18000)}
	var expected [][]byte
	for _, packet := range packets {
		verdict := manual.l.HandlePacket(packet, DirectionInbound, nil, nil)
		modified := manual.l.TakeModified(DirectionInbound)
		switch verdict {
		case VerdictModify:
			if modified == nil {
				t.Fatal("manual modify without bytes")
			}
			expected = append(expected, modified)
		case VerdictPass:
			if modified != nil {
				t.Fatal("manual pass left modified bytes")
			}
			expected = append(expected, packet)
		default:
			t.Fatalf("inbound verdict = %d", verdict)
		}
	}
	raw := concatPackets(packets...)
	addrs := [][80]byte{inboundModelAddress(1, false), inboundModelAddress(2, false), inboundModelAddress(3, false)}
	batched.start()
	batched.deliver(raw, addrs)
	sent := batched.waitSends(t, 1)
	offset := 0
	for index, packet := range packets {
		end := offset + len(packet)
		if end-offset != len(expected[index]) || !bytes.Equal(sent.raw[offset:end], expected[index]) {
			t.Fatalf("packet %d disposition differs between packed and single input", index)
		}
		offset = end
	}
	if offset != len(sent.raw) {
		t.Fatal("batch tail has no matching disposition")
	}
	batched.close(t)
}

func TestWindowsInboundBatchGateFenceAndPass(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[443],"wsize":{"size":1000},"orig":{"ttl":9}}]`, true)
	h.start()
	h.c.FenceDispatch()
	quiesced := make(chan struct{})
	go func() { _ = h.c.Quiesce(); close(quiesced) }()
	rxChannel(t, quiesced, "Quiesce waited for a future inbound batch")
	packet := buildIPv4TCP(t, nil, 19000, tcpFlagSYN|tcpFlagACK)
	address := inboundModelAddress(7, false)
	h.deliver(packet.Raw, [][80]byte{address})
	rxWait(t, "fenced batch not received", func() bool { recv, _ := h.counts(); return recv == 1 })
	time.Sleep(20 * time.Millisecond)
	if _, send := h.counts(); send != 0 {
		t.Fatal("post-fence batch sent before pass-through release")
	}
	h.c.dispatch.mu.Lock()
	dispatch, sending := h.c.dispatch.dispatch, h.c.dispatch.sending
	h.c.dispatch.mu.Unlock()
	if dispatch != 0 || sending != 0 {
		t.Fatalf("gate token held while waiting: dispatch=%d sending=%d", dispatch, sending)
	}
	h.c.AllowPassThrough()
	sent := h.waitSends(t, 1)
	if !bytes.Equal(sent.raw, packet.Raw) {
		t.Fatal("post-fence tail was dispatched/rewritten")
	}
	if sent.addrs[0] != address {
		t.Fatal("post-fence address changed")
	}
	h.close(t)
}

func TestWindowsInboundBatchLocalSendClassification(t *testing.T) {
	rules := `[{"network":["tcp"],"port":[443],"wsize":{"size":1000},"orig":{"ttl":9}}]`
	failure := errors.New("modeled native batch failure")
	for _, kind := range []string{"success", "short", "terminal", "unknown-pass", "unknown-modified"} {
		t.Run(kind, func(t *testing.T) {
			h := newInboundBatchModel(t, rules, true)
			switch kind {
			case "short":
				h.sendResult = func(p []byte, _ []windivert.Address) (int, error) { return len(p) - 1, nil }
			case "terminal":
				h.sendResult = func([]byte, []windivert.Address) (int, error) { return 0, failure }
			case "unknown-pass", "unknown-modified":
				h.sendResult = func([]byte, []windivert.Address) (int, error) { return -1, failure }
			}
			h.start()
			raw := buildIPv4UDP(t, []byte("first"), 443).Raw
			if kind == "unknown-modified" {
				synack := buildIPv4TCP(t, nil, 20000, tcpFlagSYN|tcpFlagACK)
				synack.TCPAck = 14001
				binary.BigEndian.PutUint32(synack.Raw[synack.IPHeaderLen+8:synack.IPHeaderLen+12], 14001)
				if err := refreshChecksums(synack.Raw, synack); err != nil {
					t.Fatal(err)
				}
				raw = synack.Raw
			}
			address := inboundModelAddress(9, false)
			h.deliver(raw, [][80]byte{address})
			h.waitSends(t, 1)
			switch kind {
			case "short", "terminal":
				// A known/short completion is a terminal diagnostic: the loop
				// keeps receiving but never retries this batch.
				raw2 := buildIPv4UDP(t, []byte("second"), 443).Raw
				h.deliver(raw2, [][80]byte{inboundModelAddress(10, false)})
				h.waitSends(t, 2)
				recv, _ := h.counts()
				if recv != 2 {
					t.Fatalf("terminal failure did not continue after one send: %d", recv)
				}
				if err := h.l.Close(nil); err == nil {
					t.Fatal("terminal send diagnostic was erased")
				}
				if err := h.l.WaitCaptureRetired(); err != nil {
					t.Fatalf("terminal failure should retire after drain: %v", err)
				}
				if h.e.ActiveLeases() != 0 || h.closes.Load() != 1 {
					t.Fatal("terminal failure manufactured unknown ownership")
				}
			case "unknown-pass", "unknown-modified":
				rxWait(t, "unknown completion not reported", func() bool { return h.l.Err() != nil })
				recv, send := h.counts()
				if recv != 1 || send != 1 {
					t.Fatalf("unknown completion retried or received again: recv=%d send=%d", recv, send)
				}
				h.c.drainMu.Lock()
				retained := h.c.optionalRetained[0]
				h.c.drainMu.Unlock()
				if !retained.occupied || !bytes.Equal(retained.raw, raw) || len(retained.addrs) != 1 || inboundAddressBytes(&retained.addrs[0]) != address {
					t.Fatal("received batch was not retained on unknown progress")
				}
				if len(retained.submitted) != len(raw) || len(retained.sendAddrs) != 1 {
					t.Fatal("submitted batch was not retained on unknown progress")
				}
				recvCalls, _ := h.calls()
				if len(recvCalls) != 1 {
					t.Fatalf("receive batches = %d", len(recvCalls))
				}
				// Before the terminal view consumer returns, every escaping
				// retention copies the whole original batch. The retained slot
				// must never alias the lane view.
				if len(retained.raw) == 0 || uintptr(unsafe.Pointer(&retained.raw[0])) == recvCalls[0].ptr {
					t.Fatal("retained original still aliases the native view")
				}
				if cap(retained.raw) != len(retained.raw) {
					t.Fatalf("retained original capacity = %d, want exact %d", cap(retained.raw), len(retained.raw))
				}
				if len(retained.addrs) == 0 || uintptr(unsafe.Pointer(&retained.addrs[0])) == recvCalls[0].addrPtr {
					t.Fatal("retained addresses still alias the native view")
				}
				if cap(retained.addrs) != len(retained.addrs) {
					t.Fatalf("retained address capacity = %d, want exact %d", cap(retained.addrs), len(retained.addrs))
				}
				if kind == "unknown-modified" {
					if bytes.Equal(retained.submitted, retained.raw) {
						t.Fatal("modified submission was not preserved distinctly")
					}
				} else if !bytes.Equal(retained.submitted, retained.raw) {
					t.Fatal("all-pass submission aliasing lost")
				}
				if _, err := h.l.BeginEndpointWrite(); err == nil {
					t.Fatal("unknown progress allowed new production")
				}
				if err := h.l.Close(nil); err == nil {
					t.Fatal("unknown progress closed successfully")
				}
				if err := h.l.WaitCaptureRetired(); err == nil {
					t.Fatal("unknown progress retired")
				}
				if h.e.ActiveLeases() != 1 || h.closes.Load() != 0 {
					t.Fatal("unknown native owner was released")
				}
			default:
				h.deliver(buildIPv4UDP(t, []byte("second"), 443).Raw, [][80]byte{inboundModelAddress(11, false)})
				h.waitSends(t, 2)
				h.close(t)
			}
		})
	}
}

// The classifier is also exercised directly for the local count/error matrix
// without a native call: nil error with the exact byte count is success, a
// short count is a terminal diagnostic, and a negative count is unknown.
func TestWindowsInboundBatchDrainReceipt(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[443]}]`, false)
	h.start()
	packet := buildIPv4TCP(t, nil, 21000, tcpFlagACK)
	h.input <- inboundBatchInput{raw: packet.Raw, n: -1, err: windivert.ReplayDrained}
	rxWait(t, "negative drain receipt was accepted", func() bool { return h.l.Err() != nil })
	if _, send := h.counts(); send != 0 {
		t.Fatal("invalid drain receipt produced a send")
	}
	recv, _ := h.counts()
	if recv != 1 {
		t.Fatalf("invalid drain receipt received again: %d", recv)
	}
	if err := h.l.Close(nil); err == nil {
		t.Fatal("invalid drain receipt closed successfully")
	}
	if err := h.l.WaitCaptureRetired(); err == nil {
		t.Fatal("invalid drain receipt retired")
	}
	if h.e.ActiveLeases() != 1 || h.closes.Load() != 0 {
		t.Fatal("invalid drain receipt manufactured retirement")
	}
}

func TestWindowsInboundBatchResultMatrix(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[443]}]`, false)
	for _, test := range []struct {
		n, length int
		err       error
		success   bool
		unknown   bool
	}{
		{length: 10, n: 10, success: true},
		{length: 10, n: 9, err: nil},
		{length: 10, n: 0, err: errors.New("terminal")},
		{length: 10, n: -1, unknown: true, err: errors.New("unknown")},
	} {
		n, err := test.n, test.err
		h.sendResult = func([]byte, []windivert.Address) (int, error) { return n, err }
		err = sendCapturedBatch(h.c.inbound, make([]byte, test.length), []windivert.Address{{}})
		if test.success && err != nil {
			t.Fatalf("success classified as %v", err)
		}
		if !test.success && err == nil {
			t.Fatal("failure classified as success")
		}
		if test.unknown != errors.Is(err, errCaptureSendIncomplete) {
			t.Fatalf("unknown classifier mismatch: %v", err)
		}
	}
}

// V03 model: the inbound owner consumes successive serial terminal views from
// one lane backing. Variable (including decreasing) batch sizes, IPv4 and IPv6
// All-Pass batches keep exact bytes and raw80 addresses, each view is capped to
// its receipt, and every batch produces exactly one ordinary send in receive
// order without a capture-owned staging copy.
func TestWindowsInboundBatchTerminalViewSerialBatches(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[443]}]`, false)
	h.start()
	type batch struct {
		raw   []byte
		addrs [][80]byte
	}
	var batches []batch
	for index, count := range []int{3, 1, 5, 2, 4} {
		var raw []byte
		var addrs [][80]byte
		for packet := 0; packet < count; packet++ {
			seed := byte(index*8 + packet + 1)
			if index%2 == 1 && packet == 0 {
				raw = append(raw, buildIPv6UDP(t, []byte{byte(index), byte(packet)}).Raw...)
				addrs = append(addrs, inboundModelAddress(seed, true))
				continue
			}
			raw = append(raw, buildIPv4UDP(t, []byte{byte(index), byte(packet)}, 443).Raw...)
			addrs = append(addrs, inboundModelAddress(seed, false))
		}
		batches = append(batches, batch{raw: raw, addrs: addrs})
	}
	for index, batched := range batches {
		h.deliver(batched.raw, batched.addrs)
		h.waitSends(t, index+1)
	}
	recv, sends := h.calls()
	views, consumes, into := h.viewStats()
	if views != len(batches) || consumes != len(batches) || into != 0 {
		t.Fatalf("inbound receive seam: view=%d consume=%d old-into=%d, want %d/%d/0", views, consumes, into, len(batches), len(batches))
	}
	if len(recv) != len(batches) || len(sends) != len(batches) {
		t.Fatalf("receive/send batches = %d/%d, want %d", len(recv), len(sends), len(batches))
	}
	for index, batched := range batches {
		if recv[index].rawCap != len(batched.raw) || recv[index].addrCap != len(batched.addrs) {
			t.Fatalf("batch %d view caps = %d/%d, want %d/%d", index, recv[index].rawCap, recv[index].addrCap, len(batched.raw), len(batched.addrs))
		}
		if !bytes.Equal(sends[index].raw, batched.raw) {
			t.Fatalf("batch %d send bytes differ from the received view", index)
		}
		if len(sends[index].addrs) != len(batched.addrs) {
			t.Fatalf("batch %d send addresses = %d, want %d", index, len(sends[index].addrs), len(batched.addrs))
		}
		for address := range batched.addrs {
			if sends[index].addrs[address] != batched.addrs[address] {
				t.Fatalf("batch %d address %d lost exact raw80 bytes", index, address)
			}
		}
		// All-Pass hands the same terminal view to the ordinary send; the
		// capture does not copy the batch before submitting it.
		if sends[index].ptr != recv[index].ptr {
			t.Fatalf("batch %d all-pass staging copy was introduced", index)
		}
	}
	if recv[0].ptr != recv[len(recv)-1].ptr || recv[0].addrPtr != recv[len(recv)-1].addrPtr {
		t.Fatal("successive inbound receives did not reuse one lane backing")
	}
	if forwarded, copied := h.submitStats(); forwarded != len(batches) || copied != 0 {
		t.Fatalf("all-pass batches used forwarded=%d copied=%d, want %d/0", forwarded, copied, len(batches))
	}
	h.close(t)
}

// V06 model: an ordinary empty native receive drain terminates the reader
// without publishing a consumer view and without producing a send.
func TestWindowsInboundBatchEmptyDrainNoCallback(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[443]}]`, false)
	h.start()
	h.input <- inboundBatchInput{err: windivert.ReplayDrained}
	rxWait(t, "empty drain did not finish the inbound reader", func() bool {
		h.c.drainMu.Lock()
		defer h.c.drainMu.Unlock()
		return h.c.drained[1]
	})
	if _, send := h.counts(); send != 0 {
		t.Fatal("an empty drain receipt produced a send")
	}
	if views, consumes, into := h.viewStats(); views != 1 || consumes != 0 || into != 0 {
		t.Fatalf("empty drain receipt: view=%d consume=%d old-into=%d, want 1/0/0", views, consumes, into)
	}
	h.c.drainMu.Lock()
	retained := h.c.optionalRetained[0].occupied
	h.c.drainMu.Unlock()
	if retained {
		t.Fatal("an ordinary empty drain retained a batch")
	}
	h.close(t)
}

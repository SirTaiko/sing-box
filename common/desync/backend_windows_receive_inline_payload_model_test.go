//go:build desync_windows_model && !windows

package desync

// Offline model checks for the private per-slot payload backing of reserved
// detached Windows receive records. Every observation is taken from the real
// reader, checked reservation and native-send callback of the reversible
// Windows-source overlay, so this is never a native WinDivert/Windows
// execution result.
//
// The oracle deliberately uses only source-neutral facts: payload pointer,
// length, capacity, slot membership inside the capture record ring, the owning
// record's raw binding, the exact bytes, the full 80-byte captured address and
// the record sequence. The same test source therefore also compiles against the
// prechange record type (which has no private payload field) and fails there
// behaviourally instead of making the old backend an absent symbol.

import (
	"bytes"
	"sync"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

// inlinePayloadThreshold is the accepted decision's one private-backing size. It
// is written as a literal, not as a production identifier, so this oracle stays
// compilable against the prechange record type and can fail there behaviourally.
const inlinePayloadThreshold = 128

// inlinePayloadObservation is one reinjection seen by the model Send callback.
type inlinePayloadObservation struct {
	raw         []byte
	address     [80]byte
	n, capacity int
	ptr         uintptr
	// slot is the ring index that contains ptr, or -1 when the payload does not
	// live inside the capture record ring.
	slot int
	// occupied/claimed/bound describe that slot under rxMu at send time: the
	// reservation is still charged, dispatch claimed it, and its raw slice is
	// exactly this payload.
	occupied bool
	claimed  bool
	bound    bool
	sequence uint64
	// ownerLen/ownerCap are the owning record's raw length and capacity under
	// rxMu at send time. A small payload must be exposed with exact
	// len==cap==n, so a reused slot cannot expose a stale tail through capacity.
	ownerLen int
	ownerCap int
	// neighbourPtrs are the payload pointers of the other occupied records at
	// this instant; a small payload must not alias any of them.
	neighbourPtrs []uintptr
}

func inlinePayloadRing(c *windowsCapture) (base, size uintptr, slots int) {
	return uintptr(unsafe.Pointer(&c.records[0])), unsafe.Sizeof(c.records[0]), len(c.records)
}

// inlinePayloadHeaderBytes is the invariant prefix of a record: the raw slice
// header plus the captured address. A private payload backing necessarily
// starts at or after it.
func inlinePayloadHeaderBytes() uintptr {
	return unsafe.Sizeof(windowsReceiveRecord{}.raw) + unsafe.Sizeof(windowsReceiveRecord{}.address)
}

// probeInlinePayload wraps the ordinary batch model harness with a send probe.
// It must be installed before start().
func probeInlinePayload(t *testing.T) (*outboundBatchHarness, func() []inlinePayloadObservation) {
	t.Helper()
	h := newOutboundBatchModel(t)
	base, size, slots := inlinePayloadRing(h.c)
	var mu sync.Mutex
	var observations []inlinePayloadObservation
	send := h.c.outbound.SendFunc
	h.c.outbound.SendFunc = func(packet []byte, address *windivert.Address) (int, error) {
		observation := inlinePayloadObservation{
			raw:      bytes.Clone(packet),
			address:  outboundAddressBytes(address),
			n:        len(packet),
			capacity: cap(packet),
			ptr:      uintptr(unsafe.Pointer(&packet[0])),
			slot:     -1,
		}
		if delta := observation.ptr - base; observation.ptr >= base && delta < size*uintptr(slots) {
			observation.slot = int(delta / size)
		}
		h.c.rxMu.Lock()
		// QA repair: a payload inside the ring is owned by the slot its pointer
		// falls into, identified by index, never by scanning for an equal
		// payload pointer. The previous scan excluded every record whose raw
		// pointer equalled the payload pointer before the alias check, so the
		// neighbour equality assertion could never fire: two occupied records
		// aliasing one payload both looked like the owner and neither appeared
		// as a neighbour.
		ownerFound := false
		for index := range h.c.records {
			record := &h.c.records[index]
			if !record.occupied || len(record.raw) == 0 {
				continue
			}
			recordPtr := uintptr(unsafe.Pointer(&record.raw[0]))
			owner := index == observation.slot
			if observation.slot < 0 && !ownerFound && recordPtr == observation.ptr {
				// A payload outside the ring is the record's own detached
				// allocation: the first occupied record whose raw starts at the
				// payload owns it. A second such record is a neighbour, so the
				// alias assertion stays non-vacuous here too.
				owner = true
			}
			if owner {
				ownerFound = true
				if recordPtr == observation.ptr {
					observation.occupied = true
					observation.claimed = record.claimed
					observation.sequence = record.sequence
					observation.bound = true
					observation.ownerLen = len(record.raw)
					observation.ownerCap = cap(record.raw)
				}
				continue
			}
			observation.neighbourPtrs = append(observation.neighbourPtrs, recordPtr)
		}
		h.c.rxMu.Unlock()
		mu.Lock()
		observations = append(observations, observation)
		mu.Unlock()
		return send(packet, address)
	}
	return h, func() []inlinePayloadObservation {
		mu.Lock()
		defer mu.Unlock()
		return append([]inlinePayloadObservation(nil), observations...)
	}
}

func waitReleased(t *testing.T, h *outboundBatchHarness) {
	t.Helper()
	rxWait(t, "detached records were not released", func() bool {
		h.c.rxMu.Lock()
		defer h.c.rxMu.Unlock()
		return h.c.usedRecords == 0 && h.c.usedRawBytes == 0 && !h.c.scratch.occupied
	})
}

func inlinePayloadBytes(size int, seed byte) []byte {
	payload := make([]byte, size)
	for index := range payload {
		payload[index] = seed ^ byte(index*7)
	}
	return payload
}

// A one-byte logical record is only a storage/reservation boundary probe: it is
// not a valid framed IP packet and the reader never receives it.
func TestWindowsReceiveInlinePayloadReservationBoundary(t *testing.T) {
	c := &windowsCapture{}
	c.initReceive()
	c.sequence = 7
	record, index := c.reserveRecordLocked(1)
	if record == nil || int(index) >= windowsReceiveRecords {
		t.Fatal("one-byte logical record refused")
	}
	if c.usedRecords != 1 || c.usedRawBytes != 1 || record.sequence != 7 {
		t.Fatalf("one-byte reservation not charged exactly once: records=%d raw=%d sequence=%d", c.usedRecords, c.usedRawBytes, record.sequence)
	}
	record.raw = make([]byte, 1)
	c.finishRecord(record, record.sequence, true, false)
	if c.usedRecords != 1 || c.usedRawBytes != 1 {
		t.Fatal("one receipt released the reservation")
	}
	c.finishRecord(record, record.sequence, true, true)
	if c.usedRecords != 0 || c.usedRawBytes != 0 {
		t.Fatalf("record ledger not balanced: records=%d raw=%d", c.usedRecords, c.usedRawBytes)
	}
	if record, _ := c.reserveRecordLocked(windivert.MTUMax + 1); record != nil {
		t.Fatal("oversized logical record admitted")
	}
	if record, _ := c.reserveRecordLocked(0); record != nil {
		t.Fatal("empty logical record admitted")
	}
}

func TestWindowsReceiveInlinePayloadReader(t *testing.T) {
	h, observations := probeInlinePayload(t)
	h.start()
	packets := [][]byte{
		buildIPv4UDP(t, inlinePayloadBytes(0, 0x31), 443).Raw,   // 28 bytes
		buildIPv6UDP(t, inlinePayloadBytes(0, 0x41)).Raw,        // 48 bytes
		buildIPv4UDP(t, inlinePayloadBytes(100, 0x32), 443).Raw, // 128 bytes
		buildIPv6UDP(t, inlinePayloadBytes(80, 0x42)).Raw,       // 128 bytes
		buildIPv4UDP(t, inlinePayloadBytes(101, 0x33), 443).Raw, // 129 bytes
		buildIPv6UDP(t, inlinePayloadBytes(81, 0x43)).Raw,       // 129 bytes
	}
	wantLengths := []int{28, 48, 128, 128, 129, 129}
	addrs := [][80]byte{
		outboundModelAddress(1, false),
		outboundModelAddress(2, true),
		outboundModelAddress(3, false),
		outboundModelAddress(4, true),
		outboundModelAddress(5, false),
		outboundModelAddress(6, true),
	}
	for index, packet := range packets {
		if len(packet) != wantLengths[index] {
			t.Fatalf("packet %d is %d bytes, want a valid IP/UDP packet of %d", index, len(packet), wantLengths[index])
		}
	}
	h.deliver(concatPackets(packets...), addrs)
	h.waitSends(t, len(packets))
	got := observations()
	if len(got) != len(packets) {
		t.Fatalf("observed %d reinjections, want %d", len(got), len(packets))
	}
	base, size, slots := inlinePayloadRing(h.c)
	header := inlinePayloadHeaderBytes()
	for index, observation := range got {
		if !bytes.Equal(observation.raw, packets[index]) {
			t.Errorf("send %d does not carry exactly its packet", index)
		}
		if observation.address != addrs[index] {
			t.Errorf("send %d lost the full 80-byte captured address", index)
		}
		if observation.n != wantLengths[index] || observation.capacity != wantLengths[index] {
			t.Errorf("send %d len/cap = %d/%d, want %d/%d", index, observation.n, observation.capacity, wantLengths[index], wantLengths[index])
		}
		if observation.sequence != uint64(index+1) {
			t.Errorf("send %d sequence = %d, want %d in FIFO order", index, observation.sequence, index+1)
		}
		if observation.n > inlinePayloadThreshold {
			if observation.slot >= 0 {
				t.Errorf("send %d (%d B) was staged inside the record ring, want the exact detached allocation", index, observation.n)
			}
			continue
		}
		if observation.slot < 0 || observation.slot >= slots {
			t.Errorf("send %d (%d B) payload is not inside any reserved slot", index, observation.n)
			continue
		}
		offset := (observation.ptr - base) % size
		if offset < header || offset+uintptr(observation.capacity) > size {
			t.Errorf("send %d (%d B) payload escapes its own slot: offset=%d cap=%d record=%d", index, observation.n, offset, observation.capacity, size)
		}
		if !observation.occupied || !observation.claimed || !observation.bound {
			t.Errorf("send %d slot %d is not the claimed owner of that payload (occupied=%v claimed=%v bound=%v)", index, observation.slot, observation.occupied, observation.claimed, observation.bound)
		}
		if observation.ownerLen != observation.capacity || observation.ownerCap != observation.capacity {
			t.Errorf("send %d owning slot exposes raw len/cap = %d/%d, want exact %d/%d", index, observation.ownerLen, observation.ownerCap, observation.capacity, observation.capacity)
		}
		for _, neighbour := range observation.neighbourPtrs {
			if neighbour == observation.ptr {
				t.Errorf("send %d aliases the payload of another occupied slot", index)
			}
		}
		t.Logf("send %d (%d B) slot=%d cap=%d ownerRaw=%d/%d neighbours=%d", index, observation.n, observation.slot, observation.capacity, observation.ownerLen, observation.ownerCap, len(observation.neighbourPtrs))
	}
	waitReleased(t, h)
	h.close(t)
}

func TestWindowsReceiveInlinePayloadLargeThenSmallReuse(t *testing.T) {
	h, observations := probeInlinePayload(t)
	h.start()
	large := buildIPv4UDP(t, inlinePayloadBytes(101, 0x33), 443).Raw  // 129 bytes
	first := buildIPv4UDP(t, inlinePayloadBytes(100, 0xa1), 443).Raw  // 128 bytes
	second := buildIPv4UDP(t, inlinePayloadBytes(100, 0xb2), 443).Raw // 128 bytes
	// QA addition: a shorter valid packet after the 128/129 reuse must expose
	// exactly its own length and capacity, so no stale tail of the previous
	// longer payload can leak through the slot's capacity.
	shorter := buildIPv4UDP(t, inlinePayloadBytes(0, 0xc3), 443).Raw // 28 bytes
	if len(large) != 129 || len(first) != 128 || len(second) != 128 || len(shorter) != 28 {
		t.Fatalf("unexpected packet lengths %d/%d/%d/%d", len(large), len(first), len(second), len(shorter))
	}
	if first[len(first)-1] == second[len(second)-1] {
		t.Fatal("the two small packets must differ in their last byte")
	}
	deliveries := []struct {
		packet  []byte
		address [80]byte
	}{
		{large, outboundModelAddress(1, false)},
		{first, outboundModelAddress(2, false)},
		{second, outboundModelAddress(3, false)},
		{shorter, outboundModelAddress(4, false)},
	}
	for index, delivery := range deliveries {
		h.deliver(delivery.packet, [][80]byte{delivery.address})
		h.waitSends(t, index+1)
		// Wait for the terminal release so the next reservation deterministically
		// reuses the first free slot of the ring.
		waitReleased(t, h)
	}
	got := observations()
	if len(got) != len(deliveries) {
		t.Fatalf("observed %d reinjections, want %d", len(got), len(deliveries))
	}
	if got[0].slot >= 0 {
		t.Fatal("the 129-byte record was staged inside the ring instead of an exact detached allocation")
	}
	if got[1].slot < 0 || got[2].slot < 0 {
		t.Fatal("a small record was not staged in its reserved slot")
	}
	if got[1].slot != got[2].slot || got[1].ptr != got[2].ptr {
		t.Fatalf("reused slot differs: %d/%#x then %d/%#x", got[1].slot, got[1].ptr, got[2].slot, got[2].ptr)
	}
	if got[3].slot != got[1].slot || got[3].ptr != got[1].ptr {
		t.Fatalf("shorter packet did not reuse the same slot: %d/%#x want %d/%#x", got[3].slot, got[3].ptr, got[1].slot, got[1].ptr)
	}
	// Small after large, then the same slot again, then a shorter packet: every
	// payload must be exactly the new packet, fully overwritten, with no leftover
	// tail of the longer or the previous payload exposed through capacity.
	for index, want := range [][]byte{first, second, shorter} {
		observation := got[index+1]
		if !bytes.Equal(observation.raw, want) {
			t.Errorf("reused slot send %d does not carry exactly its packet", index)
		}
		if observation.n != len(want) || observation.capacity != len(want) {
			t.Errorf("reused slot send %d len/cap = %d/%d, want %d", index, observation.n, observation.capacity, len(want))
		}
		if observation.ownerLen != len(want) || observation.ownerCap != len(want) {
			t.Errorf("reused slot send %d owning raw len/cap = %d/%d, want exact %d (no stale exposed tail)", index, observation.ownerLen, observation.ownerCap, len(want))
		}
		if observation.sequence != uint64(index+2) {
			t.Errorf("reused slot send %d sequence = %d, want %d", index, observation.sequence, index+2)
		}
		if !observation.occupied || !observation.claimed || !observation.bound {
			t.Errorf("reused slot send %d is not the claimed owner of that payload", index)
		}
	}
	h.close(t)
}

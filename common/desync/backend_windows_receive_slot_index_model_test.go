//go:build desync_windows_model && !windows

package desync

// Offline model checks for the exact reservation slot carried from the charged
// reservation into FIFO publication. This is a source-shaped model over the
// reversible Windows overlay, never a native WinDivert/Windows execution result.

import (
	"bytes"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

// waitReaderQueue waits until the reader published want queue entries.
func waitReaderQueue(t *testing.T, c *windowsCapture, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		c.rxMu.Lock()
		count := c.queueCount
		c.rxMu.Unlock()
		if count >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("publications absent: queueCount=%d want=%d", count, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestWindowsReceiveReservationCarriesSlotIndex(t *testing.T) {
	c := &windowsCapture{}
	c.initReceive()
	c.sequence = 5
	first, firstIndex := c.reserveRecordLocked(4)
	if first == nil || first != &c.records[0] || firstIndex != 0 {
		t.Fatalf("first reservation slot=%d pointer=%p", firstIndex, first)
	}
	second, secondIndex := c.reserveRecordLocked(5)
	if second == nil || second != &c.records[1] || secondIndex != 1 {
		t.Fatalf("second reservation slot=%d pointer=%p", secondIndex, second)
	}
	// A released nonzero slot is the next reservation: the carried index must
	// follow the actual ring position, not a reserved ordinal or slot zero.
	second.raw = make([]byte, 5) // exact copy of the charged span
	c.finishRecord(second, second.sequence, true, true)
	reused, reusedIndex := c.reserveRecordLocked(6)
	if reused == nil || reused != &c.records[1] || reusedIndex != 1 {
		t.Fatalf("nonzero-slot reuse index=%d pointer=%p", reusedIndex, reused)
	}
	if c.usedRecords != 2 || c.usedRawBytes != 4+6 {
		t.Fatalf("charged counters records=%d raw=%d", c.usedRecords, c.usedRawBytes)
	}
	// The last ring slot is representable in the uint16 publication index.
	last := &windowsCapture{}
	last.initReceive()
	for index := 0; index < windowsReceiveRecords-1; index++ {
		r, reserved := last.reserveRecordLocked(1)
		if r == nil || reserved != uint16(index) || r != &last.records[index] {
			t.Fatalf("prefill slot %d got index=%d pointer=%p", index, reserved, r)
		}
	}
	r, slot := last.reserveRecordLocked(1)
	if r == nil || r != &last.records[windowsReceiveRecords-1] || slot != uint16(windowsReceiveRecords-1) {
		t.Fatalf("last slot index=%d pointer=%p", slot, r)
	}
	// A refused reservation has no slot to publish: it returns no record, so
	// the reader's nil check precedes any queue write, and no counter moves.
	refused, refusedIndex := last.reserveRecordLocked(1)
	if refused != nil {
		t.Fatalf("full ring admitted a record: %p", refused)
	}
	if refusedIndex != 0 {
		t.Fatalf("refused reservation returned slot %d", refusedIndex)
	}
	if last.usedRecords != windowsReceiveRecords || last.usedRawBytes != windowsReceiveRecords || last.queueCount != 0 {
		t.Fatalf("refused reservation moved ownership: records=%d raw=%d queued=%d", last.usedRecords, last.usedRawBytes, last.queueCount)
	}
}

// Only the outbound reader is started so both publications remain in the ring
// and their exact carried indices stay observable without a worker dequeue.
func TestWindowsOutboundBatchSlotIndexFIFO(t *testing.T) {
	packets := [][]byte{
		buildIPv4UDP(t, []byte("slot-one"), 443).Raw,
		buildIPv4UDP(t, []byte("slot-two-packet"), 443).Raw,
	}
	addrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, false)}
	packed := concatPackets(packets...)
	first := true
	view := func(bufferSize int, consume func([]byte, []windivert.Address)) (int, error) {
		if !first {
			return 0, windivert.ReplayDrained
		}
		first = false
		if bufferSize < len(packed) {
			return 0, windivert.ReplayDrained
		}
		// The model owns the lane backing and lends an exact terminal view.
		lane := make([]byte, bufferSize)
		copy(lane, packed)
		viewAddrs := make([]windivert.Address, len(packets))
		for index := range viewAddrs {
			viewAddrs[index] = outboundAddressFromBytes(addrs[index])
		}
		consume(lane[:len(packed):len(packed)], viewAddrs)
		return len(packed), nil
	}
	c := &windowsCapture{done: make(chan struct{})}
	c.outbound = &windivert.Handle{RecvBatchViewFunc: view}
	c.initReceive()
	// Two nonzero slots stay free at the END of the ring: the carried index must
	// be the last two slots, and slot zero must never appear in the publication.
	for index := 0; index < windowsReceiveRecords-2; index++ {
		reserved, reservedIndex := c.reserveRecordLocked(1)
		if reserved == nil || reservedIndex != uint16(index) {
			t.Fatalf("prefill slot %d got index=%d", index, reservedIndex)
		}
		reserved.raw = make([]byte, 1)
	}
	prefillRecords, prefillRaw := c.usedRecords, c.usedRawBytes
	c.wg.Add(1)
	go c.loop()
	t.Cleanup(func() {
		select {
		case <-c.done:
		case <-time.After(time.Second):
			t.Fatal("reader did not terminate")
		}
	})
	waitReaderQueue(t, c, len(packets))
	c.rxMu.Lock()
	head, queued := c.queueHead, c.queueCount
	published := []uint16{c.queue[head], c.queue[(head+1)%windowsReceiveRecords]}
	recordOne := c.records[windowsReceiveRecords-2]
	recordTwo := c.records[windowsReceiveRecords-1]
	pending := c.pendingBatch
	sequence := c.sequence
	records, raw := c.usedRecords, c.usedRawBytes
	c.rxMu.Unlock()
	if head != 0 || queued != len(packets) {
		t.Fatalf("publication ring head=%d count=%d", head, queued)
	}
	if published[0] != uint16(windowsReceiveRecords-2) || published[1] != uint16(windowsReceiveRecords-1) {
		t.Fatalf("FIFO publication indices = %v", published)
	}
	if sequence != uint64(len(packets)) {
		t.Fatalf("original per-packet sequence = %d", sequence)
	}
	if records != prefillRecords+len(packets) || raw != prefillRaw+len(packets[0])+len(packets[1]) {
		t.Fatalf("counters records=%d raw=%d after prefill %d/%d", records, raw, prefillRecords, prefillRaw)
	}
	if pending.occupied || pending.count != 0 || pending.next != 0 {
		t.Fatalf("packed descriptor retained: %+v", pending)
	}
	want := []struct {
		record *windowsReceiveRecord
		raw    []byte
		addr   [80]byte
		seq    uint64
	}{{&recordOne, packets[0], addrs[0], 1}, {&recordTwo, packets[1], addrs[1], 2}}
	for index, item := range want {
		if !item.record.occupied || !item.record.worker || item.record.sequence != item.seq {
			t.Fatalf("published record %d ownership lost: %+v", index, item.record)
		}
		if !bytes.Equal(item.record.raw, item.raw) || cap(item.record.raw) != len(item.raw) {
			t.Fatalf("published record %d is not the exact detached copy", index)
		}
		if item.record.address != item.addr {
			t.Fatalf("published record %d lost the full 80-byte captured address", index)
		}
		if uintptr(unsafe.Pointer(&item.record.raw[0])) == uintptr(unsafe.Pointer(&c.receiveBuffer[0])) {
			t.Fatalf("published record %d aliases the packed receive buffer", index)
		}
	}
}

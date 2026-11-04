//go:build desync_windows_model && !windows

package desync

// Offline model checks for the caller-owned Windows receive address storage.
// This is a source-shaped model over the reversible Windows overlay, never a
// native WinDivert/Windows execution result.

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing-box/common/windivert"
)

// Both production receive owners are serial and must pass one reusable address
// backing to successive ordinary variable-count batches. The returned receipt
// aliases that backing, while all 80 captured bytes stay exact.
func TestWindowsInboundBatchAddressStorageReuse(t *testing.T) {
	h := newInboundBatchModel(t, `[{"network":["tcp"],"port":[1]}]`, false)
	h.start()
	first := buildIPv4UDP(t, []byte("first"), 443).Raw
	second := buildIPv4UDP(t, []byte("second-packet"), 443).Raw
	third := buildIPv4UDP(t, []byte("third"), 443).Raw
	firstAddrs := [][80]byte{inboundModelAddress(1, false), inboundModelAddress(2, false)}
	secondAddrs := [][80]byte{inboundModelAddress(3, false)}
	h.deliver(concatPackets(first, second), firstAddrs)
	h.waitSends(t, 1)
	h.deliver(third, secondAddrs)
	h.waitSends(t, 2)
	recv, allSends := h.calls()
	if len(recv) < 2 || recv[0].addrPtr == 0 || recv[0].addrPtr != recv[1].addrPtr {
		t.Fatalf("inbound receive address backing was not reused: %+v", recv)
	}
	// The terminal view is the lane's own backing, capped to the exact receipt
	// count; the old caller-owned BatchMax capacity is gone.
	if recv[0].addrCap != len(firstAddrs) || recv[1].addrCap != len(secondAddrs) {
		t.Fatalf("inbound terminal view address caps = %d/%d, want %d/%d", recv[0].addrCap, recv[1].addrCap, len(firstAddrs), len(secondAddrs))
	}
	if recv[0].rawCap != len(first)+len(second) || recv[1].rawCap != len(third) {
		t.Fatalf("inbound terminal view payload caps = %d/%d, want %d/%d", recv[0].rawCap, recv[1].rawCap, len(first)+len(second), len(third))
	}
	if views, _, into := h.viewStats(); views != 2 || into != 0 {
		t.Fatalf("inbound receive seam: view=%d old-into=%d, want 2/0", views, into)
	}
	if len(allSends) != 2 {
		t.Fatalf("inbound sends = %d, want 2", len(allSends))
	}
	if len(allSends[0].addrs) != 2 || allSends[0].addrs[0] != firstAddrs[0] || allSends[0].addrs[1] != firstAddrs[1] {
		t.Fatal("first inbound batch lost exact 80-byte addresses")
	}
	if len(allSends[1].addrs) != 1 || allSends[1].addrs[0] != secondAddrs[0] {
		t.Fatal("second inbound batch lost exact 80-byte address")
	}
	h.close(t)
}

func TestWindowsOutboundBatchAddressStorageReuse(t *testing.T) {
	h := newOutboundBatchModel(t)
	h.start()
	first := buildIPv4UDP(t, []byte("first"), 443).Raw
	second := buildIPv6UDP(t, []byte("second-packet")).Raw
	third := buildIPv4UDP(t, []byte("third"), 443).Raw
	firstAddrs := [][80]byte{outboundModelAddress(1, false), outboundModelAddress(2, true)}
	secondAddrs := [][80]byte{outboundModelAddress(3, false)}
	poison := bytes.Repeat([]byte{0x5a}, len(h.c.receiveBuffer))
	copy(h.c.receiveBuffer, poison)
	h.deliver(concatPackets(first, second), firstAddrs)
	h.waitSends(t, 2)
	h.deliver(third, secondAddrs)
	sends := h.waitSends(t, 3)
	recv, _ := h.calls()
	// The outbound owner uses the synchronous terminal view exclusively; the
	// old caller-owned Into backing and its per-call copy are gone.
	if views, consumes, into := h.viewStats(); views != 2 || consumes != 2 || into != 0 {
		t.Fatalf("outbound receive seam: view=%d consume=%d old-into=%d, want 2/2/0", views, consumes, into)
	}
	if len(recv) < 2 || recv[0].addrPtr == 0 || recv[0].addrPtr != recv[1].addrPtr {
		t.Fatalf("outbound receive lane was not reused: %+v", recv)
	}
	// The view is capped to the exact receipt; it is not a BatchMax caller
	// storage array any more.
	if recv[0].addrCap != len(firstAddrs) || recv[1].addrCap != len(secondAddrs) {
		t.Fatalf("outbound terminal view address caps = %d/%d, want %d/%d", recv[0].addrCap, recv[1].addrCap, len(firstAddrs), len(secondAddrs))
	}
	if recv[0].rawCap != len(first)+len(second) || recv[1].rawCap != len(third) {
		t.Fatalf("outbound terminal view payload caps = %d/%d, want %d/%d", recv[0].rawCap, recv[1].rawCap, len(first)+len(second), len(third))
	}
	if !bytes.Equal(h.c.receiveBuffer, poison) {
		t.Fatal("ordinary outbound batches wrote into the capture fallback backing")
	}
	for index, want := range []struct {
		raw   []byte
		addrs [][80]byte
	}{{first, firstAddrs[:1]}, {second, firstAddrs[1:]}, {third, secondAddrs}} {
		if string(sends[index].raw) != string(want.raw) {
			t.Fatalf("outbound send %d bytes mismatch", index)
		}
		if len(sends[index].addrs) != 1 || sends[index].addrs[0] != want.addrs[0] {
			t.Fatalf("outbound send %d lost exact 80-byte address", index)
		}
	}
	h.close(t)
}

// The model boundary preserves the two API contracts: RecvBatchInto aliases the
// caller backing, the old allocating RecvBatch stays detached, and short caller
// storage is rejected before the modeled receive is issued.
func TestWindowsRecvBatchModelAddressContracts(t *testing.T) {
	receipt := inboundModelAddress(7, false)
	receives := 0
	h := &windivert.Handle{RecvBatchFunc: func(p []byte) (int, []windivert.Address, error) {
		receives++
		copy(p, inboundIPv4Packet(20))
		addrs := make([]windivert.Address, 1)
		addrs[0] = inboundAddressFromBytes(receipt)
		return 20, addrs, nil
	}}
	buf := make([]byte, windivert.MTUMax)
	storage := make([]windivert.Address, windivert.BatchMax)
	_, into1, err := h.RecvBatchInto(buf, storage)
	if err != nil || len(into1) != 1 || &into1[0] != &storage[0] {
		t.Fatalf("RecvBatchInto receipt does not alias caller storage: %v", err)
	}
	if inboundAddressBytes(&into1[0]) != receipt {
		t.Fatal("RecvBatchInto receipt bytes differ")
	}
	_, into2, err := h.RecvBatchInto(buf, storage)
	if err != nil || &into2[0] != &into1[0] {
		t.Fatalf("successive RecvBatchInto calls did not share storage: %v", err)
	}
	before := receives
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("short RecvBatchInto storage was accepted")
			}
		}()
		_, _, _ = h.RecvBatchInto(buf, make([]windivert.Address, windivert.BatchMax-1))
	}()
	if receives != before {
		t.Fatal("short storage reached the modeled receive")
	}
	_, old1, err := h.RecvBatch(buf)
	if err != nil || len(old1) != 1 {
		t.Fatalf("old RecvBatch receipt: %v", err)
	}
	_, old2, err := h.RecvBatch(buf)
	if err != nil || len(old2) != 1 {
		t.Fatalf("old RecvBatch receipt: %v", err)
	}
	if &old1[0] == &old2[0] || &old1[0] == &storage[0] {
		t.Fatal("old allocating RecvBatch receipt aliases another receipt or caller storage")
	}
}

//go:build desync_windows_model && !windows

package desync

// Focused offline model checks for the narrow per-plan SendBatch adapter in
// backend_windows.go. The native boundary is played by the reversible model
// boundary; this is a source-shaped model result, never a Windows/WinDivert
// execution result.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

func planBatchAddress(seed byte, ipv6 bool) [80]byte {
	var raw [80]byte
	for index := range raw {
		raw[index] = seed + byte(index)
	}
	// Deterministic flags: captured outbound direction and, when requested, the
	// IPv6 family bit. Everything else stays zero/arbitrary captured data.
	bits := uint32(1 << 17)
	if ipv6 {
		bits |= 1 << 20
	}
	binary.LittleEndian.PutUint32(raw[8:12], bits)
	return raw
}

func planAddressFromBytes(raw [80]byte) windivert.Address {
	var address windivert.Address
	*(*[80]byte)(unsafe.Pointer(&address)) = raw
	return address
}

func planAddressBytes(address *windivert.Address) [80]byte {
	return *(*[80]byte)(unsafe.Pointer(address))
}

// planSuppliedAddress is the captured address the adapter must hand to a batch
// element: complete 80-byte clone and only the supplied-checkum bits changed.
func planSuppliedAddress(raw [80]byte) [80]byte {
	address := planAddressFromBytes(raw)
	suppliedChecksums(&address)
	return planAddressBytes(&address)
}

// planIPv4Raw builds the minimal framing shell of one IPv4 packet of exactly
// size bytes; transport bytes are not interpreted by the adapter.
func planIPv4Raw(size int, fill byte) []byte {
	raw := make([]byte, size)
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(size))
	raw[9] = 17
	for index := 20; index < size; index++ {
		raw[index] = fill
	}
	return raw
}

// planIPv6Raw builds exactly one IPv6 packet of size bytes, including the
// MTUMax quantum, where the payload length field carries the remaining bytes.
func planIPv6Raw(size int, fill byte) []byte {
	raw := make([]byte, size)
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], uint16(size-40))
	raw[6] = 17
	for index := 40; index < size; index++ {
		raw[index] = fill
	}
	return raw
}

type planBatchCall struct {
	raw   []byte
	addrs [][80]byte
}

type planBatchModel struct {
	order       []string
	sends       []planBatchCall
	batches     []planBatchCall
	errs        []error
	usable      func(batches int) bool
	sendResult  func([]byte) error
	batchResult func(raw []byte, packets int) (int, error)
}

func (m *planBatchModel) single(packet []byte) error {
	m.order = append(m.order, "send")
	m.sends = append(m.sends, planBatchCall{raw: bytes.Clone(packet)})
	if m.sendResult != nil {
		return m.sendResult(packet)
	}
	return nil
}

func (m *planBatchModel) sendPlanBatch(packets [][]byte, address windivert.Address) (int, error) {
	handle := &windivert.Handle{
		SendBatchFunc: func(raw []byte, addrs []windivert.Address) (int, error) {
			m.order = append(m.order, "batch")
			call := planBatchCall{raw: bytes.Clone(raw)}
			for index := range addrs {
				call.addrs = append(call.addrs, planAddressBytes(&addrs[index]))
			}
			m.batches = append(m.batches, call)
			if m.batchResult != nil {
				return m.batchResult(raw, len(addrs))
			}
			return len(raw), nil
		},
	}
	usable := func() bool {
		if m.usable == nil {
			return true
		}
		return m.usable(len(m.batches))
	}
	return sendPlanBatches(handle, packets, address, usable, m.single, func(err error) {
		m.errs = append(m.errs, err)
	})
}

func planConcat(packets [][]byte) []byte {
	var out []byte
	for _, packet := range packets {
		out = append(out, packet...)
	}
	return out
}

// R1198-C1: ordinary IPv4/IPv6 success keeps exact bytes, order and the full
// captured address except the supplied checksum bits; a deliberately bad
// checksum is preserved verbatim.
func TestWindowsPlanBatchBytesAddressOrder(t *testing.T) {
	first := append([]byte(nil), buildIPv4UDP(t, []byte("first"), 443).Raw...)
	second := append([]byte(nil), buildIPv4UDP(t, []byte("second"), 443).Raw...)
	second[len(second)-2] ^= 0x5a // deliberately invalid UDP checksum bytes
	third := append([]byte(nil), buildIPv4UDP(t, []byte("third"), 443).Raw...)
	captured := planBatchAddress(3, false)
	m := &planBatchModel{}
	sent, err := m.sendPlanBatch([][]byte{first, second, third}, planAddressFromBytes(captured))
	if err != nil || sent != 3 {
		t.Fatalf("IPv4 plan = %d %v", sent, err)
	}
	if len(m.batches) != 1 || len(m.sends) != 0 {
		t.Fatalf("IPv4 submissions: batches=%d singles=%d", len(m.batches), len(m.sends))
	}
	expect := planConcat([][]byte{first, second, third})
	if !bytes.Equal(m.batches[0].raw, expect) {
		t.Fatal("IPv4 packed bytes are not the exact concatenation")
	}
	if len(m.batches[0].addrs) != 3 {
		t.Fatalf("IPv4 addresses = %d", len(m.batches[0].addrs))
	}
	supplied := planSuppliedAddress(captured)
	for index, address := range m.batches[0].addrs {
		if address != supplied {
			t.Fatalf("IPv4 packet %d address was not the captured clone with supplied bits", index)
		}
	}

	v6first := append([]byte(nil), buildIPv6UDP(t, []byte("v6-first")).Raw...)
	v6second := append([]byte(nil), buildIPv6UDP(t, []byte("v6-second")).Raw...)
	v6captured := planBatchAddress(9, true)
	v6 := &planBatchModel{}
	sent, err = v6.sendPlanBatch([][]byte{v6first, v6second}, planAddressFromBytes(v6captured))
	if err != nil || sent != 2 {
		t.Fatalf("IPv6 plan = %d %v", sent, err)
	}
	if len(v6.batches) != 1 || len(v6.sends) != 0 {
		t.Fatalf("IPv6 submissions: batches=%d singles=%d", len(v6.batches), len(v6.sends))
	}
	if !bytes.Equal(v6.batches[0].raw, planConcat([][]byte{v6first, v6second})) {
		t.Fatal("IPv6 packed bytes are not the exact concatenation")
	}
	v6supplied := planSuppliedAddress(v6captured)
	for index, address := range v6.batches[0].addrs {
		if address != v6supplied {
			t.Fatalf("IPv6 packet %d address mismatch", index)
		}
	}
}

// R1198-C1/C2: empty and single plans keep the old path; an unsuitable element
// flushes the earlier segment first, then uses the real single sender once and
// only a successful send lets the remaining tail continue.
func TestWindowsPlanBatchEmptySingleAndFallback(t *testing.T) {
	address := planAddressFromBytes(planBatchAddress(5, false))
	empty := &planBatchModel{}
	if sent, err := empty.sendPlanBatch(nil, address); sent != 0 || err != nil {
		t.Fatalf("empty plan = %d %v", sent, err)
	}
	if len(empty.order) != 0 {
		t.Fatalf("empty plan made %d native calls", len(empty.order))
	}

	one := append([]byte(nil), buildIPv4UDP(t, []byte("one"), 443).Raw...)
	single := &planBatchModel{}
	if sent, err := single.sendPlanBatch([][]byte{one}, address); sent != 1 || err != nil {
		t.Fatalf("single plan = %d %v", sent, err)
	}
	if len(single.sends) != 1 || len(single.batches) != 0 || !bytes.Equal(single.sends[0].raw, one) {
		t.Fatal("single plan did not keep the existing single path")
	}

	good1 := append([]byte(nil), buildIPv4UDP(t, []byte("good1"), 443).Raw...)
	good2 := append([]byte(nil), buildIPv4UDP(t, []byte("good2"), 443).Raw...)
	bad := append(append([]byte(nil), buildIPv4UDP(t, []byte("bad"), 443).Raw...), 0xde)
	good3 := append([]byte(nil), buildIPv4UDP(t, []byte("good3"), 443).Raw...)
	good4 := append([]byte(nil), buildIPv4UDP(t, []byte("good4"), 443).Raw...)
	m := &planBatchModel{}
	sent, err := m.sendPlanBatch([][]byte{good1, good2, bad, good3, good4}, address)
	if err != nil || sent != 5 {
		t.Fatalf("midvector fallback = %d %v", sent, err)
	}
	if len(m.order) != 3 || m.order[0] != "batch" || m.order[1] != "send" || m.order[2] != "batch" {
		t.Fatalf("midvector order = %v", m.order)
	}
	if !bytes.Equal(m.batches[0].raw, planConcat([][]byte{good1, good2})) {
		t.Fatal("earlier segment was not flushed unchanged before the single")
	}
	if len(m.sends) != 1 || !bytes.Equal(m.sends[0].raw, bad) {
		t.Fatal("unsuitable element did not use the real single sender with its exact bytes")
	}
	if !bytes.Equal(m.batches[1].raw, planConcat([][]byte{good3, good4})) {
		t.Fatal("tail after a successful single was lost or reordered")
	}

	// A failing not-yet-submitted single keeps the earlier confirmed prefix,
	// reports the real single error and stops the tail.
	failed := errors.New("modeled single failure")
	prefix := &planBatchModel{sendResult: func([]byte) error { return failed }}
	sent, err = prefix.sendPlanBatch([][]byte{good1, good2, bad, good3}, address)
	if sent != 2 || !errors.Is(err, failed) {
		t.Fatalf("failed single = %d %v", sent, err)
	}
	if len(prefix.batches) != 1 || len(prefix.sends) != 1 {
		t.Fatalf("failed single submissions: batches=%d singles=%d", len(prefix.batches), len(prefix.sends))
	}

	// Family mismatch is an ineligible element, not a new rejection: both
	// packets stay on the existing single path.
	mismatch := &planBatchModel{}
	sent, err = mismatch.sendPlanBatch([][]byte{good1, good2}, planAddressFromBytes(planBatchAddress(6, true)))
	if err != nil || sent != 2 {
		t.Fatalf("family mismatch = %d %v", sent, err)
	}
	if len(mismatch.batches) != 0 || len(mismatch.sends) != 2 {
		t.Fatalf("family mismatch submissions: batches=%d singles=%d", len(mismatch.batches), len(mismatch.sends))
	}
}

// R1198-C2: the packet quantum, the byte quantum and the exact MTUMax boundary
// are chunk boundaries, not acceptance limits; every element is submitted once
// in order.
func TestWindowsPlanBatchChunkBoundaries(t *testing.T) {
	address := planAddressFromBytes(planBatchAddress(7, false))
	packets := make([][]byte, 0, 300)
	for index := 0; index < 300; index++ {
		packets = append(packets, planIPv4Raw(20, byte(index)))
	}
	m := &planBatchModel{}
	sent, err := m.sendPlanBatch(packets, address)
	if err != nil || sent != 300 {
		t.Fatalf("packet quantum = %d %v", sent, err)
	}
	if len(m.batches) != 2 || len(m.sends) != 0 {
		t.Fatalf("packet quantum submissions: batches=%d singles=%d", len(m.batches), len(m.sends))
	}
	if len(m.batches[0].addrs) != windivert.BatchMax || len(m.batches[1].addrs) != 300-windivert.BatchMax {
		t.Fatalf("packet quantum chunk sizes = %d/%d", len(m.batches[0].addrs), len(m.batches[1].addrs))
	}
	if !bytes.Equal(m.batches[0].raw, planConcat(packets[:windivert.BatchMax])) || !bytes.Equal(m.batches[1].raw, planConcat(packets[windivert.BatchMax:])) {
		t.Fatal("packet quantum chunk bytes/order changed")
	}

	wide := make([][]byte, 0, 70)
	for index := 0; index < 70; index++ {
		wide = append(wide, planIPv4Raw(1000, byte(index)))
	}
	bytesModel := &planBatchModel{}
	sent, err = bytesModel.sendPlanBatch(wide, address)
	if err != nil || sent != 70 {
		t.Fatalf("byte quantum = %d %v", sent, err)
	}
	if len(bytesModel.batches) != 2 || len(bytesModel.batches[0].raw) != 65000 || len(bytesModel.batches[1].raw) != 5000 {
		t.Fatalf("byte quantum chunks = %d bytes/%d bytes", len(bytesModel.batches[0].raw), len(bytesModel.batches[1].raw))
	}

	v6 := planAddressFromBytes(planBatchAddress(8, true))
	exact := &planBatchModel{}
	sent, err = exact.sendPlanBatch([][]byte{planIPv6Raw(65535, 1), planIPv6Raw(40, 2), planIPv6Raw(40, 3)}, v6)
	if err != nil || sent != 3 {
		t.Fatalf("exact boundary = %d %v", sent, err)
	}
	if len(exact.batches) != 1 || len(exact.batches[0].raw) != windivert.MTUMax || len(exact.batches[0].addrs) != 2 {
		t.Fatalf("exact MTUMax chunk = %d bytes/%d addresses", len(exact.batches[0].raw), len(exact.batches[0].addrs))
	}
	if len(exact.sends) != 1 || !bytes.Equal(exact.sends[0].raw, planIPv6Raw(40, 3)) {
		t.Fatal("one-packet tail did not keep the single path")
	}

	big := &planBatchModel{}
	sent, err = big.sendPlanBatch([][]byte{planIPv6Raw(windivert.MTUMax, 4), planIPv6Raw(40, 5)}, v6)
	if err != nil || sent != 2 {
		t.Fatalf("single large element = %d %v", sent, err)
	}
	if len(big.batches) != 0 || len(big.sends) != 2 {
		t.Fatalf("single large element submissions: batches=%d singles=%d", len(big.batches), len(big.sends))
	}
}

// R1198-C3: ordinary unit receipt table. Only a nil batch result confirms a
// chunk; error with a full/nonzero count, a short count and UNKNOWN after a
// successful segment all keep the previous confirmed prefix, preserve the raw
// error chain, record the batch failure once and never retry or fall back.
func TestWindowsPlanBatchReceiptTables(t *testing.T) {
	failure := errors.New("modeled batch failure")
	packets := func(count int) [][]byte {
		out := make([][]byte, 0, count)
		for index := 0; index < count; index++ {
			out = append(out, planIPv4Raw(20, byte(index)))
		}
		return out
	}
	address := planAddressFromBytes(planBatchAddress(11, false))

	full := &planBatchModel{}
	sent, err := full.sendPlanBatch(packets(300), address)
	if err != nil || sent != 300 || len(full.batches) != 2 || len(full.errs) != 0 || len(full.sends) != 0 {
		t.Fatalf("full success = %d %v batches=%d errors=%d singles=%d", sent, err, len(full.batches), len(full.errs), len(full.sends))
	}

	calls := 0
	counted := &planBatchModel{batchResult: func(raw []byte, _ int) (int, error) {
		calls++
		if calls == 2 {
			return len(raw), failure
		}
		return len(raw), nil
	}}
	sent, err = counted.sendPlanBatch(packets(300), address)
	if sent != 255 || !errors.Is(err, failure) || !errors.Is(counted.errs[0], failure) || len(counted.errs) != 1 {
		t.Fatalf("full-count error = %d %v errors=%v", sent, err, counted.errs)
	}
	if len(counted.batches) != 2 || len(counted.sends) != 0 {
		t.Fatalf("full-count error submissions: batches=%d singles=%d", len(counted.batches), len(counted.sends))
	}

	short := &planBatchModel{batchResult: func(raw []byte, _ int) (int, error) { return len(raw) - 1, nil }}
	sent, err = short.sendPlanBatch(packets(300), address)
	if sent != 0 || err == nil || len(short.errs) != 1 || len(short.batches) != 1 || len(short.sends) != 0 {
		t.Fatalf("short receipt = %d %v batches=%d errors=%d", sent, err, len(short.batches), len(short.errs))
	}

	unknownBatches := 0
	unknown := &planBatchModel{batchResult: func(raw []byte, _ int) (int, error) {
		unknownBatches++
		if unknownBatches == 2 {
			return -1, failure
		}
		return len(raw), nil
	}}
	sent, err = unknown.sendPlanBatch(packets(600), address)
	if sent != 255 || !errors.Is(err, errCaptureSendIncomplete) || !errors.Is(err, failure) {
		t.Fatalf("unknown receipt = %d %v", sent, err)
	}
	if len(unknown.errs) != 1 || !errors.Is(unknown.errs[0], errCaptureSendIncomplete) {
		t.Fatalf("unknown receipt errors = %v", unknown.errs)
	}
	if len(unknown.batches) != 2 || len(unknown.sends) != 0 {
		t.Fatalf("unknown receipt submissions: batches=%d singles=%d", len(unknown.batches), len(unknown.sends))
	}

	unusable := &planBatchModel{usable: func(batches int) bool { return batches == 0 }}
	sent, err = unusable.sendPlanBatch(packets(300), address)
	if sent != 255 || !errors.Is(err, errCaptureSendIncomplete) || len(unusable.errs) != 0 {
		t.Fatalf("unusable segment = %d %v errors=%v", sent, err, unusable.errs)
	}
	if len(unusable.batches) != 1 || len(unusable.sends) != 0 {
		t.Fatalf("unusable segment submissions: batches=%d singles=%d", len(unusable.batches), len(unusable.sends))
	}
}

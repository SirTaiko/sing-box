//go:build desync_windows_model && !windows

package desync

// Focused offline model check of the actual immediate caller for the narrow
// per-plan SendBatch adapter. Self-contained so the same test can also be run
// against the immutable pre-change backend as the nonvacuous efficiency RED.
// The native boundary is the reversible model boundary, never a native result.

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

func immAddress(seed byte, ipv6 bool) [80]byte {
	var raw [80]byte
	for index := range raw {
		raw[index] = seed + byte(index)
	}
	bits := uint32(1 << 17)
	if ipv6 {
		bits |= 1 << 20
	}
	binary.LittleEndian.PutUint32(raw[8:12], bits)
	return raw
}

func immAddressFromBytes(raw [80]byte) windivert.Address {
	var address windivert.Address
	*(*[80]byte)(unsafe.Pointer(&address)) = raw
	return address
}

func immAddressBytes(address *windivert.Address) [80]byte {
	return *(*[80]byte)(unsafe.Pointer(address))
}

func immSupplied(raw [80]byte) [80]byte {
	address := immAddressFromBytes(raw)
	suppliedChecksums(&address)
	return immAddressBytes(&address)
}

type immCall struct {
	raw   []byte
	addrs [][80]byte
}

// R1198-C4: the actual immediate caller. A successful generated burst of one
// captured record goes through one synchronous SendBatch chunk, then the
// original keeps its single engine disposition exactly once.
func TestWindowsPlanBatchImmediateDisposition(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},"rules":[{"network":["tcp"],"port":[443],"methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"tls","hex":"16030100"}]},"fooling":["ts"]}]}`), "")
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

	var sends []immCall
	var batches []immCall
	nativeDone := make(chan struct{})
	capture := &windowsCapture{lease: lease, dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	capture.releaseHold, err = lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	capture.outbound = &windivert.Handle{
		RecvBatchFunc: func([]byte) (int, []windivert.Address, error) {
			return 0, nil, windivert.ReplayDrained
		},
		SendFunc: func(raw []byte, address *windivert.Address) (int, error) {
			sends = append(sends, immCall{raw: bytes.Clone(raw), addrs: [][80]byte{immAddressBytes(address)}})
			return len(raw), nil
		},
		SendBatchFunc: func(raw []byte, addrs []windivert.Address) (int, error) {
			call := immCall{raw: bytes.Clone(raw)}
			for index := range addrs {
				call.addrs = append(call.addrs, immAddressBytes(&addrs[index]))
			}
			batches = append(batches, call)
			return len(raw), nil
		},
		ShutdownFunc: func() error { return nil },
		CloseFunc:    func() error { close(nativeDone); return nil },
		DoneChan:     nativeDone,
	}
	lease.capture = capture
	capture.startUsers()
	t.Cleanup(func() { _ = engine.Close() })

	raw := testTCPPacket(t, buildClientHello("blocked.example"), 1000)
	captured := immAddress(12, false)
	capture.rxMu.Lock()
	capture.sequence = 21
	record, _ := capture.reserveRecordLocked(len(raw))
	capture.rxMu.Unlock()
	if record == nil {
		t.Fatal("record reservation refused")
	}
	record.raw = raw[:len(raw):len(raw)]
	record.address = captured

	verdict, modified, held := capture.handleOutboundRecord(record, 21)
	if verdict != VerdictPass || held || modified != nil {
		t.Fatalf("immediate verdict = %v held=%v modified=%d", verdict, held, len(modified))
	}
	capture.disposeRecord(record, 21, verdict, modified)
	capture.finishRecord(record, 21, false, true)

	if len(batches) != 1 || len(sends) != 1 {
		t.Fatalf("immediate submissions: batches=%d singles=%d", len(batches), len(sends))
	}
	if len(batches[0].addrs) != 2 {
		t.Fatalf("immediate batch packets = %d", len(batches[0].addrs))
	}
	supplied := immSupplied(captured)
	for index, address := range batches[0].addrs {
		if address != supplied {
			t.Fatalf("immediate batch packet %d address mismatch", index)
		}
	}
	var spans [windivert.BatchMax + 1]uint32
	count, err := frameWindowsBatch(batches[0].raw, &spans)
	if err != nil || count != 2 || int(spans[2]) != len(batches[0].raw) {
		t.Fatalf("immediate batch framing = %d %v", count, err)
	}
	if !bytes.Equal(sends[0].raw, raw) {
		t.Fatal("original bytes were changed by the successful generated burst")
	}
	if sends[0].addrs[0] != captured {
		t.Fatal("original Pass address was normalized")
	}
	if engine.ActiveLeases() != 1 {
		t.Fatal("unrelated lease state changed")
	}
	if err := lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	capture.rxMu.Lock()
	used := capture.usedRecords
	capture.rxMu.Unlock()
	if used != 0 {
		t.Fatalf("record credit not returned: %d", used)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatal("native charge retained")
	}
}

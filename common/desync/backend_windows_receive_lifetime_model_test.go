//go:build desync_windows_model && !windows

package desync

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/windivert"
)

func rxQUICConfig(t *testing.T, max int) *Config {
	return qa519CompileRule(t, `{"network":["udp"],"protocol":["quic"],"methods":["fake"],"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"ab"}]}}`, fmt.Sprintf(`{"hold_timeout":"10s","max_leases":%d}`, max))
}

func TestWindowsReceiveNextCycleAndPeerFIFO(t *testing.T) {
	h := newRXModel(t, rxQUICConfig(t, 8))
	head, tail := qa519SplitInitials(t, "next.example", 40, qa519DCID(0x79), 1, 1)
	a, b := buildIPv4UDP(t, head, 443).Raw, buildIPv4UDP(t, tail, 443).Raw
	otherA, otherB := buildIPv4UDP(t, head, 444).Raw, buildIPv4UDP(t, tail, 444).Raw
	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	defer unblock()
	h.onSend = func(p []byte, _ *windivert.Address) (int, error) {
		if bytes.Equal(p, a) {
			once.Do(func() { close(entered); <-release })
		}
		return len(p), nil
	}
	h.start()
	h.send(a, 1)
	h.send(b, 2)
	rxChannel(t, entered, "first synchronous release missing")
	for i, p := range [][]byte{a, b, otherA, otherB} {
		h.send(p, i+3)
	}
	rxWait(t, "reader stalled across cycle/peer", func() bool { r, _, _, _ := h.stats(); return r == 6 })
	// An inbound modified slot cannot be stolen by the outbound serial worker.
	h.l.setModified(DirectionInbound, []byte{9, 8, 7})
	unblock()
	rxWait(t, "three completed cycles not delivered", func() bool { return h.count() == 36 })
	if !bytes.Equal(h.l.TakeModified(DirectionInbound), []byte{9, 8, 7}) {
		t.Fatal("outbound stole inbound modified slot")
	}
	h.close(t)
	h.sendMu.Lock()
	defer h.sendMu.Unlock()
	for cycle, pair := range [][2][]byte{{a, b}, {a, b}, {otherA, otherB}} {
		start := cycle * 12
		for j := 0; j < 10; j++ {
			p, err := ParsePacket(h.sent[start+j].raw)
			if err != nil || len(p.Payload) != 620 {
				t.Fatalf("fake count/default620 altered: %v", err)
			}
		}
		for j, p := range pair {
			if !bytes.Equal(h.sent[start+10+j].raw, p) {
				t.Fatalf("cycle/peer ordering %d/%d", cycle, j)
			}
		}
	}
}

func TestWindowsReceiveGeneratedFailureIsTerminalOrRetained(t *testing.T) {
	for _, at := range []int{1, 5} {
		for _, unknown := range []bool{false, true} {
			t.Run(fmt.Sprintf("fake%d/unknown%v", at, unknown), func(t *testing.T) {
				h := newRXModel(t, rxQUICConfig(t, 1))
				head, tail := qa519SplitInitials(t, "send.example", 40, qa519DCID(0x79), 1, 1)
				a, b := buildIPv4UDP(t, head, 443).Raw, buildIPv4UDP(t, tail, 443).Raw
				failure := errors.New("generated Send failure")
				calls := 0
				h.onSend = func(p []byte, _ *windivert.Address) (int, error) {
					calls++
					if calls == at {
						if unknown {
							return -1, failure
						}
						return 0, failure
					}
					return len(p), nil
				}
				h.start()
				h.send(a, 1)
				h.send(b, 2)
				rxWait(t, "fake failure missing", func() bool { return errors.Is(h.l.Err(), failure) })
				if err := h.l.Close(nil); !errors.Is(err, failure) {
					t.Fatalf("Close=%v", err)
				}
				if unknown {
					if h.l.WaitCaptureRetired() == nil || h.e.ActiveLeases() != 1 {
						t.Fatal("generated unknown released native charge")
					}
					r, _, _, _ := h.stats()
					if r != 2 {
						t.Fatalf("unknown didn't pin both originals: %d", r)
					}
					if h.count() != at {
						t.Fatal("submission continued after quarantined lane")
					}
				} else {
					if err := h.l.WaitCaptureRetired(); err != nil {
						t.Fatal(err)
					}
					if h.count() != at+2 {
						t.Fatalf("fake retry or original lost: %d", h.count())
					}
					h.sendMu.Lock()
					defer h.sendMu.Unlock()
					if !bytes.Equal(h.sent[at].raw, a) || !bytes.Equal(h.sent[at+1].raw, b) {
						t.Fatal("terminal fake failure didn't pass originals FIFO")
					}
				}
			})
		}
	}
}

func TestWindowsReceiveHeldAndInServiceCountTowardActualLimit(t *testing.T) {
	h := newRXModel(t, rxQUICConfig(t, 1))
	head, _ := qa519SplitInitials(t, "pins.example", 40, qa519DCID(0x79), 1, 1)
	a := buildIPv4UDP(t, head, 443).Raw
	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	defer unblock()
	h.onSend = func(p []byte, _ *windivert.Address) (int, error) {
		once.Do(func() { close(entered); <-release })
		return len(p), nil
	}
	h.start()
	h.send(a, 1)
	rxWait(t, "semantic transfer missing", func() bool {
		h.c.rxMu.Lock()
		defer h.c.rxMu.Unlock()
		return h.c.usedRecords == 1 && !h.c.records[0].worker
	})
	h.send([]byte{0xf3}, 2)
	rxChannel(t, entered, "in-service record missing")
	for i := 2; i < windowsReceiveRecords; i++ {
		h.send([]byte{0xf3}, i+1)
	}
	rxWait(t, "full reservation missing", func() bool { r, _, _, _ := h.stats(); return r == windowsReceiveRecords })
	h.send([]byte{0xf3}, 257)
	rxWait(t, "held transfer freed a credit", func() bool { return errors.Is(h.l.Err(), errWindowsReceiveCapacity) })
	h.c.rxMu.Lock()
	if h.c.records[0].worker || h.c.records[0].terminal || !h.c.records[0].occupied || h.c.usedRecords != 256 {
		t.Error("semantic raw pin lost")
	}
	h.c.rxMu.Unlock()
	unblock()
	if err := h.l.Close(nil); !errors.Is(err, errWindowsReceiveCapacity) {
		t.Fatal(err)
	}
	if h.l.WaitCaptureRetired() != nil || h.count() != 257 || h.e.heldBytes.Load() != 0 {
		t.Fatal("failed drain didn't join semantic owner")
	}
}

func TestWindowsReceiveCapacityBoundedCloseStickyAndEndpoint(t *testing.T) {
	h := newRXModel(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var once, unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(release) }) }
	defer unblock()
	h.onSend = func(p []byte, _ *windivert.Address) (int, error) {
		once.Do(func() { close(entered); <-release })
		return len(p), nil
	}
	h.start()
	h.send([]byte{0xf3}, 1)
	rxChannel(t, entered, "Send absent")
	for i := 1; i <= windowsReceiveRecords; i++ {
		h.send([]byte{0xf3}, i+1)
	}
	rxWait(t, "capacity latch absent", func() bool { return errors.Is(h.l.Err(), errWindowsReceiveCapacity) })
	// failFlow is allowed to replace its own diagnostic, not the sticky cause.
	h.l.failFlow(&Packet{Transport: TransportUDP, Dst: netip.MustParseAddr("198.51.100.7"), DstPort: 443}, errors.New("later flow failure"))
	start := time.Now()
	err := h.l.Close(nil)
	if !errors.Is(err, ErrLeaseCloseIncomplete) || !errors.Is(err, errWindowsReceiveCapacity) {
		t.Fatalf("bounded Close lost diagnostic/sentinel %v", err)
	}
	if time.Since(start) > leaseCloseGrace+time.Second {
		t.Fatal("Close exceeded caller bound")
	}
	if h.e.ActiveLeases() != 1 || h.shutdowns.Load() != 0 {
		t.Fatal("bounded Close unrooted active owner")
	}
	unblock()
	if !errors.Is(h.l.WaitClosed(), errWindowsReceiveCapacity) || h.l.WaitCaptureRetired() != nil {
		t.Fatal("late safety erased failure or didn't join")
	}
	var endpoint atomic.Int32
	if err = h.l.ReleaseEndpoint(func() error { endpoint.Add(1); return nil }); err != nil || endpoint.Load() != 1 {
		t.Fatalf("safe failed endpoint not released: %v", err)
	}
	next, err := h.e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP})
	if err != nil {
		t.Fatal(err)
	}
	end, err := next.BeginEndpointWrite()
	if err != nil {
		t.Fatal("new Lease inherited failure")
	}
	end()
	if err = next.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsReceiveUnsafeEndpointRootAndActiveBypass(t *testing.T) {
	t.Run("unsafe-root", func(t *testing.T) {
		h := newRXModel(t, nil)
		h.onSend = func([]byte, *windivert.Address) (int, error) { return -1, errors.New("unknown") }
		h.start()
		h.send([]byte{0xf3}, 1)
		rxWait(t, "unknown missing", func() bool { return h.count() == 1 })
		if h.l.Close(nil) == nil {
			t.Fatal("unknown accepted")
		}
		var called atomic.Int32
		endpoint := func() error { called.Add(1); return nil }
		if h.l.ReleaseEndpoint(endpoint) == nil {
			t.Fatal("unsafe endpoint released")
		}
		h.l.mu.Lock()
		retained := h.l.retainedEndpoint
		h.l.mu.Unlock()
		if retained == nil || called.Load() != 0 || h.e.ActiveLeases() != 1 {
			t.Fatal("retained charge didn't root endpoint closure")
		}
	})
	t.Run("bypass-active", func(t *testing.T) {
		h := newRXModel(t, nil)
		h.start()
		h.close(t)
		end, err := h.l.BeginEndpointWrite()
		if err != nil {
			t.Fatal("ordinary Lease.Close didn't resume")
		}
		var closed atomic.Int32
		done := make(chan error, 1)
		go func() { done <- h.l.ReleaseEndpoint(func() error { closed.Add(1); return nil }) }()
		rxWait(t, "endpoint admission not closed", func() bool { p, _ := h.l.producers.state(); return p == producerClosed })
		if closed.Load() != 0 {
			t.Fatal("endpoint closed before active bypass returned")
		}
		end()
		end()
		if err = <-done; err != nil || closed.Load() != 1 {
			t.Fatal("endpoint close did not join exactly once")
		}
	})
}

func TestWindowsReceiveOpenRaceAttachesSameOwner(t *testing.T) {
	cfg := rxQUICConfig(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var users atomic.Int32
	windivert.ReplayOpen = func(*windivert.Filter, windivert.Layer, int16, windivert.Flag) (*windivert.Handle, error) {
		once.Do(func() { close(entered); <-release })
		s, d := make(chan struct{}), make(chan struct{})
		var so sync.Once
		return &windivert.Handle{RecvFunc: func([]byte) (int, windivert.Address, error) {
			users.Add(1)
			<-s
			return 0, windivert.Address{}, windivert.ReplayDrained
		}, SendFunc: func([]byte, *windivert.Address) (int, error) { panic("no record") }, ShutdownFunc: func() error { so.Do(func() { close(s) }); return nil }, CloseFunc: func() error { close(d); return nil }, DoneChan: d}, nil
	}
	defer func() { windivert.ReplayOpen = nil }()
	e, err := NewEngine(cfg, NewWindowsReplayBackend())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	l, err := e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP, Source: netip.MustParseAddrPort("192.0.2.10:40000")})
	if err != nil {
		t.Fatal(err)
	}
	l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	opened := make(chan error, 1)
	go func() { opened <- l.StartCapture() }()
	rxChannel(t, entered, "Open absent")
	done := l.startClose(nil)
	select {
	case <-done:
		t.Fatal("no-capture safety published before opening join")
	default:
	}
	close(release)
	if !errors.Is(<-opened, errLeaseClosed) {
		t.Fatal("attachment lost Close race")
	}
	rxChannel(t, done, "opening/reader/worker join stalled")
	if l.WaitCaptureRetired() != nil || users.Load() != 1 || e.ActiveLeases() != 0 {
		t.Fatal("wrong opened-owner retirement")
	}
}

var rxAllocationSink *windowsCapture

func TestWindowsReceiveLazyAllocationBound(t *testing.T) {
	allocations := testing.AllocsPerRun(100, func() { c := &windowsCapture{}; c.initReceive(); rxAllocationSink = c })
	if allocations > 4 {
		t.Fatalf("unexpected idle allocation count %g", allocations)
	}
	if len(rxAllocationSink.receiveBuffer) != windivert.MTUMax || rxAllocationSink.usedRawBytes != 0 {
		t.Fatal("idle capture preallocated raw budget")
	}
	for _, r := range rxAllocationSink.records {
		if r.raw != nil {
			t.Fatal("idle record allocated packet bytes")
		}
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < 100; i++ {
		c := &windowsCapture{}
		c.initReceive()
		rxAllocationSink = c
	}
	runtime.ReadMemStats(&after)
	per := float64(after.TotalAlloc-before.TotalAlloc) / 100
	if per > 200000 {
		t.Fatalf("idle allocated too much: %g bytes/capture", per)
	}
	t.Logf("measured idle allocations=%g, amortized TotalAlloc=%g B/capture (allocator-rounded, not RSS); 8MiB records are lazy", allocations, per)
	rxAllocationSink = nil
}

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
	"unsafe"

	"github.com/sagernet/sing-box/common/windivert"
)

type rxModelPacket struct {
	raw     []byte
	address [80]byte
	n       int
	err     error
}
type rxModelHarness struct {
	e                     *Engine
	l                     *Lease
	c                     *windowsCapture
	input                 chan rxModelPacket
	stop                  chan struct{}
	nativeDone            chan struct{}
	stopOnce, doneOnce    sync.Once
	recvCount             atomic.Int32
	sendMu                sync.Mutex
	sent                  []rxModelPacket
	onSend                func([]byte, *windivert.Address) (int, error)
	onRecv                func()
	shutdownErr, closeErr error
	delayDone             bool
	shutdowns, closes     atomic.Int32
}

func rxAddress(id int) [80]byte {
	var a [80]byte
	for i := range a {
		a[i] = byte(i + id)
	}
	return a
}
func rxWait(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		runtime.Gosched()
	}
}
func rxChannel(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal(what)
	}
}
func newRXModel(t *testing.T, cfg *Config) *rxModelHarness {
	t.Helper()
	if cfg == nil {
		cfg = maxOneConfig(t)
	}
	h := &rxModelHarness{input: make(chan rxModelPacket, 300), stop: make(chan struct{}), nativeDone: make(chan struct{})}
	var err error
	h.e, err = NewEngine(cfg, &producerOrderBackend{})
	if err != nil {
		t.Fatal(err)
	}
	h.l, err = h.e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	h.l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	h.c = &windowsCapture{lease: h.l, dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	h.c.releaseHold, err = h.l.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	h.c.outbound = h.handle()
	h.l.capture = h.c
	t.Cleanup(func() { _ = h.e.Close() })
	return h
}
func (h *rxModelHarness) handle() *windivert.Handle {
	var previous []byte
	return &windivert.Handle{
		RecvFunc: func(p []byte) (int, windivert.Address, error) {
			for i := range previous {
				previous[i] = 0xd3
			}
			previous = nil
			if h.onRecv != nil {
				h.onRecv()
			}
			var r rxModelPacket
			select {
			case r = <-h.input:
			default:
				select {
				case r = <-h.input:
				case <-h.stop:
					return 0, windivert.Address{}, windivert.ReplayDrained
				}
			}
			copy(p, r.raw)
			previous = p
			h.recvCount.Add(1)
			var a windivert.Address
			*(*[80]byte)(unsafe.Pointer(&a)) = r.address
			n := r.n
			if n == 0 && r.err == nil {
				n = len(r.raw)
			}
			return n, a, r.err
		},
		SendFunc: func(p []byte, a *windivert.Address) (int, error) {
			n, err := len(p), error(nil)
			if h.onSend != nil {
				n, err = h.onSend(p, a)
			}
			h.sendMu.Lock()
			h.sent = append(h.sent, rxModelPacket{raw: bytes.Clone(p), address: *(*[80]byte)(unsafe.Pointer(a)), n: n, err: err})
			h.sendMu.Unlock()
			return n, err
		},
		ShutdownFunc: func() error { h.shutdowns.Add(1); h.stopOnce.Do(func() { close(h.stop) }); return h.shutdownErr },
		CloseFunc: func() error {
			h.closes.Add(1)
			if !h.delayDone {
				h.doneOnce.Do(func() { close(h.nativeDone) })
			}
			return h.closeErr
		},
		DoneChan: h.nativeDone,
	}
}
func (h *rxModelHarness) send(raw []byte, id int) {
	h.input <- rxModelPacket{raw: bytes.Clone(raw), address: rxAddress(id)}
}
func (h *rxModelHarness) count() int { h.sendMu.Lock(); defer h.sendMu.Unlock(); return len(h.sent) }
func (h *rxModelHarness) stats() (records, raw, queued int, scratch bool) {
	h.c.rxMu.Lock()
	defer h.c.rxMu.Unlock()
	return h.c.usedRecords, h.c.usedRawBytes, h.c.queueCount, h.c.scratch.occupied
}
func (h *rxModelHarness) start() { h.c.startUsers() }
func (h *rxModelHarness) close(t *testing.T) {
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

func TestWindowsReceiveActualCapacityAndFailedDrain(t *testing.T) {
	for _, kind := range []string{"records", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			h := newRXModel(t, nil)
			entered, release := make(chan struct{}), make(chan struct{})
			var once, unblockOnce sync.Once
			unblock := func() { unblockOnce.Do(func() { close(release) }) }
			defer unblock()
			h.onSend = func(p []byte, _ *windivert.Address) (int, error) {
				once.Do(func() { close(entered); <-release })
				return len(p), nil
			}
			end, err := h.l.BeginEndpointWrite()
			if err != nil {
				t.Fatal(err)
			}
			defer end()
			h.start()
			lengths := make([]int, windowsReceiveRecords)
			for i := range lengths {
				lengths[i] = 1
			}
			if kind == "bytes" {
				lengths = make([]int, 128)
				for i := 0; i < 127; i++ {
					lengths[i] = windivert.MTUMax
				}
				lengths[127] = 60583
			}
			raw := func(n int) []byte { p := bytes.Repeat([]byte{0xf3}, n); return p }
			h.send(raw(lengths[0]), 1)
			rxChannel(t, entered, "first in-service Send absent")
			for i, n := range lengths[1:] {
				h.send(raw(n), i+2)
			}
			total := 0
			for _, n := range lengths {
				total += n
			}
			rxWait(t, "did not reserve exact limit incl in-service", func() bool { r, b, _, _ := h.stats(); return r == len(lengths) && b == total })
			h.c.rxMu.Lock()
			if h.c.capacityErr != nil {
				t.Error("equality rejected")
			}
			h.c.rxMu.Unlock()
			h.send([]byte{0xf3}, len(lengths)+1)
			rxWait(t, "capacity failure absent", func() bool { return errors.Is(h.l.endpointFailure(), errWindowsReceiveCapacity) })
			r, b, q, s := h.stats()
			if r != len(lengths) || b != total || q != len(lengths)-1 || !s {
				t.Fatalf("lost in-service/scratch: %d %d %d %v", r, b, q, s)
			}
			h.c.rxMu.Lock()
			if &h.c.scratch.raw[0] != &h.c.receiveBuffer[0] {
				t.Error("overflow allocated second scratch")
			}
			h.c.rxMu.Unlock()
			if _, err = h.l.BeginEndpointWrite(); !errors.Is(err, errWindowsReceiveCapacity) {
				t.Fatalf("later admission=%v", err)
			}
			if h.shutdowns.Load() != 0 {
				t.Fatal("reader joined/ended active producer or shut receive early")
			}
			if _, err = h.e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP}); !errors.Is(err, ErrAdmissionRefused) {
				t.Fatal("MaxLeases1 lost retained capture")
			}
			// These are already-submitted native records, not new gate admissions. The
			// failed drain must use the same scratch without allocating staging slots.
			for i := 0; i < 3; i++ {
				h.send([]byte{0xf3}, len(lengths)+2+i)
			}
			unblock()
			end()
			if err = h.l.Close(nil); !errors.Is(err, errWindowsReceiveCapacity) {
				t.Fatalf("Close erased capacity=%v", err)
			}
			if err = h.l.WaitClosed(); !errors.Is(err, errWindowsReceiveCapacity) {
				t.Fatal(err)
			}
			if err = h.l.WaitCaptureRetired(); err != nil {
				t.Fatalf("actual drained failure should retire safely: %v", err)
			}
			if _, err = h.l.BeginEndpointWrite(); !errors.Is(err, errWindowsReceiveCapacity) {
				t.Fatal("normal resume cleared sticky failure")
			}
			if r, b, _, s = h.stats(); r != 0 || b != 0 || s {
				t.Fatal("terminal failed drain did not release ledger")
			}
			if h.shutdowns.Load() != 1 || h.closes.Load() != 1 || h.e.ActiveLeases() != 0 {
				t.Fatal("native owners not exactly once")
			}
			h.sendMu.Lock()
			defer h.sendMu.Unlock()
			if len(h.sent) != len(lengths)+4 {
				t.Fatalf("received originals lost: %d", len(h.sent))
			}
			for i, p := range h.sent {
				n := 1
				if i < len(lengths) {
					n = lengths[i]
				}
				if !bytes.Equal(p.raw, raw(n)) || p.address != rxAddress(i+1) {
					t.Fatalf("record %d not immutable/once/FIFO", i)
				}
			}
		})
	}
}

func TestWindowsReceiveSemanticTransferKeepsRecord(t *testing.T) {
	cfg := qa519CompileRule(t, `{"network":["udp"],"protocol":["quic"],"methods":["fake"],"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"ab"}]}}`, `{"hold_timeout":"10s","max_leases":1}`)
	h := newRXModel(t, cfg)
	head, _ := qa519SplitInitials(t, "held.example", 40, qa519DCID(0x79), 1, 1)
	packet := buildIPv4UDP(t, head, 443)
	h.start()
	h.send(packet.Raw, 1)
	rxWait(t, "semantic Hold not installed", func() bool {
		h.c.rxMu.Lock()
		defer h.c.rxMu.Unlock()
		return h.c.usedRecords == 1 && !h.c.records[0].worker
	})
	if h.e.heldBytes.Load() <= 0 || h.count() != 0 {
		t.Fatal("not a genuine semantic transfer")
	}
	h.c.rxMu.Lock()
	if h.c.usedRawBytes != len(packet.Raw) || h.c.records[0].terminal {
		t.Error("Hold returned a raw credit")
	}
	h.c.rxMu.Unlock()
	h.close(t)
	if h.count() != 1 {
		t.Fatal("held original not completed exactly once")
	}
}

func TestWindowsReceiveTokenAndCheckedReservation(t *testing.T) {
	c := &windowsCapture{}
	c.initReceive()
	for _, workerFirst := range []bool{false, true} {
		c.sequence++
		r := c.reserveRecordLocked(17)
		if r == nil {
			t.Fatal("reserve")
		}
		r.raw = make([]byte, 17)
		seq := r.sequence
		if workerFirst {
			c.finishRecord(r, seq, false, true)
		} else {
			c.finishRecord(r, seq, true, false)
		}
		if c.usedRecords != 1 || c.usedRawBytes != 17 {
			t.Fatal("single receipt freed borrowed storage")
		}
		c.finishRecord(r, seq, true, true)
		c.finishRecord(r, seq, true, true)
		if c.usedRecords != 0 || c.usedRawBytes != 0 {
			t.Fatal("not exactly once")
		}
		c.sequence++
		fresh := c.reserveRecordLocked(18)
		fresh.raw = make([]byte, 18)
		c.finishRecord(r, seq, true, true)
		if c.usedRecords != 1 || c.usedRawBytes != 18 {
			t.Fatal("stale sequence recycled new owner")
		}
		c.finishRecord(fresh, fresh.sequence, true, true)
	}
	for _, used := range []int{-1, windowsReceiveRawBytes - 1, windowsReceiveRawBytes, windowsReceiveRawBytes + 1, int(^uint(0) >> 1)} {
		for _, n := range []int{1, 2, windivert.MTUMax + 1} {
			c := &windowsCapture{usedRawBytes: used}
			r := c.reserveRecordLocked(n)
			want := used == windowsReceiveRawBytes-1 && n == 1
			if (r != nil) != want {
				t.Errorf("subtraction boundary used=%d n=%d admitted=%v", used, n, r != nil)
			}
		}
	}
	// Fixed metadata + bounded two callback environments comfortably fit the
	// 512B/record and 16KiB fixed allowances; runtime allocator rounding/RSS is
	// not represented as charged logical raw slice capacity.
	per := unsafe.Sizeof(windowsReceiveRecord{}) + 2*unsafe.Sizeof(uintptr(0)) + 2*(4*unsafe.Sizeof(uintptr(0)))
	fixed := unsafe.Sizeof(windowsCapture{}) - unsafe.Sizeof(c.records) - unsafe.Sizeof(c.scratch) - unsafe.Sizeof(c.queue)
	if per > 512 || fixed > 16<<10 {
		t.Fatalf("metadata exceeds contract %d %d", per, fixed)
	}
	t.Logf("record=%d ring=%d callbacks<=%d per_record_bound=%d fixed_capture=%d raw=%d scratch=%d", unsafe.Sizeof(windowsReceiveRecord{}), unsafe.Sizeof(c.queue), 2*(4*unsafe.Sizeof(uintptr(0))), per, fixed, windowsReceiveRawBytes, windivert.MTUMax)
	summary := windowsErrorSummary{}
	cause := errors.New("first")
	for i := 0; i < 10000; i++ {
		summary.add(cause)
	}
	summary.count = ^uint64(0)
	summary.add(errors.New("later"))
	if summary.count != ^uint64(0) || summary.first != cause {
		t.Fatal("unbounded/wrapped diagnostic summary")
	}
}

func TestWindowsReceiveFrameAndSequence(t *testing.T) {
	for _, n := range []int{1, windivert.MTUMax, 0, -1, windivert.MTUMax + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			h := newRXModel(t, nil)
			raw := bytes.Repeat([]byte{0xf3}, max(0, min(n, windivert.MTUMax)))
			h.input <- rxModelPacket{raw: raw, n: n, address: rxAddress(1)}
			h.start()
			if n > 0 && n <= windivert.MTUMax {
				rxWait(t, "valid frame missing", func() bool { return h.count() == 1 })
				h.close(t)
				return
			}
			rxChannel(t, h.c.done, "invalid receive did not stop reader")
			if err := h.l.Close(nil); err == nil {
				t.Fatal("invalid length accepted")
			}
			if h.l.WaitCaptureRetired() == nil || h.e.ActiveLeases() != 1 || h.closes.Load() != 0 {
				t.Fatal("invalid length manufactured retirement")
			}
			h.c.rxMu.Lock()
			defer h.c.rxMu.Unlock()
			if !h.c.scratch.occupied || cap(h.c.scratch.raw) != windivert.MTUMax {
				t.Fatal("invalid scratch not rooted")
			}
		})
	}
	t.Run("sequence", func(t *testing.T) {
		h := newRXModel(t, nil)
		h.c.sequence = ^uint64(0)
		h.start()
		rxChannel(t, h.c.done, "wrap did not stop")
		if h.recvCount.Load() != 0 || h.l.Close(nil) == nil || h.l.WaitCaptureRetired() == nil {
			t.Fatal("sequence wrapped/retired")
		}
	})
}

func TestWindowsReceiveSendErrorsAndLateDone(t *testing.T) {
	for _, kind := range []string{"known", "short", "unknown", "late-done"} {
		t.Run(kind, func(t *testing.T) {
			h := newRXModel(t, nil)
			failure := errors.New("modeled native failure")
			h.onSend = func(p []byte, _ *windivert.Address) (int, error) {
				switch kind {
				case "known":
					return 0, failure
				case "short":
					return len(p) - 1, nil
				case "unknown":
					return -1, failure
				}
				return len(p), nil
			}
			if kind == "late-done" {
				h.delayDone = true
				h.closeErr = failure
			}
			h.start()
			h.send([]byte{0xf3, 4}, 1)
			rxWait(t, "Send missing", func() bool { return h.count() == 1 })
			if kind == "late-done" {
				done := make(chan error, 1)
				go func() { done <- h.l.Close(nil) }()
				rxWait(t, "Close not attempted", func() bool { return h.closes.Load() == 1 })
				select {
				case <-h.l.captureRetired:
					t.Fatal("Close return substituted for Done")
				default:
				}
				h.doneOnce.Do(func() { close(h.nativeDone) })
				if !errors.Is(<-done, failure) {
					t.Fatal("lost close error")
				}
			} else if h.l.Close(nil) == nil {
				t.Fatal("lost send failure")
			}
			err := h.l.WaitCaptureRetired()
			if kind == "unknown" {
				if err == nil || h.e.ActiveLeases() != 1 || h.closes.Load() != 0 {
					t.Fatal("unknown progress was freed")
				}
				r, _, _, _ := h.stats()
				if r != 1 {
					t.Fatal("unknown original lost raw pin")
				}
				if _, e := h.l.BeginEndpointWrite(); e == nil {
					t.Fatal("unknown allowed new production")
				}
			} else if err != nil || h.e.ActiveLeases() != 0 {
				t.Fatalf("terminal failure cannot retire: %v", err)
			}
		})
	}
}

func TestWindowsReceiveFenceQueuedPublication(t *testing.T) {
	h := newRXModel(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.onRecv = func() { once.Do(func() { close(entered); <-release }) }
	h.start()
	rxChannel(t, entered, "Recv not entered")
	h.c.FenceDispatch()
	quiesced := make(chan struct{})
	go func() { _ = h.c.Quiesce(); close(quiesced) }()
	rxChannel(t, quiesced, "Quiesce counted future queued publication")
	h.send([]byte{0xf3}, 1)
	close(release)
	rxWait(t, "record not copied after fence", func() bool { r, _, _, _ := h.stats(); return r == 1 })
	if h.count() != 0 || h.e.heldBytes.Load() != 0 {
		t.Fatal("post-fence semantic dispatch/send")
	}
	h.close(t)
	if h.count() != 1 {
		t.Fatal("tail not delivered after pass gate")
	}
}

func TestWindowsReceiveOptionalStopAndReceiveFailures(t *testing.T) {
	for _, lane := range []int{0, 1, 2} {
		for _, kind := range []string{"receive", "stop"} {
			t.Run(fmt.Sprintf("lane%d/%s", lane, kind), func(t *testing.T) {
				h := newRXModel(t, nil)
				failure := errors.New("lane failure")
				handles := []*windivert.Handle{h.c.outbound, nil, nil}
				var closes, stops [3]atomic.Int32
				for i := range handles {
					i := i
					s := make(chan struct{})
					d := make(chan struct{})
					var once sync.Once
					handles[i] = &windivert.Handle{RecvFunc: func([]byte) (int, windivert.Address, error) {
						if kind == "receive" && i == lane {
							return -1, windivert.Address{}, failure
						}
						<-s
						return 0, windivert.Address{}, windivert.ReplayDrained
					}, SendFunc: func([]byte, *windivert.Address) (int, error) { panic("unexpected send") }, ShutdownFunc: func() error {
						stops[i].Add(1)
						once.Do(func() { close(s) })
						if kind == "stop" && i == lane {
							return failure
						}
						return nil
					}, CloseFunc: func() error { closes[i].Add(1); close(d); return nil }, DoneChan: d}
				}
				h.c.outbound, h.c.inbound, h.c.icmp = handles[0], handles[1], handles[2]
				h.start()
				if kind == "receive" {
					rxWait(t, "receive failure not diagnosed", func() bool { return errors.Is(h.l.Err(), failure) })
				}
				if err := h.l.Close(nil); !errors.Is(err, failure) {
					t.Fatalf("lost lane error %v", err)
				}
				if h.l.WaitCaptureRetired() == nil || h.e.ActiveLeases() != 1 {
					t.Fatal("bad lane retired")
				}
				for i := range handles {
					if stops[i].Load() != 1 || closes[i].Load() != 0 {
						t.Fatalf("lane%d stop=%d close=%d", i, stops[i].Load(), closes[i].Load())
					}
				}
			})
		}
	}
}

func TestWindowsReceivePartialOpenDrainsOpenedHandles(t *testing.T) {
	for failAt := 1; failAt <= 3; failAt++ {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			cfg, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},"capture":{"filter_ttl_expired_icmp":true},"rules":[{"network":["udp"],"methods":["fake"],"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"ab"}]}}]}`), "")
			if err != nil {
				t.Fatal(err)
			}
			var opened, received, sent, stopped, closed atomic.Int32
			failure := errors.New("partial open")
			windivert.ReplayOpen = func(*windivert.Filter, windivert.Layer, int16, windivert.Flag) (*windivert.Handle, error) {
				if int(opened.Add(1)) == failAt {
					return nil, failure
				}
				stop, done := make(chan struct{}), make(chan struct{})
				var once sync.Once
				first := true
				return &windivert.Handle{RecvFunc: func(p []byte) (int, windivert.Address, error) {
					if first {
						first = false
						received.Add(1)
						p[0] = 0xf3
						return 1, windivert.Address{}, nil
					}
					<-stop
					return 0, windivert.Address{}, windivert.ReplayDrained
				}, SendFunc: func(p []byte, _ *windivert.Address) (int, error) { sent.Add(1); return len(p), nil }, ShutdownFunc: func() error { stopped.Add(1); once.Do(func() { close(stop) }); return nil }, CloseFunc: func() error { closed.Add(1); close(done); return nil }, DoneChan: done}, nil
			}
			defer func() { windivert.ReplayOpen = nil }()
			e, err := NewEngine(cfg, NewWindowsReplayBackend())
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			l, err := e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.7:443")})
			if err != nil {
				t.Fatal(err)
			}
			l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
			if err = l.StartCapture(); !errors.Is(err, failure) {
				t.Fatalf("wrong open error %v", err)
			}
			if err = l.Close(nil); err != nil {
				t.Fatal(err)
			}
			if err = l.WaitCaptureRetired(); err != nil {
				t.Fatal(err)
			}
			want := int32(failAt - 1)
			if received.Load() != want || sent.Load() != want || stopped.Load() != want || closed.Load() != want {
				t.Fatalf("wg0 rollback didn't actually drain: recv%d send%d stop%d close%d want%d", received.Load(), sent.Load(), stopped.Load(), closed.Load(), want)
			}
		})
	}
}

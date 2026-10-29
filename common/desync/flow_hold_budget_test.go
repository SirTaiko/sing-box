package desync

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The release receipt joins detached I/O with Close/timer callbacks, but the
// engine-wide atomic budget must also remain charged until each actual return.
func TestTCPHeldBudgetReleasePaths(t *testing.T) {
	for _, name := range []string{"flush", "complete", "replacement-error", "duplicate", "covered-fin", "modify", "close"} {
		t.Run(name, func(t *testing.T) {
			rules := `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`
			if name == "modify" {
				rules = `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["host+3"]},"orig":{"ttl":7}}]`
			}
			h := newHeldHarness(t, rules, `{"hold_timeout":"10s"}`)
			f := h.lease.tcpFlow
			hello := buildClientHello("budget.example")
			packets := []*Packet{
				buildIPv4TCP(t, hello[:12], 1000, tcpFlagACK|tcpFlagPSH),
				buildIPv4TCP(t, hello[12:24], 1012, tcpFlagACK|tcpFlagPSH),
			}
			tail := buildIPv4TCP(t, hello[24:], 1024, tcpFlagACK|tcpFlagPSH)
			if name == "duplicate" || name == "covered-fin" {
				flags := uint8(tcpFlagACK | tcpFlagPSH)
				if name == "covered-fin" {
					flags |= tcpFlagFIN
				}
				packets[1] = buildIPv4TCP(t, hello[:12], 1000, flags)
				tail = buildIPv4TCP(t, hello[12:], 1012, tcpFlagACK|tcpFlagPSH)
			}
			total := len(packets[0].Raw) + len(packets[1].Raw)
			// Exercise the existing limits with measured frame lengths, not a
			// fixture-specific native/UDP accounting constant.
			f.limits.MaxHeldBytes = total
			f.limits.MaxHeldBytesTotal = total * 4
			type observation struct {
				local, queued int
				global        int64
				verdict       Verdict
				modified      bool
				refused       bool
			}
			entered := make(chan observation, len(packets))
			returning := make(chan int64, len(packets))
			releases := []chan struct{}{make(chan struct{}), make(chan struct{})}
			var once [2]sync.Once
			unblock := func(i int) { once[i].Do(func() { close(releases[i]) }) }
			t.Cleanup(func() { unblock(0); unblock(1) })
			var calls, sends atomic.Int32
			injectErr := errors.New("held replacement failed")
			inject := func([]byte) error {
				sends.Add(1)
				if name == "replacement-error" {
					return injectErr
				}
				return nil
			}
			remaining := total
			for i, packet := range packets {
				want := remaining
				complete := func(v Verdict, _ string, modified []byte) {
					calls.Add(1)
					f.mu.Lock()
					obs := observation{local: f.heldBytes, queued: len(f.holds), global: h.engine.heldBytes.Load(), verdict: v, modified: len(modified) != 0}
					// The callback takes f.mu itself. A same-flow admission probe
					// must see the active reservation even though holds is empty.
					size := total - want + 1
					obs.refused = !f.canHold(size)
					if !obs.refused { // Undo only this unexpected probe reservation.
						h.engine.heldBytes.Add(-int64(size))
					}
					f.mu.Unlock()
					entered <- obs
					<-releases[i]
					returning <- h.engine.heldBytes.Load()
				}
				if v := h.lease.HandlePacket(packet.Raw, DirectionOutbound, inject, complete); v != VerdictHold {
					t.Fatalf("record %d admission = %v, want Hold", i, v)
				}
				remaining -= len(packet.Raw)
			}
			if got := h.engine.heldBytes.Load(); got != int64(total) {
				t.Fatalf("admitted bytes = %d, measured frames = %d", got, total)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				switch name {
				case "flush":
					f.flushHeld("incomplete")
				case "close":
					if err := h.lease.Close(nil); err != nil {
						t.Error(err)
					}
				default:
					if v := h.lease.HandlePacket(tail.Raw, DirectionOutbound, inject, nil); v == VerdictHold {
						t.Error("complete message still held")
					}
				}
			}()
			remaining = total
			for i, packet := range packets {
				var obs observation
				select {
				case obs = <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("held completer did not enter")
				}
				if obs.local != remaining || obs.global != int64(remaining) || obs.queued != 0 || !obs.refused {
					t.Errorf("callback %d: local=%d global=%d queued=%d per-flow-refused=%v; want bytes=%d queued=0 refused=true", i, obs.local, obs.global, obs.queued, obs.refused, remaining)
				}
				wantVerdict := VerdictPass
				if name == "modify" {
					wantVerdict = VerdictModify
				} else if name == "duplicate" || (i == 0 && (name == "complete" || name == "covered-fin")) {
					wantVerdict = VerdictDrop
				}
				if obs.verdict != wantVerdict || obs.modified != (wantVerdict == VerdictModify) {
					t.Errorf("callback %d disposition=%v modified=%v, want %v", i, obs.verdict, obs.modified, wantVerdict)
				}
				// Another flow can acquire its own mutex while this callback is
				// blocked. Its global-budget admission must still refuse excess.
				limits := f.limits
				limits.MaxHeldBytesTotal = total
				other := newFlowState(limits, &h.engine.heldBytes, nil)
				size := total - remaining + 1
				if other.canHold(size) {
					t.Errorf("callback %d allowed cross-flow global budget overcommit", i)
					h.engine.heldBytes.Add(-int64(size))
				}
				select {
				case <-done:
					t.Error("release finished before callback return")
				default:
				}
				unblock(i)
				if got := <-returning; got != int64(remaining) {
					t.Errorf("callback %d returning with charge %d, want %d", i, got, remaining)
				}
				remaining -= len(packet.Raw)
			}
			waitTCPBudgetSignal(t, done)
			if name == "replacement-error" && (sends.Load() == 0 || !f.failed) {
				t.Error("fixture did not exercise replacement error")
			}
			for range 2 {
				if err := h.lease.Close(nil); err != nil {
					t.Fatal(err)
				}
			}
			f.expire() // A stopped/late timer cannot release these bytes again.
			if got := h.engine.heldBytes.Load(); got != 0 || f.heldBytes != 0 || calls.Load() != int32(len(packets)) {
				t.Fatalf("after terminal returns/repeated close: global=%d local=%d calls=%d", got, f.heldBytes, calls.Load())
			}
			other := newFlowState(f.limits, &h.engine.heldBytes, nil)
			if !other.canHold(total) {
				t.Fatal("completed callbacks hoarded global capacity")
			}
			h.engine.heldBytes.Add(-int64(total)) // Paired reservation-only probe.
		})
	}
}

func TestTCPHeldBudgetCancellationJoinsActiveCallback(t *testing.T) {
	for _, trigger := range []string{"flush", "timer"} {
		t.Run(trigger, func(t *testing.T) {
			timeout := "10s"
			if trigger == "timer" {
				timeout = "20ms"
			}
			h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["host+0"]}}]`, `{"hold_timeout":"`+timeout+`"}`)
			packet := buildIPv4TCP(t, buildClientHello("budget.example")[:12], 1000, tcpFlagACK|tcpFlagPSH)
			entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			var calls atomic.Int32
			if v := h.lease.HandlePacket(packet.Raw, DirectionOutbound, nil, func(Verdict, string, []byte) {
				calls.Add(1)
				close(entered)
				<-release
				close(returned)
			}); v != VerdictHold {
				t.Fatalf("admission=%v", v)
			}
			charged := int64(len(packet.Raw))
			if got := h.engine.heldBytes.Load(); got != charged {
				t.Fatalf("reserved=%d, measured=%d", got, charged)
			}
			if trigger == "flush" {
				go h.lease.tcpFlow.flushHeld("active")
			}
			waitTCPBudgetSignal(t, entered)
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			stop := context.AfterFunc(ctx, func() { result <- h.lease.Close(ctx.Err()) })
			defer stop()
			cancel()
			if err := <-result; !errors.Is(err, ErrLeaseCloseIncomplete) {
				t.Errorf("active cancellation Close=%v, want incomplete", err)
			}
			if got := h.engine.heldBytes.Load(); got != charged {
				t.Errorf("active cancellation retained %d bytes, want measured %d", got, charged)
			}
			select {
			case <-h.lease.captureRetired:
				t.Error("capture retired before held callback returned")
			default:
			}
			unblock()
			waitTCPBudgetSignal(t, returned)
			if err := h.lease.WaitClosed(); err != nil {
				t.Fatal(err)
			}
			if err := h.lease.WaitCaptureRetired(); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := h.lease.Close(nil); err != nil {
					t.Fatal(err)
				}
			}
			h.lease.tcpFlow.expire()
			if calls.Load() != 1 || h.engine.heldBytes.Load() != 0 || h.engine.ActiveLeases() != 0 {
				t.Fatalf("final calls=%d bytes=%d leases=%d", calls.Load(), h.engine.heldBytes.Load(), h.engine.ActiveLeases())
			}
		})
	}
}

func waitTCPBudgetSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("held budget schedule did not complete")
	}
}

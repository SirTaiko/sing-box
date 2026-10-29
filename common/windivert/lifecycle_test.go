package windivert

// W3 regressions for the close-versus-native-operation gate. These exercise the
// real registration/cancel/drain/retirement state machine the Windows handle
// uses, deterministically and on every platform; the driver-facing bindings
// (per-lane OVERLAPPED/event, CancelIoEx, DeviceIoControl) remain covered by the
// platform-qualified wrapper tests and the native lab stage.

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestIOLifecycleRefusesRegistrationAfterClose(t *testing.T) {
	var retired atomic.Int32
	gate := newIOLifecycle(20*time.Millisecond, nil, func() error {
		retired.Add(1)
		return nil
	})
	if err := gate.begin("recv"); err != nil {
		t.Fatalf("initial registration refused: %v", err)
	}
	gate.end("recv")
	if err := gate.Close(); err != nil {
		t.Fatalf("clean close failed: %v", err)
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times, want 1", retired.Load())
	}
	if err := gate.begin("send"); err == nil {
		t.Fatal("registration after close was accepted")
	}
	select {
	case <-gate.Done():
	default:
		t.Fatal("Done is not closed after a clean close")
	}
	// Idempotent: a second close returns the same result and retires once.
	if err := gate.Close(); err != nil {
		t.Fatalf("second close failed: %v", err)
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times after repeated close, want 1", retired.Load())
	}
}

func TestIOLifecycleWaitsForTerminalReceipt(t *testing.T) {
	cancelSeen := make(chan struct{}, 1)
	var retired atomic.Int32
	gate := newIOLifecycle(200*time.Millisecond, func(key any) {
		if key != "recv" {
			t.Errorf("cancel hook called for %v, want recv", key)
		}
		cancelSeen <- struct{}{}
	}, func() error {
		retired.Add(1)
		return nil
	})
	if err := gate.begin("recv"); err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- gate.Close() }()
	select {
	case <-cancelSeen:
	case <-time.After(time.Second):
		t.Fatal("close did not request cancellation of the registered operation")
	}
	// Close must not claim completion, and Done must stay open, while the
	// operation has not produced its terminal receipt.
	select {
	case err := <-closed:
		t.Fatalf("close returned (%v) while an operation was still pending", err)
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-gate.Done():
		t.Fatal("Done closed while an operation was still pending")
	default:
	}
	if retired.Load() != 0 {
		t.Fatal("native resources were retired before the terminal receipt")
	}
	gate.end("recv")
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close after the terminal receipt failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not observe the terminal receipt")
	}
	select {
	case <-gate.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close after retirement")
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times, want 1", retired.Load())
	}
}

func TestIOLifecycleBoundedGraceDefersRetirement(t *testing.T) {
	var retired atomic.Int32
	gate := newIOLifecycle(20*time.Millisecond, func(key any) {}, func() error {
		retired.Add(1)
		return nil
	})
	if err := gate.begin("send"); err != nil {
		t.Fatal(err)
	}
	err := gate.Close()
	if err == nil {
		t.Fatal("close without a terminal receipt inside the grace reported success")
	}
	if retired.Load() != 0 {
		t.Fatal("native resources were retired without a terminal receipt")
	}
	select {
	case <-gate.Done():
		t.Fatal("Done closed although retirement was deferred")
	default:
	}
	gate.end("send")
	select {
	case <-gate.Done():
	case <-time.After(time.Second):
		t.Fatal("deferred retirement never completed after the terminal receipt")
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times, want 1", retired.Load())
	}
	// The settlement is not a stale failure: once the late retirement is
	// proven, Done is closed and the transient deferral is superseded by
	// success, exactly as the native close-barrier regression requires.
	if err := gate.Close(); err != nil {
		t.Fatalf("repeated close after proven retirement = %v, want nil", err)
	}
}

// TestIOLifecycleLateRetirementSupersedesDeferral pins the close-result lifetime
// across the deferred-retirement path: while the terminal receipt is still
// outstanding every Close is non-success, and once the late retirement is proven
// (Done closed) the transient deferral is superseded by success. A stale
// deferral would make every later Close of a fully retired handle report a
// failure forever, which the native close-barrier regression forbids.
func TestIOLifecycleLateRetirementSupersedesDeferral(t *testing.T) {
	var retired atomic.Int32
	gate := newIOLifecycle(20*time.Millisecond, func(key any) {}, func() error {
		retired.Add(1)
		return nil
	})
	if err := gate.begin("recv"); err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err == nil {
		t.Fatal("close without a terminal receipt inside the grace reported success")
	}
	// Still outstanding: no success, no retirement, no Done.
	if err := gate.Close(); err == nil {
		t.Fatal("close reported success while the terminal receipt was still outstanding")
	}
	select {
	case <-gate.Done():
		t.Fatal("Done closed while the terminal receipt was still outstanding")
	default:
	}
	if retired.Load() != 0 {
		t.Fatal("native resources were retired before the terminal receipt")
	}
	gate.end("recv")
	select {
	case <-gate.Done():
	case <-time.After(time.Second):
		t.Fatal("deferred retirement never completed after the terminal receipt")
	}
	// Repeated and concurrent Close calls observe the proven retirement instead
	// of the deferral that described the earlier outstanding state.
	for index := 0; index < 2; index++ {
		if err := gate.Close(); err != nil {
			t.Fatalf("repeated close %d after proven retirement = %v, want nil", index, err)
		}
	}
	var waitGroup sync.WaitGroup
	results := make(chan error, 8)
	for index := 0; index < 8; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- gate.Close()
		}()
	}
	waitGroup.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent close after proven retirement = %v, want nil", err)
		}
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times, want exactly one retirement", retired.Load())
	}
}

// TestIOLifecycleLateRetirementFailureKeepsDoneOpen pins the other settlement of
// the deferred path: a late retirement attempt that fails is a durable failure.
// Done stays open because the device/events are not proven released, and every
// later Close keeps reporting that failure instead of inventing success.
func TestIOLifecycleLateRetirementFailureKeepsDoneOpen(t *testing.T) {
	var retired atomic.Int32
	retireErr := errors.New("device release failed after deferred retirement")
	gate := newIOLifecycle(20*time.Millisecond, func(key any) {}, func() error {
		retired.Add(1)
		return retireErr
	})
	if err := gate.begin("send"); err != nil {
		t.Fatal(err)
	}
	if err := gate.Close(); err == nil {
		t.Fatal("close without a terminal receipt inside the grace reported success")
	}
	gate.end("send")
	// A failed late retirement never closes Done, so the failure is observed
	// through the close result itself within a bound.
	deadline := time.Now().Add(2 * time.Second)
	for !errors.Is(gate.Close(), retireErr) {
		if time.Now().After(deadline) {
			t.Fatalf("late retirement failure never became the close result: %v", gate.Close())
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-gate.Done():
		t.Fatal("Done closed although the late native retirement failed")
	default:
	}
	if err := gate.Close(); !errors.Is(err, retireErr) {
		t.Fatalf("repeated close lost the late retirement failure: %v", err)
	}
	if retired.Load() != 1 {
		t.Fatalf("retirement attempted %d times, want exactly one", retired.Load())
	}
}

func TestIOLifecycleConcurrentClose(t *testing.T) {
	var retired atomic.Int32
	gate := newIOLifecycle(50*time.Millisecond, nil, func() error {
		retired.Add(1)
		return nil
	})
	var waitGroup sync.WaitGroup
	results := make(chan error, 8)
	for index := 0; index < 8; index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			results <- gate.Close()
		}()
	}
	waitGroup.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent close reported %v", err)
		}
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times under concurrent close, want 1", retired.Load())
	}
	select {
	case <-gate.Done():
	case <-time.After(time.Second):
		t.Fatal("Done did not close")
	}
}

// TestIOLifecycleSubmissionBarrier covers the window between registration and
// the kernel seeing the request. Close's cancellation runs while the operation
// has registered but has not submitted yet, so that cancellation cannot find
// the request (ERROR_NOT_FOUND). The operation then submits, observes that
// closing won and cancels its own request; only that post-submission
// cancellation can produce a terminal receipt. Without the armed handshake the
// operation would never complete and Done could never close.
func TestIOLifecycleSubmissionBarrier(t *testing.T) {
	type cancellation struct {
		key     string
		found   bool // the request existed when cancellation ran
		byClose bool
	}
	cancellations := make(chan cancellation, 4)
	var armed atomic.Bool
	var retired atomic.Int32
	gate := newIOLifecycle(40*time.Millisecond, func(key any) {
		cancellations <- cancellation{key: key.(string), found: armed.Load(), byClose: true}
	}, func() error {
		retired.Add(1)
		return nil
	})
	submission := make(chan struct{})
	registered := make(chan struct{})
	// The lane goroutine: register, wait at the barrier, then arm/submit.
	laneDone := make(chan error, 1)
	go func() {
		if err := gate.begin("recv"); err != nil {
			laneDone <- err
			return
		}
		close(registered)
		<-submission // Close runs while the request does not exist yet
		armed.Store(true)
		if !gate.arm("recv") {
			// The handshake did not observe the close; with the real protocol
			// this request would never receive a cancellation. Leave it
			// registered, exactly as a lost submission would.
			laneDone <- nil
			return
		}
		// The kernel only completes this request because the post-submission
		// cancellation found it; deregistering without that receipt would be
		// the very memory-reuse hazard the protocol prevents.
		cancellations <- cancellation{key: "recv", found: true, byClose: false}
		gate.end("recv")
		laneDone <- nil
	}()
	select {
	case <-registered:
	case <-time.After(time.Second):
		t.Fatal("registration never became visible")
	}
	closeErr := gate.Close()
	if closeErr == nil {
		t.Fatal("close before submission reported success although the operation was still pending")
	}
	select {
	case <-gate.Done():
		t.Fatal("Done closed while the submitted operation had no terminal receipt")
	default:
	}
	close(submission)
	if err := <-laneDone; err != nil {
		t.Fatalf("lane registration failed: %v", err)
	}
	select {
	case <-gate.Done():
	case <-time.After(time.Second):
		t.Fatal("deferred retirement never completed after the self-cancellation")
	}
	if retired.Load() != 1 {
		t.Fatalf("retire ran %d times, want 1", retired.Load())
	}
	var sawCloseCancel, sawSelfCancel bool
	for {
		select {
		case cancel := <-cancellations:
			if cancel.byClose {
				sawCloseCancel = true
				if cancel.found {
					t.Fatal("the close-time cancellation was expected to miss the not-yet-submitted request")
				}
			} else {
				sawSelfCancel = true
				if !cancel.found {
					t.Fatal("the post-submission cancellation did not find the submitted request")
				}
			}
			continue
		default:
		}
		break
	}
	if !sawCloseCancel || !sawSelfCancel {
		t.Fatalf("cancellation evidence incomplete: close=%v self=%v", sawCloseCancel, sawSelfCancel)
	}
}

// TestIOLifecycleFailedRetirementKeepsDoneOpen pins the distinction between a
// failed retirement attempt and a proven one: a CloseHandle failure is reported
// but Done must stay open, and a repeated Close must keep returning the same
// non-success result instead of inventing a successful second attempt.
func TestIOLifecycleFailedRetirementKeepsDoneOpen(t *testing.T) {
	var retired atomic.Int32
	retireErr := errors.New("device release failed")
	gate := newIOLifecycle(20*time.Millisecond, nil, func() error {
		retired.Add(1)
		return retireErr
	})
	if err := gate.begin("send"); err != nil {
		t.Fatal(err)
	}
	gate.end("send")
	err := gate.Close()
	if !errors.Is(err, retireErr) {
		t.Fatalf("close error = %v, want the failed retirement", err)
	}
	select {
	case <-gate.Done():
		t.Fatal("Done closed although native retirement failed")
	default:
	}
	if repeated := gate.Close(); !errors.Is(repeated, retireErr) {
		t.Fatalf("repeated close lost the retirement failure: %v", repeated)
	}
	if retired.Load() != 1 {
		t.Fatalf("retirement attempted %d times, want exactly one blind-free attempt", retired.Load())
	}
}

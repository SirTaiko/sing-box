package dialer

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
)

// fakeConnectCompletion substitutes only the three native results of an
// overlapped connect: the event wait, the harvested result and the
// cancellation request. No socket, event handle or kernel I/O exists.
type fakeConnectCompletion struct {
	mu          sync.Mutex
	signaled    bool
	transferred uint32
	signal      chan struct{}
	waits       []time.Duration
	cancels     int
	cancelErr   error
	cancelHook  func()
	released    int
	sockets     int
	releaseHook func()
	waitErrors  int
	resultErr   error
	// closeSocketErr is the retirement result of the faked socket close. It is
	// only set by the retirement regressions; closeSocketProven says whether
	// that result still proves the release (the would-block-retried case).
	closeSocketErr    error
	closeSocketProven bool
}

func newFakeConnectCompletion() *fakeConnectCompletion {
	return &fakeConnectCompletion{signal: make(chan struct{})}
}

func (f *fakeConnectCompletion) complete(transferred uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.transferred = transferred
	if !f.signaled {
		f.signaled = true
		close(f.signal)
	}
}

func (f *fakeConnectCompletion) owner(payload []byte) *outstandingConnect {
	return &outstandingConnect{
		wait: func(timeout time.Duration) (bool, error) {
			f.mu.Lock()
			f.waits = append(f.waits, timeout)
			if f.waitErrors > 0 {
				f.waitErrors--
				f.mu.Unlock()
				return false, errors.New("substituted wait failure")
			}
			signaled := f.signaled
			signal := f.signal
			f.mu.Unlock()
			if signaled {
				return true, nil
			}
			if timeout < 0 {
				<-signal
				return true, nil
			}
			timer := time.NewTimer(timeout)
			defer timer.Stop()
			select {
			case <-signal:
				return true, nil
			case <-timer.C:
				return false, nil
			}
		},
		result: func() (uint32, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.transferred, f.resultErr
		},
		cancel: func() error {
			f.mu.Lock()
			f.cancels++
			hook := f.cancelHook
			err := f.cancelErr
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
			return err
		},
		release: func() {
			f.mu.Lock()
			f.released++
			hook := f.releaseHook
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
		},
		retireSocket: func() (bool, error) {
			f.mu.Lock()
			f.sockets++
			retireErr := f.closeSocketErr
			proven := f.closeSocketProven
			f.mu.Unlock()
			if retireErr != nil {
				return proven, retireErr
			}
			return true, nil
		},
		buffer: payload,
	}
}

func (f *fakeConnectCompletion) counters() (waits int, cancels int, released int, sockets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waits), f.cancels, f.released, f.sockets
}

func (f *fakeConnectCompletion) lastWait() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.waits) == 0 {
		return -2
	}
	return f.waits[len(f.waits)-1]
}

// boundedWaits returns the caller-budget waits in the order they were recorded.
// The autonomous retention poll deliberately waits without a caller budget
// (a negative timeout) and is therefore not a caller-budget wait: mixing the
// two in one "last slice" assertion is a test-accounting defect, not a product
// invariant.
func (f *fakeConnectCompletion) boundedWaits() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	bounded := make([]time.Duration, 0, len(f.waits))
	for _, wait := range f.waits {
		if wait >= 0 {
			bounded = append(bounded, wait)
		}
	}
	return bounded
}

// hasUnboundedWait reports whether the autonomous retention poll is already
// waiting without a caller budget.
func (f *fakeConnectCompletion) hasUnboundedWait() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, wait := range f.waits {
		if wait < 0 {
			return true
		}
	}
	return false
}

// waitFor polls a condition with a bounded wall-clock budget, so a test never
// depends on a production second call to trigger cleanup.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("%s did not happen without a second call", what)
}

// A pending ConnectEx reports its accepted bytes only at terminal completion.
// Reusing the initiation value duplicates the initial payload on the same
// connection; using the completion value writes only the remainder.
func TestConnectTransferredUsesAuthoritativeCompletionCount(t *testing.T) {
	cases := []struct {
		name                   string
		asynchronous           bool
		initiation, completion uint32
		payload, wantRemainder int
	}{
		{"sync-full", false, 5, 0, 5, 5},
		{"sync-partial", false, 2, 0, 5, 2},
		{"pending-full", true, 0, 5, 5, 5},
		{"pending-partial", true, 0, 3, 5, 3},
		// The two sources diverge: only the completion count is authoritative
		// for an asynchronous operation. Reusing the initiation value here
		// would silently drop four payload bytes.
		{"pending-divergent", true, 5, 1, 5, 1},
		{"clamped", true, 0, 9, 5, 5},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := connectTransferred(testCase.asynchronous, testCase.initiation, testCase.completion, testCase.payload); got != testCase.wantRemainder {
				t.Fatalf("accepted bytes = %d, want %d", got, testCase.wantRemainder)
			}
		})
	}
}

// A caller budget that ends before the kernel reports completion must return
// promptly without freeing the OVERLAPPED, event, socket or payload. The
// retained owner then reaps the operation autonomously when the completion
// finally arrives, beyond the old five-second cancel wait.
func TestConnectCompletionRetainedUntilLateCompletion(t *testing.T) {
	fake := newFakeConnectCompletion()
	deadline := time.Now().Add(-time.Second)
	start := time.Now()
	_, err := fake.owner([]byte("FIRST")).awaitConnectCompletion(context.Background(), deadline)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if elapsed > time.Second {
		t.Fatalf("caller waited %v for an already-expired budget", elapsed)
	}
	waits, cancels, released, sockets := fake.counters()
	if cancels != 1 {
		t.Fatalf("cancels = %d, want exactly one cancellation request", cancels)
	}
	if released != 0 || sockets != 0 {
		t.Fatalf("released=%d sockets=%d before completion: outstanding I/O was disposed", released, sockets)
	}
	// The cancelled operation is still pending: the old implementation freed
	// the event here and returned. Completion arrives late, without any second
	// call into the production function.
	fake.complete(0)
	waitFor(t, "late completion cleanup", func() bool {
		_, _, released, sockets := fake.counters()
		return released == 1 && sockets == 1
	})
	time.Sleep(20 * time.Millisecond)
	if _, _, released, sockets := fake.counters(); released != 1 || sockets != 1 {
		t.Fatalf("cleanup was not exactly once: released=%d sockets=%d", released, sockets)
	}
	if waits == 0 {
		t.Fatal("the retained owner never waited for completion")
	}
}

// CancelIoEx only requests cancellation. Its failure, including the not-found
// result of an already completed operation, must never be treated as proof of
// completion.
func TestConnectCompletionCancelFailureRetainsOperation(t *testing.T) {
	fake := newFakeConnectCompletion()
	fake.cancelErr = errors.New("substituted CancelIoEx failure")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fake.owner(nil).awaitConnectCompletion(ctx, time.Time{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the canceled context", err)
	}
	if _, cancels, released, sockets := fake.counters(); cancels != 1 || released != 0 || sockets != 0 {
		t.Fatalf("cancels=%d released=%d sockets=%d: failed cancellation disposed the operation", cancels, released, sockets)
	}
	fake.complete(0)
	waitFor(t, "cleanup after failed cancellation", func() bool {
		_, _, released, sockets := fake.counters()
		return released == 1 && sockets == 1
	})
}

// A completion that races the cancellation is harvested inline: the resources
// are released once and the socket stays with the caller, which owns it on the
// completion path.
func TestConnectCompletionRacingCancelIsHarvested(t *testing.T) {
	fake := newFakeConnectCompletion()
	fake.cancelHook = func() { fake.complete(3) }
	_, err := fake.owner([]byte("FIRST")).awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	transferred, cancels, released, sockets := 0, 0, 0, 0
	fake.mu.Lock()
	transferred = int(fake.transferred)
	cancels, released, sockets = fake.cancels, fake.released, fake.sockets
	fake.mu.Unlock()
	if cancels != 1 || released != 1 {
		t.Fatalf("cancels=%d released=%d, want one of each", cancels, released)
	}
	if sockets != 0 {
		t.Fatalf("socket closed %d times on the inline completion path", sockets)
	}
	if transferred != 3 {
		t.Fatalf("completion count = %d, want 3", transferred)
	}
}

// A failing wait never proves completion; the operation stays owned and is
// reaped when the completion is subsequently observed.
func TestConnectCompletionWaitFailureRetainsOperation(t *testing.T) {
	fake := newFakeConnectCompletion()
	fake.waitErrors = 1
	_, err := fake.owner(nil).awaitConnectCompletion(context.Background(), time.Now().Add(time.Second))
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the substituted wait failure", err)
	}
	if _, cancels, released, _ := fake.counters(); cancels != 1 || released != 0 {
		t.Fatalf("cancels=%d released=%d: wait failure disposed the operation", cancels, released)
	}
	fake.complete(0)
	waitFor(t, "cleanup after wait failure", func() bool {
		_, _, released, sockets := fake.counters()
		return released == 1 && sockets == 1
	})
}

// The submitted initial payload must stay reachable while the kernel owns the
// asynchronous operation; the retained owner is the only root after the caller
// returns.
func TestConnectCompletionRetainsSubmittedBuffer(t *testing.T) {
	fake := newFakeConnectCompletion()
	collected := make(chan struct{}, 1)
	func() {
		payload := new([4096]byte)
		runtime.SetFinalizer(payload, func(*[4096]byte) { collected <- struct{}{} })
		owner := fake.owner(payload[:])
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := owner.awaitConnectCompletion(ctx, time.Time{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want the canceled context", err)
		}
	}()
	early := false
	for i := 0; i < 8; i++ {
		runtime.GC()
		runtime.Gosched()
		select {
		case <-collected:
			early = true
		default:
		}
	}
	fake.complete(0)
	waitFor(t, "buffer retained until completion", func() bool {
		_, _, released, sockets := fake.counters()
		return released == 1 && sockets == 1
	})
	if early {
		t.Fatal("submitted initial payload became collectible while the operation was outstanding")
	}
}

// The caller-budget wait slices stay bounded: a pending operation with a live
// caller deadline is re-checked at the deadline granularity, never with the old
// fixed five-second block. The assertions cover the caller-budget waits only;
// the autonomous retention poll (-1) is a deliberately unbudgeted wait of the
// retained owner and is asserted separately, so the test never races that poll
// for its accounting.
func TestConnectCompletionWaitIsBoundedByCallerBudget(t *testing.T) {
	fake := newFakeConnectCompletion()
	start := time.Now()
	_, err := fake.owner(nil).awaitConnectCompletion(context.Background(), time.Now().Add(30*time.Millisecond))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("caller latency = %v for a 30ms budget", elapsed)
	}
	bounded := fake.boundedWaits()
	if len(bounded) == 0 {
		t.Fatal("no caller-budget wait was recorded")
	}
	longest := time.Duration(0)
	for _, wait := range bounded {
		if wait <= 0 {
			t.Fatalf("caller-budget wait = %v, want a positive bounded slice", wait)
		}
		if wait > longest {
			longest = wait
		}
	}
	if longest > connectCancelGrace+connectPollSlice {
		t.Fatalf("longest caller-budget wait = %v, want nothing near the old fixed five-second block", longest)
	}
	fake.complete(0)
	waitFor(t, "autonomous unbudgeted retention poll", fake.hasUnboundedWait)
	waitFor(t, "cleanup after bounded wait", func() bool {
		_, _, released, sockets := fake.counters()
		return released == 1 && sockets == 1
	})
}

// retainedTestBackend is the memory-only capture backend of the admission
// regressions: it never opens a native capture.
type retainedTestBackend struct{}

func (retainedTestBackend) Name() string { return "memory-only" }

func (retainedTestBackend) Open(*desync.Lease) (desync.Capture, error) {
	return nil, errors.New("no native capture in this fixture")
}

// admissionLease is an AttemptLease whose Close discharges an actual
// desync.Engine admission, so the retained operation's charge is observable
// through the real Engine.
type admissionLease struct {
	*fakeAttemptLease
	lease *desync.Lease
}

func (l *admissionLease) Close(reason error) error { return l.lease.Close(reason) }

// ReportNativeFailure forwards the retained retirement diagnostic to the real
// engine lease, exactly like the production desyncLease bridge.
func (l *admissionLease) ReportNativeFailure(err error) { l.lease.ReportNativeFailure(err) }

// A retained native operation must stay charged against the existing admission
// budget until the kernel reports terminal completion. Before the fix the
// per-attempt caller closed the lease on its way out, so sequential callers with
// MaxLeases=1 produced an unbounded retained population in a pool that claimed a
// hard cap of one.
func TestRetainedOperationKeepsAdmissionUntilCompletion(t *testing.T) {
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, retainedTestBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	// Positive control: a live lease consumes the single slot.
	first, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); err == nil {
		t.Fatal("admission fixture does not enforce MaxLeases=1")
	}
	if err = first.Close(nil); err != nil {
		t.Fatal(err)
	}
	admitted, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	hold, err := admitted.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	fake := newFakeConnectCompletion()
	operation := fake.owner([]byte("FIRST"))
	operation.lease = &admissionLease{fakeAttemptLease: &fakeAttemptLease{hook: &fakeAttemptHook{}}, lease: admitted}
	operation.nativeHold = hold
	if _, err = operation.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if !operation.retained {
		t.Fatal("the operation was not retained, so the fixture proves nothing")
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d while the operation is retained, want the single charged admission", active)
	}
	if _, err = engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); err == nil {
		t.Fatal("a new native operation was admitted while a retained operation still owns the only slot")
	}
	// Terminal native completion, without any further caller action.
	fake.complete(0)
	waitFor(t, "retained operation admission discharge", func() bool {
		return engine.ActiveLeases() == 0
	})
	reopened, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatalf("admission after terminal completion: %v", err)
	}
	_ = reopened.Close(nil)
	if _, _, released, sockets := fake.counters(); released != 1 || sockets != 1 {
		t.Fatalf("released=%d sockets=%d, want exactly one terminal cleanup", released, sockets)
	}
}

// The per-attempt caller path must not close the lease of a retained attempt.
// It is the retained completion owner that discharges the admission, and a
// plain failure still closes the lease exactly once.
func TestRetainedAttemptKeepsLeaseUntilCompletion(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "plain-failure-closes-lease"
		if retained {
			name = "retained-failure-keeps-lease"
		}
		t.Run(name, func(t *testing.T) {
			hook := &fakeAttemptHook{}
			installPayloadFunc(t, func(context.Context, net.Dialer, string, string, []byte, AttemptLease) (net.Conn, int, error) {
				failure := errors.New("substituted native failure")
				if retained {
					return nil, 0, &retainedAttemptError{err: failure}
				}
				return nil, 0, failure
			})
			dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
			conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err = conn.Write([]byte("FIRST")); err == nil {
				t.Fatal("fixture expected the substituted failure")
			}
			hook.mu.Lock()
			closes := hook.closes
			hook.mu.Unlock()
			if retained {
				if closes != 0 {
					t.Fatalf("lease closes = %d, want 0 while the native operation is retained", closes)
				}
				return
			}
			if closes != 1 {
				t.Fatalf("lease closes = %d, want exactly 1 for a plain failure", closes)
			}
		})
	}
}

// The retained operation owns the admission reference acquired before the
// native connect existed. Only the terminal receipt discharges it: until then
// the closed attempt stays a charged tombstone in the real Engine, and the
// release runs autonomously at completion without another caller action.
func TestRetainedOperationDischargesNativeHoldOnTerminalCompletion(t *testing.T) {
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, retainedTestBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	admitted, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	release, err := admitted.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	fake := newFakeConnectCompletion()
	operation := fake.owner([]byte("FIRST"))
	operation.lease = &admissionLease{fakeAttemptLease: &fakeAttemptLease{hook: &fakeAttemptHook{}}, lease: admitted}
	operation.nativeHold = release
	if _, err = operation.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if !operation.retained {
		t.Fatal("the operation was not retained, so the fixture proves nothing")
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d while the native hold owns the slot, want 1", active)
	}
	if _, err = engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); err == nil {
		t.Fatal("a second attempt was admitted while the retained native hold owned the only slot")
	}
	fake.complete(0)
	waitFor(t, "retained native hold discharge", func() bool {
		return engine.ActiveLeases() == 0
	})
	reopened, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatalf("admission after terminal discharge: %v", err)
	}
	_ = reopened.Close(nil)
}

// Capture teardown of a retained operation starts before the terminal receipt
// and is not deferred until that receipt; the admission reference stays with
// the operation until the receipt arrives.
func TestRetainedOperationStartsCaptureCloseBeforeTerminalReceipt(t *testing.T) {
	fake := newFakeConnectCompletion()
	hook := &fakeAttemptHook{}
	lease := &fakeAttemptLease{hook: hook}
	var released atomic.Int32
	operation := fake.owner(nil)
	operation.lease = lease
	operation.nativeHold = func() { released.Add(1) }
	if _, err := operation.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if !operation.retained {
		t.Fatal("the operation was not retained, so the fixture proves nothing")
	}
	waitFor(t, "capture teardown initiated before the receipt", func() bool {
		hook.mu.Lock()
		defer hook.mu.Unlock()
		return hook.closes == 1
	})
	fake.mu.Lock()
	signaled := fake.signaled
	fake.mu.Unlock()
	if signaled {
		t.Fatal("fixture signalled terminal completion before teardown was observed")
	}
	if released.Load() != 0 {
		t.Fatal("native hold was discharged before the terminal receipt")
	}
	fake.complete(0)
	waitFor(t, "terminal native discharge", func() bool {
		return released.Load() == 1
	})
}

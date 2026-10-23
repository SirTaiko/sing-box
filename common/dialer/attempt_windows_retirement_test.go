//go:build windows

package dialer

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"

	"golang.org/x/sys/windows"
)

// captureStringPanic runs one formatting call and converts a panic into a test
// failure. The defect under test is a panic raised while the message is built,
// so the regression must be reported as an assertion failure, never as a test
// process crash that could be mistaken for an unrelated build/runtime problem.
func captureStringPanic(t *testing.T, what string, call func() string) string {
	t.Helper()
	var (
		rendered   string
		panicValue any
	)
	func() {
		defer func() { panicValue = recover() }()
		rendered = call()
	}()
	if panicValue != nil {
		t.Fatalf("%s panicked while building its diagnostic: %v", what, panicValue)
	}
	return rendered
}

// captureErrorPanic runs one production call whose error joins are formatted
// eagerly and converts a formatting panic into a test failure.
func captureErrorPanic(t *testing.T, what string, call func() error) error {
	t.Helper()
	var (
		err        error
		panicValue any
	)
	func() {
		defer func() { panicValue = recover() }()
		err = call()
	}()
	if panicValue != nil {
		t.Fatalf("%s panicked while building its error: %v", what, panicValue)
	}
	return err
}

// TestWA1UnresolvedRetirementRendersDescriptorDiagnostics pins the diagnostic
// contract of the retirement token. windows.Handle is a defined uintptr type,
// so handing it to sing's format.ToString panics with "unknown value" while the
// message is built; the panic escaped the production joins instead of reporting
// the retirement failure. Every descriptor kind must render as an ordinary
// error string while the close error stays joined and classified.
func TestWA1UnresolvedRetirementRendersDescriptorDiagnostics(t *testing.T) {
	closeErr := errors.New("injected ambiguous close failure")
	for _, handle := range []windows.Handle{0, 0x42, windows.Handle(^uintptr(0))} {
		t.Run("handle-"+strconv.FormatUint(uint64(handle), 16), func(t *testing.T) {
			token := &unresolvedSocketRetirement{handle: handle, err: closeErr}
			rendered := captureStringPanic(t, "unresolvedSocketRetirement.Error", token.Error)
			descriptor := strconv.FormatUint(uint64(handle), 10)
			if !strings.Contains(rendered, "desync: socket retirement unresolved for descriptor "+descriptor) {
				t.Fatalf("rendered token = %q, want the descriptor %s rendered without a panic", rendered, descriptor)
			}
			if !strings.Contains(rendered, closeErr.Error()) {
				t.Fatalf("rendered token = %q, want the original close error preserved", rendered)
			}
			if !errors.Is(token, closeErr) {
				t.Fatalf("token = %v, want the original close error still classified", token)
			}
		})
	}
}

// TestWA1UnresolvedRetirementRendersThroughJoinedProductionPaths renders every
// production join that can carry an unresolved retirement token. exceptions.Errors
// formats each joined member eagerly, so before the fix each of these paths
// panicked instead of returning its error.
func TestWA1UnresolvedRetirementRendersThroughJoinedProductionPaths(t *testing.T) {
	handle := windows.Handle(0x42)
	carrier := windows.Handle(0x99)
	ambiguous := errors.New("injected ambiguous close failure")

	t.Run("original-socket-retirement", func(t *testing.T) {
		installOriginalCloseSeam(t, ambiguous)
		err := captureErrorPanic(t, "retireOriginalSocket", func() error { return retireOriginalSocket(handle) })
		assertUnresolvedRetirementDiagnostic(t, err, ambiguous, handle)
	})

	t.Run("adoption-carrier-retirement", func(t *testing.T) {
		installAdoptionSeams(t, carrier, nil, ambiguous)
		var adopted net.Conn
		err := captureErrorPanic(t, "adoptConnectedSocket", func() error {
			var adoptErr error
			adopted, adoptErr = adoptConnectedSocket(handle)
			return adoptErr
		})
		if adopted != nil {
			t.Fatal("a failed carrier retirement published a connection")
		}
		assertUnresolvedRetirementDiagnostic(t, err, ambiguous, carrier)
	})

	t.Run("adoption-and-carrier-retirement", func(t *testing.T) {
		adoptErr := errors.New("injected adoption failure")
		installAdoptionSeams(t, carrier, adoptErr, ambiguous)
		err := captureErrorPanic(t, "adoptConnectedSocket", func() error {
			_, callErr := adoptConnectedSocket(handle)
			return callErr
		})
		if err == nil || !errors.Is(err, adoptErr) {
			t.Fatalf("error = %v, want the adoption error preserved", err)
		}
		assertUnresolvedRetirementDiagnostic(t, err, ambiguous, carrier)
	})

	t.Run("constructor-rejection-and-carrier-retirement", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, nil)
		ctorErr := errors.New("injected constructor rejection")
		newAdoptionFile = func(candidate windows.Handle) (adoptionFile, error) {
			seams.ctorInputs = append(seams.ctorInputs, candidate)
			return nil, ctorErr
		}
		seams.closeErrors = []error{ambiguous}
		err := captureErrorPanic(t, "adoptConnectedSocket", func() error {
			_, callErr := adoptConnectedSocket(handle)
			return callErr
		})
		if err == nil || !errors.Is(err, ctorErr) {
			t.Fatalf("error = %v, want the constructor error preserved", err)
		}
		assertUnresolvedRetirementDiagnostic(t, err, ambiguous, carrier)
	})

	t.Run("readiness-probe-retirement", func(t *testing.T) {
		originalClose := closeCarrierSocket
		originalProbe := duplicateProbe
		t.Cleanup(func() {
			closeCarrierSocket = originalClose
			duplicateProbe = originalProbe
		})
		probe := windows.Handle(0x77)
		duplicateProbe = func(windows.Handle) (windows.Handle, error) { return probe, nil }
		closeCarrierSocket = func(windows.Handle) error { return ambiguous }
		err := captureErrorPanic(t, "probeConnectedContext", func() error {
			_, callErr := probeConnectedContext(handle)
			return callErr
		})
		assertUnresolvedRetirementDiagnostic(t, err, ambiguous, probe)
	})

	t.Run("failed-duplicate-retirement", func(t *testing.T) {
		originalClose := closeCarrierSocket
		t.Cleanup(func() { closeCarrierSocket = originalClose })
		closeCarrierSocket = func(windows.Handle) error { return ambiguous }
		cause := errors.New("injected duplicate validation failure")
		err := captureErrorPanic(t, "retireFailedDuplicate", func() error {
			return retireFailedDuplicate(carrier, cause)
		})
		if !errors.Is(err, cause) {
			t.Fatalf("error = %v, want the validation cause preserved", err)
		}
		assertUnresolvedRetirementDiagnostic(t, err, ambiguous, carrier)
	})

	t.Run("attempt-retirement-join", func(t *testing.T) {
		attemptErr := errors.New("injected attempt error")
		installOriginalCloseSeam(t, ambiguous)
		state := attemptRetirement{handle: handle, holdOwned: true, err: attemptErr}
		captureErrorPanic(t, "attemptRetirement.retire", func() error {
			state.retire()
			return nil
		})
		if !errors.Is(state.err, attemptErr) {
			t.Fatalf("error = %v, want the attempt error preserved", state.err)
		}
		assertUnresolvedRetirementDiagnostic(t, state.err, ambiguous, handle)
	})
}

// assertUnresolvedRetirementDiagnostic renders a joined production error and
// requires both the unresolved descriptor diagnostic and the close error.
func assertUnresolvedRetirementDiagnostic(t *testing.T, err error, closeErr error, handle windows.Handle) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a retirement error")
	}
	rendered := captureStringPanic(t, "joined retirement error", err.Error)
	descriptor := strconv.FormatUint(uint64(handle), 10)
	if !strings.Contains(rendered, "socket retirement unresolved for descriptor "+descriptor) {
		t.Fatalf("rendered error = %q, want the unresolved descriptor %s", rendered, descriptor)
	}
	if !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want the injected close error classified", err)
	}
	var unresolved *unresolvedSocketRetirement
	if !errors.As(err, &unresolved) || unresolved.handle != handle {
		t.Fatalf("error = %v, want the unresolved-retirement token for %#x", err, handle)
	}
}

// TestRetainedWouldBlockRetirementRetriesAndDischargesCharge is the real
// Engine MaxLeases=1 composition of the documented would-block rule: the same
// retained owner retries closesocket once, the proven release discharges the
// single charge exactly once, and the transient close error is still reported
// on the attempt's lease diagnostic instead of being dropped.
func TestRetainedWouldBlockRetirementRetriesAndDischargesCharge(t *testing.T) {
	handle := windows.Handle(0x42)
	calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
	engine, admitted, hold, nativeHoldCalls := newRetainedRetirementEngine(t)
	defer engine.Close()
	fake := newFakeConnectCompletion()
	owner := fake.owner([]byte("FIRST"))
	owner.retireSocket = func() (bool, error) { return retireOriginalSocketOutcome(handle) }
	owner.lease = admitted
	owner.nativeHold = hold
	if _, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if !owner.retained {
		t.Fatal("the operation was not retained, so the fixture proves nothing")
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d while the operation is retained, want 1", active)
	}
	fake.complete(0)
	waitFor(t, "retained operation admission discharge", func() bool {
		return engine.ActiveLeases() == 0
	})
	if got := nativeHoldCalls.Load(); got != 1 {
		t.Fatalf("native hold discharged %d times, want exactly once", got)
	}
	if len(*calls) != 2 {
		t.Fatalf("closesocket calls = %v, want the original attempt plus exactly one retry", *calls)
	}
	if _, _, released, _ := fake.counters(); released != 1 {
		t.Fatalf("released=%d, want one terminal receipt (the socket retirement is counted through its own seam)", released)
	}
	waitFor(t, "retirement diagnostic", func() bool { return admitted.lease.Err() != nil })
	reported := admitted.lease.Err()
	if !errors.Is(reported, windows.WSAEWOULDBLOCK) {
		t.Fatalf("lease diagnostic = %v, want the transient would-block close error preserved", reported)
	}
}

// TestRetainedAmbiguousRetirementReportsAndKeepsCharge drives the ambiguous
// rule through the real retirement contract: the descriptor is never retried,
// the single charge stays as an unresolved tombstone across Engine.Close, and
// the joined error renders on the lease diagnostic without panicking.
func TestRetainedAmbiguousRetirementReportsAndKeepsCharge(t *testing.T) {
	handle := windows.Handle(0x42)
	ambiguous := errors.New("injected ambiguous close failure")
	calls := installOriginalCloseSeam(t, ambiguous)
	engine, admitted, hold, nativeHoldCalls := newRetainedRetirementEngine(t)
	defer engine.Close()
	fake := newFakeConnectCompletion()
	owner := fake.owner([]byte("FIRST"))
	owner.retireSocket = func() (bool, error) { return retireOriginalSocketOutcome(handle) }
	owner.lease = admitted
	owner.nativeHold = hold
	if _, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	fake.complete(0)
	waitFor(t, "retirement diagnostic", func() bool { return admitted.lease.Err() != nil })

	if len(*calls) != 1 {
		t.Fatalf("closesocket calls = %v, want no blind numeric retry", *calls)
	}
	if got := nativeHoldCalls.Load(); got != 0 {
		t.Fatalf("native hold discharged %d times after an unproven retirement", got)
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d, want the kept charge of the unresolved descriptor", active)
	}
	rendered := admitted.lease.Err().Error()
	if !strings.Contains(rendered, "socket retirement unresolved for descriptor 66") || !errors.Is(admitted.lease.Err(), ambiguous) {
		t.Fatalf("lease diagnostic = %q, want the rendered unresolved descriptor carrying the close error", rendered)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d after Engine.Close, want the retained tombstone", active)
	}
	time.Sleep(50 * time.Millisecond)
	if len(*calls) != 1 {
		t.Fatalf("closesocket calls = %v after Engine.Close, want no further native side effect", *calls)
	}
	if _, _, released, _ := fake.counters(); released != 1 {
		t.Fatalf("released=%d, want one terminal receipt (the socket retirement is counted through its own seam)", released)
	}
}

// TestRetainedWouldBlockRetryFailureKeepsCharge pins the bounded retry: a
// would-block outcome that turns into an ambiguous error after the retry leaves
// the descriptor unresolved, keeps the charge, performs no further retry and
// still reports the failure.
func TestRetainedWouldBlockRetryFailureKeepsCharge(t *testing.T) {
	handle := windows.Handle(0x42)
	ambiguous := errors.New("injected retry failure")
	calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, ambiguous)
	engine, admitted, hold, nativeHoldCalls := newRetainedRetirementEngine(t)
	defer engine.Close()
	fake := newFakeConnectCompletion()
	owner := fake.owner(nil)
	owner.retireSocket = func() (bool, error) { return retireOriginalSocketOutcome(handle) }
	owner.lease = admitted
	owner.nativeHold = hold
	if _, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	fake.complete(0)
	waitFor(t, "retirement diagnostic", func() bool { return admitted.lease.Err() != nil })
	if len(*calls) != 2 {
		t.Fatalf("closesocket calls = %v, want the original attempt plus exactly one retry", *calls)
	}
	if got := nativeHoldCalls.Load(); got != 0 {
		t.Fatalf("native hold discharged %d times after a failed retry", got)
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d, want the kept charge", active)
	}
	if !errors.Is(admitted.lease.Err(), ambiguous) {
		t.Fatalf("lease diagnostic = %v, want the retry error reported", admitted.lease.Err())
	}
}

// newRetainedRetirementEngine builds the real Engine MaxLeases=1 / real lease /
// real admission-hold fixture of the retained-retirement compositions. The
// lease the dialer sees is the same thin forwarding wrapper the accepted
// retained tests use; the admission owner is the real engine lease.
func newRetainedRetirementEngine(t *testing.T) (*desync.Engine, *admissionLease, func(), *atomic.Int32) {
	t.Helper()
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, retainedTestBackend{})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	hold, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	var calls atomic.Int32
	wrapped := func() {
		calls.Add(1)
		hold()
	}
	return engine, &admissionLease{fakeAttemptLease: &fakeAttemptLease{hook: &fakeAttemptHook{}}, lease: lease}, wrapped, &calls
}

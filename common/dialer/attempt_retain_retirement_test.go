package dialer

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
)

// TestRetainedOperationKeepsChargeWhenSocketRetirementFails pins the WA1
// retirement outcome on the retained path: terminal completion is an I/O
// receipt, not a socket release. When closesocket fails the operation keeps its
// native admission charge, issues no second close and performs no further
// native side effect; only a proven release discharges the hold.
func TestRetainedOperationKeepsChargeWhenSocketRetirementFails(t *testing.T) {
	fake := newFakeConnectCompletion()
	fake.closeSocketErr = errors.New("injected closesocket failure")
	fake.closeSocketProven = false
	var holdCalls atomic.Int32
	owner := fake.owner(nil)
	owner.nativeHold = func() { holdCalls.Add(1) }

	// An already expired caller budget retains the operation without waiting.
	if _, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	fake.complete(0)
	waitFor(t, "socket retirement attempt", func() bool {
		_, _, _, sockets := fake.counters()
		return sockets == 1
	})
	time.Sleep(50 * time.Millisecond)

	if got := holdCalls.Load(); got != 0 {
		t.Fatalf("native hold discharged %d times after a failed socket retirement: the charge must stay on the same attempt", got)
	}
	if _, _, released, sockets := fake.counters(); released != 1 || sockets != 1 {
		t.Fatalf("released=%d sockets=%d, want one terminal release and exactly one closesocket attempt (no blind retry)", released, sockets)
	}
}

// TestRetainedOperationDischargesChargeOnlyAfterProvenRelease is the ordinary
// control for the same path: a successful retirement discharges the hold once.
func TestRetainedOperationDischargesChargeOnlyAfterProvenRelease(t *testing.T) {
	fake := newFakeConnectCompletion()
	var holds atomic.Int32
	owner := fake.owner(nil)
	owner.nativeHold = func() { holds.Add(1) }
	if _, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	fake.complete(0)
	waitFor(t, "native hold discharge", func() bool { return holds.Load() == 1 })
	if _, _, _, sockets := fake.counters(); sockets != 1 {
		t.Fatalf("sockets = %d, want exactly one retirement", sockets)
	}
}

// TestRetainedUnprovenRetirementReportsOnLeaseAndKeepsCharge is the real
// Engine MaxLeases=1 composition of the ambiguous-retirement rule: the retained
// operation's socket release is not proven, so the attempt reports the close
// error on its existing lease diagnostic, keeps the single charged slot as an
// unresolved tombstone, issues no second close and performs no adoption or
// replay. Engine.Close() must not invent a proof: the tombstone stays charged
// and no further native side effect happens.
func TestRetainedUnprovenRetirementReportsOnLeaseAndKeepsCharge(t *testing.T) {
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, retainedTestBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	admitted, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	hold, err := admitted.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	var nativeHoldCalls atomic.Int32
	var retireCalls atomic.Int32
	retireErr := errors.New("injected ambiguous closesocket failure")
	fake := newFakeConnectCompletion()
	owner := fake.owner([]byte("FIRST"))
	// An ambiguous close is never retried and never proves the release.
	owner.retireSocket = func() (bool, error) {
		retireCalls.Add(1)
		return false, retireErr
	}
	owner.lease = &admissionLease{fakeAttemptLease: &fakeAttemptLease{hook: &fakeAttemptHook{}}, lease: admitted}
	owner.nativeHold = func() {
		nativeHoldCalls.Add(1)
		hold()
	}
	if _, err = owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the caller deadline", err)
	}
	if !owner.retained {
		t.Fatal("the operation was not retained, so the fixture proves nothing")
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d while the operation is retained, want the single charged admission", active)
	}
	// Terminal native completion arrives late, without another caller action.
	fake.complete(0)
	waitFor(t, "terminal retirement attempt", func() bool { return retireCalls.Load() == 1 })
	waitFor(t, "lease retirement diagnostic", func() bool { return admitted.Err() != nil })

	if got := admitted.Err(); got == nil || !errors.Is(got, retireErr) || !strings.Contains(got.Error(), "injected ambiguous closesocket failure") {
		t.Fatalf("lease diagnostic = %v, want the reported retirement failure", got)
	}
	if got := nativeHoldCalls.Load(); got != 0 {
		t.Fatalf("native hold discharged %d times after an unproven retirement", got)
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d after an unproven retirement, want the kept charge", active)
	}
	if _, err = engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); err == nil {
		t.Fatal("a new attempt was admitted while the unresolved descriptor still owns the only slot")
	}
	if _, _, released, _ := fake.counters(); released != 1 || retireCalls.Load() != 1 {
		t.Fatalf("released=%d retireCalls=%d, want one terminal receipt and exactly one closesocket attempt", released, retireCalls.Load())
	}

	// Engine.Close must not free or fake the unresolved descriptor's charge.
	if err = engine.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d after Engine.Close, want the retained tombstone", active)
	}
	if _, _, released, _ := fake.counters(); released != 1 || retireCalls.Load() != 1 {
		t.Fatalf("released=%d retireCalls=%d after Engine.Close, want no further native side effect", released, retireCalls.Load())
	}
	if got := nativeHoldCalls.Load(); got != 0 {
		t.Fatalf("native hold discharged %d times across Engine.Close after an unproven retirement", got)
	}
	if !engine.Closed() {
		t.Fatal("the engine did not report its shutdown")
	}
}

// TestRetainedProvenRetirementDischargesChargeWithoutDiagnostic is the positive
// control of the same real-Engine composition: a proven terminal release
// discharges the charge exactly once, publishes nothing on the lease diagnostic
// and performs no adoption or replay.
func TestRetainedProvenRetirementDischargesChargeWithoutDiagnostic(t *testing.T) {
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, retainedTestBackend{})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	admitted, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	hold, err := admitted.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	fake := newFakeConnectCompletion()
	owner := fake.owner([]byte("FIRST"))
	owner.lease = &admissionLease{fakeAttemptLease: &fakeAttemptLease{hook: &fakeAttemptHook{}}, lease: admitted}
	owner.nativeHold = hold
	if _, err = owner.awaitConnectCompletion(context.Background(), time.Now().Add(-time.Second)); !errors.Is(err, context.DeadlineExceeded) {
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
	if got := admitted.Err(); got != nil {
		t.Fatalf("lease diagnostic = %v, want nothing after a proven retirement", got)
	}
	if _, _, released, sockets := fake.counters(); released != 1 || sockets != 1 {
		t.Fatalf("released=%d sockets=%d, want exactly one terminal receipt and one retirement", released, sockets)
	}
}

package desync

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

// retainedTestEngine builds a packet-capable engine with an explicit per-engine
// lease bound. The bound is a test-owned value: there is no runtime knob.
func retainedTestEngine(t *testing.T, maxLeases int) (*Engine, *testBackend) {
	t.Helper()
	backend := &testBackend{name: "test"}
	limits := defaultLimits()
	limits.MaxLeases = maxLeases
	engine, err := NewEngine(&Config{Limits: limits}, backend)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine, backend
}

func retainedTCPIntent() Intent {
	return Intent{
		Family:      FamilyIPv4,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443"),
	}
}

func retainedNewAttempt(t *testing.T, engine *Engine) *Lease {
	t.Helper()
	lease, err := engine.NewAttempt(retainedTCPIntent())
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	return lease
}

// R01/R06/R11 (engine scope): a closed attempt with a native reference keeps its
// original charged slot. Closing the lease does not release it, closing the
// engine does not release it, and the release callback is the only path that
// removes it.
func TestRetainedAdmissionChargesOneSlotUntilRelease(t *testing.T) {
	engine, _ := retainedTestEngine(t, 1)
	lease := retainedNewAttempt(t, engine)
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("ActiveLeases after admission = %d, want 1", got)
	}
	release, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("ActiveLeases after retained close = %d, want charged tombstone 1", got)
	}
	_, err = engine.NewAttempt(retainedTCPIntent())
	if !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("second attempt error = %v, want ErrAdmissionRefused", err)
	}
	if err == nil || !strings.Contains(err.Error(), "active lease limit reached (1)") {
		t.Fatalf("capacity refusal lost its actionable reason: %v", err)
	}
	if err = engine.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("ActiveLeases after engine close with native hold = %d, want 1", got)
	}
	// Repeated Close is idempotent and must not wait for the native receipt.
	if err = lease.Close(nil); err != nil {
		t.Fatalf("repeated Lease.Close: %v", err)
	}
	release()
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("ActiveLeases after native release = %d, want 0", got)
	}
	release()
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("repeated release undercounted the slot: ActiveLeases = %d", got)
	}
	_, err = engine.NewAttempt(retainedTCPIntent())
	if !errors.Is(err, ErrAdmissionRefused) || !errors.Is(err, errEngineClosed) {
		t.Fatalf("attempt after engine close = %v, want refusal classified as engine closed", err)
	}
}

// R05: each hold is discharged exactly once and a duplicate release cannot
// discharge a different hold or produce a negative count.
func TestNativeHoldReleaseExactlyOnce(t *testing.T) {
	engine, _ := retainedTestEngine(t, 1)
	lease := retainedNewAttempt(t, engine)
	first, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("first AcquireNativeHold: %v", err)
	}
	second, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("second AcquireNativeHold: %v", err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	first()
	first()
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("ActiveLeases after one of two releases = %d, want 1", got)
	}
	second()
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("ActiveLeases after both releases = %d, want 0", got)
	}
	second()
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("duplicate second release changed the charge: %d", got)
	}
}

// R11/R15: acquisition is refused after the lease gate or the engine closed,
// with the existing reason preserved and ErrAdmissionRefused classification.
func TestNativeHoldRefusalClassification(t *testing.T) {
	engine, _ := retainedTestEngine(t, 1)
	lease := retainedNewAttempt(t, engine)
	if err := lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	if _, err := lease.AcquireNativeHold(); !errors.Is(err, ErrAdmissionRefused) || !errors.Is(err, errLeaseClosed) {
		t.Fatalf("hold after lease close = %v, want refusal classified as lease closed", err)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if _, err := lease.AcquireNativeHold(); !errors.Is(err, ErrAdmissionRefused) || !errors.Is(err, errEngineClosed) {
		t.Fatalf("hold after engine close = %v, want refusal classified as engine closed", err)
	}
	closedEngine, _ := retainedTestEngine(t, 1)
	closedLease := retainedNewAttempt(t, closedEngine)
	if err := closedEngine.Close(); err != nil {
		t.Fatalf("closedEngine.Close: %v", err)
	}
	if _, err := closedLease.AcquireNativeHold(); !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("hold on closed engine lease = %v, want admission refusal", err)
	}
}

// R02: the state-only production owner has the admission role but no packet
// capability. Its leases charge and retain exactly like a packet lease, and its
// default bound stays the existing 4096.
func TestStateOnlyEngineAdmissionRole(t *testing.T) {
	engine, err := NewStateEngine(nil, nil)
	if err == nil {
		t.Fatalf("NewStateEngine(nil) unexpectedly succeeded")
	}
	engine, err = NewStateEngine(&option.DirectDesyncOptions{}, nil)
	if err != nil {
		t.Fatalf("NewStateEngine: %v", err)
	}
	defer engine.Close()
	if engine.PacketEnabled() {
		t.Fatalf("state-only engine reports packet capability")
	}
	if engine.limits.MaxLeases != 4096 {
		t.Fatalf("state-only default MaxLeases = %d, want 4096", engine.limits.MaxLeases)
	}
	lease := retainedNewAttempt(t, engine)
	if lease.PacketEnabled() {
		t.Fatalf("state-only lease reports packet capability")
	}
	release, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("state-only AcquireNativeHold: %v", err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("state-only Lease.Close: %v", err)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("state-only retained charge = %d, want 1", got)
	}
	release()
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("state-only charge after release = %d, want 0", got)
	}
}

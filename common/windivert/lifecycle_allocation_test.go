package windivert

// W3 allocation regression for the close-versus-registration gate. Registering
// one admitted native I/O must not allocate a per-operation object: the gate
// keeps the small registration record (the armed flag) inside its pending map,
// which the Windows lanes hit once per DeviceIoControl/OVERLAPPED operation.
// The same begin/arm/end sequence stays behaviorally identical, so the checks
// below also pin membership, the armed transition and operation ownership.

import (
	"testing"
	"time"
)

// TestIOLifecycleRegistrationDoesNotAllocate measures the exact begin/arm/end
// cycle of one registered native operation with standard library instrumentation.
// A pre-created pointer key is used so the measured allocations can only come
// from the registration record itself, never from forming the key.
func TestIOLifecycleRegistrationDoesNotAllocate(t *testing.T) {
	gate := newIOLifecycle(time.Second, nil, func() error { return nil })
	defer func() {
		if err := gate.Close(); err != nil {
			t.Fatalf("close after the registration cycles failed: %v", err)
		}
	}()
	key := &struct{ lane string }{lane: "recv"}

	// Membership and duplicate-key behaviour are the map's own semantics and are
	// unchanged by the value representation: a repeated registration for the same
	// key replaces the record, and a single end removes it.
	if err := gate.begin(key); err != nil {
		t.Fatalf("first begin refused an open gate: %v", err)
	}
	if err := gate.begin(key); err != nil {
		t.Fatalf("duplicate begin refused an open gate: %v", err)
	}
	if registered := len(gate.pending); registered != 1 {
		t.Fatalf("duplicate registration left %d entries, want 1", registered)
	}
	gate.end(key)
	if registered := len(gate.pending); registered != 0 {
		t.Fatalf("end of a duplicated key left %d entries, want 0", registered)
	}

	var cycles int
	cycle := func() {
		if err := gate.begin(key); err != nil {
			t.Fatalf("begin refused an open gate: %v", err)
		}
		operation, loaded := gate.pending[key]
		if !loaded {
			t.Fatal("begin did not register the operation")
		}
		if operation.armed {
			t.Fatal("a freshly registered operation reported itself armed")
		}
		if closed := gate.arm(key); closed {
			t.Fatal("arm reported a closed gate")
		}
		operation, loaded = gate.pending[key]
		if !loaded {
			t.Fatal("arm lost the registered operation")
		}
		if !operation.armed {
			t.Fatal("arm did not publish the armed transition")
		}
		gate.end(key)
		if _, stillRegistered := gate.pending[key]; stillRegistered {
			t.Fatal("end left the operation registered")
		}
		cycles++
	}

	// Small finite count: AllocsPerRun warms the cycle once and then runs it
	// exactly this many times, so a warmed steady state is averaged without any
	// benchmark platform or long loop.
	const runs = 200
	allocs := testing.AllocsPerRun(runs, cycle)
	if cycles != runs+1 {
		t.Fatalf("registration cycle ran %d times, want %d: operations were lost", cycles, runs+1)
	}
	if allocs != 0 {
		t.Fatalf("begin/arm/end allocated %.2f objects per admitted native I/O, want 0", allocs)
	}
}

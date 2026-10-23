//go:build windows

package dialer

import (
	"errors"
	"net"
	"testing"

	"github.com/sagernet/sing-box/common/desync"

	"golang.org/x/sys/windows"
)

// TestWA1AttemptRetirementKeepsChargeForUnresolvedTemporaryDescriptor is the
// SEC346-S1 regression. A successful close of the original descriptor O is not
// proof that the attempt retired: a readiness probe P, the adoption carrier C
// or a failed duplicate of the same attempt may still be unresolved. Before the
// fix, attemptRetirement.retire returned as soon as O closed successfully, so
// the deferred admission release ran and the unresolved temporary descriptor
// became uncharged even though its numeric handle was never proven released.
//
// The obligations below are produced by the actual production retirement
// functions through their documented native seams, not hand-built errors, and
// the charge is the real Engine MaxLeases=1 admission of the same attempt.
func TestWA1AttemptRetirementKeepsChargeForUnresolvedTemporaryDescriptor(t *testing.T) {
	ambiguous := errors.New("injected ambiguous close failure")
	original := windows.Handle(0x42)

	readinessObligation := func(t *testing.T) error {
		t.Helper()
		originalProbe := duplicateProbe
		originalClose := closeCarrierSocket
		t.Cleanup(func() {
			duplicateProbe = originalProbe
			closeCarrierSocket = originalClose
		})
		duplicateProbe = func(windows.Handle) (windows.Handle, error) { return windows.Handle(0x77), nil }
		closeCarrierSocket = func(windows.Handle) error { return ambiguous }
		_, err := probeConnectedContext(original)
		return err
	}

	carrierObligation := func(t *testing.T) error {
		t.Helper()
		installAdoptionSeams(t, windows.Handle(0x99), nil, ambiguous)
		_, err := adoptConnectedSocket(original)
		return err
	}

	failedDuplicateObligation := func(t *testing.T) error {
		t.Helper()
		originalClose := closeCarrierSocket
		t.Cleanup(func() { closeCarrierSocket = originalClose })
		closeCarrierSocket = func(windows.Handle) error { return ambiguous }
		return retireFailedDuplicate(windows.Handle(0x55), errors.New("injected duplicate validation failure"))
	}

	unresolvedCases := []struct {
		name       string
		obligation func(*testing.T) error
	}{
		{"readiness-probe-ambiguous", readinessObligation},
		{"carrier-ambiguous", carrierObligation},
		{"failed-duplicate-ambiguous", failedDuplicateObligation},
	}
	for _, testCase := range unresolvedCases {
		t.Run(testCase.name, func(t *testing.T) {
			obligation := testCase.obligation(t)
			if !hasUnresolvedRetirement(obligation) {
				t.Fatalf("fixture obligation = %v, want a production unresolved-retirement token", obligation)
			}
			// The original descriptor O closes successfully: only the
			// temporary descriptor obligation is left.
			calls := installOriginalCloseSeam(t)
			engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
			defer engine.Close()
			adopted, peer := net.Pipe()
			defer peer.Close()
			state := attemptRetirement{handle: original, conn: adopted, holdOwned: true, err: obligation}
			state.retire()
			// Reproduce the production deferred decision exactly: the hold
			// is released only while the attempt still owns it.
			if state.holdOwned {
				hold()
			}
			if len(*calls) != 1 {
				t.Fatalf("original closesocket calls = %v, want exactly one proven close", *calls)
			}
			if !errors.Is(state.err, obligation) {
				t.Fatalf("retirement error = %v, want the unresolved obligation preserved", state.err)
			}
			if state.conn != nil {
				t.Fatal("an unresolved temporary descriptor published the adopted connection")
			}
			if _, err := adopted.Read(make([]byte, 1)); err == nil {
				t.Fatal("the adopted connection was not rolled back")
			}
			if got := discharges.Load(); got != 0 {
				t.Fatalf("native hold discharged %d time(s) despite an unresolved temporary descriptor", got)
			}
			if err := admitted.Close(state.err); err != nil {
				t.Fatalf("attempt lease Close: %v", err)
			}
			if active := engine.ActiveLeases(); active != 1 {
				t.Fatalf("active leases = %d after the caller closed its lease, want the kept charge", active)
			}
			if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); !errors.Is(err, desync.ErrAdmissionRefused) {
				t.Fatalf("replacement attempt error = %v, want an admission refusal while the charge is unresolved", err)
			}
			if err := engine.Close(); err != nil {
				t.Fatalf("Engine.Close: %v", err)
			}
			if active := engine.ActiveLeases(); active != 1 {
				t.Fatalf("active leases = %d after Engine.Close, want the unresolved tombstone", active)
			}
			if got := discharges.Load(); got != 0 {
				t.Fatalf("native hold discharged %d time(s) after Engine.Close", got)
			}
		})
	}

	// Positive control: an ambiguous original descriptor keeps the charge,
	// exactly as before this correction (successful O is not required).
	t.Run("original-ambiguous-control", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, ambiguous)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		state := attemptRetirement{handle: original, holdOwned: true}
		state.retire()
		if state.holdOwned {
			hold()
		}
		if len(*calls) != 1 {
			t.Fatalf("original closesocket calls = %v, want no blind retry", *calls)
		}
		if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); !errors.Is(err, desync.ErrAdmissionRefused) {
			t.Fatalf("replacement attempt error = %v, want an admission refusal", err)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 1 || discharges.Load() != 0 {
			t.Fatalf("active=%d discharges=%d, want the kept charge of an ambiguous original", active, discharges.Load())
		}
	})

	// Positive control: a fully proven attempt discharges its single charge
	// exactly once.
	t.Run("all-proven-control", func(t *testing.T) {
		installOriginalCloseSeam(t)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		state := attemptRetirement{handle: original, holdOwned: true}
		state.retire()
		if state.holdOwned {
			hold()
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one proven discharge", got)
		}
		if err := admitted.Close(nil); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after a proven retirement, want 0", active)
		}
		if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); err != nil {
			t.Fatalf("replacement attempt after a proven retirement: %v", err)
		}
	})

	// Positive control: the documented WSAEWOULDBLOCK owner retry proves the
	// release, so the charge may be discharged while the transient close error
	// stays reported and no connection is published.
	t.Run("would-block-then-proven-control", func(t *testing.T) {
		installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		adopted, peer := net.Pipe()
		defer peer.Close()
		state := attemptRetirement{handle: original, conn: adopted, holdOwned: true}
		state.retire()
		if state.holdOwned {
			hold()
		}
		if !errors.Is(state.err, windows.WSAEWOULDBLOCK) {
			t.Fatalf("retirement error = %v, want the transient close error preserved", state.err)
		}
		if hasUnresolvedRetirement(state.err) {
			t.Fatalf("retirement error = %v, want a proven release classified as resolved", state.err)
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one proven discharge", got)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after the proven owner retry, want 0", active)
		}
	})
}

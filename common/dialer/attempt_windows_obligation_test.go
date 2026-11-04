//go:build windows

package dialer

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"

	"golang.org/x/sys/windows"
)

// TestWA1AttemptRetirementKeepsChargeForUnresolvedTemporaryDescriptor is the
// SEC346-S1 regression. A successful close of the original descriptor O is not
// proof that the attempt retired: the adoption carrier C, the unpublished netFD
// or a failed duplicate of the same attempt may still be unresolved. The
// obligations below are produced by the actual production adoption bridge and
// retirement functions through their documented native seams, and the charge is
// the real Engine MaxLeases=1 admission of the same attempt.
func TestWA1AttemptRetirementKeepsChargeForUnresolvedTemporaryDescriptor(t *testing.T) {
	ambiguous := errors.New("injected ambiguous close failure")
	original := windows.Handle(0x42)
	remainderWriteError := errors.New("injected remainder write failure")
	remainderRollbackError := errors.New("injected remainder rollback failure")
	remainderPayload := []byte("abcdef")

	contextMissObligation := func(t *testing.T) error {
		t.Helper()
		seams := installAdoptionSeams(t, windows.Handle(0x99), nil)
		seams.closeErrors = []error{ambiguous}
		duplicateForAdoption = func(windows.Handle) (windows.Handle, error) {
			// The production retirement helper creates the obligation: the
			// carrier born without a connected context cannot be retired.
			return 0, retireFailedDuplicate(windows.Handle(0x77), &connectedContextNotVisible{cause: errors.New("injected missing connected context")})
		}
		_, err := adoptConnectedSocket(original)
		return err
	}

	// A failed address observation inside the direct bridge closes the raw
	// carrier; its ambiguous close result is the unresolved obligation.
	carrierObligation := func(t *testing.T) error {
		t.Helper()
		scripted := newScriptedSocketAdoption()
		scripted.addressesErr = errors.New("injected address observation failure")
		closeSeam := closeCarrierSocket
		t.Cleanup(func() { closeCarrierSocket = closeSeam })
		closeCarrierSocket = func(windows.Handle) error { return ambiguous }
		_, err := bridgeOwnedCarrier(scripted.api(), windows.Handle(0x99), time.Now().Add(time.Second))
		return err
	}

	failedDuplicateObligation := func(t *testing.T) error {
		t.Helper()
		originalClose := closeCarrierSocket
		t.Cleanup(func() { closeCarrierSocket = originalClose })
		closeCarrierSocket = func(windows.Handle) error { return ambiguous }
		return retireFailedDuplicate(windows.Handle(0x55), errors.New("injected duplicate validation failure"))
	}

	// A carrier that becomes ready only after the shared acquisition budget is
	// rejected by the production late-carrier path; its unproven retirement is
	// the obligation that must keep this attempt charged.
	lateCarrierObligation := func(t *testing.T) error {
		t.Helper()
		lateCarrier := windows.Handle(0xa1)
		start := time.Now()
		seams := installAdoptionSeams(t, lateCarrier, nil)
		seams.closeErrors = []error{ambiguous}
		installAdoptionClock(t, start, start.Add(time.Millisecond), start.Add(adoptContextBudget))
		duplicateForAdoption = func(windows.Handle) (windows.Handle, error) {
			return lateCarrier, nil
		}
		_, err := adoptConnectedSocket(original)
		return err
	}

	// DA-INIT Engine composition: the actual bridge routine observes an init
	// failure and a failed FD.Close, so the known carrier keeps the charge.
	initFailureObligation := func(t *testing.T) error {
		t.Helper()
		scripted := newScriptedSocketAdoption()
		scripted.initErr = errors.New("injected netFD init failure")
		scripted.closeFDErrors = []error{ambiguous}
		_, err := bridgeOwnedCarrier(scripted.api(), windows.Handle(0x99), time.Now().Add(time.Second))
		if !hasUnresolvedRetirement(err) {
			t.Fatalf("bridge error = %v, want the unresolved FD cleanup obligation", err)
		}
		return err
	}

	// DA-LATE Engine composition: the late success is rolled back by the
	// bridge and its bad adopted close keeps the charge.
	lateBadAdoptedCloseObligation := func(t *testing.T) error {
		t.Helper()
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		scripted := newScriptedSocketAdoption()
		sentinel := errors.New("injected late adopted rollback failure")
		scripted.conn = &failingCloseConn{Conn: client, closeErr: sentinel}
		start := time.Now()
		installAdoptionClock(t, start, start.Add(adoptContextBudget))
		_, err := bridgeOwnedCarrier(scripted.api(), windows.Handle(0x99), start.Add(adoptContextBudget))
		if scripted.conn.(*failingCloseConn).closes != 1 {
			t.Fatalf("adopted connection Close calls = %d, want exactly one rollback", scripted.conn.(*failingCloseConn).closes)
		}
		assertOpaqueAdoptionRetirement(t, err, adoptionRetirementStageAdoptedRollback, sentinel)
		return err
	}

	// DA-PROGRESS Engine composition: the actual remainder helper observes a
	// write failure and its one-shot adopted rollback Close also fails, so the
	// returned error keeps the accepted progress, both exact causes and the
	// existing opaque marker. The adopted connection was rolled back exactly
	// once by that helper and is not published.
	var remainderAdopted *failingCloseConn
	remainderBadRollbackObligation := func(t *testing.T) error {
		t.Helper()
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		partial := &partialWriteConn{Conn: client, writeN: 0, writeErr: remainderWriteError}
		badRollback := &failingCloseConn{Conn: partial, closeErr: remainderRollbackError}
		written, err := writeAdoptedRemainder(badRollback, remainderPayload, 2)
		if written != 2 {
			t.Fatalf("written = %d, want the accepted count preserved", written)
		}
		if !errors.Is(err, remainderWriteError) || !errors.Is(err, remainderRollbackError) {
			t.Fatalf("error = %v, want both the write and rollback identities", err)
		}
		if badRollback.closes != 1 {
			t.Fatalf("adopted Close calls = %d, want exactly one remainder rollback", badRollback.closes)
		}
		assertOpaqueAdoptionRetirement(t, err, adoptionRetirementStageAdoptedRollback, remainderRollbackError)
		remainderAdopted = badRollback
		return err
	}

	unresolvedCases := []struct {
		name       string
		deferred   bool
		obligation func(*testing.T) error
		// rollbackCloses, when set, reads the Close count of the adopted
		// connection whose one-shot remainder rollback failed. The shared body
		// then proves that retirement, the lease close and two Engine.Close
		// calls never close that connection a second time.
		rollbackCloses func() int
	}{
		{"carrier-context-ambiguous", true, contextMissObligation, nil},
		{"carrier-address-close-ambiguous", true, carrierObligation, nil},
		{"failed-duplicate-ambiguous", true, failedDuplicateObligation, nil},
		{"carrier-budget-expired-ambiguous", true, lateCarrierObligation, nil},
		{"netfd-init-failure-bad-close", false, initFailureObligation, nil},
		{"late-success-bad-adopted-close", false, lateBadAdoptedCloseObligation, nil},
		{"remainder-write-bad-rollback", false, remainderBadRollbackObligation, func() int { return remainderAdopted.closes }},
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
			var adopted, peer net.Conn
			if testCase.deferred {
				adopted, peer = net.Pipe()
				defer peer.Close()
			}
			state := attemptRetirement{handle: original, conn: adopted, holdOwned: true, err: obligation}
			// A remainder-generated obligation already rolled its adopted
			// connection back once; retirement and the later closes must never
			// close that connection again.
			checkRemainderRollback := func(stage string) {
				if testCase.rollbackCloses == nil {
					return
				}
				if got := testCase.rollbackCloses(); got != 1 {
					t.Fatalf("adopted connection Close calls = %d %s, want exactly one remainder rollback", got, stage)
				}
			}
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
			checkRemainderRollback("after retirement")
			if testCase.deferred {
				if _, err := adopted.Read(make([]byte, 1)); err == nil {
					t.Fatal("the adopted connection was not rolled back")
				}
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
			checkRemainderRollback("after the attempt lease close")
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
			// A repeated Engine.Close must be inert: it may not discharge the
			// native hold, remove the retained tombstone, or reopen admission.
			if err := engine.Close(); err != nil {
				t.Fatalf("second Engine.Close: %v", err)
			}
			if !engine.Closed() {
				t.Fatal("engine reports open after two Close calls")
			}
			if active := engine.ActiveLeases(); active != 1 {
				t.Fatalf("active leases = %d after the second Engine.Close, want the unresolved tombstone", active)
			}
			if got := discharges.Load(); got != 0 {
				t.Fatalf("native hold discharged %d time(s) after the second Engine.Close", got)
			}
			if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); !errors.Is(err, desync.ErrAdmissionRefused) {
				t.Fatalf("replacement attempt error = %v, want an admission refusal after the second Engine.Close", err)
			}
			checkRemainderRollback("after two Engine.Close calls")
		})
	}

	// DA-PROGRESS proven control: the same real remainder helper with a working
	// one-shot adopted rollback keeps the write failure and the actual progress,
	// closes the adopted connection exactly once, carries no unresolved marker,
	// retires the original descriptor once and discharges the attempt's single
	// charge through the ordinary Engine lifecycle.
	t.Run("remainder-write-good-rollback-proven-control", func(t *testing.T) {
		client, peer := net.Pipe()
		t.Cleanup(func() { _ = peer.Close() })
		partial := &partialWriteConn{Conn: client, writeN: 0, writeErr: remainderWriteError}
		written, err := writeAdoptedRemainder(partial, remainderPayload, 2)
		if written != 2 {
			t.Fatalf("written = %d, want the accepted count preserved", written)
		}
		if !errors.Is(err, remainderWriteError) {
			t.Fatalf("error = %v, want the write failure preserved", err)
		}
		if partial.closes != 1 {
			t.Fatalf("adopted Close calls = %d, want exactly one rollback", partial.closes)
		}
		assertNoOpaqueAdoptionRetirement(t, err)
		calls := installOriginalCloseSeam(t)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		state := attemptRetirement{handle: original, holdOwned: true, err: err}
		state.retire()
		if state.conn != nil {
			t.Fatal("a failed remainder write must not publish the adopted connection")
		}
		if len(*calls) != 1 {
			t.Fatalf("original closesocket calls = %v, want exactly one proven close", *calls)
		}
		if !errors.Is(state.err, remainderWriteError) || hasUnresolvedRetirement(state.err) {
			t.Fatalf("retirement error = %v, want the write failure kept and no unresolved marker", state.err)
		}
		if partial.closes != 1 {
			t.Fatalf("adopted Close calls = %d after retirement, want the one proven rollback", partial.closes)
		}
		if state.holdOwned {
			hold()
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one", got)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after a proven remainder rollback, want 0", active)
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("Engine.Close: %v", err)
		}
		if !engine.Closed() || engine.ActiveLeases() != 0 || discharges.Load() != 1 {
			t.Fatalf("closed=%v active=%d discharges=%d after Engine.Close, want the proven retirement", engine.Closed(), engine.ActiveLeases(), discharges.Load())
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("second Engine.Close: %v", err)
		}
		if !engine.Closed() || engine.ActiveLeases() != 0 || discharges.Load() != 1 {
			t.Fatalf("closed=%v active=%d discharges=%d after the second Engine.Close", engine.Closed(), engine.ActiveLeases(), discharges.Load())
		}
		if partial.closes != 1 {
			t.Fatalf("adopted Close calls = %d after two Engine.Close calls, want the one proven rollback", partial.closes)
		}
		if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); !errors.Is(err, desync.ErrAdmissionRefused) {
			t.Fatalf("replacement attempt error = %v, want the existing closed-engine refusal", err)
		}
	})

	// R3-ORIGINAL-PROVEN-BAD-CLOSE: the original socket's documented
	// would-block outcome was proven by its owner retry and the adopted
	// rollback failure used to be silently dropped. The joined chain keeps the
	// attempt error, the transient original diagnostic and the rollback
	// failure, the rollback happens exactly once, and the charge stays.
	t.Run("original-wouldblock-proven-bad-adopted-close", func(t *testing.T) {
		attemptErr := errors.New("injected attempt error")
		sentinel := errors.New("injected adopted connection close failure")
		calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		client, peer := net.Pipe()
		defer peer.Close()
		adopted := &failingCloseConn{Conn: client, closeErr: sentinel}
		state := attemptRetirement{handle: original, conn: adopted, holdOwned: true, err: attemptErr}
		state.retire()
		if state.holdOwned {
			hold()
		}
		if len(*calls) != 2 {
			t.Fatalf("original closesocket calls = %v, want the attempt plus exactly one owner retry", *calls)
		}
		if adopted.closes != 1 {
			t.Fatalf("adopted connection Close calls = %d, want exactly one rollback", adopted.closes)
		}
		if state.conn != nil {
			t.Fatal("an unproven adopted rollback must not publish the connection")
		}
		if !errors.Is(state.err, attemptErr) || !errors.Is(state.err, windows.WSAEWOULDBLOCK) || !errors.Is(state.err, sentinel) {
			t.Fatalf("retirement error = %v, want the attempt, transient original and rollback causes joined", state.err)
		}
		assertOpaqueAdoptionRetirement(t, state.err, adoptionRetirementStageAdoptedRollback, sentinel)
		if got := discharges.Load(); got != 0 {
			t.Fatalf("native hold discharged %d time(s) despite an unproven adopted rollback", got)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 1 {
			t.Fatalf("active leases = %d, want the kept charge", active)
		}
		if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); !errors.Is(err, desync.ErrAdmissionRefused) {
			t.Fatalf("replacement attempt error = %v, want an admission refusal", err)
		}
		if err := engine.Close(); err != nil {
			t.Fatalf("Engine.Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 1 || discharges.Load() != 0 {
			t.Fatalf("active=%d discharges=%d after Engine.Close, want the retained tombstone", active, discharges.Load())
		}
		// A second Engine.Close must keep the tombstone and the native hold.
		if err := engine.Close(); err != nil {
			t.Fatalf("second Engine.Close: %v", err)
		}
		if !engine.Closed() {
			t.Fatal("engine reports open after two Close calls")
		}
		if active := engine.ActiveLeases(); active != 1 || discharges.Load() != 0 {
			t.Fatalf("active=%d discharges=%d after the second Engine.Close, want the retained tombstone", active, discharges.Load())
		}
		if _, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP}); !errors.Is(err, desync.ErrAdmissionRefused) {
			t.Fatalf("replacement attempt error = %v, want an admission refusal after the second Engine.Close", err)
		}
	})

	// R3-PROVEN-CONTROLS: the same late/init/original branches with a proven
	// cleanup keep their causes, carry no opaque marker and discharge their
	// single charge exactly once.
	t.Run("timely-success-remains-usable", func(t *testing.T) {
		seams := installAdoptionSeams(t, windows.Handle(0x99), nil)
		installAdoptionClock(t, time.Now())
		conn, err := adoptConnectedSocket(original)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if conn == nil || conn != seams.conn {
			t.Fatalf("returned connection = %v, want the adopted connection", conn)
		}
		// The timely success stays usable and is not rolled back.
		received := make(chan error, 1)
		go func() {
			buffer := make([]byte, 1)
			_, readErr := seams.peer.Read(buffer)
			if readErr == nil && buffer[0] != 'x' {
				readErr = errors.New("unexpected payload")
			}
			received <- readErr
		}()
		if _, writeErr := conn.Write([]byte("x")); writeErr != nil {
			_ = seams.peer.Close()
			<-received
			t.Fatalf("timely adopted connection unusable: %v", writeErr)
		}
		if readErr := <-received; readErr != nil {
			t.Fatalf("timely adopted payload: %v", readErr)
		}
		calls := installOriginalCloseSeam(t)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		state := attemptRetirement{handle: original, conn: conn, holdOwned: true}
		state.retire()
		if state.conn != conn || state.err != nil || !state.holdOwned {
			t.Fatalf("state = %+v, want the timely connection kept and the charge dischargeable", state)
		}
		if len(*calls) != 1 {
			t.Fatalf("original closesocket calls = %v, want exactly one proven close", *calls)
		}
		assertNoOpaqueAdoptionRetirement(t, state.err)
		if state.holdOwned {
			hold()
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one", got)
		}
		if err := admitted.Close(nil); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after a timely success, want 0", active)
		}
		_ = conn.Close()
	})

	t.Run("late-success-good-rollback-proven-control", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		scripted := newScriptedSocketAdoption()
		scripted.conn = client
		start := time.Now()
		installAdoptionClock(t, start, start.Add(adoptContextBudget))
		conn, err := bridgeOwnedCarrier(scripted.api(), windows.Handle(0x99), start.Add(adoptContextBudget))
		if conn != nil || err == nil {
			t.Fatalf("conn = %v, err = %v, want an unpublished late success", conn, err)
		}
		if !strings.Contains(err.Error(), "adoption completed after the adoption budget expired") {
			t.Fatalf("error = %v, want the late-success cause", err)
		}
		if _, writeErr := client.Write([]byte("x")); writeErr == nil {
			t.Fatal("the late adopted connection was not rolled back")
		}
		assertNoOpaqueAdoptionRetirement(t, err)
		calls := installOriginalCloseSeam(t)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		state := attemptRetirement{handle: original, holdOwned: true, err: err}
		state.retire()
		if state.holdOwned {
			hold()
		}
		if len(*calls) != 1 {
			t.Fatalf("original closesocket calls = %v, want exactly one proven close", *calls)
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one", got)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after the proven branch, want 0", active)
		}
	})

	t.Run("init-failure-good-close-proven-control", func(t *testing.T) {
		scripted := newScriptedSocketAdoption()
		scripted.initErr = errors.New("injected netFD init failure")
		closeCalls := installCarrierCloseSeam(t)
		conn, err := bridgeOwnedCarrier(scripted.api(), windows.Handle(0x99), time.Now().Add(time.Second))
		if conn != nil || err == nil {
			t.Fatalf("conn = %v, err = %v, want an unpublished init failure", conn, err)
		}
		if scripted.closeFDCalls != 1 || len(*closeCalls) != 0 {
			t.Fatalf("FD closes = %d raw closes = %v, want exactly one FD cleanup", scripted.closeFDCalls, *closeCalls)
		}
		assertNoOpaqueAdoptionRetirement(t, err)
		if hasUnresolvedRetirement(err) {
			t.Fatalf("error = %v, want no unresolved obligation after a proven FD cleanup", err)
		}
		calls := installOriginalCloseSeam(t)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		state := attemptRetirement{handle: original, holdOwned: true, err: err}
		state.retire()
		if state.holdOwned {
			hold()
		}
		if len(*calls) != 1 {
			t.Fatalf("original closesocket calls = %v, want exactly one proven close", *calls)
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one", got)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after the proven branch, want 0", active)
		}
	})

	t.Run("original-diagnostic-good-rollback-proven-control", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		engine, admitted, hold, discharges := newRetainedRetirementEngine(t)
		defer engine.Close()
		client, peer := net.Pipe()
		defer peer.Close()
		state := attemptRetirement{handle: original, conn: client, holdOwned: true}
		state.retire()
		if state.conn != nil {
			t.Fatal("a diagnostic close result still rolls the connection back")
		}
		if len(*calls) != 2 {
			t.Fatalf("original closesocket calls = %v, want the attempt plus exactly one owner retry", *calls)
		}
		if !errors.Is(state.err, windows.WSAEWOULDBLOCK) {
			t.Fatalf("retirement error = %v, want the transient original diagnostic preserved", state.err)
		}
		if hasUnresolvedRetirement(state.err) {
			t.Fatalf("retirement error = %v, want no unresolved marker after a proven retry", state.err)
		}
		if _, writeErr := client.Write([]byte("x")); writeErr == nil {
			t.Fatal("the rolled-back connection is still usable")
		}
		if state.holdOwned {
			hold()
		}
		if got := discharges.Load(); got != 1 {
			t.Fatalf("native hold discharged %d time(s), want exactly one", got)
		}
		if err := admitted.Close(state.err); err != nil {
			t.Fatalf("attempt lease Close: %v", err)
		}
		if active := engine.ActiveLeases(); active != 0 {
			t.Fatalf("active leases = %d after the proven branch, want 0", active)
		}
	})

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

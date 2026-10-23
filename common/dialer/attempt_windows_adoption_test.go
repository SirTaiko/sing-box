//go:build windows

package dialer

import (
	"errors"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// fakeAdoptionFile records the single net.FileConn adoption seam of
// adoptConnectedSocket. The handle it reports is the carrier duplicate the
// production code created, so the test can prove the original handle never
// reaches the carrier constructor.
type fakeAdoptionFile struct {
	handle     windows.Handle
	events     *[]string
	conn       net.Conn
	adoptErr   error
	closeErr   error
	closeCalls int
}

func (f *fakeAdoptionFile) adopt() (net.Conn, error) {
	*f.events = append(*f.events, "adopt")
	if f.adoptErr != nil {
		return nil, f.adoptErr
	}
	return f.conn, nil
}

func (f *fakeAdoptionFile) close() error {
	*f.events = append(*f.events, "close-carrier")
	f.closeCalls++
	return f.closeErr
}

// adoptionSeams installs the fake duplication/constructor/close seams for one
// subtest and restores the production values afterwards.
type adoptionSeams struct {
	carrier     windows.Handle
	file        *fakeAdoptionFile
	dupInputs   []windows.Handle
	ctorInputs  []windows.Handle
	closeInputs []windows.Handle
	closeErrors []error
	closeCalls  int
	// peer is the other end of the adopted duplex fixture. It lets a test
	// complete a write deterministically instead of blocking forever on an
	// unread net.Pipe.
	peer net.Conn
}

func installAdoptionSeams(t *testing.T, carrier windows.Handle, adoptErr, closeErr error) *adoptionSeams {
	t.Helper()
	seams := &adoptionSeams{carrier: carrier}
	var events []string
	// The adopted-connection fixture exists before the constructor is called:
	// subtests that replace the carrier's connection (a rollback that also
	// fails) must be able to install it before the adoption runs, and the
	// constructor stub only records that the production sequence reached it.
	client, server := net.Pipe()
	t.Cleanup(func() { _ = server.Close() })
	seams.peer = server
	seams.file = &fakeAdoptionFile{
		handle:   carrier,
		events:   &events,
		conn:     client,
		adoptErr: adoptErr,
		closeErr: closeErr,
	}
	originalDuplicate := duplicateForAdoption
	originalNewFile := newAdoptionFile
	originalClose := closeCarrierSocket
	t.Cleanup(func() {
		duplicateForAdoption = originalDuplicate
		newAdoptionFile = originalNewFile
		closeCarrierSocket = originalClose
	})
	duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
		seams.dupInputs = append(seams.dupInputs, handle)
		return carrier, nil
	}
	newAdoptionFile = func(handle windows.Handle) (adoptionFile, error) {
		seams.ctorInputs = append(seams.ctorInputs, handle)
		seams.file.handle = handle
		return seams.file, nil
	}
	closeCarrierSocket = func(handle windows.Handle) error {
		seams.closeInputs = append(seams.closeInputs, handle)
		var err error
		if seams.closeCalls < len(seams.closeErrors) {
			err = seams.closeErrors[seams.closeCalls]
		}
		seams.closeCalls++
		return err
	}
	return seams
}

// TestSec328AdoptionCarrierOwnership pins the ownership split of the single
// net.FileConn adoption: the socket-aware carrier File must wrap a dedicated
// duplicate, the adoption must happen before the carrier is retired, the
// carrier must be retired exactly once, and the original handle must never be
// handed to the carrier constructor.
func TestSec328AdoptionCarrierOwnership(t *testing.T) {
	original := windows.Handle(0x42)
	carrier := windows.Handle(0x99)

	t.Run("success", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, nil)
		conn, err := adoptConnectedSocket(original)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(seams.dupInputs) != 1 || seams.dupInputs[0] != original {
			t.Fatalf("duplication inputs = %v, want exactly one call with the original handle", seams.dupInputs)
		}
		if len(seams.ctorInputs) != 1 || seams.ctorInputs[0] != carrier {
			t.Fatalf("constructor inputs = %v, want the carrier duplicate %#x, never the original %#x", seams.ctorInputs, carrier, original)
		}
		if seams.file.closeCalls != 1 {
			t.Fatalf("carrier close calls = %d, want exactly one", seams.file.closeCalls)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("extra closesocket calls = %v, want none after a successful socket-aware File.Close", seams.closeInputs)
		}
		if conn != seams.file.conn {
			t.Fatalf("returned connection = %v, want the adopted connection", conn)
		}
		_ = conn.Close()
	})
}

// TestWA1AdoptionRetirementContract pins the error ownership of the adoption:
// a failed adoption or a failed carrier retirement never publishes a
// connection, every actually created descriptor keeps exactly one owner, and
// simultaneous errors stay visible. Only the documented WSAEWOULDBLOCK outcome
// may be retried, and only through closesocket.
func TestWA1AdoptionRetirementContract(t *testing.T) {
	original := windows.Handle(0x42)
	carrier := windows.Handle(0x99)
	ambiguous := errors.New("injected ambiguous close failure")

	t.Run("adoption-failure-retires-carrier", func(t *testing.T) {
		adoptErr := errors.New("injected duplication failure")
		seams := installAdoptionSeams(t, carrier, adoptErr, nil)
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a failed adoption must not publish a connection")
		}
		if !errors.Is(err, adoptErr) {
			t.Fatalf("error = %v, want the adoption error", err)
		}
		if seams.file.closeCalls != 1 {
			t.Fatalf("carrier close calls = %d, want exactly one", seams.file.closeCalls)
		}
	})

	t.Run("adoption-and-retirement-errors-visible", func(t *testing.T) {
		adoptErr := errors.New("injected duplication failure")
		installAdoptionSeams(t, carrier, adoptErr, ambiguous)
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a failed adoption must not publish a connection")
		}
		if !errors.Is(err, adoptErr) || !errors.Is(err, ambiguous) {
			t.Fatalf("error = %v, want both the adoption and the retirement error", err)
		}
	})

	t.Run("retirement-failure-does-not-publish", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, ambiguous)
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a carrier retirement failure must not publish the adopted connection")
		}
		if err == nil || !strings.Contains(err.Error(), "retire adoption carrier") {
			t.Fatalf("error = %v, want a carrier retirement error", err)
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || unresolved.handle != carrier {
			t.Fatalf("error = %v, want an unresolved-retirement token for the carrier %#x", err, carrier)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("closesocket retries = %v, want none after an ambiguous close error", seams.closeInputs)
		}
		// The adopted connection is rolled back exactly once.
		if _, writeErr := seams.file.conn.Write([]byte("x")); writeErr == nil {
			t.Fatal("the adopted connection must be closed when the carrier cannot be retired")
		}
	})

	t.Run("wouldblock-retries-closesocket", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, windows.WSAEWOULDBLOCK)
		seams.closeErrors = []error{nil}
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a failed carrier retirement must not publish the adopted connection")
		}
		if err == nil {
			t.Fatal("expected the original would-block retirement error")
		}
		if len(seams.closeInputs) != 1 || seams.closeInputs[0] != carrier {
			t.Fatalf("closesocket retries = %v, want exactly one retry of the carrier %#x", seams.closeInputs, carrier)
		}
		var unresolved *unresolvedSocketRetirement
		if errors.As(err, &unresolved) {
			t.Fatalf("error = %v, want no unresolved-retirement token after a successful retry", err)
		}
	})

	t.Run("wouldblock-retry-failure-retains-token", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, windows.WSAEWOULDBLOCK)
		seams.closeErrors = []error{ambiguous}
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a failed carrier retirement must not publish the adopted connection")
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || !errors.Is(err, ambiguous) {
			t.Fatalf("error = %v, want an unresolved-retirement token carrying the retry error", err)
		}
		if len(seams.closeInputs) != 1 {
			t.Fatalf("closesocket retries = %v, want exactly one retry before the ambiguous error stops it", seams.closeInputs)
		}
	})

	t.Run("constructor-rejection-retires-unwrapped-carrier", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, nil)
		ctorErr := errors.New("injected constructor rejection")
		newAdoptionFile = func(handle windows.Handle) (adoptionFile, error) {
			seams.ctorInputs = append(seams.ctorInputs, handle)
			return nil, ctorErr
		}
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a rejected carrier constructor must not publish a connection")
		}
		if !errors.Is(err, ctorErr) {
			t.Fatalf("error = %v, want the constructor error", err)
		}
		if len(seams.closeInputs) != 1 || seams.closeInputs[0] != carrier {
			t.Fatalf("closesocket inputs = %v, want the unwrapped carrier retired once", seams.closeInputs)
		}
	})

	t.Run("duplication-failure-acquires-nothing", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, nil)
		dupErr := errors.New("injected carrier duplication failure")
		duplicateForAdoption = func(handle windows.Handle) (windows.Handle, error) {
			seams.dupInputs = append(seams.dupInputs, handle)
			return 0, dupErr
		}
		conn, err := adoptConnectedSocket(original)
		if conn != nil {
			t.Fatal("a failed carrier duplication must not publish a connection")
		}
		if !errors.Is(err, dupErr) {
			t.Fatalf("error = %v, want the duplication error", err)
		}
		if len(seams.ctorInputs) != 0 {
			t.Fatalf("constructor inputs = %v, want no carrier construction without a descriptor", seams.ctorInputs)
		}
		if len(seams.closeInputs) != 0 {
			t.Fatalf("closesocket inputs = %v, want no close of an unacquired result", seams.closeInputs)
		}
	})

	t.Run("rollback-error-visible", func(t *testing.T) {
		seams := installAdoptionSeams(t, carrier, nil, ambiguous)
		seams.file.conn = &failingCloseConn{Conn: seams.file.conn, closeErr: errors.New("injected rollback failure")}
		_, err := adoptConnectedSocket(original)
		if err == nil || !strings.Contains(err.Error(), "injected rollback failure") {
			t.Fatalf("error = %v, want the rollback failure to stay visible", err)
		}
	})
}

// failingCloseConn makes only Close fail so a rollback error can be observed
// without any socket.
type failingCloseConn struct {
	net.Conn
	closeErr error
}

func (c *failingCloseConn) Close() error {
	_ = c.Conn.Close()
	return c.closeErr
}

// TestWA1SocketAwareConstructorRejectsInvalidHandles pins the fail-closed
// boundary before the hidden constructor: it panics on an invalid handle, so
// the adapter must reject one and leave the descriptor with its current owner.
func TestWA1SocketAwareConstructorRejectsInvalidHandles(t *testing.T) {
	for _, handle := range []windows.Handle{0, windows.InvalidHandle} {
		if _, err := newSocketAdoptionFile(handle); err == nil {
			t.Fatalf("newSocketAdoptionFile(%#x) = nil error, want a rejection", handle)
		}
	}
}

// TestWA1AdoptedConnectionSurvivesGCPressure is the GC/handle-reuse control:
// after a successful adoption the carrier is already retired (once), so no
// generic File finalizer or second close may act on it, and the adopted
// connection stays usable across garbage collection.
//
// The fixture is a real duplex peer: the single write after the GC cycles is
// completed by an owned reader goroutine that is always joined, so the test is
// finite (no unread net.Pipe write exists anywhere in it) and no timeout is
// part of its pass criterion.
func TestWA1AdoptedConnectionSurvivesGCPressure(t *testing.T) {
	original := windows.Handle(0x42)
	carrier := windows.Handle(0x99)
	seams := installAdoptionSeams(t, carrier, nil, nil)
	conn, err := adoptConnectedSocket(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 4; i++ {
		runtime.GC()
		time.Sleep(time.Millisecond)
	}
	if seams.file.closeCalls != 1 {
		t.Fatalf("carrier close calls = %d, want exactly one deterministic retirement", seams.file.closeCalls)
	}
	if len(seams.closeInputs) != 0 {
		t.Fatalf("extra closesocket calls = %v, want none", seams.closeInputs)
	}
	// The peer reads the exact payload and reports the result, so the write
	// below can never block and the reader goroutine is finished before the
	// test returns.
	received := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)
		_, readErr := seams.peer.Read(buffer)
		if readErr == nil && buffer[0] != 'x' {
			readErr = errors.New("unexpected payload")
		}
		received <- readErr
	}()
	_, writeErr := conn.Write([]byte("x"))
	if writeErr != nil {
		_ = seams.peer.Close()
		<-received
		t.Fatalf("adopted connection unusable after GC: %v", writeErr)
	}
	if readErr := <-received; readErr != nil {
		t.Fatalf("adopted connection payload after GC: %v", readErr)
	}
	if err = conn.Close(); err != nil {
		t.Fatalf("close adopted connection: %v", err)
	}
	// Closing the adopted connection is net-owned and must not retire the
	// already-retired carrier a second time.
	if seams.file.closeCalls != 1 || len(seams.closeInputs) != 0 {
		t.Fatalf("carrier close calls = %d, closesocket calls = %v after the adopted close, want one deterministic retirement and no second close", seams.file.closeCalls, seams.closeInputs)
	}
}

// TestWA1ReadinessProbeRetirementStopsSequence pins the probe rule: a probe
// whose closesocket fails is not hidden by starting another probe, and the
// adoption sequence stops with the unresolved descriptor charged to it.
func TestWA1ReadinessProbeRetirementStopsSequence(t *testing.T) {
	original := windows.Handle(0x42)
	originalClose := closeCarrierSocket
	originalDuplicate := duplicateProbe
	t.Cleanup(func() {
		closeCarrierSocket = originalClose
		duplicateProbe = originalDuplicate
	})
	probes := 0
	duplicateProbe = func(handle windows.Handle) (windows.Handle, error) {
		probes++
		return windows.Handle(0x77), nil
	}
	closeCarrierSocket = func(handle windows.Handle) error {
		return errors.New("injected probe close failure")
	}
	err := waitConnectedContext(original)
	var unresolved *unresolvedSocketRetirement
	if !errors.As(err, &unresolved) || unresolved.handle != 0x77 {
		t.Fatalf("error = %v, want an unresolved-retirement token for the probe", err)
	}
	if probes != 1 {
		t.Fatalf("probes = %d, want exactly one: a failed probe retirement must stop the sequence", probes)
	}
}

// TestWA1ProbeDuplicationFailureAcquiresNothing pins the other half of the
// probe rule: a probe whose creation failed never owned a descriptor, so
// nothing may be closed, and the existing bounded observation simply ends
// (the single net.FileConn result stays authoritative).
func TestWA1ProbeDuplicationFailureAcquiresNothing(t *testing.T) {
	originalClose := closeCarrierSocket
	originalProbe := duplicateProbe
	t.Cleanup(func() {
		closeCarrierSocket = originalClose
		duplicateProbe = originalProbe
	})
	probeErr := errors.New("injected probe duplication failure")
	probes := 0
	closes := 0
	duplicateProbe = func(windows.Handle) (windows.Handle, error) {
		probes++
		return 0, probeErr
	}
	closeCarrierSocket = func(windows.Handle) error {
		closes++
		return nil
	}
	if err := waitConnectedContext(windows.Handle(0x42)); err != nil {
		t.Fatalf("error = %v, want the bounded observation to end without a probe-retirement error", err)
	}
	if probes == 0 {
		t.Fatal("the bounded observation never attempted a probe")
	}
	if closes != 0 {
		t.Fatalf("close calls = %d, want no close of an unacquired probe result", closes)
	}
}

// installOriginalCloseSeam replaces the original-socket disposal seam for one
// subtest and records every closesocket it received.
func installOriginalCloseSeam(t *testing.T, errs ...error) *[]windows.Handle {
	t.Helper()
	original := closeOriginalSocket
	t.Cleanup(func() { closeOriginalSocket = original })
	var calls []windows.Handle
	closeOriginalSocket = func(handle windows.Handle) error {
		calls = append(calls, handle)
		if len(calls) <= len(errs) {
			return errs[len(calls)-1]
		}
		return nil
	}
	return &calls
}

// TestWA1OriginalSocketRetirementContract pins the disposal contract of the
// original native socket: exactly one owner and one socket API, a documented
// WSAEWOULDBLOCK outcome retried by that owner, an ambiguous outcome reported
// as an unresolved descriptor instead of a blind numeric retry, and a close
// failure that stays visible.
func TestWA1OriginalSocketRetirementContract(t *testing.T) {
	handle := windows.Handle(0x42)
	ambiguous := errors.New("injected ambiguous original close failure")

	t.Run("proven-release", func(t *testing.T) {
		calls := installOriginalCloseSeam(t)
		if err := retireOriginalSocket(handle); err != nil {
			t.Fatalf("error = %v, want a proven release", err)
		}
		if len(*calls) != 1 || (*calls)[0] != handle {
			t.Fatalf("closesocket calls = %v, want exactly one with %#x", *calls, handle)
		}
	})

	t.Run("wouldblock-retried-then-proven", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		err := retireOriginalSocket(handle)
		if err == nil {
			t.Fatal("a close that reported WSAEWOULDBLOCK must stay visible")
		}
		var unresolved *unresolvedSocketRetirement
		if errors.As(err, &unresolved) {
			t.Fatalf("error = %v, want no unresolved token after a successful retry", err)
		}
		if len(*calls) != 2 {
			t.Fatalf("closesocket calls = %d, want the original attempt plus one retry", len(*calls))
		}
	})

	t.Run("ambiguous-no-retry", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, ambiguous)
		err := retireOriginalSocket(handle)
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || unresolved.handle != handle || !errors.Is(err, ambiguous) {
			t.Fatalf("error = %v, want an unresolved token for %#x carrying the close error", err, handle)
		}
		if len(*calls) != 1 {
			t.Fatalf("closesocket calls = %v, want no blind numeric retry", *calls)
		}
	})

	t.Run("wouldblock-retry-failure-retains-token", func(t *testing.T) {
		calls := installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, ambiguous)
		err := retireOriginalSocket(handle)
		var unresolved *unresolvedSocketRetirement
		if !errors.As(err, &unresolved) || !errors.Is(err, ambiguous) {
			t.Fatalf("error = %v, want an unresolved token carrying the retry error", err)
		}
		if len(*calls) != 2 {
			t.Fatalf("closesocket calls = %d, want one retry before the ambiguous error stops it", len(*calls))
		}
	})
}

// TestWA1AttemptRetirementRollsBackAndKeepsCharge pins what the deferred
// retirement does with the rest of the attempt: an adopted connection is never
// published while the original socket is unretired, an unproven release keeps
// the admission charge instead of faking a released descriptor, and a proven
// release leaves the atomically recorded charge to its existing owner.
func TestWA1AttemptRetirementRollsBackAndKeepsCharge(t *testing.T) {
	handle := windows.Handle(0x42)
	attemptErr := errors.New("injected attempt error")
	ambiguous := errors.New("injected ambiguous original close failure")

	t.Run("unproven-release-rolls-back-and-keeps-charge", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		installOriginalCloseSeam(t, ambiguous)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true, err: attemptErr}
		state.retire()
		if state.conn != nil {
			t.Fatal("the adopted connection must be rolled back")
		}
		if _, err := client.Write([]byte("x")); err == nil {
			t.Fatal("the rolled-back connection is still usable")
		}
		if state.holdOwned {
			t.Fatal("an unproven release must keep the attempt's admission charge")
		}
		if !errors.Is(state.err, attemptErr) {
			t.Fatalf("error = %v, want the attempt error preserved", state.err)
		}
		var unresolved *unresolvedSocketRetirement
		if !errors.As(state.err, &unresolved) || !errors.Is(state.err, ambiguous) {
			t.Fatalf("error = %v, want the retirement error joined with the attempt error", state.err)
		}
	})

	t.Run("proven-release-keeps-published-connection", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		calls := installOriginalCloseSeam(t)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true}
		state.retire()
		if state.conn != client || state.err != nil || !state.holdOwned {
			t.Fatalf("state = %+v, want the connection kept and the charge discharged", state)
		}
		if len(*calls) != 1 {
			t.Fatalf("closesocket calls = %d, want exactly one", len(*calls))
		}
	})

	t.Run("wouldblock-retried-then-proven-rolls-back", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		installOriginalCloseSeam(t, windows.WSAEWOULDBLOCK, nil)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true, err: attemptErr}
		state.retire()
		var unresolved *unresolvedSocketRetirement
		if errors.As(state.err, &unresolved) {
			t.Fatalf("error = %v, want no unresolved token after a successful retry", state.err)
		}
		if state.conn != nil {
			t.Fatal("a close that reported an error still rolls the connection back")
		}
		if !errors.Is(state.err, attemptErr) || !strings.Contains(state.err.Error(), "desync: retire original socket") {
			t.Fatalf("error = %v, want the attempt and retirement errors visible", state.err)
		}
		if !state.holdOwned {
			t.Fatal("a proven release must discharge the charge through its existing owner")
		}
	})

	t.Run("clean-retirement-keeps-connection", func(t *testing.T) {
		client, server := net.Pipe()
		t.Cleanup(func() {
			_ = client.Close()
			_ = server.Close()
		})
		installOriginalCloseSeam(t)
		state := attemptRetirement{handle: handle, conn: client, holdOwned: true}
		state.retire()
		if state.conn == nil || state.err != nil || !state.holdOwned {
			t.Fatalf("state = %+v, want an untouched connection and a dischargeable charge", state)
		}
	})
}

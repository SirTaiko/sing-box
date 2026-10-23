//go:build windows

package desync

// Combined terminal-receipt / retained-admission regression for the submission
// 11 A10-S1/A10-S2 correction on the combined final tree (TFO5).
//
// The production question is not only "does the operation retire?" but "does a
// terminal receipt discharge exactly one reference of the real, already charged
// Engine attempt?" A sender-only fixture cannot answer that: it would replace
// the accounting with a counter. This regression therefore runs the complete
// production Windows sender body against a real Engine with MaxLeases=1 and a
// real Lease obtained from Engine.NewAttempt, drives it through the compiled
// stream wrapper (the same public WrapConn bridge the direct outbound attaches),
// and inspects the real lease reference count:
//
//   - counted terminal receipt: operation retired, transfer count authoritative;
//   - aborted terminal receipt (A10-S2): retired with an unknown prefix, no
//     replay, and no borrowed count;
//   - unproven completion: both the factory and the operation reference stay
//     owned, the single charged slot stays charged and capacity refuses a second
//     attempt until the real receipt arrives.
//
// WSASend/WSAGetOverlappedResult/CancelIoEx are API-result seams and the
// completion event is the platform event (a real auto-reset kernel event on
// Windows, the audited auto-reset double in the Linux-hosted API-result run).
// No socket is opened. Native Windows execution remains required for wire-level
// evidence; this is control-flow and accounting evidence.

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// admissionEngineConn is the connection the platform sender factory receives: a
// memory connection that carries the real accepted attempt. Its admission
// capability forwards to the exact Engine lease, exactly like the direct
// bridge's leaseConn in production, and it is also the already-owned native
// source the factory needs, so no socket is created or dialed here.
type admissionEngineConn struct {
	*fakeConn
	lease *Lease
}

func (c *admissionEngineConn) AcquireNativeHold() (func(), error) {
	return c.lease.AcquireNativeHold()
}

func (c *admissionEngineConn) NativeStreamConn() net.Conn { return c }

func (c *admissionEngineConn) SyscallConn() (syscall.RawConn, error) {
	return admissionRawConn{}, nil
}

// admissionRawConn is a memory-only RawConn: it hands the sender a fake handle
// and never runs socket I/O.
type admissionRawConn struct{}

func (admissionRawConn) Control(control func(uintptr)) error {
	control(8)
	return nil
}

func (admissionRawConn) Read(func(uintptr) bool) error  { return nil }
func (admissionRawConn) Write(func(uintptr) bool) error { return nil }

// engineHoldCount reads the real reference count of the admitted attempt. It is
// the accounting under test: one reference for the sender factory and one for
// the current operation.
func engineHoldCount(engine *Engine, lease *Lease) int {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return lease.nativeHolds
}

func awaitEngineHoldCount(t *testing.T, engine *Engine, lease *Lease, want int) int {
	t.Helper()
	stop := time.Now().Add(2 * time.Second)
	for {
		got := engineHoldCount(engine, lease)
		if got == want {
			return got
		}
		if time.Now().After(stop) {
			t.Fatalf("native hold references = %d, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// engineTerminalStream builds the compiled stream wrapper over the admitted
// connection with the real platform sender factory.
func engineTerminalStream(t *testing.T, conn *admissionEngineConn) (net.Conn, *fakeConn) {
	t.Helper()
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	config.native = &windowsStreamNative{}
	return wrapStream(t, config, conn, MatchFacts{}), conn.fakeConn
}

func TestWindowsTerminalReceiptDischargesRealEngineHoldOnce(t *testing.T) {
	block := []byte("unrecognised-block")
	for _, testCase := range []struct {
		name         string
		count        uint32
		queryErr     error
		wantRetained bool
		wantWritten  int
		wantForward  string
	}{
		{
			name:        "counted-terminal",
			count:       2,
			wantWritten: len(block),
			wantForward: string(block[2:]),
		},
		{
			name:     "aborted-terminal-uncounted",
			count:    5, // sentinel: a failed query does not update the output
			queryErr: windows.ERROR_OPERATION_ABORTED,
		},
		{
			name:         "unproven-retained",
			count:        3,
			queryErr:     windows.ERROR_IO_INCOMPLETE,
			wantRetained: true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			engine, _ := retainedTestEngine(t, 1)
			lease := retainedNewAttempt(t, engine)
			conn := &admissionEngineConn{fakeConn: newFakeConn(), lease: lease}

			var (
				handle    atomic.Uintptr
				submitOne sync.Once
			)
			submitted := make(chan struct{})
			state := &windowsSeamState{
				send: func(_ []byte, _ uint32, overlapped *windows.Overlapped) error {
					handle.Store(uintptr(overlapped.HEvent))
					submitOne.Do(func() { close(submitted) })
					return windows.ERROR_IO_PENDING
				},
				result: func(*windows.Overlapped, bool) (uint32, error) {
					return testCase.count, testCase.queryErr
				},
			}
			stubWindowsSeams(t, state)
			wrapped, forwarded := engineTerminalStream(t, conn)
			t.Cleanup(func() {
				_ = wrapped.Close()
				_ = lease.Close(nil)
				_ = engine.Close()
			})

			type writeResult struct {
				written int
				err     error
			}
			done := make(chan writeResult, 1)
			go func() {
				n, writeErr := wrapped.Write(block)
				done <- writeResult{written: n, err: writeErr}
			}()
			select {
			case <-submitted:
			case <-time.After(5 * time.Second):
				t.Fatal("the production body never submitted the send")
			}
			// The provider completes the operation and signals the real
			// auto-reset event; the production wait consumes that one signal.
			if setErr := windows.SetEvent(windows.Handle(handle.Load())); setErr != nil {
				t.Fatalf("SetEvent: %v", setErr)
			}
			var result writeResult
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Write did not return after the terminal receipt")
			}
			written, err := result.written, result.err
			if written != testCase.wantWritten {
				t.Fatalf("Write = %d,%v; want %d accepted bytes", written, err, testCase.wantWritten)
			}
			switch {
			case testCase.wantRetained:
				if err == nil || !streamCompletionUnproven(err) {
					t.Fatalf("Write error = %v, want the unknown-completion marker", err)
				}
			case testCase.queryErr != nil:
				if written != 0 || !streamCompletionUnproven(err) || !errors.Is(err, testCase.queryErr) {
					t.Fatalf("Write = %d,%v; want 0 and the unknown-prefix marker carrying %v", written, err, testCase.queryErr)
				}
			default:
				if err != nil {
					t.Fatalf("counted Write error = %v", err)
				}
			}
			if got := string(forwarded.collected()); got != testCase.wantForward {
				t.Fatalf("forwarded %q, want %q", got, testCase.wantForward)
			}
			if testCase.wantRetained {
				// Nothing about the provider is established: the factory and the
				// operation reference are both still owned by the attempt, so the
				// single admitted slot stays charged and refuses a second attempt.
				if holds := engineHoldCount(engine, lease); holds != 2 {
					t.Fatalf("retained native hold references = %d, want 2 (factory + operation)", holds)
				}
				if active := engine.ActiveLeases(); active != 1 {
					t.Fatalf("ActiveLeases while the operation is retained = %d, want the charged slot 1", active)
				}
				if _, attemptErr := engine.NewAttempt(retainedTCPIntent()); !errors.Is(attemptErr, ErrAdmissionRefused) {
					t.Fatalf("second attempt error = %v, want a capacity refusal (MaxLeases=1)", attemptErr)
				}
				// The real receipt arrives late and discharges the operation
				// reference exactly once, without releasing the factory one.
				if err = windows.SetEvent(windows.Handle(handle.Load())); err != nil {
					t.Fatalf("late SetEvent: %v", err)
				}
				awaitEngineHoldCount(t, engine, lease, 1)
			} else if holds := engineHoldCount(engine, lease); holds != 1 {
				// The terminal receipt retired the operation and discharged its
				// reference; only the sender-factory reference remains.
				t.Fatalf("native hold references after the terminal receipt = %d, want 1 (factory only)", holds)
			}
			if active := engine.ActiveLeases(); active != 1 {
				t.Fatalf("ActiveLeases before the sender release = %d, want 1", active)
			}
			// Closing the wrapper releases the sender-factory reference; the lease
			// teardown then removes the original charged slot exactly once.
			if err = wrapped.Close(); err != nil {
				t.Fatalf("wrapped Close: %v", err)
			}
			awaitEngineHoldCount(t, engine, lease, 0)
			if err = lease.Close(nil); err != nil {
				t.Fatalf("lease Close: %v", err)
			}
			if active := engine.ActiveLeases(); active != 0 {
				t.Fatalf("ActiveLeases after the release = %d, want 0", active)
			}
			// Idempotent recovery: repeated close/release must neither resurrect
			// the slot nor make another reference acquirable.
			_ = wrapped.Close()
			_ = lease.Close(nil)
			if active := engine.ActiveLeases(); active != 0 {
				t.Fatalf("ActiveLeases after repeated close = %d, want 0", active)
			}
			if _, holdErr := lease.AcquireNativeHold(); !errors.Is(holdErr, ErrAdmissionRefused) {
				t.Fatalf("AcquireNativeHold after the release = %v, want a refusal", holdErr)
			}
			if holds := engineHoldCount(engine, lease); holds != 0 {
				t.Fatalf("native hold references after the refusal = %d, want 0", holds)
			}
		})
	}
}

//go:build windows

package desync

// Submission 11 regressions for the two completion-boundary residuals of the
// security recheck t_e7503c34:
//
//   - A10-S1: an already observed terminal completion (the auto-reset event was
//     signalled and consumed) must be retired even when Close or the write
//     deadline wins the caller-cause selection and the count query then fails.
//     The consumed signal is the only one the provider sends, so demanding a
//     second one retains a finished operation forever.
//   - A10-S2: ERROR_OPERATION_ABORTED proves that the operation is terminal, not
//     what prefix it transferred. WSAGetOverlappedResult does not update
//     lpcbTransfer when it fails, so the operation is retired with an
//     unknown-prefix marker and the wrapper never replays the block.
//
// The tests drive the complete production Windows sender body through the real
// stream wrapper. WSASend/WSAGetOverlappedResult/CancelIoEx are injected
// API-result seams, the completion event is a real auto-reset kernel event (so
// one wait consumes one signal) and WaitForSingleObject is the real call. No
// socket is opened; native Windows execution is still required for wire-level
// evidence.

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// v11CountUnavailable is the substituted result of a count query that cannot
// answer for the operation (WSAENOTSOCK: the socket handle is already gone).
var v11CountUnavailable = syscall.Errno(10038)

// v11WinFactory hands a pre-built production sender to the wrapper and gives it
// the wrapper's live deadline source, exactly like newPlatformStreamNative.
type v11WinFactory struct{ sender *windowsSender }

func (*v11WinFactory) Prepare(uintptr, streamSocketConfig) error { return nil }

func (f *v11WinFactory) NewSender(_ net.Conn, deadline func() time.Time) (streamSender, error) {
	f.sender.deadline = deadline
	f.sender.source = deadline
	return f.sender, nil
}

// v11WinStream wraps conn for a rule that needs the native sender for an
// unsplit block and adopts the given production sender.
func v11WinStream(t *testing.T, sender *windowsSender) (net.Conn, *fakeConn) {
	t.Helper()
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	config.native = &v11WinFactory{sender: sender}
	conn := newFakeConn()
	return wrapStream(t, config, conn, MatchFacts{}), conn
}

type v11SenderState struct {
	retained    bool
	sending     bool
	submitted   int
	eventClosed bool
}

func v11StateOf(sender *windowsSender) v11SenderState {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return v11SenderState{
		retained:    sender.retained,
		sending:     sender.sending,
		submitted:   len(sender.submitted),
		eventClosed: sender.eventClosed,
	}
}

// v11Drain retires an operation that the code under test left owned, before
// the API-result seams are restored. The extra signal is fixture cleanup only:
// it is not evidence that a provider signals twice, and it never substitutes
// for an assertion. A failed assertion that left an operation retained is
// reported by the test itself; this only prevents a cleanup-time seam race.
func v11Drain(t *testing.T, sender *windowsSender) {
	t.Helper()
	if v11StateOf(sender).retained && !v11StateOf(sender).eventClosed {
		_ = windows.SetEvent(sender.event)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if !v11StateOf(sender).sending {
			return
		}
		if time.Now().After(deadline) {
			t.Error("the autonomous completion owner did not retire the operation during cleanup")
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// A10-S1: the provider signals the completion event and one wait consumes that
// single auto-reset signal; Close or the deadline then wins the caller-cause
// selection and the count query fails. The observed terminal receipt must still
// retire the exact operation, exactly once, without a second signal, while the
// caller keeps the cause of its own path and the wrapper does not replay the
// unknown prefix.
func TestWindowsV11ObservedTerminalRetiresThroughCallerCause(t *testing.T) {
	for _, mode := range []string{"ordinary", "close", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var (
				queries      atomic.Int32
				blockingWait atomic.Int32
			)
			waitEntered := make(chan struct{})
			var enteredOnce sync.Once
			var signalOnce sync.Once
			ownerWait := windowsWaitForSingleObject
			state := &windowsSeamState{
				send: func([]byte, uint32, *windows.Overlapped) error {
					return windows.ERROR_IO_PENDING
				},
				cancel: func(overlapped *windows.Overlapped) error {
					// The abort is a request; the provider completes the
					// cancelled operation and signals its event once.
					signalOnce.Do(func() { _ = windows.SetEvent(overlapped.HEvent) })
					return nil
				},
				wait: func(event windows.Handle, milliseconds uint32) (uint32, error) {
					enteredOnce.Do(func() { close(waitEntered) })
					return ownerWait(event, milliseconds)
				},
			}
			stubWindowsSeams(t, state)
			// A failing query leaves the count output untouched, exactly as
			// documented. The terminal completion itself was observed, so the
			// operation is terminal and its prefix unknown.
			windowsWSAGetOverlappedResult = func(_ windows.Handle, _ *windows.Overlapped, _ *uint32, wait bool, _ *uint32) error {
				queries.Add(1)
				if wait {
					blockingWait.Add(1)
				}
				return v11CountUnavailable
			}
			sender := newTestWindowsSender(t, nil)
			sender.handle = 8
			wrapped, fallback := v11WinStream(t, sender)
			t.Cleanup(func() {
				v11Drain(t, sender)
				_ = wrapped.Close()
				sender.Release()
			})

			type writeResult struct {
				written int
				err     error
			}
			done := make(chan writeResult, 1)
			go func() {
				written, err := wrapped.Write([]byte("unrecognised-block"))
				done <- writeResult{written, err}
			}()
			select {
			case <-waitEntered:
			case <-time.After(5 * time.Second):
				t.Fatal("the production body never waited for the completion event")
			}
			switch mode {
			case "ordinary":
				// The provider completes the send on its own.
				signalOnce.Do(func() { _ = windows.SetEvent(sender.event) })
			case "close":
				if err := wrapped.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
			case "deadline":
				if err := wrapped.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatalf("SetWriteDeadline: %v", err)
				}
			}

			var result writeResult
			select {
			case result = <-done:
			case <-time.After(5 * time.Second):
				_ = windows.SetEvent(sender.event)
				t.Fatal("the Write did not return after the observed terminal completion")
			}
			wantCause := error(v11CountUnavailable)
			switch mode {
			case "close":
				wantCause = net.ErrClosed
			case "deadline":
				wantCause = os.ErrDeadlineExceeded
			}
			if result.written != 0 || !streamCompletionUnproven(result.err) || !errors.Is(result.err, wantCause) {
				t.Fatalf("Write = %d,%v; want 0 and an unknown-prefix marker carrying %v", result.written, result.err, wantCause)
			}
			if got := fallback.collected(); len(got) != 0 {
				t.Fatalf("the wrapper replayed %q after an unknown prefix", got)
			}
			// A receipt that was already observed must not be re-queried as if
			// it were unproven: the blocking query is the retained path.
			if blocking := blockingWait.Load(); blocking != 0 {
				t.Fatalf("observed terminal completion was queried with wait=true %d time(s)", blocking)
			}
			if got := queries.Load(); got != 1 {
				t.Fatalf("completion queries = %d, want exactly 1", got)
			}
			receipt := v11StateOf(sender)
			if receipt.retained || receipt.sending || receipt.submitted != 0 {
				t.Fatalf("after the terminal receipt: retained=%v sending=%v submitted=%d, want retired",
					receipt.retained, receipt.sending, receipt.submitted)
			}
			// Close already released the sender, so the retirement owns the
			// (deferred) event close in that case; otherwise the event belongs
			// to the sender until Release.
			if wantClosed := mode == "close"; receipt.eventClosed != wantClosed {
				t.Fatalf("eventClosed = %v, want %v after the terminal retirement", receipt.eventClosed, wantClosed)
			}
			sender.Release()
			sender.Release()
			if final := v11StateOf(sender); !final.eventClosed {
				t.Fatal("the completion event was not owned until Release and closed exactly once")
			}
		})
	}
}

// A10-S2: ERROR_OPERATION_ABORTED is terminal but does not carry a guaranteed
// transfer count. The untouched (or sentinel-filled) result output must not be
// reported as bytes accepted, the terminal operation is retired exactly once
// and the wrapper does not replay a possibly transmitted prefix. The successful
// counted control keeps the authoritative prefix and forwards only the unsent
// tail.
func TestWindowsV11AbortedWithoutCountIsUnknownPrefix(t *testing.T) {
	block := []byte("unrecognised-block")
	for _, testCase := range []struct {
		name    string
		counted bool
		fill    bool
		sent    uint32
	}{
		{name: "aborted-untouched-output"},
		{name: "aborted-sentinel-output", fill: true, sent: 5},
		{name: "successful-count-control", counted: true, sent: 2},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var submissions atomic.Int32
			ownerWait := windowsWaitForSingleObject
			state := &windowsSeamState{
				send: func([]byte, uint32, *windows.Overlapped) error {
					submissions.Add(1)
					return windows.ERROR_IO_PENDING
				},
				wait: func(event windows.Handle, milliseconds uint32) (uint32, error) {
					// The provider completes the operation and signals its
					// auto-reset event; the real wait consumes that signal.
					_ = windows.SetEvent(event)
					return ownerWait(event, milliseconds)
				},
			}
			stubWindowsSeams(t, state)
			windowsWSAGetOverlappedResult = func(_ windows.Handle, _ *windows.Overlapped, n *uint32, _ bool, _ *uint32) error {
				if testCase.counted {
					*n = testCase.sent
					return nil
				}
				if testCase.fill {
					// The output is unspecified on failure; a sentinel proves
					// that the implementation does not borrow it as a count.
					*n = testCase.sent
				}
				return windows.ERROR_OPERATION_ABORTED
			}
			sender := newTestWindowsSender(t, nil)
			sender.handle = 8
			wrapped, fallback := v11WinStream(t, sender)
			defer func() {
				v11Drain(t, sender)
				_ = wrapped.Close()
				sender.Release()
			}()

			written, err := wrapped.Write(block)
			if testCase.counted {
				if written != len(block) || err != nil {
					t.Fatalf("Write = %d,%v; want the whole block acknowledged after the counted prefix", written, err)
				}
				if got := string(fallback.collected()); got != string(block[testCase.sent:]) {
					t.Fatalf("forwarded %q, want only the unsent tail %q", got, block[testCase.sent:])
				}
			} else {
				if written != 0 {
					t.Fatalf("Write acknowledged %d bytes for an aborted operation without an authoritative count", written)
				}
				if !errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
					t.Fatalf("Write error %v does not preserve the caller-visible aborted status", err)
				}
				if !streamCompletionUnproven(err) {
					t.Fatalf("Write error %v does not mark the prefix as unknown", err)
				}
				if got := fallback.collected(); len(got) != 0 {
					t.Fatalf("the wrapper replayed %q after an aborted operation with an unknown prefix", got)
				}
			}
			final := v11StateOf(sender)
			if final.retained || final.sending || final.submitted != 0 {
				t.Fatalf("after a terminal abort: retained=%v sending=%v submitted=%d, want retired exactly once",
					final.retained, final.sending, final.submitted)
			}
			if got := submissions.Load(); got != 1 {
				t.Fatalf("WSASend submissions = %d, want exactly 1", got)
			}
		})
	}
}

// A10-S1 not-terminal control plus bounded Close: when the provider cannot yet
// prove the completion, the exact submitted allocation, the OVERLAPPED and the
// event stay owned and Close returns inside its bound without freeing them.
// The single late terminal signal - no second Write or Close - then retires the
// operation exactly once and releases the deferred event close.
func TestWindowsV11PendingCloseBoundedThenLateTerminalRetires(t *testing.T) {
	submitted := make(chan struct{})
	var submittedOnce sync.Once
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error {
			submittedOnce.Do(func() { close(submitted) })
			return windows.ERROR_IO_PENDING
		},
		// The abort is only a request: the provider has not completed the
		// operation, so nothing may be freed.
		cancel: func(*windows.Overlapped) error { return nil },
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 0, v11CountUnavailable
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)
	sender.handle = 8
	wrapped, fallback := v11WinStream(t, sender)
	defer func() {
		v11Drain(t, sender)
		_ = wrapped.Close()
		sender.Release()
	}()

	if err := wrapped.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	written, err := wrapped.Write([]byte("unrecognised-block"))
	if written != 0 || !streamCompletionUnproven(err) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write = %d,%v; want 0 and an unproven completion carrying os.ErrDeadlineExceeded", written, err)
	}
	select {
	case <-submitted:
	default:
		t.Fatal("the send was never submitted")
	}
	if got := fallback.collected(); len(got) != 0 {
		t.Fatalf("the wrapper replayed %q for an unproven completion", got)
	}
	retained := v11StateOf(sender)
	if !retained.retained || !retained.sending || retained.submitted == 0 || retained.eventClosed {
		t.Fatalf("unproven completion state: retained=%v sending=%v submitted=%d eventClosed=%v, want the exact store owned",
			retained.retained, retained.sending, retained.submitted, retained.eventClosed)
	}

	start := time.Now()
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	elapsed := time.Since(start)
	if window := v7Window(); elapsed > window {
		t.Fatalf("Close took %v, beyond the %v flush bound + watchdog grace", elapsed, window)
	}
	// Close released the sender, but the owned operation must keep its event
	// until the provider reports the terminal completion.
	if after := v11StateOf(sender); after.eventClosed || !after.retained || after.submitted == 0 {
		t.Fatalf("Close freed an unproven operation: retained=%v submitted=%d eventClosed=%v",
			after.retained, after.submitted, after.eventClosed)
	}

	// One late terminal signal is enough: the autonomous owner retires the
	// exact operation and performs the deferred event close.
	if err := windows.SetEvent(sender.event); err != nil {
		t.Fatalf("SetEvent: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		late := v11StateOf(sender)
		if !late.retained && !late.sending && late.submitted == 0 && late.eventClosed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the late terminal completion did not retire the operation: retained=%v sending=%v submitted=%d eventClosed=%v",
				late.retained, late.sending, late.submitted, late.eventClosed)
		}
		time.Sleep(time.Millisecond)
	}
	sender.Release()
	sender.Release()
	if final := v11StateOf(sender); !final.eventClosed {
		t.Fatal("the deferred completion event was not closed exactly once")
	}
	if _, err := sender.Send([]byte("second-block"), sendOptions{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after the released retained operation = %v, want net.ErrClosed", err)
	}
}

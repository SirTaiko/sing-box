//go:build windows

package desync

// Submission 10 Windows-sender regressions for the independent QA findings of
// t_820c6bd7:
//
//   - Q9-D1: the sender deadline publication converges on the current source
//     under an arbitrary number of concurrent completed setters, so the
//     production sender never keeps enforcing a stale stricter or stale longer
//     value. The test drives the real wrapper and the real Windows send body
//     through the four-writer interleaving and then requires the sender to
//     accept I/O after the completed clear.
//   - Q9-D2: a synchronous WSASend success whose completion count cannot be read
//     is a terminal operation with an unknown transferred prefix. Its resources
//     are retired (the provider is finished), the caller error is preserved and
//     the wrapper is told that the prefix is unknown instead of "zero accepted".
//
// WSASend/WSAGetOverlappedResult/CancelIoEx/WaitForSingleObject are injected
// API-result seams and the completion event is a real kernel event, so no
// socket is opened. Native Windows execution is still required for wire-level
// evidence.

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// v10ResultQueryFailure is the substituted API result of a count query that
// refuses to report the operation (WSAENOTSOCK: the socket handle is gone). The
// operation itself may have completed; only the count is unavailable.
var v10ResultQueryFailure = syscall.Errno(10038)

// Q9-D2: a synchronous submission that succeeded is a finished operation. When
// the count query then fails, the prefix that reached the wire is unknown, so
// the result must be marked (no replay authorisation) while the exact
// allocation, the OVERLAPPED and the event are retired - the provider is done
// with them, and nothing will ever report the count.
func TestWindowsV10UncountedSyncCompletionRetiresWithoutReplay(t *testing.T) {
	var submissions, queries atomic.Int32
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error {
			submissions.Add(1)
			return nil
		},
		result: func(_ *windows.Overlapped, wait bool) (uint32, error) {
			if wait {
				t.Error("a synchronous completion must be queried without waiting")
			}
			if queries.Add(1) == 1 {
				return 0, v10ResultQueryFailure
			}
			return 7, nil
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)

	written, err := sender.Send([]byte("abcdef"), sendOptions{oob: true, oobByte: 'Q'})
	if written != 0 {
		t.Fatalf("Send reported %d bytes for an unreadable count, want the unknown prefix to stay unreported", written)
	}
	if !streamCompletionUnproven(err) {
		t.Fatalf("Send error = %v, want an unknown-completion marker", err)
	}
	if !errors.Is(err, v10ResultQueryFailure) {
		t.Fatalf("Send error %v does not preserve the caller-visible query error", err)
	}

	// Terminal, so nothing is retained: no backing store, no outstanding
	// operation, and the event is not closed before Release.
	buffer, eventClosed, sending := v9SenderState(sender)
	if buffer != 0 || sending || eventClosed {
		t.Fatalf("state after an uncounted terminal completion: buffer=%d eventClosed=%v sending=%v, want retired",
			buffer, eventClosed, sending)
	}

	// The retired operation releases the single OVERLAPPED: the next send is
	// admitted and reports its own authoritative count.
	written, err = sender.Send([]byte("abcdef"), sendOptions{})
	if err != nil || written != 7 {
		t.Fatalf("Send after a retired uncounted completion = %d,%v, want 7,nil", written, err)
	}
	if got := submissions.Load(); got != 2 {
		t.Fatalf("WSASend submissions = %d, want 2", got)
	}

	sender.Release()
	if _, closed, _ := v9SenderState(sender); !closed {
		t.Fatal("Release did not close the completion event of a retired operation")
	}
	// Release is idempotent and the event was closed exactly once by the
	// terminal retirement path.
	sender.Release()
	if _, closed, _ := v9SenderState(sender); !closed {
		t.Fatal("the completion event is not closed after Release")
	}
}

// Q9-D2 positive control: an observed completion whose count is reported keeps
// the authoritative prefix and retires the operation.
func TestWindowsV10ReportedSyncCompletionControl(t *testing.T) {
	state := &windowsSeamState{
		send:   func([]byte, uint32, *windows.Overlapped) error { return nil },
		result: func(*windows.Overlapped, bool) (uint32, error) { return 6, nil },
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)

	written, err := sender.Send([]byte("abcdef"), sendOptions{})
	if err != nil || written != 6 {
		t.Fatalf("Send = %d,%v, want 6,nil", written, err)
	}
	if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
		t.Fatalf("state after a reported completion: buffer=%d sending=%v, want retired", buffer, sending)
	}
}

// Q9-D2/A10-S2 terminal-receipt control: an aborted receipt is terminal and
// retires the operation, but it does not establish the prefix that was
// transferred before the abort (the result output is not updated on failure).
func TestWindowsV10AbortedReceiptRetiresUncounted(t *testing.T) {
	state := &windowsSeamState{
		send:   v9PendingSend(nil),
		cancel: func(*windows.Overlapped) error { return nil },
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 2, windows.ERROR_OPERATION_ABORTED
		},
	}
	stubWindowsSeams(t, state)
	deadline := time.Now().Add(20 * time.Millisecond)
	sender := newTestWindowsSender(t, func() time.Time { return deadline })

	written, err := sender.Send([]byte("abcdef"), sendOptions{})
	if written != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !streamCompletionUnproven(err) {
		t.Fatalf("Send = %d,%v, want 0 and an unknown-prefix marker carrying os.ErrDeadlineExceeded", written, err)
	}
	if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
		t.Fatalf("state after a partial terminal receipt: buffer=%d sending=%v, want retired", buffer, sending)
	}
}

// Q9-D2 second path to the same defect: the completion signal arrives normally
// but the non-blocking count query fails. The operation is terminal (the event
// is signalled), so it is retired with the unknown-prefix marker instead of
// reporting zero.
func TestWindowsV10UncountedSignalledCompletionRetiresWithoutReplay(t *testing.T) {
	state := &windowsSeamState{
		send: v9PendingSend(nil),
		wait: func(event windows.Handle, _ uint32) (uint32, error) {
			// The provider completes the operation and signals its event.
			_ = windows.SetEvent(event)
			return uint32(windows.WAIT_OBJECT_0), nil
		},
		result: func(_ *windows.Overlapped, wait bool) (uint32, error) {
			if wait {
				t.Error("the ordinary completion path must query without waiting")
			}
			return 0, v10ResultQueryFailure
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)

	written, err := sender.Send([]byte("abcdef"), sendOptions{})
	if written != 0 || !streamCompletionUnproven(err) || !errors.Is(err, v10ResultQueryFailure) {
		t.Fatalf("Send = %d,%v, want 0 and an unknown-completion marker carrying the query error", written, err)
	}
	if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
		t.Fatalf("state after an uncounted signalled completion: buffer=%d sending=%v, want retired", buffer, sending)
	}
}

// v10WinPublication is one deadline the gated sender received.
type v10WinPublication struct {
	value  time.Time
	resume chan struct{}
}

// v10GateWindows holds every deadline publication until the test releases it,
// so the concurrent-setter interleaving is deterministic.
type v10GateWindows struct {
	*windowsSender
	calls chan *v10WinPublication
}

func (s *v10GateWindows) SetWriteDeadline(deadline time.Time) {
	publication := &v10WinPublication{value: deadline, resume: make(chan struct{})}
	select {
	case s.calls <- publication:
	case <-time.After(5 * time.Second):
		close(publication.resume)
	}
	<-publication.resume
	s.windowsSender.SetWriteDeadline(deadline)
}

type v10WindowsFactory struct{ sender *v10GateWindows }

func (*v10WindowsFactory) Prepare(uintptr, streamSocketConfig) error { return nil }

func (f *v10WindowsFactory) NewSender(_ net.Conn, deadline func() time.Time) (streamSender, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	f.sender.windowsSender = &windowsSender{handle: 8, event: event, deadline: deadline, source: deadline, holder: newTestAdmissionHolder()}
	f.sender.overlapped.HEvent = event
	return f.sender, nil
}

func (s *v10GateWindows) next(t *testing.T, want time.Time, label string) *v10WinPublication {
	t.Helper()
	select {
	case publication := <-s.calls:
		if !publication.value.Equal(want) {
			t.Fatalf("%s: published %v, want %v", label, publication.value, want)
		}
		return publication
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: no deadline publication reached the sender", label)
		return nil
	}
}

func releaseV10Win(publication *v10WinPublication) { close(publication.resume) }

// Q9-D1 Windows consequence: three concurrent completed setters supersede the
// adoption publication, and the last one clears the deadline. The production
// Windows sender must end on the cleared value - a stale expired publication
// would make deadlineExpiredLocked deny the submission that follows.
func TestWindowsV10ConcurrentCompletedSettersLeaveNoStalePublication(t *testing.T) {
	long := time.Now().Add(time.Hour)
	mid := time.Now().Add(30 * time.Minute)
	expired := time.Now().Add(-time.Minute)
	cleared := time.Time{}

	var submissions atomic.Int32
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error {
			submissions.Add(1)
			return nil
		},
		result: func(*windows.Overlapped, bool) (uint32, error) { return 18, nil },
	}
	stubWindowsSeams(t, state)
	sender := &v10GateWindows{calls: make(chan *v10WinPublication, 16)}
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	config.native = &v10WindowsFactory{sender: sender}
	wrapped := wrapStream(t, config, newFakeConn(), MatchFacts{})
	t.Cleanup(func() { _ = wrapped.Close() })
	if err := wrapped.SetWriteDeadline(long); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("unrecognised-block"))
		writeDone <- err
	}()
	p1 := sender.next(t, long, "adoption pass 1")

	first := setWriteDeadlineAsync(wrapped, mid)
	p2 := sender.next(t, mid, "setter 1 publication")
	releaseV10Win(p1)
	p3 := sender.next(t, mid, "adoption pass 2")
	releaseV10Win(p2)
	awaitV10(t, first, "setter 1")

	second := setWriteDeadlineAsync(wrapped, expired)
	p4 := sender.next(t, expired, "setter 2 publication")
	releaseV10Win(p3)
	p5 := sender.next(t, expired, "adoption pass 3")
	releaseV10Win(p4)
	awaitV10(t, second, "setter 2")

	third := setWriteDeadlineAsync(wrapped, cleared)
	p6 := sender.next(t, cleared, "setter 3 publication")
	releaseV10Win(p6)
	awaitV10(t, third, "setter 3")

	// The third pass of the adoption publication lands after the completed
	// clear. It must converge on the current source instead of returning.
	releaseV10Win(p5)
	select {
	case publication := <-sender.calls:
		if !publication.value.IsZero() {
			t.Fatalf("the repairing publication delivered %v, want the completed clear", publication.value)
		}
		releaseV10Win(publication)
	case <-time.After(5 * time.Second):
		t.Fatal("no repairing publication: the Windows sender still enforces the stale expired deadline")
	}

	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("Write after three completed setters = %v, want the native send to be submitted", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the Write did not finish")
	}
	if got := submissions.Load(); got != 1 {
		t.Fatalf("WSASend submissions after the completed clear = %d, want 1 (a stale expired publication denies I/O)", got)
	}
}

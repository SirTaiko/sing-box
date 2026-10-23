//go:build windows

package desync

// Submission 9 Windows-sender regressions for the stream findings of the
// security recheck t_8c719ee9:
//
//   - A-S1: a completed expired write deadline must keep the native sender from
//     submitting, even when an adoption publication that snapshotted an older
//     value is still in flight.
//   - A-S2: a completion-status query that cannot report the operation is not a
//     terminal receipt. The exact submitted allocation, the OVERLAPPED and the
//     completion event stay owned by an autonomous owner until the provider
//     reports the completion, and are then retired exactly once.
//   - A-S3: a prefix harvested during a failing wait survives to the wrapper,
//     which forwards only the unsent tail.
//
// WSASend/WSAGetOverlappedResult/CancelIoEx/WaitForSingleObject are injected
// API-result seams and the completion event is a real kernel event, so no
// socket is opened. Native Windows execution is still required for wire-level
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

// v9ResultQueryFailure is the substituted API result of a status query that
// refuses to report the operation (WSAENOTSOCK: the socket handle is gone). It
// is not a completion receipt.
var v9ResultQueryFailure = syscall.Errno(10038)

func v9PendingSend(entered chan struct{}) func([]byte, uint32, *windows.Overlapped) error {
	var once sync.Once
	return func(_ []byte, _ uint32, _ *windows.Overlapped) error {
		if entered != nil {
			once.Do(func() { close(entered) })
		}
		return windows.ERROR_IO_PENDING
	}
}

// v9SenderState reports the sender's observable operation state: the retained
// backing store, the completion event and whether an operation is outstanding.
// An unproven completion keeps the operation outstanding (sending) with its
// store retained and its event open, so a new send is refused; a real receipt
// retires it.
func v9SenderState(sender *windowsSender) (retainedBuffer int, eventClosed, sending bool) {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return len(sender.submitted), sender.eventClosed, sender.sending
}

func v9WaitSenderState(t *testing.T, sender *windowsSender, settled func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if settled() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the autonomous completion owner never retired the retained operation")
}

// A-S2: an unanswerable status query leaves the operation owned; the exact
// allocation and the event survive a Release, a new send is refused, and the
// real completion retires everything exactly once without a later Write/Close.
func TestWindowsV9QueryFailureKeepsCompletionOwnership(t *testing.T) {
	submitted := make(chan struct{})
	state := &windowsSeamState{
		send: v9PendingSend(submitted),
		// The abort is only a request: it does not complete the operation.
		cancel: func(*windows.Overlapped) error { return nil },
		result: func(_ *windows.Overlapped, wait bool) (uint32, error) {
			if !wait {
				t.Error("the abort path must query with wait=true")
			}
			return 0, v9ResultQueryFailure
		},
	}
	stubWindowsSeams(t, state)
	deadline := time.Now().Add(20 * time.Millisecond)
	sender := newTestWindowsSender(t, func() time.Time { return deadline })

	written, err := sender.Send([]byte("synthetic-buffer"), sendOptions{oob: true, oobByte: 'Z'})
	if written != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !streamCompletionUnproven(err) {
		t.Fatalf("Send = %d,%v, want 0 and an unproven completion carrying os.ErrDeadlineExceeded", written, err)
	}
	retainedBuffer, eventClosed, sending := v9SenderState(sender)
	if retainedBuffer == 0 || eventClosed || !sending {
		t.Fatalf("state after the unanswered query: buffer=%d eventClosed=%v sending=%v, want the operation still owned",
			retainedBuffer, eventClosed, sending)
	}

	// Release models Close: an owned operation must not lose its event, and the
	// sender must refuse a new send instead of reusing the retained OVERLAPPED.
	sender.Release()
	if _, closed, _ := v9SenderState(sender); closed {
		t.Fatal("Release closed the completion event of an operation that is still owned")
	}
	if _, err := sender.Send([]byte("second-block"), sendOptions{}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after retention = %v, want net.ErrClosed", err)
	}

	// The provider finally reports the completion: the autonomous owner retires
	// the exact allocation and closes the event exactly once.
	_ = windows.SetEvent(sender.event)
	v9WaitSenderState(t, sender, func() bool {
		buffer, closed, sending := v9SenderState(sender)
		return buffer == 0 && closed && !sending
	})
	sender.Release()
	if _, closed, _ := v9SenderState(sender); !closed {
		t.Fatal("the completion event is not closed after the terminal retirement")
	}
}

// A-S2 control: a status query that reports the aborted operation establishes a
// terminal operation, so the operation is retired immediately. The aborted
// status does not carry a documented count, so the prefix is reported as
// unknown instead of borrowing the query's untouched output.
func TestWindowsV9AbortedReceiptRetiresUncounted(t *testing.T) {
	state := &windowsSeamState{
		send:   v9PendingSend(nil),
		cancel: func(*windows.Overlapped) error { return nil },
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 3, windows.ERROR_OPERATION_ABORTED
		},
	}
	stubWindowsSeams(t, state)
	deadline := time.Now().Add(20 * time.Millisecond)
	sender := newTestWindowsSender(t, func() time.Time { return deadline })

	written, err := sender.Send([]byte("abcdef"), sendOptions{})
	if written != 0 || !errors.Is(err, os.ErrDeadlineExceeded) || !streamCompletionUnproven(err) {
		t.Fatalf("Send = %d,%v, want 0 and an unknown-prefix marker carrying os.ErrDeadlineExceeded", written, err)
	}
	buffer, eventClosed, sending := v9SenderState(sender)
	if buffer != 0 || sending {
		t.Fatalf("state after a terminal abort receipt: buffer=%d sending=%v, want retired", buffer, sending)
	}
	if eventClosed {
		t.Fatal("the completion event was closed although Release has not run")
	}
	sender.Release()
	if _, closed, _ := v9SenderState(sender); !closed {
		t.Fatal("Release after the terminal receipt did not close the event")
	}
}

// A-S3: a successful terminal completion harvested while the wait failed keeps
// its authoritative prefix, so only the unsent tail is reported to the wrapper.
func TestWindowsV9WaitFailurePreservesHarvestedCount(t *testing.T) {
	waitError := errors.New("substituted wait failure")
	state := &windowsSeamState{
		send:   v9PendingSend(nil),
		cancel: func(*windows.Overlapped) error { return nil },
		wait:   func(windows.Handle, uint32) (uint32, error) { return 0, waitError },
		result: func(_ *windows.Overlapped, wait bool) (uint32, error) {
			if !wait {
				t.Error("a cancel harvest must query with wait=true")
			}
			return 2, nil
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)

	written, err := sender.Send([]byte("FIRST"), sendOptions{})
	if written != 2 || !errors.Is(err, waitError) || streamCompletionUnproven(err) {
		t.Fatalf("Send = %d,%v, want the harvested prefix 2 with the original wait error", written, err)
	}
	if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
		t.Fatalf("state after a harvested receipt: buffer=%d sending=%v, want retired", buffer, sending)
	}
	sender.Release()
}

// A-S3/A-S2: a failing wait whose harvest also cannot answer proves nothing, so
// the operation is retained rather than reported as a zero-length send.
func TestWindowsV9WaitFailureWithUnansweredQueryKeepsOwnership(t *testing.T) {
	waitError := errors.New("substituted wait failure")
	// Only the caller's wait fails; the autonomous owner's later waits observe
	// the completion event normally.
	ownerWait := windowsWaitForSingleObject
	var waitCalls atomic.Int32
	state := &windowsSeamState{
		send:   v9PendingSend(nil),
		cancel: func(*windows.Overlapped) error { return nil },
		wait: func(event windows.Handle, milliseconds uint32) (uint32, error) {
			if waitCalls.Add(1) == 1 {
				return 0, waitError
			}
			return ownerWait(event, milliseconds)
		},
		result: func(*windows.Overlapped, bool) (uint32, error) { return 0, v9ResultQueryFailure },
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)

	written, err := sender.Send([]byte("FIRST"), sendOptions{})
	if written != 0 || !errors.Is(err, waitError) || !streamCompletionUnproven(err) {
		t.Fatalf("Send = %d,%v, want 0 and an unproven completion carrying the wait error", written, err)
	}
	if buffer, closed, sending := v9SenderState(sender); buffer == 0 || closed || !sending {
		t.Fatalf("state after an unanswered harvest: buffer=%d eventClosed=%v sending=%v, want the operation still owned",
			buffer, closed, sending)
	}
	sender.Release()
	_ = windows.SetEvent(sender.event)
	v9WaitSenderState(t, sender, func() bool {
		buffer, closed, _ := v9SenderState(sender)
		return buffer == 0 && closed
	})
}

// A-S1: the live connection deadline closes the window in which a stale cached
// publication could still authorize a submission after the caller's expired
// setter completed.
func TestWindowsV9ExpiredSetterBlocksSubmissionThroughStalePublication(t *testing.T) {
	var submissions atomic.Int32
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error {
			submissions.Add(1)
			return nil
		},
		result: func(*windows.Overlapped, bool) (uint32, error) { return 5, nil },
	}
	stubWindowsSeams(t, state)
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	// The published value is a stale clear, the live source is the caller's
	// completed expired setter.
	sender := &windowsSender{
		handle:   8,
		event:    event,
		deadline: func() time.Time { return time.Time{} },
		source:   func() time.Time { return time.Now().Add(-time.Second) },
		holder:   newTestAdmissionHolder(),
	}
	sender.overlapped.HEvent = event
	t.Cleanup(sender.Release)

	written, err := sender.Send([]byte("synthetic-buffer"), sendOptions{})
	if written != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Send = %d,%v, want 0 and os.ErrDeadlineExceeded", written, err)
	}
	if got := submissions.Load(); got != 0 {
		t.Fatalf("WSASend submissions = %d, want 0 after the caller's setter completed", got)
	}
}

// v9GateWindows holds the first deadline publication, so the test can land a
// caller setter between the adoption snapshot and the adoption publication.
type v9GateWindows struct {
	*windowsSender
	calls           atomic.Int32
	entered, resume chan struct{}
}

func (s *v9GateWindows) SetWriteDeadline(deadline time.Time) {
	if s.calls.Add(1) == 1 {
		close(s.entered)
		<-s.resume
	}
	s.windowsSender.SetWriteDeadline(deadline)
}

type v9WindowsFactory struct{ sender *v9GateWindows }

func (*v9WindowsFactory) Prepare(uintptr, streamSocketConfig) error { return nil }

func (f *v9WindowsFactory) NewSender(_ net.Conn, deadline func() time.Time) (streamSender, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, err
	}
	f.sender.windowsSender = &windowsSender{handle: 8, event: event, deadline: deadline, source: deadline, holder: newTestAdmissionHolder()}
	f.sender.overlapped.HEvent = event
	return f.sender, nil
}

// A-S1 through the complete Windows send body: the wrapper adoption publishes a
// stale zero deadline after the caller's expired setter completed, and the
// sender must still refuse the submission.
func TestWindowsV9AdoptionDeadlineCannotPermitSubmission(t *testing.T) {
	var submissions atomic.Int32
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error {
			submissions.Add(1)
			return nil
		},
		result: func(*windows.Overlapped, bool) (uint32, error) { return 18, nil },
	}
	stubWindowsSeams(t, state)
	sender := &v9GateWindows{entered: make(chan struct{}), resume: make(chan struct{})}
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	config.native = &v9WindowsFactory{sender: sender}
	wrapped := wrapStream(t, config, newFakeConn(), MatchFacts{})
	t.Cleanup(func() { _ = wrapped.Close() })

	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("unrecognised-block"))
		writeDone <- err
	}()
	select {
	case <-sender.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the adoption never published a deadline")
	}
	if err := wrapped.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	close(sender.resume)
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the Write did not finish")
	}
	if got := submissions.Load(); got != 0 {
		t.Fatalf("WSASend submissions after the completed expired setter = %d, want 0", got)
	}
}

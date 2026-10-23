//go:build windows

package desync

// Windows-only unit checks for the overlapped send lifecycle. They do not open
// a socket: WSASend/CancelIoEx/WSAGetOverlappedResult are injected, while the
// completion event is a real kernel event so the wait path is exercised
// exactly as it runs in production. Native Windows execution is still required
// for wire-level evidence (deferred to the tester/Windows lab); this file
// compiles with the Windows test binary.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsSeamState struct {
	mu     sync.Mutex
	send   func(data []byte, flags uint32, overlapped *windows.Overlapped) error
	result func(overlapped *windows.Overlapped, wait bool) (uint32, error)
	cancel func(overlapped *windows.Overlapped) error
	// wait substitutes the completion-event wait; nil keeps the real one. Only
	// a wait that fails cannot be provoked with a valid event handle.
	wait func(event windows.Handle, milliseconds uint32) (uint32, error)
}

func stubWindowsSeams(t *testing.T, state *windowsSeamState) {
	t.Helper()
	originalSend := windowsWSASend
	originalResult := windowsWSAGetOverlappedResult
	originalCancel := windowsCancelIoEx
	originalWait := windowsWaitForSingleObject
	windowsWSASend = func(_ windows.Handle, bufs *windows.WSABuf, _ uint32, _ *uint32, flags uint32, overlapped *windows.Overlapped, _ *byte) error {
		state.mu.Lock()
		send := state.send
		state.mu.Unlock()
		return send(wsabufBytes(bufs), flags, overlapped)
	}
	windowsWSAGetOverlappedResult = func(_ windows.Handle, overlapped *windows.Overlapped, transferred *uint32, wait bool, _ *uint32) error {
		state.mu.Lock()
		result := state.result
		state.mu.Unlock()
		value, err := result(overlapped, wait)
		*transferred = value
		return err
	}
	windowsCancelIoEx = func(_ windows.Handle, overlapped *windows.Overlapped) error {
		state.mu.Lock()
		cancel := state.cancel
		state.mu.Unlock()
		if cancel == nil {
			return nil
		}
		return cancel(overlapped)
	}
	windowsWaitForSingleObject = func(event windows.Handle, milliseconds uint32) (uint32, error) {
		state.mu.Lock()
		wait := state.wait
		state.mu.Unlock()
		if wait == nil {
			return originalWait(event, milliseconds)
		}
		return wait(event, milliseconds)
	}
	t.Cleanup(func() {
		windowsWSASend = originalSend
		windowsWSAGetOverlappedResult = originalResult
		windowsCancelIoEx = originalCancel
		windowsWaitForSingleObject = originalWait
	})
}

func wsabufBytes(buf *windows.WSABuf) []byte {
	if buf == nil || buf.Len == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(buf.Buf, int(buf.Len))...)
}

func newTestWindowsSender(t *testing.T, deadline func() time.Time) *windowsSender {
	t.Helper()
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	sender := &windowsSender{event: event, deadline: deadline, holder: newTestAdmissionHolder()}
	sender.overlapped.HEvent = event
	t.Cleanup(sender.Release)
	return sender
}

// A pending send whose deadline expires during the wait is cancelled, and the
// aborted status establishes a terminal operation. It does not establish a
// count: WSAGetOverlappedResult does not update lpcbTransfer when it fails, so
// the transferred prefix is unknown, reported as such, and the operation is
// retired.
//
// An already expired deadline is a different contract: it must not submit at
// all (see TestWindowsV8ExpiredDeadlinePreventsSubmission), because checking it
// after WSASend already put bytes on the wire.
func TestWindowsSendPendingDeadlineAbortIsUncounted(t *testing.T) {
	submitted := make(chan struct{})
	state := &windowsSeamState{
		send: func(_ []byte, _ uint32, _ *windows.Overlapped) error {
			close(submitted)
			return windows.ERROR_IO_PENDING
		},
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 3, windows.ERROR_OPERATION_ABORTED
		},
		cancel: func(overlapped *windows.Overlapped) error {
			return windows.SetEvent(overlapped.HEvent)
		},
	}
	stubWindowsSeams(t, state)
	deadline := time.Now().Add(30 * time.Millisecond)
	sender := newTestWindowsSender(t, func() time.Time { return deadline })
	t.Cleanup(sender.CancelPending)
	type sendResult struct {
		written int
		err     error
	}
	done := make(chan sendResult, 1)
	go func() {
		written, err := sender.Send([]byte("abcdef"), sendOptions{})
		done <- sendResult{written, err}
	}()
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the send was never submitted")
	}
	select {
	case result := <-done:
		if !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("error = %v, want os.ErrDeadlineExceeded", result.err)
		}
		if !streamCompletionUnproven(result.err) {
			t.Fatalf("error %v does not mark the aborted prefix as unknown", result.err)
		}
		if result.written != 0 {
			t.Fatalf("written = %d, want 0: the aborted status carries no authoritative count", result.written)
		}
	case <-time.After(2 * time.Second):
		_ = windows.SetEvent(sender.event)
		t.Fatal("the expiring deadline did not abort the pending send")
	}
	if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
		t.Fatalf("state after the terminal abort: buffer=%d sending=%v, want retired", buffer, sending)
	}
}

// A pending send completes through the completion event without a deadline.
func TestWindowsSendWaitsForCompletionEvent(t *testing.T) {
	state := &windowsSeamState{
		send: func(_ []byte, _ uint32, overlapped *windows.Overlapped) error {
			go func() { _ = windows.SetEvent(overlapped.HEvent) }()
			return windows.ERROR_IO_PENDING
		},
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 7, nil
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)
	written, err := sender.Send([]byte("abcdef"), sendOptions{})
	if err != nil || written != 7 {
		t.Fatalf("Send = %d,%v, want 7,nil", written, err)
	}
}

// A synchronous WSASend completion returns its count directly.
func TestWindowsSendSynchronousCompletion(t *testing.T) {
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error { return nil },
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 6, nil
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)
	written, err := sender.Send([]byte("abcdef"), sendOptions{})
	if err != nil || written != 6 {
		t.Fatalf("Send = %d,%v, want 6,nil", written, err)
	}
}

// OOB sends append the urgent byte and set MSG_OOB.
func TestWindowsSendOOBAppendsUrgentByte(t *testing.T) {
	var (
		captured []byte
		flags    uint32
	)
	state := &windowsSeamState{}
	state.send = func(data []byte, sendFlags uint32, _ *windows.Overlapped) error {
		state.mu.Lock()
		captured = data
		flags = sendFlags
		state.mu.Unlock()
		return nil
	}
	state.result = func(*windows.Overlapped, bool) (uint32, error) { return 7, nil }
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)
	written, err := sender.Send([]byte("abcdef"), sendOptions{oob: true, oobByte: 'Z'})
	if err != nil || written != 7 {
		t.Fatalf("Send = %d,%v, want 7,nil", written, err)
	}
	state.mu.Lock()
	got := append([]byte(nil), captured...)
	state.mu.Unlock()
	if flags != windows.MSG_OOB {
		t.Fatalf("flags = %#x, want MSG_OOB", flags)
	}
	if !bytes.Equal(got, []byte("abcdefZ")) {
		t.Fatalf("OOB buffer = %q, want the real bytes plus the urgent byte", got)
	}
}

// CancelPending aborts an in-flight send and releases the waiter. The aborted
// status is a terminal receipt without a count, so the operation is retired,
// the prefix is marked unknown and the caller keeps net.ErrClosed.
func TestWindowsSendCancelPendingReleasesWaiter(t *testing.T) {
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error { return windows.ERROR_IO_PENDING },
		result: func(*windows.Overlapped, bool) (uint32, error) {
			return 2, windows.ERROR_OPERATION_ABORTED
		},
		cancel: func(overlapped *windows.Overlapped) error {
			_ = windows.SetEvent(overlapped.HEvent)
			return nil
		},
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)
	type sendResult struct {
		written int
		err     error
	}
	done := make(chan sendResult, 1)
	go func() {
		written, err := sender.Send([]byte("abcdef"), sendOptions{})
		done <- sendResult{written, err}
	}()
	time.Sleep(20 * time.Millisecond)
	sender.CancelPending()
	select {
	case result := <-done:
		if result.err == nil {
			t.Fatal("cancelled send must report an error")
		}
		if !errors.Is(result.err, net.ErrClosed) || !streamCompletionUnproven(result.err) {
			t.Fatalf("error = %v, want net.ErrClosed through the unknown-prefix marker", result.err)
		}
		if result.written != 0 {
			t.Fatalf("written = %d, want 0: the aborted status carries no authoritative count", result.written)
		}
		if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
			t.Fatalf("state after the terminal abort: buffer=%d sending=%v, want retired", buffer, sending)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CancelPending did not release the blocked send")
	}
}

// Release during an in-flight send defers the event close to the send's end.
func TestWindowsSendReleaseDuringInflightSend(t *testing.T) {
	state := &windowsSeamState{
		send: func(_ []byte, _ uint32, overlapped *windows.Overlapped) error {
			go func() {
				time.Sleep(20 * time.Millisecond)
				_ = windows.SetEvent(overlapped.HEvent)
			}()
			return windows.ERROR_IO_PENDING
		},
		result: func(*windows.Overlapped, bool) (uint32, error) { return 4, nil },
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, nil)
	done := make(chan error, 1)
	go func() {
		_, err := sender.Send([]byte("abcdef"), sendOptions{})
		done <- err
	}()
	time.Sleep(5 * time.Millisecond)
	sender.Release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not finish after Release")
	}
	// Release is idempotent.
	sender.Release()
}

func TestWindowsSendTimeoutConversion(t *testing.T) {
	if timeout, expired := windowsSendTimeout(nil); timeout != windows.INFINITE || expired {
		t.Fatalf("nil deadline = %d,%v", timeout, expired)
	}
	if timeout, expired := windowsSendTimeout(func() time.Time { return time.Time{} }); timeout != windows.INFINITE || expired {
		t.Fatalf("zero deadline = %d,%v", timeout, expired)
	}
	if _, expired := windowsSendTimeout(func() time.Time { return time.Now().Add(-time.Millisecond) }); !expired {
		t.Fatal("past deadline must report expired")
	}
	if timeout, expired := windowsSendTimeout(func() time.Time { return time.Now().Add(500 * time.Millisecond) }); expired || timeout == 0 || timeout == windows.INFINITE {
		t.Fatalf("future deadline = %d,%v", timeout, expired)
	}
}

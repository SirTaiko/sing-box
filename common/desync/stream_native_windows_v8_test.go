//go:build windows

package desync

// Submission 8 behavior regressions for the security findings A1 (deadline
// enforcement) and A2 (submitted-buffer lifetime) of the Windows overlapped
// sender. They reuse the injected WSASend/WSAGetOverlappedResult/CancelIoEx
// seams and a real completion event, so no socket is opened. Native Windows
// execution is still required for wire-level evidence.

import (
	"errors"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func v8WindowsPendingSend(submitted chan struct{}) func([]byte, uint32, *windows.Overlapped) error {
	var once sync.Once
	return func(_ []byte, _ uint32, _ *windows.Overlapped) error {
		if submitted != nil {
			once.Do(func() { close(submitted) })
		}
		return windows.ERROR_IO_PENDING
	}
}

func v8WindowsSignalOnCancel(overlapped *windows.Overlapped) error {
	return windows.SetEvent(overlapped.HEvent)
}

type v8WindowsSendResult struct {
	written int
	err     error
}

// A1: an already expired deadline must keep the bytes out of the socket; the
// previous implementation called WSASend first and checked the deadline later.
func TestWindowsV8ExpiredDeadlinePreventsSubmission(t *testing.T) {
	submissions := 0
	state := &windowsSeamState{
		send: func([]byte, uint32, *windows.Overlapped) error {
			submissions++
			return nil
		},
		result: func(*windows.Overlapped, bool) (uint32, error) { return 5, nil },
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, func() time.Time { return time.Now().Add(-time.Second) })
	written, err := sender.Send([]byte("FIRST"), sendOptions{})
	if submissions != 0 {
		t.Fatalf("WSASend submissions = %d, want 0 for an expired deadline", submissions)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("error = %v, want os.ErrDeadlineExceeded", err)
	}
	if written != 0 {
		t.Fatalf("written = %d, want 0", written)
	}
}

// A1: a deadline shortened while the send is pending must abort it. The abort
// is terminal but carries no documented count, so the operation is retired with
// an unknown prefix instead of reporting the unset output as zero.
func TestWindowsV8PendingDeadlineShortenAbortsUncounted(t *testing.T) {
	submitted := make(chan struct{})
	state := &windowsSeamState{
		send:   v8WindowsPendingSend(submitted),
		result: func(*windows.Overlapped, bool) (uint32, error) { return 3, windows.ERROR_OPERATION_ABORTED },
		cancel: v8WindowsSignalOnCancel,
	}
	stubWindowsSeams(t, state)
	sender := newTestWindowsSender(t, func() time.Time { return time.Time{} })
	t.Cleanup(sender.CancelPending)
	done := make(chan v8WindowsSendResult, 1)
	go func() {
		written, err := sender.Send([]byte("abcdef"), sendOptions{})
		done <- v8WindowsSendResult{written, err}
	}()
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the send was never submitted")
	}
	start := time.Now()
	sender.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case result := <-done:
		if !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Fatalf("error = %v, want os.ErrDeadlineExceeded", result.err)
		}
		if result.written != 0 || !streamCompletionUnproven(result.err) {
			t.Fatalf("written = %d, error = %v; want 0 and an unknown-prefix marker (no documented count on abort)", result.written, result.err)
		}
		if buffer, _, sending := v9SenderState(sender); buffer != 0 || sending {
			t.Fatalf("state after the terminal abort: buffer=%d sending=%v, want retired", buffer, sending)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("the shortened deadline took %v to abort the pending send", elapsed)
		}
	case <-time.After(2 * time.Second):
		_ = windows.SetEvent(sender.event)
		t.Fatal("a shortened write deadline did not wake the pending send")
	}
}

// A1: extending the deadline while the send is pending must keep it alive past
// the original value and return the real completion.
func TestWindowsV8PendingDeadlineExtensionKeepsSendAlive(t *testing.T) {
	submitted := make(chan struct{})
	state := &windowsSeamState{
		send:   v8WindowsPendingSend(submitted),
		result: func(*windows.Overlapped, bool) (uint32, error) { return 6, nil },
		cancel: v8WindowsSignalOnCancel,
	}
	stubWindowsSeams(t, state)
	deadline := time.Now().Add(40 * time.Millisecond)
	sender := newTestWindowsSender(t, func() time.Time { return deadline })
	t.Cleanup(sender.CancelPending)
	done := make(chan v8WindowsSendResult, 1)
	go func() {
		written, err := sender.Send([]byte("abcdef"), sendOptions{})
		done <- v8WindowsSendResult{written, err}
	}()
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the send was never submitted")
	}
	sender.SetWriteDeadline(time.Now().Add(400 * time.Millisecond))
	// Past the original 40 ms deadline the send must still be outstanding.
	time.Sleep(90 * time.Millisecond)
	select {
	case result := <-done:
		t.Fatalf("the pending send was aborted at the extended-away deadline: %d,%v", result.written, result.err)
	default:
	}
	_ = windows.SetEvent(sender.event)
	select {
	case result := <-done:
		if result.err != nil || result.written != 6 {
			t.Fatalf("Send = %d,%v, want the real completion 6,nil", result.written, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the completed send was not collected")
	}
}

// A1: clearing the deadline while the send is pending removes the bound; the
// operation completes normally instead of being aborted.
func TestWindowsV8PendingDeadlineClearKeepsSendAlive(t *testing.T) {
	submitted := make(chan struct{})
	state := &windowsSeamState{
		send:   v8WindowsPendingSend(submitted),
		result: func(*windows.Overlapped, bool) (uint32, error) { return 6, nil },
		cancel: v8WindowsSignalOnCancel,
	}
	stubWindowsSeams(t, state)
	deadline := time.Now().Add(30 * time.Millisecond)
	sender := newTestWindowsSender(t, func() time.Time { return deadline })
	t.Cleanup(sender.CancelPending)
	done := make(chan v8WindowsSendResult, 1)
	go func() {
		written, err := sender.Send([]byte("abcdef"), sendOptions{})
		done <- v8WindowsSendResult{written, err}
	}()
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the send was never submitted")
	}
	sender.SetWriteDeadline(time.Time{})
	time.Sleep(80 * time.Millisecond)
	select {
	case result := <-done:
		t.Fatalf("the send was aborted although the deadline was cleared: %d,%v", result.written, result.err)
	default:
	}
	_ = windows.SetEvent(sender.event)
	select {
	case result := <-done:
		if result.err != nil || result.written != 6 {
			t.Fatalf("Send = %d,%v, want 6,nil", result.written, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the completed send was not collected")
	}
}

// A2: the actual submitted backing store - here the private OOB allocation the
// caller cannot root - must stay reachable until the terminal completion.
func TestWindowsV8SubmittedBufferRetainedUntilCompletion(t *testing.T) {
	collected := make(chan struct{}, 1)
	submitted := make(chan struct{})
	var (
		sender   *windowsSender
		retained []byte
	)
	state := &windowsSeamState{}
	state.send = func(data []byte, flags uint32, _ *windows.Overlapped) error {
		if flags != windows.MSG_OOB {
			t.Errorf("flags = %#x, want MSG_OOB", flags)
		}
		if len(data) != 4097 {
			t.Errorf("submitted length = %d, want the 4096 caller bytes plus the urgent byte", len(data))
		}
		// The seam runs while the sender holds its own mutex, i.e. after the
		// submission was recorded and before the wait.
		if sender == nil || sender.submitted == nil {
			t.Error("the submitted buffer is not retained by the operation owner")
		} else {
			retained = append([]byte(nil), sender.submitted...)
			runtime.SetFinalizer((*[4097]byte)(unsafe.Pointer(&sender.submitted[0])), func(*[4097]byte) {
				collected <- struct{}{}
			})
		}
		close(submitted)
		return windows.ERROR_IO_PENDING
	}
	state.result = func(*windows.Overlapped, bool) (uint32, error) { return 4097, nil }
	state.cancel = v8WindowsSignalOnCancel
	stubWindowsSeams(t, state)
	sender = newTestWindowsSender(t, func() time.Time { return time.Time{} })
	t.Cleanup(sender.CancelPending)

	done := make(chan v8WindowsSendResult, 1)
	go func() {
		p := new([4096]byte)
		written, err := sender.Send(p[:], sendOptions{oob: true, oobByte: 'Z'})
		runtime.KeepAlive(p)
		done <- v8WindowsSendResult{written, err}
	}()
	select {
	case <-submitted:
	case <-time.After(2 * time.Second):
		t.Fatal("the OOB send was never submitted")
	}

	early := false
	for i := 0; i < 8; i++ {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(time.Millisecond)
		select {
		case <-collected:
			early = true
		default:
		}
	}
	_ = windows.SetEvent(sender.event)
	select {
	case result := <-done:
		if result.err != nil || result.written != 4097 {
			t.Fatalf("Send = %d,%v, want 4097,nil", result.written, result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the OOB send did not complete")
	}
	if early {
		t.Fatal("the private OOB buffer was finalized while the WSASend was still pending")
	}
	if len(retained) != 4097 || retained[4096] != 'Z' {
		t.Fatalf("retained buffer = %d bytes, tail %q, want the exact submitted OOB buffer", len(retained), string(retained[4096:]))
	}
	if sender.submitted != nil {
		t.Fatal("the submitted buffer is still retained after the terminal completion")
	}
}

// Control for the retention test: the same finalizer and GC loop do observe a
// genuinely unreachable allocation, so the retention assertion above is a real
// difference and not an inert finalizer.
func TestWindowsV8FinalizerObservationControl(t *testing.T) {
	collected := make(chan struct{}, 1)
	func() {
		placeholder := new([4097]byte)
		runtime.SetFinalizer(placeholder, func(*[4097]byte) { collected <- struct{}{} })
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		runtime.Gosched()
		select {
		case <-collected:
			return
		default:
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("an unreachable finalized buffer was never collected")
}

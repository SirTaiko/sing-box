package desync

// Submission 9 regressions for the stream findings of the security recheck
// t_8c719ee9 (A-S1 deadline publication ordering, A-S2/A-S3 completion
// ownership and count preservation) at the wrapper level.
//
// The platform sender seam is a caching double, so these tests need no socket
// and no host network state. The Windows sender body itself is covered by
// stream_native_windows_v9_test.go, which runs through the API-result seam.

import (
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// v9DeadlineSender caches the deadline it was published, like the Windows
// overlapped sender, and accounts for the native bytes it accepted. gated makes
// the first publication block, so a test can land a caller deadline setter
// between the adoption snapshot and the adoption publication - the exact
// ordering A-S1 reports.
type v9DeadlineSender struct {
	mu        sync.Mutex
	deadline  time.Time
	calls     int
	accepted  int
	gated     bool
	entered   chan struct{}
	resume    chan struct{}
	sendError error
}

func (s *v9DeadlineSender) SetWriteDeadline(deadline time.Time) {
	if s.gated {
		s.mu.Lock()
		s.calls++
		first := s.calls == 1
		s.mu.Unlock()
		if first {
			close(s.entered)
			<-s.resume
		}
	}
	s.mu.Lock()
	s.deadline = deadline
	s.mu.Unlock()
}

func (s *v9DeadlineSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	deadline := s.deadline
	sendError := s.sendError
	s.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	if sendError != nil {
		return 0, sendError
	}
	s.mu.Lock()
	s.accepted += len(data)
	s.mu.Unlock()
	return len(data), nil
}

func (s *v9DeadlineSender) WaitNotSent(time.Duration) bool { return true }

func (s *v9DeadlineSender) CancelPending() {}

func (s *v9DeadlineSender) Release() {}

func (s *v9DeadlineSender) state() (time.Time, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline, s.accepted
}

func newV9GatedSender() *v9DeadlineSender {
	return &v9DeadlineSender{gated: true, entered: make(chan struct{}), resume: make(chan struct{})}
}

// v9NativeStream wraps conn for a rule that needs the native sender for an
// unsplit block.
func v9NativeStream(t *testing.T, sender streamSender) (net.Conn, *fakeConn) {
	t.Helper()
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	return wrapStream(t, config, conn, MatchFacts{}), conn
}

// A-S1: a completed expired SetWriteDeadline must not be overwritten by an
// adoption publication that snapshotted the deadline before it, and the native
// send must not accept bytes afterwards.
func TestStreamV9AdoptionCannotOverwriteCompletedDeadline(t *testing.T) {
	sender := newV9GatedSender()
	wrapped, _ := v9NativeStream(t, sender)
	t.Cleanup(func() { _ = wrapped.Close() })

	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("unrecognised-block"))
		writeDone <- err
	}()
	select {
	case <-sender.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sender adoption did not publish a deadline")
	}
	expired := time.Now().Add(-time.Second)
	if err := wrapped.SetWriteDeadline(expired); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	close(sender.resume)
	select {
	case <-writeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not finish")
	}
	last, accepted := sender.state()
	if !last.Equal(expired) {
		t.Fatalf("the sender enforces %v, want the completed caller deadline %v (stale adoption publication won)", last, expired)
	}
	if accepted != 0 {
		t.Fatalf("the native sender accepted %d bytes through a completed expired deadline", accepted)
	}
}

// A-S1, reverse order: an adoption publication that snapshotted a stricter
// deadline must not re-tighten the sender after a completed extension or clear.
func TestStreamV9CompletedDeadlineClearSurvivesStaleAdoption(t *testing.T) {
	sender := newV9GatedSender()
	wrapped, _ := v9NativeStream(t, sender)
	t.Cleanup(func() { _ = wrapped.Close() })
	if err := wrapped.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	block := []byte("unrecognised-block")
	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write(block)
		writeDone <- err
	}()
	select {
	case <-sender.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sender adoption did not publish a deadline")
	}
	if err := wrapped.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear write deadline: %v", err)
	}
	close(sender.resume)
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("Write after a completed clear: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write did not finish")
	}
	last, accepted := sender.state()
	if !last.IsZero() {
		t.Fatalf("the sender enforces %v, want the completed clear", last)
	}
	if accepted != len(block) {
		t.Fatalf("the native sender accepted %d of %d bytes: the stale stricter adoption deadline survived", accepted, len(block))
	}
}

// v9UnprovenSender reports a send whose terminal completion could not be
// established, after the provider may already have transmitted a prefix.
type v9UnprovenSender struct {
	mu     sync.Mutex
	accept int
	err    error
}

func (s *v9UnprovenSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	s.accept += len(data)
	s.mu.Unlock()
	return 0, newStreamUnknownCompletionError(s.err)
}

func (s *v9UnprovenSender) WaitNotSent(time.Duration) bool { return true }

func (s *v9UnprovenSender) CancelPending() {}

func (s *v9UnprovenSender) Release() {}

// v9ShortSender reports an authoritative prefix together with a terminal error,
// i.e. a completion whose count is known.
type v9ShortSender struct {
	sent int
	err  error
}

func (s *v9ShortSender) Send([]byte, sendOptions) (int, error) { return s.sent, s.err }

func (s *v9ShortSender) WaitNotSent(time.Duration) bool { return true }

func (s *v9ShortSender) CancelPending() {}

func (s *v9ShortSender) Release() {}

// A-S2/A-S3: an unproven completion never authorizes replaying the block tail -
// the provider may have delivered an unknown prefix - while an authoritative
// short count still does.
func TestStreamV9UnprovenCompletionIsNotReplayed(t *testing.T) {
	block := []byte("unrecognised-block")

	t.Run("unproven-completion", func(t *testing.T) {
		sender := &v9UnprovenSender{err: errors.New("substituted completion query failure")}
		wrapped, conn := v9NativeStream(t, sender)
		t.Cleanup(func() { _ = wrapped.Close() })
		_, err := wrapped.Write(block)
		if !streamCompletionUnproven(err) {
			t.Fatalf("Write error = %v, want an unproven-completion error", err)
		}
		if got := string(conn.collected()); got != "" {
			t.Fatalf("the wrapper forwarded %q after an unproven native completion", got)
		}
	})

	t.Run("known-prefix-control", func(t *testing.T) {
		sendErr := errors.New("substituted native send failure")
		sender := &v9ShortSender{sent: 3, err: sendErr}
		wrapped, conn := v9NativeStream(t, sender)
		t.Cleanup(func() { _ = wrapped.Close() })
		_, err := wrapped.Write(block)
		if !errors.Is(err, sendErr) {
			t.Fatalf("Write error = %v, want the original send error", err)
		}
		if got := string(conn.collected()); got != string(block[3:]) {
			t.Fatalf("forwarded %q, want the unsent tail %q", got, string(block[3:]))
		}
	})

	t.Run("short-count-control", func(t *testing.T) {
		sender := &v9ShortSender{sent: 2}
		wrapped, conn := v9NativeStream(t, sender)
		t.Cleanup(func() { _ = wrapped.Close() })
		if _, err := wrapped.Write(block); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := string(conn.collected()); got != string(block[2:]) {
			t.Fatalf("forwarded %q, want the unsent tail %q", got, string(block[2:]))
		}
	})
}

package desync

// Submission 10 regressions for the stream findings of the independent QA
// t_820c6bd7 (Q9-D1 deadline publication ordering under concurrent completed
// setters, Q9-D2 an unreadable count after an observed completion) at the
// wrapper level.
//
// The platform sender seam is a caching double, so these tests need no socket
// and no host network state. The production Windows sender body is covered by
// stream_native_windows_v10_test.go through the API-result seam.

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v10DeadlinePublication is one deadline the wrapper delivered to the sender.
// The test releases it explicitly, so every interleaving is deterministic.
type v10DeadlinePublication struct {
	value  time.Time
	resume chan struct{}
}

// v10PublishingSender caches the deadline it is published, like the Windows
// overlapped sender, refuses a send once the cached deadline has passed (the
// consequence a stale publication has on the production sender) and can hold
// every publication until the test releases it.
type v10PublishingSender struct {
	mu           sync.Mutex
	published    time.Time
	publications []time.Time
	accepted     int
	calls        chan *v10DeadlinePublication
	gate         atomic.Bool
}

func newV10PublishingSender() *v10PublishingSender {
	sender := &v10PublishingSender{calls: make(chan *v10DeadlinePublication, 16)}
	sender.gate.Store(true)
	return sender
}

func (s *v10PublishingSender) SetWriteDeadline(deadline time.Time) {
	if s.gate.Load() {
		publication := &v10DeadlinePublication{value: deadline, resume: make(chan struct{})}
		select {
		case s.calls <- publication:
		case <-time.After(5 * time.Second):
			// The test stopped consuming publications: do not deadlock the
			// wrapper, deliver the value unverified and let the assertion fail.
			close(publication.resume)
		}
		<-publication.resume
	}
	s.mu.Lock()
	s.published = deadline
	s.publications = append(s.publications, deadline)
	s.mu.Unlock()
}

func (s *v10PublishingSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.published.IsZero() && !time.Now().Before(s.published) {
		return 0, os.ErrDeadlineExceeded
	}
	s.accepted += len(data)
	return len(data), nil
}

func (s *v10PublishingSender) WaitNotSent(time.Duration) bool { return true }
func (s *v10PublishingSender) CancelPending()                 {}
func (s *v10PublishingSender) Release()                       {}

// state reports the last published deadline, the accepted byte count and the
// deadlines that were actually delivered, in delivery order.
func (s *v10PublishingSender) state() (time.Time, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.published, s.accepted
}

// delivered reports the deadlines that were actually delivered, in order.
func (s *v10PublishingSender) delivered() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.publications...)
}

// next returns the next publication, failing the test when the wrapper does not
// publish one and asserting the published value.
func (s *v10PublishingSender) next(t *testing.T, want time.Time, label string) *v10DeadlinePublication {
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

// nextWithin is next with a shorter bound, used for the repairing publication
// that must follow the last completed setter.
func (s *v10PublishingSender) nextWithin(t *testing.T, timeout time.Duration, want time.Time, label string, detail string) *v10DeadlinePublication {
	t.Helper()
	select {
	case publication := <-s.calls:
		if !publication.value.Equal(want) {
			t.Fatalf("%s: published %v, want %v", label, publication.value, want)
		}
		return publication
	case <-time.After(timeout):
		t.Fatalf("%s: no deadline publication after %s (%s)", label, timeout, detail)
		return nil
	}
}

func releaseV10(publication *v10DeadlinePublication) { close(publication.resume) }

// setWriteDeadlineAsync runs one caller deadline update and reports its error.
func setWriteDeadlineAsync(conn net.Conn, deadline time.Time) <-chan error {
	done := make(chan error, 1)
	go func() { done <- conn.SetWriteDeadline(deadline) }()
	return done
}

func awaitV10(t *testing.T, done <-chan error, label string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: SetWriteDeadline did not return", label)
	}
}

// Q9-D1: three concurrent caller deadline setters complete while an adoption
// publication is in flight, and each one lands after the in-flight publication
// read its value. A bounded number of verification passes can be exhausted, so
// the sender is left enforcing the expired value while the effective deadline is
// cleared; the publication protocol must instead converge on the current
// source, and the sender must then accept I/O (the consequence the production
// Windows sender exhibits for a stale expired value).
func TestStreamV10ThreeCompletedSettersLeaveNoStalePublication(t *testing.T) {
	long := time.Now().Add(time.Hour)
	mid := time.Now().Add(30 * time.Minute)
	expired := time.Now().Add(-time.Minute)
	cleared := time.Time{}

	sender := newV10PublishingSender()
	wrapped, conn := v9NativeStream(t, sender)
	t.Cleanup(func() { _ = wrapped.Close() })
	stream := wrapped.(*streamConn)
	stream.storeWriteDeadline(long)

	// Publisher P: the adoption/verification publication.
	adopted := make(chan struct{})
	go func() {
		stream.adoptSender(sender)
		close(adopted)
	}()
	p1 := sender.next(t, long, "adoption pass 1")

	first := setWriteDeadlineAsync(wrapped, mid)
	p2 := sender.next(t, mid, "setter 1 publication")
	releaseV10(p1)
	p3 := sender.next(t, mid, "adoption pass 2")
	releaseV10(p2)
	awaitV10(t, first, "setter 1")

	second := setWriteDeadlineAsync(wrapped, expired)
	p4 := sender.next(t, expired, "setter 2 publication")
	releaseV10(p3)
	p5 := sender.next(t, expired, "adoption pass 3")
	releaseV10(p4)
	awaitV10(t, second, "setter 2")

	third := setWriteDeadlineAsync(wrapped, cleared)
	p6 := sender.next(t, cleared, "setter 3 publication")
	releaseV10(p6)
	awaitV10(t, third, "setter 3")
	if effective := stream.currentWriteDeadline(); !effective.IsZero() {
		t.Fatalf("effective deadline = %v, want the completed clear", effective)
	}

	// The adoption's third publication lands after the third setter, so it
	// delivers a stale expired value. The publication must not return before
	// the value it delivered is current again.
	releaseV10(p5)
	p7 := sender.nextWithin(t, 5*time.Second, cleared, "repaired publication",
		"the sender still enforces the stale expired deadline")
	releaseV10(p7)
	select {
	case <-adopted:
	case <-time.After(5 * time.Second):
		t.Fatal("the adoption publication did not return")
	}

	published, accepted := sender.state()
	effective := stream.currentWriteDeadline()
	if !published.Equal(effective) {
		t.Fatalf("the sender enforces %v after three completed setters, the effective deadline is %v (publications %v)",
			published, effective, sender.delivered())
	}
	if accepted != 0 {
		t.Fatalf("the sender accepted %d bytes before the consequence check", accepted)
	}

	// Consequence: with the cleared deadline published, a native send must
	// reach the sender instead of being refused by a stale expired value.
	sender.gate.Store(false)
	block := []byte("unrecognised-block")
	if _, err := wrapped.Write(block); err != nil {
		t.Fatalf("Write after the completed clear: %v (stale publication denies I/O)", err)
	}
	if _, accepted = sender.state(); accepted != len(block) {
		t.Fatalf("the native sender accepted %d of %d bytes after the completed clear", accepted, len(block))
	}
	if len(conn.collected()) != 0 {
		t.Fatalf("the wrapper forwarded %q to the fallback connection", conn.collected())
	}
}

// v10UnknownCompletionSender reports a send whose completion was observed but
// whose transferred prefix could not be read, exactly what the Windows sender
// returns for a synchronous WSASend success whose completion query fails.
type v10UnknownCompletionSender struct {
	mu      sync.Mutex
	sent    int
	cause   error
	accepts int
}

func (s *v10UnknownCompletionSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	s.accepts += len(data)
	s.mu.Unlock()
	if s.cause == nil {
		return s.sent, nil
	}
	return 0, newStreamUnknownCompletionError(s.cause)
}

func (s *v10UnknownCompletionSender) WaitNotSent(time.Duration) bool { return true }
func (s *v10UnknownCompletionSender) CancelPending()                 {}
func (s *v10UnknownCompletionSender) Release()                       {}

// v10PlainZeroSender reports a plain (0, err) result, the shape the Windows
// sender used to produce for an unreadable completion count.
type v10PlainZeroSender struct {
	cause error
}

func (s *v10PlainZeroSender) Send([]byte, sendOptions) (int, error) { return 0, s.cause }
func (s *v10PlainZeroSender) WaitNotSent(time.Duration) bool        { return true }
func (s *v10PlainZeroSender) CancelPending()                        {}
func (s *v10PlainZeroSender) Release()                              {}

// v10PartialSender reports an authoritative partial count.
type v10PartialSender struct {
	sent int
}

func (s *v10PartialSender) Send([]byte, sendOptions) (int, error) { return s.sent, nil }
func (s *v10PartialSender) WaitNotSent(time.Duration) bool        { return true }
func (s *v10PartialSender) CancelPending()                        {}
func (s *v10PartialSender) Release()                              {}

// Q9-D2: a completion the provider observed but could not count is an unknown
// prefix, not "zero bytes accepted". The wrapper must not replay the block, and
// the caller keeps the original error through the marker. The controls show
// what the wrapper does with a plain zero report and with an authoritative
// partial count.
func TestStreamV10UnknownCompletionPrefixIsNotReplayed(t *testing.T) {
	block := []byte("unrecognised-block")
	countQueryFailure := errors.New("substituted completion count failure")

	t.Run("sync-count-unavailable", func(t *testing.T) {
		sender := &v10UnknownCompletionSender{cause: countQueryFailure}
		wrapped, conn := v9NativeStream(t, sender)
		t.Cleanup(func() { _ = wrapped.Close() })
		_, err := wrapped.Write(block)
		if err == nil {
			t.Fatal("Write with an uncounted completion returned nil")
		}
		if !streamCompletionUnproven(err) {
			t.Fatalf("Write error = %v, want an unknown-completion marker", err)
		}
		if !errors.Is(err, countQueryFailure) {
			t.Fatalf("Write error %v does not preserve the caller-visible cause", err)
		}
		if got := string(conn.collected()); got != "" {
			t.Fatalf("the wrapper forwarded %q after an uncounted completion", got)
		}
		if sender.accepts != len(block) {
			t.Fatalf("the native send saw %d of %d bytes", sender.accepts, len(block))
		}
	})

	t.Run("plain-zero-control", func(t *testing.T) {
		sender := &v10PlainZeroSender{cause: countQueryFailure}
		wrapped, conn := v9NativeStream(t, sender)
		t.Cleanup(func() { _ = wrapped.Close() })
		if _, err := wrapped.Write(block); err == nil {
			t.Fatal("Write with a plain native error returned nil")
		}
		if got := string(conn.collected()); got != string(block) {
			t.Fatalf("forwarded %q for a plain zero report, want the whole block %q", got, block)
		}
	})

	t.Run("partial-count-control", func(t *testing.T) {
		sender := &v10PartialSender{sent: 4}
		wrapped, conn := v9NativeStream(t, sender)
		t.Cleanup(func() { _ = wrapped.Close() })
		if _, err := wrapped.Write(block); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := string(conn.collected()); got != string(block[4:]) {
			t.Fatalf("forwarded %q, want the unsent tail %q", got, block[4:])
		}
	})
}

package desync

// Permanent regression for QA-D1, the independent scoped QA finding on stream
// v4 (task t_661cbe61, reproduced by the tester from
// TestQA661R3CloseFlushBoundedForDeadlineBlindSender): Close's pending flush
// only bounded the underlying connection's write deadline, while the Windows
// overlapped WSASend sender takes its wait bound from the wrapper's recorded
// deadline source. A sender first constructed by the Close flush therefore saw
// a zero source and waited INFINITE, so Close could not honour its documented
// <=250 ms bound without a second Close or caller action.
//
// The injected sender below models exactly that Windows contract: a pending
// send waits on a completion event whose timeout comes only from the wrapper
// deadline source, a zero source is an INFINITE wait only CancelPending can
// release, and the deadline set on the underlying conn is deliberately
// ignored. The assertions are the substantive QA ones: the first block is
// genuinely retained, the sender is constructed by the flush, Close returns
// on its own inside the bound, an earlier caller deadline is not extended, and
// every retained byte still reaches the wire exactly once.

import (
	"bytes"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// v5DeadlineBlindSender mirrors the Windows overlapped send lifecycle without
// a real socket: readiness is a wait on the wrapper deadline source, and the
// conn deadline is never consulted. With cacheOnly it models a platform sender
// that only applies deadline pushes through SetWriteDeadline and never calls
// the source itself.
type v5DeadlineBlindSender struct {
	mu          sync.Mutex
	deadline    func() time.Time
	cached      time.Time
	cacheOnly   bool
	released    chan struct{}
	releaseOnce sync.Once
	sends       int
	observed    time.Time
	cancelled   int
}

func newV5DeadlineBlindSender() *v5DeadlineBlindSender {
	return &v5DeadlineBlindSender{released: make(chan struct{})}
}

// SetWriteDeadline records a pushed deadline. It is called by the wrapper when
// the active sender is registered and on every later caller update.
func (s *v5DeadlineBlindSender) SetWriteDeadline(deadline time.Time) {
	s.mu.Lock()
	s.cached = deadline
	s.mu.Unlock()
}

func (s *v5DeadlineBlindSender) effectiveDeadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cacheOnly {
		return s.cached
	}
	if s.deadline == nil {
		return time.Time{}
	}
	return s.deadline()
}

func (s *v5DeadlineBlindSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	s.sends++
	s.mu.Unlock()
	deadline := s.effectiveDeadline()
	s.mu.Lock()
	s.observed = deadline
	s.mu.Unlock()
	if deadline.IsZero() {
		// No deadline is an INFINITE wait, exactly like WaitForSingleObject
		// with windows.INFINITE. Only cancellation releases it.
		<-s.released
		return 0, net.ErrClosed
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-s.released:
		return 0, net.ErrClosed
	case <-timer.C:
		return 0, os.ErrDeadlineExceeded
	}
}

func (s *v5DeadlineBlindSender) WaitNotSent(time.Duration) bool { return true }

func (s *v5DeadlineBlindSender) CancelPending() {
	s.mu.Lock()
	s.cancelled++
	s.mu.Unlock()
	s.releaseOnce.Do(func() { close(s.released) })
}

func (s *v5DeadlineBlindSender) state() (sends int, observed time.Time, cancelled int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sends, s.observed, s.cancelled
}

// v5DeadlineNative records the deadline source handed to the platform sender.
type v5DeadlineNative struct {
	mu       sync.Mutex
	sender   *v5DeadlineBlindSender
	deadline func() time.Time
	created  int
}

func (n *v5DeadlineNative) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *v5DeadlineNative) NewSender(_ net.Conn, deadline func() time.Time) (streamSender, error) {
	n.mu.Lock()
	n.deadline = deadline
	n.created++
	n.mu.Unlock()
	n.sender.mu.Lock()
	n.sender.deadline = deadline
	n.sender.mu.Unlock()
	return n.sender, nil
}

func (n *v5DeadlineNative) state() (created int, deadline func() time.Time) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.created, n.deadline
}

// v5HeldPartialTLS is a TLS record whose declared body is longer than the
// written prefix, so the first block is retained until Close (or the hold
// fallback) flushes it.
func v5HeldPartialTLS() []byte {
	return []byte{0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00, 0x02}
}

// v5DeadlineBlindFlushFixture compiles a native-send rule (split + OOB), wraps
// a memory conn and retains the incomplete first block.
func v5DeadlineBlindFlushFixture(t *testing.T, sender *v5DeadlineBlindSender) (*v5DeadlineBlindSender, *v5DeadlineNative, *fakeConn, net.Conn, []byte) {
	t.Helper()
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	native := &v5DeadlineNative{sender: sender}
	config.native = native
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	held := v5HeldPartialTLS()
	if n, err := wrapped.Write(held); err != nil || n != len(held) {
		t.Fatalf("Write = %d,%v, want %d,nil", n, err, len(held))
	}
	if got := conn.collected(); len(got) != 0 {
		t.Fatalf("expected a retained first block, already emitted %x", got)
	}
	return sender, native, conn, wrapped, held
}

// QA-D1: Close's pending flush must be bounded by streamCloseFlushLimit for a
// sender that only honours the wrapper deadline source. Covered for both an
// absent caller deadline (INFINITE sender wait) and a caller deadline later
// than the flush bound (the bound must win).
func TestStreamV5CloseFlushBoundedForDeadlineBlindSender(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		setCaller  bool
		callerTerm time.Duration
	}{
		{name: "no-caller-deadline"},
		{name: "later-caller-deadline", setCaller: true, callerTerm: 10 * time.Second},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			sender, native, conn, wrapped, held := v5DeadlineBlindFlushFixture(t, newV5DeadlineBlindSender())
			if testCase.setCaller {
				if err := wrapped.SetWriteDeadline(time.Now().Add(testCase.callerTerm)); err != nil {
					t.Fatalf("SetWriteDeadline: %v", err)
				}
			}
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- wrapped.Close() }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(1500 * time.Millisecond):
				sender.CancelPending()
				if value, source := native.state(); source != nil {
					t.Logf("Close-flush sender #%d deadline source = %v", value, source())
				} else {
					t.Logf("Close-flush sender #%d never received a deadline source", value)
				}
				// Release the blocked sender so the rest of the suite can
				// proceed; this is the failure path, not the passing escape.
				select {
				case <-done:
				case <-time.After(2 * time.Second):
				}
				sends, observed, _ := sender.state()
				t.Fatalf("Close's pending flush is unbounded for a deadline-blind sender (sends=%d, observed=%v); "+
					"the Windows overlapped sender waits INFINITE on a zero wrapper deadline", sends, observed)
			}
			created, _ := native.state()
			if created != 1 {
				t.Fatalf("senders constructed = %d, want the flush to construct exactly one", created)
			}
			deadline := time.Time{}
			if _, source := native.state(); source != nil {
				deadline = source()
			}
			if deadline.IsZero() {
				t.Fatal("the native sender constructed by the Close flush received no deadline")
			}
			latest := start.Add(streamCloseFlushLimit + 500*time.Millisecond)
			if deadline.After(latest) {
				t.Fatalf("Close-flush deadline %v is later than the %v bound (start %v)", deadline, streamCloseFlushLimit, start)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("Close took %v, want a bounded return", elapsed)
			}
			// The flush must have completed on its own; Close then performs
			// its ordinary one-shot cancellation. A second Close or caller
			// escape is not part of the passing path.
			sends, observed, cancelled := sender.state()
			if sends != 1 {
				t.Fatalf("sender calls = %d, want the retained block sent once", sends)
			}
			if !observed.Equal(deadline) {
				t.Fatalf("sender observed %v, want the bounded wrapper deadline %v", observed, deadline)
			}
			if cancelled != 1 {
				t.Fatalf("Close lifecycle cancelled = %d, want 1", cancelled)
			}
			// Byte preservation: the deadline-expired segment is forwarded,
			// never dropped or duplicated.
			if got := conn.collected(); !bytes.Equal(got, held) {
				t.Fatalf("retained bytes changed after the bounded flush: got %x want %x", got, held)
			}
		})
	}
}

// QA-D1 adjacent contract: Close's flush must not extend an earlier caller
// deadline. The flush bound is an upper bound, not a replacement deadline.
func TestStreamV5CloseFlushKeepsStricterCallerDeadline(t *testing.T) {
	sender, native, conn, wrapped, held := v5DeadlineBlindFlushFixture(t, newV5DeadlineBlindSender())
	callerDeadline := time.Now().Add(40 * time.Millisecond)
	if err := wrapped.SetWriteDeadline(callerDeadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- wrapped.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(1500 * time.Millisecond):
		sender.CancelPending()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("Close's pending flush ignored the caller deadline and never returned")
	}
	elapsed := time.Since(start)
	if elapsed >= streamCloseFlushLimit {
		t.Fatalf("Close took %v: the flush extended the stricter caller deadline %v instead of preserving it",
			elapsed, callerDeadline.Sub(start))
	}
	created, source := native.state()
	if created != 1 || source == nil {
		t.Fatalf("senders constructed = %d, want one with a deadline source", created)
	}
	if got := source(); !got.Equal(callerDeadline) {
		t.Fatalf("Close-flush deadline = %v, want the stricter caller deadline %v", got, callerDeadline)
	}
	conn.mu.Lock()
	connDeadline := conn.writeDeadline
	conn.mu.Unlock()
	if !connDeadline.Equal(callerDeadline) {
		t.Fatalf("underlying conn deadline = %v, want the stricter caller deadline %v", connDeadline, callerDeadline)
	}
	if got := conn.collected(); !bytes.Equal(got, held) {
		t.Fatalf("retained bytes changed after the bounded flush: got %x want %x", got, held)
	}
}

// QA-D1: a platform sender that caches the deadline pushed through
// SetWriteDeadline (instead of reading the wrapper source lazily) must receive
// the flush bound when the flush registers it, not only a zero initialization.
func TestStreamV5CloseFlushReachesCachingSender(t *testing.T) {
	caching := newV5DeadlineBlindSender()
	caching.cacheOnly = true
	sender, native, conn, wrapped, held := v5DeadlineBlindFlushFixture(t, caching)
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- wrapped.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(1500 * time.Millisecond):
		sender.CancelPending()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("Close's pending flush never pushed a deadline to a sender that caches it")
	}
	created, _ := native.state()
	if created != 1 {
		t.Fatalf("senders constructed = %d, want one", created)
	}
	sends, observed, cancelled := sender.state()
	if sends != 1 || cancelled != 1 {
		t.Fatalf("sender calls=%d cancelled=%d, want 1/1", sends, cancelled)
	}
	if observed.IsZero() {
		t.Fatal("sender registered by the Close flush cached no deadline")
	}
	if latest := start.Add(streamCloseFlushLimit + 500*time.Millisecond); observed.After(latest) {
		t.Fatalf("cached deadline %v is later than the %v bound (start %v)", observed, streamCloseFlushLimit, start)
	}
	if got := conn.collected(); !bytes.Equal(got, held) {
		t.Fatalf("retained bytes changed after the bounded flush: got %x want %x", got, held)
	}
}

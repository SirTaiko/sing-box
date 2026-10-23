package desync

// Permanent regressions for the TFO3 deferred-adoption deadline review
// (security t_8c719ee9 B-S3). A deferred first-send sender is adopted only
// after the pending write created the native connection; a public
// SetWriteDeadline that completes inside that window used to be overwritten by
// the adoption's stale snapshot, so later native I/O ignored the caller's
// deadline. Both orders are pinned here, together with the serial control.

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bytes"
)

// adoptionDeadlineSender is a native sender whose first deadline publication is
// held open by the test, which is the adoption publication window. Later
// publications are not gated, so the fixture can never deadlock: only the
// ordering of the published values is measured.
type adoptionDeadlineSender struct {
	mu       sync.Mutex
	deadline time.Time
	accepted int

	calls   atomic.Int32
	entered chan struct{}
	resume  chan struct{}
}

func newAdoptionDeadlineSender(gated bool) *adoptionDeadlineSender {
	sender := &adoptionDeadlineSender{}
	if gated {
		sender.entered = make(chan struct{})
		sender.resume = make(chan struct{})
	}
	return sender
}

func (s *adoptionDeadlineSender) SetWriteDeadline(deadline time.Time) {
	if s.calls.Add(1) == 1 && s.entered != nil {
		close(s.entered)
		<-s.resume
	}
	s.mu.Lock()
	s.deadline = deadline
	s.mu.Unlock()
}

func (s *adoptionDeadlineSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	deadline := s.deadline
	s.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	s.mu.Lock()
	s.accepted += len(data)
	s.mu.Unlock()
	return len(data), nil
}

func (s *adoptionDeadlineSender) WaitNotSent(time.Duration) bool { return true }
func (s *adoptionDeadlineSender) CancelPending()                 {}
func (s *adoptionDeadlineSender) Release()                       {}

func (s *adoptionDeadlineSender) counters() (time.Time, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline, s.accepted
}

// deferredNativeConfig compiles a deferred first-send rule whose per-segment
// control requires the native sender, and installs the recording sender.
func deferredNativeConfig(t *testing.T, sender streamSender) *StreamConfig {
	t.Helper()
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	config.native = &nativeRecorder{sender: sender}
	config.random = bytes.NewReader(bytes.Repeat([]byte{0}, 1<<16))
	return config
}

// A setter that completes while the deferred sender is being adopted must be
// the value the sender keeps, in both directions: a stricter deadline that
// arrives during adoption must not be replaced by the older value, and an
// extension/clear that arrives during adoption must not be replaced either.
func TestDeferredAdoptionKeepsCompletedDeadline(t *testing.T) {
	for _, mode := range []string{"shorten-during-adoption", "extend-during-adoption"} {
		t.Run(mode, func(t *testing.T) {
			sender := newAdoptionDeadlineSender(true)
			config := deferredNativeConfig(t, sender)
			conn := wrapStream(t, config, newFakePendingConn(), MatchFacts{})
			defer conn.Close()
			// A live starting deadline makes the adoption publish a value that
			// a concurrent setter can supersede.
			start := time.Now().Add(time.Minute)
			if err := conn.SetWriteDeadline(start); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				_, err := conn.Write([]byte("unrecognised-block"))
				done <- err
			}()
			select {
			case <-sender.entered:
			case <-time.After(time.Second):
				t.Fatal("adoption did not publish the write deadline")
			}
			next := time.Now().Add(-time.Second)
			if mode == "extend-during-adoption" {
				next = time.Time{}
			}
			if err := conn.SetWriteDeadline(next); err != nil {
				t.Fatal(err)
			}
			close(sender.resume)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("first write did not finish")
			}
			last, accepted := sender.counters()
			if !last.Equal(next) {
				t.Fatalf("%s: retained deadline = %v, want the completed newer %v", mode, last, next)
			}
			_, later := conn.Write([]byte("NEXT"))
			_, accepted = sender.counters()
			if mode == "shorten-during-adoption" {
				if accepted != 0 {
					t.Fatalf("expired deadline admitted %d later native bytes", accepted)
				}
				if later == nil {
					t.Fatal("later native write under the retained expired deadline succeeded")
				}
				return
			}
			if later != nil {
				t.Fatalf("cleared deadline rejected a later native write: %v", later)
			}
			if accepted == 0 {
				t.Fatal("a cleared deadline must admit later native bytes")
			}
		})
	}
}

// Serial control: a deadline set before adoption is published by the adoption
// itself and enforced by the native sender, so no native byte is accepted.
func TestDeferredAdoptionDeadlineBeforeAdoptionControl(t *testing.T) {
	sender := newAdoptionDeadlineSender(false)
	config := deferredNativeConfig(t, sender)
	conn := wrapStream(t, config, newFakePendingConn(), MatchFacts{})
	defer conn.Close()
	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("unrecognised-block")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if _, accepted := sender.counters(); accepted != 0 {
		t.Fatalf("expired pre-adoption deadline admitted %d native bytes", accepted)
	}
}

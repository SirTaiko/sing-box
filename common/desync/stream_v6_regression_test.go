package desync

// Permanent regression for QA-D2, the independent scoped QA finding on stream
// v5 (task t_8defa195, report t_8defa195-qa.md §4, probes
// TestQA8V5ConcurrentCallerClearCannotExtendClose,
// TestQA8V5ConcurrentCallerClearPassThroughFlush and the no-seam
// t_8defa195-natural-ordering-probe.go).
//
// Finding: Close's pending flush stores the 250 ms bound (flushDeadline) and
// delegates the effective deadline to the underlying conn, but a caller
// SetWriteDeadline/SetDeadline computes its own effective deadline and
// delegates it in a separate step. net.Conn requires every method to be safe
// for concurrent use, so this interleaving is legal:
//
//	caller:            effective = <computed before the bound existed>
//	flush:             flushDeadline.Store(now+250ms); conn.SetWriteDeadline(bound)
//	flush:             writeFull(conn, retained)      -> blocks (peer not reading)
//	caller:            conn.SetWriteDeadline(effective)  // zero or +2s, last value
//
// The conn then has no usable deadline and the flush's plain write - the
// unsent tail after a short/zero native send (R2), or a pass-through flush -
// never times out, so Close hangs past the documented bound (forever when the
// deadline was cleared) until a second Close or an external conn close.
//
// The regression is deterministic: the only seam is a gate on the first
// deadline call of the test conn, which makes a legal interleaving repeatable
// (the tester used the same seam; production has no hook). It is not a stress
// test - the deterministic cases are the proof; the no-seam loop at the end
// only guards the plain-scheduling path and does not claim coverage.
//
// Assertions per deterministic case: the flush really was writing the retained
// bytes on the plain conn, the caller update really was in flight when the
// flush block started, Close returns on its own inside the bound (no second
// Close, no caller escape), and the connection's last write deadline is the
// bounded effective value rather than the stale caller value.

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

// v6Gate is a one-shot scheduling gate: the first deadline call on the conn
// blocks until open() is called. It only exists in this test double.
type v6Gate struct {
	mu      sync.Mutex
	used    bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newV6Gate() *v6Gate {
	return &v6Gate{entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *v6Gate) block() {
	if g == nil {
		return
	}
	g.mu.Lock()
	first := !g.used
	g.used = true
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.release
	}
}

func (g *v6Gate) open() {
	if g == nil {
		return
	}
	g.once.Do(func() { close(g.release) })
}

func (g *v6Gate) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("the caller deadline update never reached the connection")
	}
}

// v6BlockedConn models a TCP connection whose peer stopped reading: Write
// blocks until the current write deadline expires, the connection is closed or
// the deadline changes (the Go poller recomputes a blocked write's timer, so a
// concurrent deadline update extends, clears or shortens the wait).
type v6BlockedConn struct {
	mu            sync.Mutex
	writeDeadline time.Time
	readDeadline  time.Time
	setLog        []time.Time
	attempts      [][]byte
	closed        bool
	closedCh      chan struct{}
	changed       chan struct{}
	blocked       chan struct{}
	blockedOnce   sync.Once
	writeGate     *v6Gate
	combinedGate  *v6Gate
}

func newV6BlockedConn() *v6BlockedConn {
	return &v6BlockedConn{
		closedCh: make(chan struct{}),
		changed:  make(chan struct{}),
		blocked:  make(chan struct{}),
	}
}

func (c *v6BlockedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.attempts = append(c.attempts, append([]byte(nil), p...))
	c.mu.Unlock()
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return 0, net.ErrClosed
		}
		deadline := c.writeDeadline
		changed := c.changed
		closedCh := c.closedCh
		c.mu.Unlock()
		c.blockedOnce.Do(func() { close(c.blocked) })
		var timer *time.Timer
		var timerC <-chan time.Time
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(remaining)
			timerC = timer.C
		}
		select {
		case <-closedCh:
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-timerC:
			return 0, os.ErrDeadlineExceeded
		}
	}
}

func (c *v6BlockedConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (c *v6BlockedConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	c.mu.Unlock()
	return nil
}

func (c *v6BlockedConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (c *v6BlockedConn) RemoteAddr() net.Addr { return fakeAddr{} }

func (c *v6BlockedConn) SetDeadline(deadline time.Time) error {
	c.combinedGate.block()
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.setLog = append(c.setLog, deadline)
	c.wakeLocked()
	c.mu.Unlock()
	return nil
}

func (c *v6BlockedConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *v6BlockedConn) SetWriteDeadline(deadline time.Time) error {
	c.writeGate.block()
	c.mu.Lock()
	c.writeDeadline = deadline
	c.setLog = append(c.setLog, deadline)
	c.wakeLocked()
	c.mu.Unlock()
	return nil
}

// wakeLocked releases a blocked Write so it re-reads the deadline.
func (c *v6BlockedConn) wakeLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *v6BlockedConn) waitBlocked(timeout time.Duration) bool {
	select {
	case <-c.blocked:
		return true
	case <-time.After(timeout):
		return false
	}
}

func (c *v6BlockedConn) deadlineLog() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.setLog...)
}

func (c *v6BlockedConn) lastWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.setLog) == 0 {
		return time.Time{}
	}
	return c.setLog[len(c.setLog)-1]
}

func (c *v6BlockedConn) readDeadlineValue() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline
}

func (c *v6BlockedConn) writeAttempts() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.attempts...)
}

// v6CacheSender models the Windows overlapped sender's contract without a
// socket: it caches the deadline pushed through SetWriteDeadline (it never
// calls the wrapper source) and a pending send waits on that cached value, a
// zero value being an unbounded wait released only by CancelPending.
type v6CacheSender struct {
	mu          sync.Mutex
	cached      time.Time
	observed    time.Time
	sends       int
	cancelled   int
	released    chan struct{}
	releaseOnce sync.Once
}

func newV6CacheSender() *v6CacheSender {
	return &v6CacheSender{released: make(chan struct{})}
}

func (s *v6CacheSender) SetWriteDeadline(deadline time.Time) {
	s.mu.Lock()
	s.cached = deadline
	s.mu.Unlock()
}

func (s *v6CacheSender) Send([]byte, sendOptions) (int, error) {
	s.mu.Lock()
	s.sends++
	deadline := s.cached
	s.observed = deadline
	s.mu.Unlock()
	if deadline.IsZero() {
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

func (s *v6CacheSender) WaitNotSent(time.Duration) bool { return true }

func (s *v6CacheSender) CancelPending() {
	s.mu.Lock()
	s.cancelled++
	s.mu.Unlock()
	s.releaseOnce.Do(func() { close(s.released) })
}

func (s *v6CacheSender) state() (cached, observed time.Time, sends, cancelled int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cached, s.observed, s.sends, s.cancelled
}

// v6Native counts sender construction (the QA-D1 contract: the flush creates
// exactly one sender) and hands out the injected sender.
type v6Native struct {
	mu      sync.Mutex
	created int
	sender  streamSender
}

func (n *v6Native) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *v6Native) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	n.mu.Lock()
	n.created++
	n.mu.Unlock()
	if n.sender == nil {
		return nil, errors.New("v6: no injected sender")
	}
	return n.sender, nil
}

func (n *v6Native) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.created
}

// v6HeldFirstBlock is a TLS record whose declared body is longer than the
// written prefix, so the first block is retained until a later Write or Close.
func v6HeldFirstBlock() []byte {
	return []byte{0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00, 0x02}
}

// v6NativeFixture compiles a native-send rule (split + OOB), wraps conn and
// retains the incomplete first block.
func v6NativeFixture(t *testing.T, conn *v6BlockedConn, sender streamSender, positions ...string) (net.Conn, *v6Native, []byte) {
	t.Helper()
	rule := splitRule(positions...)
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	native := &v6Native{sender: sender}
	config.native = native
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	held := v6HeldFirstBlock()
	if n, err := wrapped.Write(held); err != nil || n != len(held) {
		t.Fatalf("Write = %d,%v, want %d,nil", n, err, len(held))
	}
	if got := conn.writeAttempts(); len(got) != 0 {
		t.Fatalf("expected a retained first block, already wrote %x", got)
	}
	if got := conn.deadlineLog(); len(got) != 0 {
		t.Fatalf("deadline published before Close: %v", got)
	}
	return wrapped, native, held
}

// v6RunClose starts Close and waits for it, closing the conn (a test escape
// only on the failure path) so a stuck flush cannot leak a goroutine.
func v6RunClose(t *testing.T, conn *v6BlockedConn, wrapped net.Conn, window time.Duration) (time.Duration, error) {
	t.Helper()
	start := time.Now()
	done := make(chan error, 1)
	go func() { done <- wrapped.Close() }()
	select {
	case err := <-done:
		return time.Since(start), err
	case <-time.After(window):
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
		t.Fatalf("Close did not return within %v: the %v flush bound was lost (conn deadline log %v)",
			window, streamCloseFlushLimit, conn.deadlineLog())
		return 0, nil
	}
}

// v6AssertBoundedClose checks the QA-D2 invariant on a completed Close.
func v6AssertBoundedClose(t *testing.T, elapsed time.Duration, err error, start time.Time, conn *v6BlockedConn, value time.Time) {
	t.Helper()
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	if elapsed > time.Second {
		t.Fatalf("Close took %v after a concurrent caller deadline update (%v)", elapsed, value)
	}
	last := conn.lastWriteDeadline()
	if last.IsZero() {
		t.Fatalf("the connection's last write deadline is cleared after a caller update(%v): "+
			"the %v flush bound was lifted (deadline log %v)", value, streamCloseFlushLimit, conn.deadlineLog())
	}
	if latest := start.Add(streamCloseFlushLimit + 500*time.Millisecond); last.After(latest) {
		t.Fatalf("the connection's last write deadline %v is later than the %v flush bound (deadline log %v)",
			last, streamCloseFlushLimit, conn.deadlineLog())
	}
}

// QA-D2: a caller SetWriteDeadline that is in flight while Close installs its
// flush bound must not leave a cleared or later deadline as the last value on
// the connection. The first subtest is the ordinary control (the update
// completes before Close), the gated subtests reproduce the legal overlap at
// the conn call boundary.
func TestStreamV6InFlightCallerWriteDeadlineCannotLiftCloseBound(t *testing.T) {
	cases := []struct {
		name     string
		gate     bool
		deadline func() time.Time
	}{
		{name: "control-update-completes-before-close", deadline: func() time.Time { return time.Time{} }},
		{name: "clear-in-flight-during-flush", gate: true, deadline: func() time.Time { return time.Time{} }},
		{name: "later-deadline-in-flight-during-flush", gate: true, deadline: func() time.Time { return time.Now().Add(2 * time.Second) }},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			conn := newV6BlockedConn()
			if testCase.gate {
				conn.writeGate = newV6Gate()
			}
			t.Cleanup(func() {
				conn.writeGate.open()
				_ = conn.Close()
			})
			sender := newTraceSender()
			// A zero-length native send is the ordinary short-send path: the
			// unsent tail is forwarded on the plain conn inside the flush.
			sender.shortAt = 0
			sender.shortLen = 0
			wrapped, native, held := v6NativeFixture(t, conn, sender, "2")
			value := testCase.deadline()
			callerDone := make(chan error, 1)
			go func() { callerDone <- wrapped.SetWriteDeadline(value) }()
			callerPending := testCase.gate
			if testCase.gate {
				conn.writeGate.waitEntered(t)
			} else {
				select {
				case err := <-callerDone:
					if err != nil {
						t.Fatalf("SetWriteDeadline: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("SetWriteDeadline did not return")
				}
			}
			start := time.Now()
			closeDone := make(chan error, 1)
			go func() { closeDone <- wrapped.Close() }()
			if testCase.gate {
				if !conn.waitBlocked(time.Second) {
					t.Fatal("the Close flush never reached the plain conn write")
				}
				// Non-vacuity: the caller update is still in flight while the
				// flush is blocked, which is exactly the QA-D2 interleaving.
				select {
				case <-callerDone:
					t.Fatal("the caller update completed before the flush blocked; the interleaving was not reproduced")
				default:
				}
				conn.writeGate.open()
			}
			var err error
			select {
			case err = <-closeDone:
			case <-time.After(time.Second):
				_ = conn.Close()
				select {
				case <-closeDone:
				case <-time.After(2 * time.Second):
				}
				t.Fatalf("Close did not return within %v after an in-flight caller SetWriteDeadline(%v); "+
					"conn deadline log %v", time.Since(start), value, conn.deadlineLog())
			}
			// The caller update must also finish; it re-publishes the bound.
			if callerPending {
				select {
				case callerErr := <-callerDone:
					if callerErr != nil {
						t.Fatalf("deferred SetWriteDeadline: %v", callerErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("the in-flight SetWriteDeadline never returned")
				}
			}
			v6AssertBoundedClose(t, time.Since(start), err, start, conn, value)
			if created := native.count(); created != 1 {
				t.Fatalf("native senders constructed = %d, want the flush to construct exactly one", created)
			}
			attempts := conn.writeAttempts()
			if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
				t.Fatalf("plain-conn write attempts = %d (%x), want exactly the retained block %x",
					len(attempts), attempts, held)
			}
		})
	}
}

// QA-D2 also applies to SetDeadline: it carries the write half, so an in-flight
// SetDeadline must be capped the same way, while the read deadline is still
// delegated unchanged.
func TestStreamV6InFlightCallerSetDeadlineCannotLiftCloseBound(t *testing.T) {
	cases := []struct {
		name    string
		value   func() time.Time
		atWrite bool
	}{
		{name: "combined-call-in-flight", value: func() time.Time { return time.Now().Add(2 * time.Second) }},
		{name: "write-delegation-in-flight", atWrite: true, value: func() time.Time { return time.Time{} }},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			conn := newV6BlockedConn()
			if testCase.atWrite {
				conn.writeGate = newV6Gate()
			} else {
				conn.combinedGate = newV6Gate()
			}
			t.Cleanup(func() {
				conn.writeGate.open()
				conn.combinedGate.open()
				_ = conn.Close()
			})
			sender := newTraceSender()
			sender.shortAt = 0
			sender.shortLen = 0
			wrapped, _, held := v6NativeFixture(t, conn, sender, "2")
			value := testCase.value()
			callerDone := make(chan error, 1)
			go func() { callerDone <- wrapped.SetDeadline(value) }()
			if testCase.atWrite {
				conn.writeGate.waitEntered(t)
			} else {
				conn.combinedGate.waitEntered(t)
			}
			start := time.Now()
			closeDone := make(chan error, 1)
			go func() { closeDone <- wrapped.Close() }()
			if !conn.waitBlocked(time.Second) {
				t.Fatal("the Close flush never reached the plain conn write")
			}
			select {
			case <-callerDone:
				t.Fatal("the caller SetDeadline completed before the flush blocked; the interleaving was not reproduced")
			default:
			}
			conn.writeGate.open()
			conn.combinedGate.open()
			var err error
			select {
			case err = <-closeDone:
			case <-time.After(time.Second):
				_ = conn.Close()
				select {
				case <-closeDone:
				case <-time.After(2 * time.Second):
				}
				t.Fatalf("Close did not return within %v after an in-flight caller SetDeadline(%v); "+
					"conn deadline log %v", time.Since(start), value, conn.deadlineLog())
			}
			select {
			case callerErr := <-callerDone:
				if callerErr != nil {
					t.Fatalf("deferred SetDeadline: %v", callerErr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("the in-flight SetDeadline never returned")
			}
			v6AssertBoundedClose(t, time.Since(start), err, start, conn, value)
			if got := conn.readDeadlineValue(); !got.Equal(value) {
				t.Fatalf("read deadline = %v, want the caller's SetDeadline value %v", got, value)
			}
			attempts := conn.writeAttempts()
			if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
				t.Fatalf("plain-conn write attempts = %d, want exactly the retained block", len(attempts))
			}
		})
	}
}

// The same exposure exists without any native sender: a retained first block
// whose rule resolves to pass-through is flushed with a plain conn write.
func TestStreamV6PassThroughFlushInFlightClearBounded(t *testing.T) {
	conn := newV6BlockedConn()
	conn.writeGate = newV6Gate()
	t.Cleanup(func() {
		conn.writeGate.open()
		_ = conn.Close()
	})
	rule := hostcaseRule()
	rule.Domain = badoption.Listable[string]{"example.com"}
	config := mustCompileStream(t, rule)
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	input := []byte("GET / HTTP/1.1\r\nX-Pad: 1")
	if n, err := wrapped.Write(input); err != nil || n != len(input) {
		t.Fatalf("Write = %d,%v, want %d,nil", n, err, len(input))
	}
	if got := conn.writeAttempts(); len(got) != 0 {
		t.Fatalf("expected a retained first block, already wrote %q", got)
	}
	callerDone := make(chan error, 1)
	go func() { callerDone <- wrapped.SetWriteDeadline(time.Time{}) }()
	conn.writeGate.waitEntered(t)
	start := time.Now()
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	if !conn.waitBlocked(time.Second) {
		t.Fatal("the pass-through Close flush never reached the plain conn write")
	}
	select {
	case <-callerDone:
		t.Fatal("the caller update completed before the flush blocked; the interleaving was not reproduced")
	default:
	}
	conn.writeGate.open()
	var err error
	select {
	case err = <-closeDone:
	case <-time.After(time.Second):
		_ = conn.Close()
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
		}
		t.Fatalf("pass-through Close flush did not return within %v after an in-flight caller "+
			"SetWriteDeadline(clear); conn deadline log %v", time.Since(start), conn.deadlineLog())
	}
	select {
	case callerErr := <-callerDone:
		if callerErr != nil {
			t.Fatalf("deferred SetWriteDeadline: %v", callerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the in-flight SetWriteDeadline never returned")
	}
	v6AssertBoundedClose(t, time.Since(start), err, start, conn, time.Time{})
	attempts := conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], input) {
		t.Fatalf("plain-conn write attempts = %d (%q), want exactly the retained block %q",
			len(attempts), attempts, input)
	}
}

// QA-D1's pushed-deadline contract must survive the QA-D2 correction: a
// platform sender that caches only the pushed value must end up with the
// bounded effective deadline, not the stale caller value.
func TestStreamV6CorrectionReachesCachingSender(t *testing.T) {
	conn := newV6BlockedConn()
	conn.writeGate = newV6Gate()
	t.Cleanup(func() {
		conn.writeGate.open()
		_ = conn.Close()
	})
	sender := newV6CacheSender()
	wrapped, _, held := v6NativeFixture(t, conn, sender, "2")
	callerDone := make(chan error, 1)
	go func() { callerDone <- wrapped.SetWriteDeadline(time.Time{}) }()
	conn.writeGate.waitEntered(t)
	start := time.Now()
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	if !conn.waitBlocked(time.Second) {
		t.Fatal("the Close flush never reached the plain conn write")
	}
	select {
	case <-callerDone:
		t.Fatal("the caller update completed before the flush blocked; the interleaving was not reproduced")
	default:
	}
	conn.writeGate.open()
	var err error
	select {
	case err = <-closeDone:
	case <-time.After(1500 * time.Millisecond):
		_ = conn.Close()
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
		}
		t.Fatalf("Close did not return on a caching sender after an in-flight caller update; "+
			"conn deadline log %v", conn.deadlineLog())
	}
	select {
	case callerErr := <-callerDone:
		if callerErr != nil {
			t.Fatalf("deferred SetWriteDeadline: %v", callerErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the in-flight SetWriteDeadline never returned")
	}
	v6AssertBoundedClose(t, time.Since(start), err, start, conn, time.Time{})
	cached, observed, sends, cancelled := sender.state()
	if cached.IsZero() {
		t.Fatalf("the caching sender kept no bounded deadline push (cached %v, sends %d)", cached, sends)
	}
	if latest := start.Add(streamCloseFlushLimit + 500*time.Millisecond); cached.After(latest) {
		t.Fatalf("the caching sender's deadline %v is later than the %v flush bound", cached, streamCloseFlushLimit)
	}
	if observed.IsZero() {
		t.Fatal("the caching sender ran an unbounded send (zero cached deadline)")
	}
	if sends != 1 || cancelled != 1 {
		t.Fatalf("caching sender sends=%d cancelled=%d, want 1/1", sends, cancelled)
	}
	attempts := conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
		t.Fatalf("plain-conn write attempts = %d, want exactly the retained block", len(attempts))
	}
}

// Ordinary-scheduling control (no gate anywhere): caller updates and Close race
// plainly. Whenever the flush reaches the plain write, the connection's
// effective deadline must be the bounded value within a generous window - a
// cleared or extended value left behind is the QA-D2 hang. This guards the
// plain path; it is not the coverage proof (the deterministic cases above are).
func TestStreamV6OrdinaryInterleavingKeepsCloseBound(t *testing.T) {
	const iterations = 200
	for i := 0; i < iterations; i++ {
		conn := newV6BlockedConn()
		sender := newTraceSender()
		sender.shortAt = 0
		sender.shortLen = 0
		wrapped, _, _ := v6NativeFixture(t, conn, sender, "2")
		var value time.Time
		if i%2 == 1 {
			value = time.Now().Add(2 * time.Second)
		}
		started := time.Now()
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		closeDone := make(chan error, 1)
		go func() {
			defer wg.Done()
			<-start
			_ = wrapped.SetWriteDeadline(value)
		}()
		go func() {
			defer wg.Done()
			<-start
			closeDone <- wrapped.Close()
		}()
		close(start)
		if !conn.waitBlocked(300 * time.Millisecond) {
			_ = conn.Close()
			select {
			case <-closeDone:
			case <-time.After(time.Second):
			}
			wg.Wait()
			continue
		}
		window := time.Now().Add(100 * time.Millisecond)
		sawBound := false
		for {
			last := conn.lastWriteDeadline()
			if !last.IsZero() && !last.After(started.Add(streamCloseFlushLimit+500*time.Millisecond)) {
				sawBound = true
				break
			}
			if time.Now().After(window) {
				break
			}
			time.Sleep(200 * time.Microsecond)
		}
		if !sawBound {
			log := conn.deadlineLog()
			_ = conn.Close()
			select {
			case <-closeDone:
			case <-time.After(time.Second):
			}
			wg.Wait()
			t.Fatalf("iteration %d: the flush bound was not the connection's effective write deadline "+
				"within 100 ms (caller value %v, deadline log %v)", i, value, log)
		}
		// The assertion already ran; release the blocked write early so the
		// ordinary control stays cheap. Closing is not part of the assertion.
		_ = conn.Close()
		select {
		case err := <-closeDone:
			if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("iteration %d: Close: %v", i, err)
			}
		case <-time.After(time.Second):
			wg.Wait()
			t.Fatalf("iteration %d: Close did not return after the conn was closed", i)
		}
		wg.Wait()
	}
}

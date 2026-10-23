package desync

// Permanent regression for QA-D3 (task t_9403b749, finding in
// t_f6e5a210-qa.md §4, independent probes t_f6e5a210-qa9-probes.go).
//
// Finding. Close's retained-block flush published the 250 ms bound
// (flushDeadline) to the underlying conn and to a deadline-caching platform
// sender, and publishWriteDeadline verified the *sources* after delegating.
// With one in-flight caller update that correction is enough (QA-D2). With two
// concurrent callers it is not: caller X computes its effective value before
// the flush stores the bound, caller Z changes the wrapper source meanwhile, X
// re-reads the sources and delegates the value it read *before* the bound
// existed, and that delegation lands after the flush published and verified its
// own bound. The connection is then left with a cleared or later write
// deadline while the flush is blocked, so Close never reaches its own
// cancelPendingSend/closeUnderlying: unbounded for a cleared value, extended to
// the stale value otherwise. Any finite number of verification passes can be
// defeated the same way by one more stale writer, so the repair cannot be
// another pass.
//
// Repair under test. The flush bound is enforced on the connection lifetime by
// a watchdog armed with the effective deadline (caller deadline or flush bound,
// whichever is earlier) plus streamFlushWatchdogGrace; when it fires it runs the
// same abort Close uses for a blocked Write (cancel the native send, close the
// underlying connection). The bound therefore no longer depends on the value
// left in the shared deadline slot, and no ordering assumption about other
// deadline writers is needed. The deadline itself is still published, and a
// final clamp re-asserts it for observers after the flush.
//
// These tests are hermetic: in-memory conns and injected native seams only. The
// only seam is a one-shot gate in a test double, which makes a legal
// interleaving repeatable; production has no hook. The deterministic cases are
// the proof; the repeated-update loop is a guard, not a coverage claim.

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

// v7Gate blocks one selected deadline call before it is applied to the conn.
// It is armed by the test and consumed by the first matching call, so the
// flush's own (different-valued) publication is never gated.
type v7Gate struct {
	mu      sync.Mutex
	armed   bool
	match   func(time.Time) bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newV7Gate(match func(time.Time) bool) *v7Gate {
	return &v7Gate{match: match, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *v7Gate) arm() {
	g.mu.Lock()
	g.armed = true
	g.mu.Unlock()
}

func (g *v7Gate) maybeBlock(deadline time.Time) {
	g.mu.Lock()
	if !g.armed || !g.match(deadline) {
		g.mu.Unlock()
		return
	}
	g.armed = false
	g.mu.Unlock()
	close(g.entered)
	<-g.release
}

func (g *v7Gate) open() {
	g.once.Do(func() { close(g.release) })
}

func (g *v7Gate) waitEntered(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s never reached the connection", what)
	}
}

func v7IsZero(value time.Time) bool  { return value.IsZero() }
func v7IsLater(value time.Time) bool { return !value.IsZero() }

// v7BlockedConn models a TCP connection whose peer stopped reading: Write
// blocks until the current write deadline expires, the connection is closed or
// the deadline changes (the Go poller recomputes a blocked write's timer, so a
// concurrent deadline update clears, extends or shortens the wait). writeEntered
// fires when a Write is entered, even when the connection is already closed, so
// a test can tell "the flush reached the plain write" from "the flush never got
// there".
type v7BlockedConn struct {
	mu            sync.Mutex
	writeDeadline time.Time
	readDeadline  time.Time
	setLog        []time.Time
	attempts      [][]byte
	closed        bool
	closedCh      chan struct{}
	changed       chan struct{}
	writeEntered  chan struct{}
	writeOnce     sync.Once
	writeGates    []*v7Gate
	combinedGates []*v7Gate
}

func newV7BlockedConn() *v7BlockedConn {
	return &v7BlockedConn{
		closedCh:     make(chan struct{}),
		changed:      make(chan struct{}),
		writeEntered: make(chan struct{}),
	}
}

func (c *v7BlockedConn) addWriteGate(match func(time.Time) bool, armed bool) *v7Gate {
	gate := newV7Gate(match)
	gate.armed = armed
	c.mu.Lock()
	c.writeGates = append(c.writeGates, gate)
	c.mu.Unlock()
	return gate
}

func (c *v7BlockedConn) gates() []*v7Gate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*v7Gate(nil), c.writeGates...)
}

func (c *v7BlockedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.attempts = append(c.attempts, append([]byte(nil), p...))
	c.mu.Unlock()
	c.writeOnce.Do(func() { close(c.writeEntered) })
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

func (c *v7BlockedConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (c *v7BlockedConn) Close() error {
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.closedCh)
	}
	c.mu.Unlock()
	return nil
}

func (c *v7BlockedConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (c *v7BlockedConn) RemoteAddr() net.Addr { return fakeAddr{} }

func (c *v7BlockedConn) SetDeadline(deadline time.Time) error {
	for _, gate := range c.gates() {
		gate.maybeBlock(deadline)
	}
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.setLog = append(c.setLog, deadline)
	c.wakeLocked()
	c.mu.Unlock()
	return nil
}

func (c *v7BlockedConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *v7BlockedConn) SetWriteDeadline(deadline time.Time) error {
	for _, gate := range c.gates() {
		gate.maybeBlock(deadline)
	}
	c.mu.Lock()
	c.writeDeadline = deadline
	c.setLog = append(c.setLog, deadline)
	c.wakeLocked()
	c.mu.Unlock()
	return nil
}

func (c *v7BlockedConn) wakeLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *v7BlockedConn) waitWriteEntered(t *testing.T, what string) {
	t.Helper()
	select {
	case <-c.writeEntered:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s never reached the plain conn write", what)
	}
}

func (c *v7BlockedConn) deadlineLog() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.setLog...)
}

func (c *v7BlockedConn) lastWriteDeadline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.setLog) == 0 {
		return time.Time{}
	}
	return c.setLog[len(c.setLog)-1]
}

func (c *v7BlockedConn) readDeadlineValue() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline
}

func (c *v7BlockedConn) writeAttempts() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.attempts...)
}

// v7ZeroSender makes no progress on its first native send, which is the
// ordinary R2 path: the unsent tail is written on the plain conn inside the
// Close flush.
type v7ZeroSender struct {
	mu    sync.Mutex
	sends int
}

func (s *v7ZeroSender) Send(data []byte, _ sendOptions) (int, error) {
	s.mu.Lock()
	s.sends++
	count := s.sends
	s.mu.Unlock()
	if count == 1 {
		return 0, nil
	}
	return len(data), nil
}

func (s *v7ZeroSender) WaitNotSent(time.Duration) bool { return true }

func (s *v7ZeroSender) sendCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sends
}

// v7StuckSender models a platform native send that does not observe any
// deadline: it blocks until CancelPending releases it. That is the worst case
// of the Windows overlapped contract (a defeated or otherwise ineffective
// deadline push) and of any send path the wrapper cannot bound through the
// connection deadline, so the Close flush must abort it instead of waiting.
type v7StuckSender struct {
	mu        sync.Mutex
	sends     int
	cancelled int
	started   chan struct{}
	released  chan struct{}
	startOnce sync.Once
	endOnce   sync.Once
}

func newV7StuckSender() *v7StuckSender {
	return &v7StuckSender{started: make(chan struct{}), released: make(chan struct{})}
}

func (s *v7StuckSender) Send([]byte, sendOptions) (int, error) {
	s.mu.Lock()
	s.sends++
	s.mu.Unlock()
	s.startOnce.Do(func() { close(s.started) })
	<-s.released
	return 0, net.ErrClosed
}

func (s *v7StuckSender) WaitNotSent(time.Duration) bool { return true }

func (s *v7StuckSender) CancelPending() {
	s.mu.Lock()
	s.cancelled++
	s.mu.Unlock()
	s.endOnce.Do(func() { close(s.released) })
}

func (s *v7StuckSender) state() (sends, cancelled int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sends, s.cancelled
}

// v7Native counts sender construction and hands out the injected sender.
type v7Native struct {
	mu      sync.Mutex
	created int
	sender  streamSender
}

func (n *v7Native) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *v7Native) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	n.mu.Lock()
	n.created++
	n.mu.Unlock()
	if n.sender == nil {
		return nil, errors.New("v7: no injected sender")
	}
	return n.sender, nil
}

func (n *v7Native) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.created
}

// v7HeldFirstBlock is a TLS record whose declared body is longer than the
// written prefix, so the first block is retained until Close.
func v7HeldFirstBlock() []byte {
	return []byte{0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00, 0x02}
}

// v7NativeFixture wraps conn with a native-send rule and retains the first
// block, so Close takes the TryLock flush path.
func v7NativeFixture(t *testing.T, conn *v7BlockedConn, sender streamSender, positions ...string) (net.Conn, *v7Native, []byte) {
	t.Helper()
	rule := splitRule(positions...)
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	native := &v7Native{sender: sender}
	config.native = native
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	held := v7HeldFirstBlock()
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

// v7PassThroughFixture retains an incomplete HTTP header whose rule resolves
// to pass-through, so Close flushes it with one plain conn write and no native
// sender is involved.
func v7PassThroughFixture(t *testing.T, conn *v7BlockedConn) (net.Conn, []byte) {
	t.Helper()
	rule := hostcaseRule()
	rule.Domain = badoption.Listable[string]{"example.com"}
	config := mustCompileStream(t, rule)
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	held := []byte("GET / HTTP/1.1\r\nX-Pad: 1")
	if n, err := wrapped.Write(held); err != nil || n != len(held) {
		t.Fatalf("Write = %d,%v, want %d,nil", n, err, len(held))
	}
	if got := conn.writeAttempts(); len(got) != 0 {
		t.Fatalf("expected a retained first block, already wrote %q", got)
	}
	if got := conn.deadlineLog(); len(got) != 0 {
		t.Fatalf("deadline published before Close: %v", got)
	}
	return wrapped, held
}

// v7Window is the acceptance window for a Close that had to be released by the
// lifetime watchdog: the effective deadline plus the fixed watchdog grace plus
// generous scheduler slack (the deterministic proof is the return itself, not
// the exact millisecond).
func v7Window() time.Duration {
	return streamCloseFlushLimit + streamFlushWatchdogGrace + 200*time.Millisecond
}

// v7AssertCloseReturned asserts the liveness part of the QA-D3 invariant:
// Close returned on its own inside the bound, without a second Close or an
// external conn close, with an acceptable error.
func v7AssertCloseReturned(t *testing.T, conn *v7BlockedConn, elapsed time.Duration, err error, closed bool, what string) {
	t.Helper()
	if !closed {
		t.Fatalf("%s: Close did not return within %v (deadline log %v)", what, elapsed, conn.deadlineLog())
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("%s: Close: %v", what, err)
	}
	if window := v7Window(); elapsed > window {
		t.Fatalf("%s: Close took %v, beyond the %v flush bound + watchdog grace (deadline log %v)",
			what, elapsed, streamCloseFlushLimit, conn.deadlineLog())
	}
}

// v7AssertBoundedClose additionally checks that the connection's last
// published write deadline is non-zero and inside the window (the final
// clamp). It is only used by the deterministic cases, where no caller
// publication is still in flight when Close returns.
func v7AssertBoundedClose(t *testing.T, conn *v7BlockedConn, start time.Time, elapsed time.Duration, err error, closed bool, what string) {
	t.Helper()
	v7AssertCloseReturned(t, conn, elapsed, err, closed, what)
	last := conn.lastWriteDeadline()
	if last.IsZero() {
		t.Fatalf("%s: the connection's last write deadline is cleared: the flush bound was lifted off the deadline slot (log %v)",
			what, conn.deadlineLog())
	}
	if latest := start.Add(v7Window()); last.After(latest) {
		t.Fatalf("%s: the connection's last write deadline %v is later than the bound (%v, log %v)",
			what, last, latest, conn.deadlineLog())
	}
}

type v7Result struct {
	conn    *v7BlockedConn
	start   time.Time
	elapsed time.Duration
	err     error
	closed  bool
	xErr    error
}

// v7RunTwoCaller reproduces the QA-D3 interleaving deterministically:
//
//	X: SetWriteDeadline(Xvalue)  -> its first conn delegation is gated
//	Z: SetWriteDeadline/SetDeadline(Zvalue) completes while X is in flight
//	X: continues -> reads the sources (before Close stored the bound), then its
//	   stale re-publication is gated
//	Close: stores the bound, publishes it, flushes and blocks
//	the stale publication is released last -> the deadline slot is cleared or
//	extended while the flush is blocked
func v7RunTwoCaller(t *testing.T, fixture func(*v7BlockedConn) net.Conn, xValue, zValue time.Time, zUsesSetDeadline bool, firstMatch, staleMatch func(time.Time) bool) *v7Result {
	t.Helper()
	conn := newV7BlockedConn()
	wrapped := fixture(conn)
	result := &v7Result{conn: conn}

	xGate := conn.addWriteGate(firstMatch, true)
	staleGate := conn.addWriteGate(staleMatch, false)
	t.Cleanup(func() {
		xGate.open()
		staleGate.open()
		_ = conn.Close()
	})

	xDone := make(chan error, 1)
	go func() { xDone <- wrapped.SetWriteDeadline(xValue) }()
	xGate.waitEntered(t, "caller X's first deadline delegation")

	if zUsesSetDeadline {
		if err := wrapped.SetDeadline(zValue); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
	} else if err := wrapped.SetWriteDeadline(zValue); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	staleGate.arm()
	xGate.open()
	staleGate.waitEntered(t, "caller X's re-publication of the pre-bound value")

	// Non-vacuity: the stale write is still in flight when Close starts.
	select {
	case err := <-xDone:
		t.Fatalf("caller X completed before Close started; the interleaving was not reproduced (%v)", err)
	default:
	}

	result.start = time.Now()
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	conn.waitWriteEntered(t, "the retained-block Close flush")

	// Release the stale publication: it lands after the flush published and
	// verified its bound, and after the flush's plain write started.
	staleGate.open()

	select {
	case result.err = <-closeDone:
		result.elapsed = time.Since(result.start)
		result.closed = true
	case <-time.After(v7Window()):
		result.elapsed = time.Since(result.start)
		// Test escape only on the failure path: release the fixture so the
		// suite can continue, without counting it as a bounded Close.
		_ = conn.Close()
		select {
		case result.err = <-closeDone:
		case <-time.After(2 * time.Second):
		}
	}
	select {
	case result.xErr = <-xDone:
	case <-time.After(2 * time.Second):
		t.Fatal("caller X never returned")
	}
	return result
}

// QA-D3 case A: X sets +2 s, Z clears; X's stale re-publication of the
// pre-bound value (zero) lands last, while the flush writes the unsent tail of
// a zero-progress native send on the plain conn.
func TestStreamV7TwoCallerStaleClearCannotExtendClose(t *testing.T) {
	var native *v7Native
	var held []byte
	result := v7RunTwoCaller(t, func(conn *v7BlockedConn) net.Conn {
		wrapped, n, h := v7NativeFixture(t, conn, &v7ZeroSender{}, "2")
		native, held = n, h
		return wrapped
	}, time.Now().Add(2*time.Second), time.Time{}, false, v7IsLater, v7IsZero)
	if result.xErr != nil {
		t.Fatalf("caller X: %v", result.xErr)
	}
	v7AssertBoundedClose(t, result.conn, result.start, result.elapsed, result.err, result.closed,
		"two callers (X=+2s, Z=clear)")
	attempts := result.conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
		t.Fatalf("plain-conn write attempts = %d (%x), want exactly the retained block %x",
			len(attempts), attempts, held)
	}
	if created := native.count(); created != 1 {
		t.Fatalf("native senders constructed = %d, want the flush to construct exactly one", created)
	}
	t.Logf("Close %v, deadline log %v", result.elapsed, result.conn.deadlineLog())
}

// QA-D3 case B: X clears, Z sets +2 s; the stale publication that lands last is
// the later value, which used to extend the flush instead of clearing it.
func TestStreamV7TwoCallerStaleLaterCannotExtendClose(t *testing.T) {
	result := v7RunTwoCaller(t, func(conn *v7BlockedConn) net.Conn {
		wrapped, _, _ := v7NativeFixture(t, conn, &v7ZeroSender{}, "2")
		return wrapped
	}, time.Time{}, time.Now().Add(2*time.Second), false, v7IsZero, v7IsLater)
	if result.xErr != nil {
		t.Fatalf("caller X: %v", result.xErr)
	}
	v7AssertBoundedClose(t, result.conn, result.start, result.elapsed, result.err, result.closed,
		"two callers (X=clear, Z=+2s)")
	t.Logf("Close %v, deadline log %v", result.elapsed, result.conn.deadlineLog())
}

// QA-D3 case C: the second caller uses the combined SetDeadline, whose write
// half is capped like SetWriteDeadline while the read half stays the caller's.
func TestStreamV7TwoCallerSetDeadlineStaleClearCannotExtendClose(t *testing.T) {
	var zValue = time.Time{}
	result := v7RunTwoCaller(t, func(conn *v7BlockedConn) net.Conn {
		wrapped, _, _ := v7NativeFixture(t, conn, &v7ZeroSender{}, "2")
		return wrapped
	}, time.Now().Add(2*time.Second), zValue, true, v7IsLater, v7IsZero)
	if result.xErr != nil {
		t.Fatalf("caller X: %v", result.xErr)
	}
	v7AssertBoundedClose(t, result.conn, result.start, result.elapsed, result.err, result.closed,
		"two callers with SetDeadline (Z=clear)")
	// Ordinary read-half semantics: the combined call's read deadline is
	// delegated unchanged.
	if got := result.conn.readDeadlineValue(); !got.IsZero() {
		t.Fatalf("read deadline = %v, want the caller's zero SetDeadline value", got)
	}
	t.Logf("Close %v, deadline log %v", result.elapsed, result.conn.deadlineLog())
}

// QA-D3 case F: the same interleaving without a native sender; the retained
// block resolves to pass-through and the flush writes it on the plain conn.
func TestStreamV7TwoCallerPassThroughFlushStaleClearCannotExtendClose(t *testing.T) {
	var held []byte
	result := v7RunTwoCaller(t, func(conn *v7BlockedConn) net.Conn {
		wrapped, h := v7PassThroughFixture(t, conn)
		held = h
		return wrapped
	}, time.Now().Add(2*time.Second), time.Time{}, false, v7IsLater, v7IsZero)
	if result.xErr != nil {
		t.Fatalf("caller X: %v", result.xErr)
	}
	v7AssertBoundedClose(t, result.conn, result.start, result.elapsed, result.err, result.closed,
		"two callers, pass-through flush (X=+2s, Z=clear)")
	attempts := result.conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
		t.Fatalf("plain-conn write attempts = %d (%q), want exactly the retained block %q",
			len(attempts), attempts, held)
	}
	t.Logf("Close %v, deadline log %v", result.elapsed, result.conn.deadlineLog())
}

// A native send that does not observe any deadline cannot extend Close: the
// lifetime watchdog aborts the flush (cancel the send, close the connection) at
// the bound instead of waiting for a send that never returns. A concurrent
// caller clearing the deadline while the send is stuck must not change that.
func TestStreamV7DeadlineBlindNativeSendCannotOutliveCloseBound(t *testing.T) {
	conn := newV7BlockedConn()
	sender := newV7StuckSender()
	wrapped, native, held := v7NativeFixture(t, conn, sender, "2")
	t.Cleanup(func() { _ = conn.Close() })

	start := time.Now()
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	select {
	case <-sender.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the Close flush never reached the native send")
	}
	// A concurrent caller clears the deadline while the flush is stuck in the
	// send. Its publication is capped by the bound; the abort must not depend
	// on the deadline slot at all.
	if err := wrapped.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(v7Window()):
		_ = conn.Close()
		sender.CancelPending()
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
		}
		t.Fatalf("Close did not return within %v with a native send that ignores the deadline (log %v)",
			time.Since(start), conn.deadlineLog())
	}
	elapsed := time.Since(start)
	v7AssertBoundedClose(t, conn, start, elapsed, nil, true, "deadline-blind native send")
	sends, cancelled := sender.state()
	if sends != 1 || cancelled != 1 {
		t.Fatalf("stuck sender sends=%d cancelled=%d, want 1/1 (the abort must be the single Close lifecycle cancel)",
			sends, cancelled)
	}
	if created := native.count(); created != 1 {
		t.Fatalf("native senders constructed = %d, want 1", created)
	}
	attempts := conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
		t.Fatalf("plain-conn write attempts = %d (%x), want exactly the retained block %x",
			len(attempts), attempts, held)
	}
	t.Logf("Close %v, deadline log %v", elapsed, conn.deadlineLog())
}

// Positive control: the same harness and the same gates, but Close installs the
// bound before X re-reads the sources, so X re-publishes the bounded effective
// value. It must be bounded with a bounded last deadline - the failing cases
// above are the ordering, not the fixture.
func TestStreamV7BoundInstalledBeforeStaleReadControl(t *testing.T) {
	conn := newV7BlockedConn()
	wrapped, _, held := v7NativeFixture(t, conn, &v7ZeroSender{}, "2")
	xGate := conn.addWriteGate(v7IsLater, true)
	t.Cleanup(func() {
		xGate.open()
		_ = conn.Close()
	})
	xDone := make(chan error, 1)
	go func() { xDone <- wrapped.SetWriteDeadline(time.Now().Add(2 * time.Second)) }()
	xGate.waitEntered(t, "caller X's first deadline delegation")

	start := time.Now()
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	conn.waitWriteEntered(t, "the retained-block Close flush")

	// The clear and X's release both arrive after the bound exists: X's
	// verification read observes the bound.
	if err := wrapped.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	xGate.open()
	var err error
	closed := false
	var elapsed time.Duration
	select {
	case err = <-closeDone:
		closed = true
		elapsed = time.Since(start)
	case <-time.After(v7Window()):
		elapsed = time.Since(start)
		_ = conn.Close()
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
		}
	}
	select {
	case xErr := <-xDone:
		if xErr != nil {
			t.Fatalf("caller X: %v", xErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("caller X never returned")
	}
	v7AssertBoundedClose(t, conn, start, elapsed, err, closed, "control: bound installed before the stale read")
	attempts := conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
		t.Fatalf("plain-conn write attempts = %d, want exactly the retained block", len(attempts))
	}
	t.Logf("control: Close %v, deadline log %v", elapsed, conn.deadlineLog())
}

// Arbitrary and repeated concurrent updates: several caller goroutines keep
// issuing SetWriteDeadline and SetDeadline (clear, later and stricter values)
// while Close flushes a retained block. Every Close must return on its own and
// the retained bytes must be written exactly once - no matter how many stale
// publications land. The last-deadline value is not asserted here: a
// publication still in flight when Close returns can land afterwards.
func TestStreamV7RepeatedConcurrentDeadlineUpdatesKeepCloseBounded(t *testing.T) {
	const iterations = 12
	const writers = 4
	for iteration := 0; iteration < iterations; iteration++ {
		conn := newV7BlockedConn()
		sender := &v7ZeroSender{}
		wrapped, native, held := v7NativeFixture(t, conn, sender, "2")

		stop := make(chan struct{})
		var wg sync.WaitGroup
		for writer := 0; writer < writers; writer++ {
			writer := writer
			wg.Add(1)
			go func() {
				defer wg.Done()
				for step := 0; ; step++ {
					select {
					case <-stop:
						return
					default:
					}
					switch (writer + step) % 3 {
					case 0:
						_ = wrapped.SetWriteDeadline(time.Time{})
					case 1:
						_ = wrapped.SetWriteDeadline(time.Now().Add(2 * time.Second))
					case 2:
						_ = wrapped.SetDeadline(time.Now().Add(70 * time.Millisecond))
					}
					time.Sleep(100 * time.Microsecond)
				}
			}()
		}
		time.Sleep(2 * time.Millisecond)

		start := time.Now()
		closeDone := make(chan error, 1)
		go func() { closeDone <- wrapped.Close() }()
		closed := false
		var err error
		var elapsed time.Duration
		select {
		case err = <-closeDone:
			closed = true
			elapsed = time.Since(start)
		case <-time.After(v7Window()):
			elapsed = time.Since(start)
			close(stop)
			wg.Wait()
			_ = conn.Close()
			select {
			case <-closeDone:
			case <-time.After(2 * time.Second):
			}
			t.Fatalf("iteration %d: Close did not return within %v under %d concurrent deadline writers (log %v)",
				iteration, elapsed, writers, conn.deadlineLog())
		}
		close(stop)
		wg.Wait()
		v7AssertCloseReturned(t, conn, elapsed, err, closed, "repeated concurrent deadline updates")
		attempts := conn.writeAttempts()
		if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
			t.Fatalf("iteration %d: plain-conn write attempts = %d (%x), want exactly the retained block %x",
				iteration, len(attempts), attempts, held)
		}
		if sends := sender.sendCount(); sends != 1 {
			t.Fatalf("iteration %d: native sends = %d, want 1", iteration, sends)
		}
		if created := native.count(); created != 1 {
			t.Fatalf("iteration %d: native senders constructed = %d, want 1", iteration, created)
		}
	}
}

// A stricter caller deadline must stay stricter even when a concurrent caller
// clears the connection deadline while the flush is blocked: the watchdog is
// armed with the effective deadline, so the flush ends on the caller's deadline
// rather than on the 250 ms bound.
func TestStreamV7StricterCallerDeadlineSurvivesConcurrentClear(t *testing.T) {
	conn := newV7BlockedConn()
	wrapped, _, held := v7NativeFixture(t, conn, &v7ZeroSender{}, "2")
	callerDeadline := time.Now().Add(60 * time.Millisecond)
	if err := wrapped.SetWriteDeadline(callerDeadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}

	start := time.Now()
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	conn.waitWriteEntered(t, "the retained-block Close flush")

	// A concurrent caller clears the deadline while the flush is blocked. Its
	// publication is capped by the bound, but the flush must still end on the
	// stricter caller deadline, not on the 250 ms bound.
	if err := wrapped.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	var err error
	closed := false
	var elapsed time.Duration
	select {
	case err = <-closeDone:
		closed = true
		elapsed = time.Since(start)
	case <-time.After(v7Window()):
		elapsed = time.Since(start)
		_ = conn.Close()
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
		}
	}
	if !closed {
		t.Fatalf("Close did not return within %v (log %v)", elapsed, conn.deadlineLog())
	}
	if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
	if elapsed >= streamCloseFlushLimit {
		t.Fatalf("Close took %v: the stricter caller deadline was replaced by the flush bound (log %v)",
			elapsed, conn.deadlineLog())
	}
	attempts := conn.writeAttempts()
	if len(attempts) != 1 || !bytes.Equal(attempts[0], held) {
		t.Fatalf("plain-conn write attempts = %d, want exactly the retained block", len(attempts))
	}
	t.Logf("Close %v (caller deadline %v), log %v", elapsed, callerDeadline, conn.deadlineLog())
}

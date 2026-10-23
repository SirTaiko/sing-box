package desync

// Submission 8 behavior regressions for the security findings A3 and A-O1:
// sender ownership when creation crosses Close, exactly-once shutdown for
// repeated Close, and context cancellation as a terminal shutdown owner.
//
// The platform sender seam is a recording double, so these tests need no
// socket and no host network state.

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// v8CountConn counts every Close the wrapper performs on the owned connection;
// a second close of an already closed connection is counted too, which is what
// the exactly-once assertions need.
type v8CountConn struct {
	*fakeConn
	closes atomic.Int32
}

func newV8CountConn() *v8CountConn {
	return &v8CountConn{fakeConn: newFakeConn()}
}

func (c *v8CountConn) Close() error {
	c.closes.Add(1)
	return c.fakeConn.Close()
}

// v8GateNative holds NewSender until the test opens the gate, so a Close can
// complete while the sender factory is still running.
type v8GateNative struct {
	entered chan struct{}
	gate    chan struct{}
	sender  streamSender
	created atomic.Int32
}

func (n *v8GateNative) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *v8GateNative) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	n.created.Add(1)
	if n.entered != nil {
		close(n.entered)
		<-n.gate
	}
	return n.sender, nil
}

// v8Sender records its lifecycle. blocked sends wait until CancelPending, which
// models a platform send that ignores the connection deadline.
type v8Sender struct {
	sends    atomic.Int32
	cancels  atomic.Int32
	releases atomic.Int32

	started chan struct{}
	stop    chan struct{}
	blocked bool
	once    sync.Once
}

func newV8BlockedSender() *v8Sender {
	return &v8Sender{blocked: true, started: make(chan struct{}), stop: make(chan struct{})}
}

func (s *v8Sender) Send(data []byte, _ sendOptions) (int, error) {
	s.sends.Add(1)
	if s.blocked {
		if s.started != nil {
			s.once.Do(func() { close(s.started) })
		}
		<-s.stop
		return 0, net.ErrClosed
	}
	return len(data), nil
}

func (s *v8Sender) WaitNotSent(time.Duration) bool { return true }

func (s *v8Sender) CancelPending() {
	s.cancels.Add(1)
	s.releaseWaiter()
}

func (s *v8Sender) Release() { s.releases.Add(1) }

func (s *v8Sender) releaseWaiter() {
	if s.stop == nil {
		return
	}
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
}

// v8NativeRule compiles a split rule that requires a native sender for every
// protocol, so a Write reaches NewSender instead of the plain sender.
func v8NativeRule(t *testing.T) *StreamConfig {
	t.Helper()
	rule := splitRule("1")
	rule.Split.SplitAnyProtocol = true
	rule.Split.Disorder = "any"
	return mustCompileStream(t, rule)
}

// A3: a sender whose factory crosses Close must never be published or used for
// a send, and its resource must be released exactly once - without Close
// waiting for the write mutex.
func TestStreamV8LateSenderAfterCloseIsDisposedOnce(t *testing.T) {
	sender := &v8Sender{}
	native := &v8GateNative{sender: sender, entered: make(chan struct{}), gate: make(chan struct{})}
	config := v8NativeRule(t)
	config.native = native
	conn := newV8CountConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	t.Cleanup(func() { _ = wrapped.Close() })

	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("ABCDEFG"))
		writeDone <- err
	}()
	select {
	case <-native.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the sender factory was never entered")
	}

	closeDone := make(chan struct{})
	go func() {
		_ = wrapped.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind the pending sender factory")
	}

	// The factory now returns a fully created sender after the single
	// terminal shutdown has already completed.
	close(native.gate)
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("Write succeeded through a sender created after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return after the deferred sender was rejected")
	}

	if got := sender.sends.Load(); got != 0 {
		t.Fatalf("sends after terminal Close = %d, want 0", got)
	}
	if got := sender.releases.Load(); got != 1 {
		t.Fatalf("releases = %d, want the arriving sender released exactly once", got)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("underlying closes = %d, want 1", got)
	}
	if got := len(conn.collected()); got != 0 {
		t.Fatalf("bytes written after terminal Close = %q, want none", conn.collected())
	}

	// A repeated Close must not release the sender again.
	_ = wrapped.Close()
	if got := sender.releases.Load(); got != 1 {
		t.Fatalf("releases after repeated Close = %d, want 1", got)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("underlying closes after repeated Close = %d, want 1", got)
	}
}

// A3 retained control: a sender published before Close is owned by the Close
// shutdown and is cancelled and released exactly once.
func TestStreamV8SenderBeforeCloseIsOwnedByClose(t *testing.T) {
	sender := newV8BlockedSender()
	config := v8NativeRule(t)
	config.native = &v8GateNative{sender: sender}
	conn := newV8CountConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	t.Cleanup(func() { _ = wrapped.Close() })

	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("ABCDEFG"))
		writeDone <- err
	}()
	select {
	case <-sender.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the native send never started")
	}

	closeDone := make(chan struct{})
	go func() {
		_ = wrapped.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked behind an in-flight native send")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("an aborted native send must report an error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked Write was not released by Close")
	}
	if got := sender.sends.Load(); got != 1 {
		t.Fatalf("sends = %d, want 1", got)
	}
	if got := sender.cancels.Load(); got != 1 {
		t.Fatalf("cancels = %d, want the single Close cancel", got)
	}
	if got := sender.releases.Load(); got != 1 {
		t.Fatalf("releases = %d, want 1", got)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("underlying closes = %d, want 1", got)
	}

	_ = wrapped.Close()
	_ = wrapped.Close()
	if got := sender.cancels.Load(); got != 1 {
		t.Fatalf("cancels after repeated Close = %d, want 1", got)
	}
	if got := sender.releases.Load(); got != 1 {
		t.Fatalf("releases after repeated Close = %d, want 1", got)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("underlying closes after repeated Close = %d, want 1", got)
	}
}

// A-O1: context cancellation is a terminal shutdown owner and must use the same
// once-guarded cleanup as Close instead of closing the raw connection.
func TestStreamV8ContextCancellationUsesOnceGuard(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		config := mustCompileStream(t, splitRule("1"))
		conn := newV8CountConn()
		wrapped := wrapStreamWithContext(t, ctx, config, conn)
		cancel()
		waitV8Closed(t, conn)
		_ = wrapped.Close()
		_ = wrapped.Close()
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("underlying closes = %d, want 1 (cancellation bypassed the once guard)", got)
		}
	})

	t.Run("native-send-pending", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		sender := newV8BlockedSender()
		config := v8NativeRule(t)
		config.native = &v8GateNative{sender: sender}
		conn := newV8CountConn()
		wrapped := wrapStreamWithContext(t, ctx, config, conn)
		t.Cleanup(func() { _ = wrapped.Close() })

		writeDone := make(chan error, 1)
		go func() {
			_, err := wrapped.Write([]byte("ABCDEFG"))
			writeDone <- err
		}()
		select {
		case <-sender.started:
		case <-time.After(2 * time.Second):
			t.Fatal("the native send never started")
		}
		cancel()
		select {
		case err := <-writeDone:
			if err == nil {
				t.Fatal("cancellation must abort the pending native send")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("cancellation did not release the pending Write")
		}
		waitV8Closed(t, conn)
		if got := sender.cancels.Load(); got != 1 {
			t.Fatalf("cancels = %d, want 1", got)
		}
		if got := sender.releases.Load(); got != 1 {
			t.Fatalf("releases = %d, want 1", got)
		}
		_ = wrapped.Close()
		_ = wrapped.Close()
		if got := conn.closes.Load(); got != 1 {
			t.Fatalf("underlying closes = %d, want 1", got)
		}
		if got := sender.cancels.Load(); got != 1 {
			t.Fatalf("cancels after Close = %d, want 1", got)
		}
		if got := sender.releases.Load(); got != 1 {
			t.Fatalf("releases after Close = %d, want 1", got)
		}
	})
}

// Repeated concurrent Close calls share one terminal sender transition and one
// underlying close, even with a Write blocked in a native send.
func TestStreamV8RepeatedConcurrentCloseKeepsSingleShutdown(t *testing.T) {
	sender := newV8BlockedSender()
	config := v8NativeRule(t)
	config.native = &v8GateNative{sender: sender}
	conn := newV8CountConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	t.Cleanup(func() {
		sender.releaseWaiter()
		_ = wrapped.Close()
	})

	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("ABCDEFG"))
		writeDone <- err
	}()
	select {
	case <-sender.started:
	case <-time.After(2 * time.Second):
		t.Fatal("the native send never started")
	}

	const callers = 8
	var wg sync.WaitGroup
	results := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- wrapped.Close()
		}()
	}
	closed := make(chan struct{})
	go func() {
		wg.Wait()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent Close calls did not all return")
	}
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close error: %v", err)
		}
	}
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the blocked Write was not released by Close")
	}
	if got := sender.cancels.Load(); got != 1 {
		t.Fatalf("cancels = %d, want 1", got)
	}
	if got := sender.releases.Load(); got != 1 {
		t.Fatalf("releases = %d, want 1", got)
	}
	if got := conn.closes.Load(); got != 1 {
		t.Fatalf("underlying closes = %d, want 1", got)
	}
}

func waitV8Closed(t *testing.T, conn *v8CountConn) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if conn.closes.Load() > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("the underlying connection was never closed")
}

// wrapStreamWithContext wraps conn with an explicit context; wrapStream always
// uses a background context.
func wrapStreamWithContext(t *testing.T, ctx context.Context, config *StreamConfig, conn net.Conn) net.Conn {
	t.Helper()
	wrapped, err := config.WrapConn(ctx, conn, MatchFacts{})
	if err != nil {
		t.Fatalf("WrapConn: %v", err)
	}
	return wrapped
}

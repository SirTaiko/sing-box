package desync

// Combined-artifact integration regressions: the deferred first-send attachment
// (firstSendSender, TFO2/B3) exercised through the real consumer path
// (StreamConfig.WrapConn -> Write -> processBlock -> native sender factory)
// together with the stream8 terminal sender ownership (adoptSender /
// shutdownSender, A3/A-O1) and the O2 caller-byte accounting.
//
// Each lane tested its own half: the deferred-stream tests never asserted the
// exact caller count returned by Write, and the sender-ownership tests only used
// an eager sender that the wrapper creates directly. These tests lock the
// crossing point: the wrapper adopts a firstSendSender attachment, the platform
// sender only exists after the first deferred write, and Close/cancellation must
// reach it exactly once without losing, duplicating or over-reporting caller
// bytes.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// combinedFirstSendRule compiles a native split rule whose first fragment is
// compatible with a deferred first send (fix_seg only, never OOB/disorder), so
// the wrapper really attaches a firstSendSender instead of refusing the first
// send. It is Linux-only for the same reason as the native send it selects.
func combinedFirstSendRule(t *testing.T) *StreamConfig {
	t.Helper()
	if !streamCaps().fixSeg {
		t.Skip("fix_seg native send is Linux only")
	}
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.FixSeg = &option.DirectDesyncStreamFixSeg{Default: true}
	return mustCompileStream(t, rule)
}

// closedState reports whether the wrapped deferred connection was closed. It is
// the observation point the cancellation test waits on before releasing the
// gated native factory, so the assertion order is deterministic.
func (c *fakePendingConn) closedState() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// combinedLifecycleSender records every optional sender capability the wrapper
// forwards, so the combined path can assert exactly-once release/cancel and the
// deadline that arrived before the sender existed.
type combinedLifecycleSender struct {
	sends     atomic.Int32
	cancels   atomic.Int32
	releases  atomic.Int32
	deadlines atomic.Int32
}

func (s *combinedLifecycleSender) Send(p []byte, _ sendOptions) (int, error) {
	s.sends.Add(1)
	return len(p), nil
}

func (s *combinedLifecycleSender) WaitNotSent(time.Duration) bool { return true }
func (s *combinedLifecycleSender) CancelPending()                 { s.cancels.Add(1) }
func (s *combinedLifecycleSender) Release()                       { s.releases.Add(1) }
func (s *combinedLifecycleSender) SetWriteDeadline(time.Time)     { s.deadlines.Add(1) }

// combinedGateNative blocks the creation of the established platform sender, so
// a Close can complete while the deferred attachment is still waiting for it.
type combinedGateNative struct {
	sender  *combinedLifecycleSender
	entered chan struct{}
	gate    chan struct{}
}

func (n *combinedGateNative) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *combinedGateNative) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	close(n.entered)
	<-n.gate
	return n.sender, nil
}

// wrapCombinedWithContext wraps one connection through the public consumer
// entry point with an explicit context, so cancellation is exercised on the
// production path.
func wrapCombinedWithContext(t *testing.T, ctx context.Context, config *StreamConfig, conn net.Conn) net.Conn {
	t.Helper()
	wrapped, err := config.WrapConn(ctx, conn, MatchFacts{})
	if err != nil {
		t.Fatalf("WrapConn: %v", err)
	}
	return wrapped
}

// waitPendingClosed waits, bounded, for the wrapper's terminal shutdown to reach
// the owned deferred connection.
func waitPendingClosed(t *testing.T, pending *fakePendingConn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !pending.closedState() {
		if time.Now().After(deadline) {
			t.Fatal("the wrapper did not perform its terminal shutdown")
		}
		time.Sleep(200 * time.Microsecond)
	}
}

// combinedWireStream reassembles the three places a transformed block can reach
// the peer: the deferred first send (SYN data), the established native sender,
// and the plain forwarding write on the same connection.
func combinedWireStream(pending *fakePendingConn, inner []byte) []byte {
	total := append([]byte(nil), pending.activationPayload()...)
	total = append(total, inner...)
	return append(total, pending.establishedWrites()...)
}

// A short native send of the fragment after the deferred first send must be
// counted and preserved exactly: the unsent tail is forwarded on the same
// connection, exactly once, and the caller count covers exactly what reached
// the peer. A dropped tail would lose bytes; a reported tail that never moved
// would let the caller skip real stream data.
func TestStreamCombinedDeferredAttachmentPartialCounts(t *testing.T) {
	t.Run("short-send-without-error", func(t *testing.T) {
		config := combinedFirstSendRule(t)
		sender := &v4ScriptedSender{short: 1}
		config.native = &nativeRecorder{sender: sender}
		pending := newFakePendingConn()
		wrapped := wrapStream(t, config, pending, MatchFacts{})
		defer wrapped.Close()
		input := []byte("ABCDEF")
		written, err := wrapped.Write(input)
		if err != nil || written != len(input) {
			t.Fatalf("Write = (%d, %v), want (%d, nil): the short native send must forward its tail", written, err, len(input))
		}
		if got := pending.activationPayload(); !bytes.Equal(got, []byte("AB")) {
			t.Fatalf("deferred first-send payload = %q, want the first fragment %q", got, "AB")
		}
		if pending.activationCount() != 1 {
			t.Fatalf("deferred activations = %d, want exactly 1", pending.activationCount())
		}
		inner := sender.emitted()
		if !bytes.Equal(inner, []byte("C")) {
			t.Fatalf("established native sender emitted %q, want the accepted prefix %q", inner, "C")
		}
		if got := pending.establishedWrites(); !bytes.Equal(got, []byte("DEF")) {
			t.Fatalf("forwarded tail on the same connection = %q, want %q", got, "DEF")
		}
		total := combinedWireStream(pending, inner)
		if !bytes.Equal(total, input) {
			t.Fatalf("wire stream = %q, want exactly %q once", total, input)
		}
	})

	t.Run("short-send-with-error", func(t *testing.T) {
		config := combinedFirstSendRule(t)
		sender := &v4ScriptedSender{short: 1, failErr: net.ErrClosed}
		config.native = &nativeRecorder{sender: sender}
		pending := newFakePendingConn()
		wrapped := wrapStream(t, config, pending, MatchFacts{})
		defer wrapped.Close()
		input := []byte("ABCDEF")
		written, err := wrapped.Write(input)
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write error = %v, want the native send error %v", err, net.ErrClosed)
		}
		if written != len(input) {
			t.Fatalf("Write = %d, want %d: every caller byte that reached the connection must be reported", written, len(input))
		}
		inner := sender.emitted()
		if !bytes.Equal(inner, []byte("C")) {
			t.Fatalf("established native sender emitted %q, want the accepted prefix %q", inner, "C")
		}
		total := combinedWireStream(pending, inner)
		if !bytes.Equal(total, input) {
			t.Fatalf("wire stream = %q, want exactly %q once", total, input)
		}
	})
}

// A Close that lands while the deferred attachment is waiting for its platform
// sender must (1) carry the first fragment that already went into the owned
// attempt, (2) refuse every later fragment, (3) prove the caller count of the
// partial delivery, and (4) settle release/cancel/deadline on the late inner
// sender exactly once - without a second Write or a second Close.
func TestStreamCombinedDeferredAttachmentCrossesClose(t *testing.T) {
	config := combinedFirstSendRule(t)
	sender := &combinedLifecycleSender{}
	native := &combinedGateNative{sender: sender, entered: make(chan struct{}), gate: make(chan struct{})}
	config.native = native
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	type writeResult struct {
		written int
		err     error
	}
	done := make(chan writeResult, 1)
	go func() {
		written, err := wrapped.Write([]byte("ABCDEF"))
		done <- writeResult{written: written, err: err}
	}()
	<-native.entered
	// The deadline, the cancellation and the release all arrive while the inner
	// sender does not exist yet.
	wrapped.SetWriteDeadline(time.Now().Add(time.Minute))
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(native.gate)
	var result writeResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the deferred write did not finish after Close")
	}
	if result.written != 2 {
		t.Fatalf("Write = %d, want 2: only the first fragment reached the owned attempt", result.written)
	}
	if !errors.Is(result.err, net.ErrClosed) {
		t.Fatalf("Write error = %v, want %v: the fragment after Close must not be sent", result.err, net.ErrClosed)
	}
	if sender.sends.Load() != 0 {
		t.Fatalf("late inner sender performed %d sends after Close", sender.sends.Load())
	}
	if sender.releases.Load() != 1 {
		t.Fatalf("late inner sender released %d times, want exactly once", sender.releases.Load())
	}
	if sender.cancels.Load() != 1 {
		t.Fatalf("late inner sender canceled %d times, want exactly the Close cancellation", sender.cancels.Load())
	}
	if sender.deadlines.Load() != 1 {
		t.Fatalf("deadline stored before the inner sender existed was applied %d times, want once", sender.deadlines.Load())
	}
	if pending.activationCount() != 1 {
		t.Fatalf("deferred activations = %d, want exactly 1", pending.activationCount())
	}
	if got := pending.activationPayload(); !bytes.Equal(got, []byte("AB")) {
		t.Fatalf("deferred first-send payload = %q, want %q", got, "AB")
	}
	if got := pending.establishedWrites(); len(got) != 0 {
		t.Fatalf("bytes %q were written after Close", got)
	}
	if written, err := wrapped.Write([]byte("x")); written != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after Close = (%d, %v), want (0, %v)", written, err, net.ErrClosed)
	}
}

// Context cancellation is the other terminal shutdown owner (A-O1). On the
// combined path it must go through the same once-guarded teardown as Close and
// reach the deferred attachment, whose inner sender must never send afterwards.
func TestStreamCombinedDeferredAttachmentContextCancel(t *testing.T) {
	config := combinedFirstSendRule(t)
	sender := &combinedLifecycleSender{}
	native := &combinedGateNative{sender: sender, entered: make(chan struct{}), gate: make(chan struct{})}
	config.native = native
	pending := newFakePendingConn()
	ctx, cancel := context.WithCancel(context.Background())
	wrapped := wrapCombinedWithContext(t, ctx, config, pending)
	type writeResult struct {
		written int
		err     error
	}
	done := make(chan writeResult, 1)
	go func() {
		written, err := wrapped.Write([]byte("ABCDEF"))
		done <- writeResult{written: written, err: err}
	}()
	<-native.entered
	cancel()
	waitPendingClosed(t, pending)
	close(native.gate)
	var result writeResult
	select {
	case result = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the deferred write did not finish after cancellation")
	}
	if result.written != 2 {
		t.Fatalf("Write = %d, want 2: only the first fragment reached the owned attempt", result.written)
	}
	if !errors.Is(result.err, net.ErrClosed) {
		t.Fatalf("Write error = %v, want %v after cancellation", result.err, net.ErrClosed)
	}
	if sender.sends.Load() != 0 {
		t.Fatalf("late inner sender performed %d sends after cancellation", sender.sends.Load())
	}
	if sender.releases.Load() != 1 {
		t.Fatalf("late inner sender released %d times, want exactly once", sender.releases.Load())
	}
	if sender.cancels.Load() != 1 {
		t.Fatalf("late inner sender canceled %d times, want exactly the terminal cancellation", sender.cancels.Load())
	}
	if pending.activationCount() != 1 {
		t.Fatalf("deferred activations = %d, want exactly 1", pending.activationCount())
	}
	if got := pending.establishedWrites(); len(got) != 0 {
		t.Fatalf("bytes %q were written after cancellation", got)
	}
	if written, err := wrapped.Write([]byte("x")); written != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after cancellation = (%d, %v), want (0, %v)", written, err, net.ErrClosed)
	}
}

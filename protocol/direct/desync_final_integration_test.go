package direct

// Cross-feature integration of the accepted lanes at the real attachment seam
// (protocol/direct WrapPendingTCP): the stream Close bound (stream v7), the
// owned deferred TFO attempt (t_e317e2a5) and the O2 write-count/tail contract
// (t_74daade5) meet on one wrapper. The dialer-side pending connection is a
// hermetic in-memory model with no socket, no network and no host state.
//
// Provenance:
//   - Close bound: t_9403b749-report.md §3 and t_f6e5a210-qa.md §4 (QA-D3).
//   - Deferred TFO seam: t_e317e2a5-report.md "What this run changed".
//   - Write accounting: t_74daade5-report.md (O2) and stream_write_count_o2_test.go.
//
// The deferred fake deliberately models the two properties the real owned
// attempt has: nothing exists before the first transformed write, and every
// later write goes to the established connection. The Close case adds the
// property that matters for QA-D3: an established write can be blocked and
// deadline-blind, so only the connection lifetime bounds Close.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// finalEstablished records every byte that reached the established connection.
type finalEstablished struct {
	mu     sync.Mutex
	wire   []byte
	writes [][]byte
	closed bool
}

func (c *finalEstablished) record(p []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wire = append(c.wire, p...)
	c.writes = append(c.writes, append([]byte(nil), p...))
}

func (c *finalEstablished) collected() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.wire...)
}

func (c *finalEstablished) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *finalEstablished) Write(p []byte) (int, error) {
	c.record(p)
	return len(p), nil
}

func (c *finalEstablished) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *finalEstablished) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *finalEstablished) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *finalEstablished) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *finalEstablished) SetDeadline(time.Time) error      { return nil }
func (c *finalEstablished) SetReadDeadline(time.Time) error  { return nil }
func (c *finalEstablished) SetWriteDeadline(time.Time) error { return nil }

// finalPendingConn is the deferred owned attempt as the wrapper sees it.
//
// The first Write is the TFO payload: it creates the single owned attempt and
// accepts firstAccept bytes of the fragment (a short or failing send models the
// pre-SYN/initial-data write). Later writes go to the established connection;
// with blockAfterFirst they block until the connection is closed, which is the
// deadline-blind blocked peer QA-D3 covers.
type finalPendingConn struct {
	mu sync.Mutex

	established *finalEstablished
	activations int
	payload     []byte
	writes      int
	deadlines   []time.Time

	firstAccept     func(length int) (int, error)
	blockAfterFirst bool

	closed    chan struct{}
	closeOnce sync.Once
	blocked   chan struct{}
	blockOnce sync.Once
}

func newFinalPendingConn() *finalPendingConn {
	return &finalPendingConn{closed: make(chan struct{}), blocked: make(chan struct{})}
}

func (c *finalPendingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	if c.established == nil {
		c.established = &finalEstablished{}
		c.activations++
		accept := len(p)
		var sendErr error
		if c.firstAccept != nil {
			accept, sendErr = c.firstAccept(len(p))
		}
		if accept < 0 {
			accept = 0
		}
		if accept > len(p) {
			accept = len(p)
		}
		c.payload = append([]byte(nil), p[:accept]...)
		established := c.established
		c.mu.Unlock()
		if accept > 0 {
			established.record(p[:accept])
		}
		return accept, sendErr
	}
	established := c.established
	block := c.blockAfterFirst
	c.mu.Unlock()
	if block {
		c.blockOnce.Do(func() { close(c.blocked) })
		<-c.closed
		return 0, net.ErrClosed
	}
	return established.Write(p)
}

func (c *finalPendingConn) Read([]byte) (int, error) { return 0, net.ErrClosed }

func (c *finalPendingConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	c.mu.Lock()
	established := c.established
	c.mu.Unlock()
	if established != nil {
		_ = established.Close()
	}
	return nil
}

func (c *finalPendingConn) LocalAddr() net.Addr  { return M.Socksaddr{} }
func (c *finalPendingConn) RemoteAddr() net.Addr { return M.Socksaddr{} }
func (c *finalPendingConn) SetDeadline(deadline time.Time) error {
	return c.SetWriteDeadline(deadline)
}
func (c *finalPendingConn) SetReadDeadline(time.Time) error { return nil }
func (c *finalPendingConn) SetWriteDeadline(deadline time.Time) error {
	// Models a platform sender that bypasses the Go poller: the value is
	// recorded but it never interrupts an in-flight write.
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return nil
}

func (c *finalPendingConn) NativePending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.established == nil
}

func (c *finalPendingConn) NeedHandshake() bool { return c.NativePending() }

func (c *finalPendingConn) Established() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.established == nil {
		return nil
	}
	return c.established
}

func (c *finalPendingConn) state() (activations int, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activations, append([]byte(nil), c.payload...)
}

func (c *finalPendingConn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func (c *finalPendingConn) lastDeadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.deadlines) == 0 {
		return time.Time{}, false
	}
	return c.deadlines[len(c.deadlines)-1], true
}

// finalSplitConfig compiles one split rule through the ordinary option surface,
// so the test uses the same configuration compiler as production.
func finalSplitConfig(t *testing.T) *desync.StreamConfig {
	t.Helper()
	rule := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos:         badoption.Listable[string]{"2"},
			SplitAnyProtocol: true,
		},
	}
	config, err := desync.CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	if err != nil {
		t.Fatal(err)
	}
	if config == nil {
		t.Fatal("CompileStream returned no configuration")
	}
	return config
}

// finalAttach runs the real bridge seam: WrapPendingTCP wraps the deferred
// connection with the compiled stream configuration, exactly once.
func finalAttach(t *testing.T, pending net.Conn) net.Conn {
	t.Helper()
	hook := &desyncHook{stream: finalSplitConfig(t), lifetime: context.Background()}
	intent := dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.7"), 443),
	}
	wrapped, err := hook.WrapPendingTCP(context.Background(), intent, pending)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped == nil {
		t.Fatal("WrapPendingTCP returned no connection")
	}
	if !N.NeedHandshakeForWrite(wrapped) {
		t.Fatal("attached wrapper hid the pending TFO handshake")
	}
	return wrapped
}

// finalRetainedPrefix is an incomplete TLS handshake record: it is structurally
// incomplete (the record header announces 0x40 payload bytes), so the wrapper
// retains it as the first block until more bytes arrive, the hold timer fires or
// Close flushes it. Holding it is what makes Close take the flush path where the
// single owned TFO attempt is created.
func finalRetainedPrefix() []byte {
	return []byte{0x16, 0x03, 0x01, 0x00, 0x40, 'A', 'B', 'C'}
}

// finalWire concatenates everything that reached the established connection.
func finalWire(pending *finalPendingConn) []byte {
	established := pending.Established()
	if established == nil {
		return nil
	}
	return established.(*finalEstablished).collected()
}

// TestFinalAttachmentCloseFlushDeferredTailIsBoundedAndDeliveredOnce is the
// positive control for the combined path: Close on an attached deferred
// connection flushes the retained block through the single owned TFO attempt,
// delivers the retained bytes exactly once and returns on its own bound
// without waiting for the watchdog.
func TestFinalAttachmentCloseFlushDeferredTailIsBoundedAndDeliveredOnce(t *testing.T) {
	pending := newFinalPendingConn()
	wrapped := finalAttach(t, pending)

	retained := finalRetainedPrefix()
	written, err := wrapped.Write(retained)
	if err != nil || written != len(retained) {
		t.Fatalf("retaining Write = %d,%v, want %d,nil", written, err, len(retained))
	}
	if activations, _ := pending.state(); activations != 0 {
		t.Fatalf("activations before Close = %d, want 0 (the block must be retained)", activations)
	}

	start := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- wrapped.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("Close took %v, want the ordinary flush path", elapsed)
	}

	activations, payload := pending.state()
	if activations != 1 {
		t.Fatalf("activations = %d, want exactly 1 (single owned TFO attempt)", activations)
	}
	// The single owned attempt carries the first split fragment as its TFO
	// payload; the remaining fragments are written on the established
	// connection, so the whole retained block reaches the wire exactly once.
	if len(payload) == 0 || len(payload) >= len(retained) {
		t.Fatalf("TFO payload = %x, want the first split fragment of the retained block", payload)
	}
	if !bytes.Equal(payload, retained[:len(payload)]) {
		t.Fatalf("TFO payload = %x, want a prefix of the retained block %x", payload, retained)
	}
	if wire := finalWire(pending); !bytes.Equal(wire, retained) {
		t.Fatalf("wire bytes = %x, want the retained block exactly once %x", wire, retained)
	}
	if written, err := wrapped.Write([]byte("x")); !errors.Is(err, net.ErrClosed) || written != 0 {
		t.Fatalf("Write after Close = %d,%v, want 0,net.ErrClosed", written, err)
	}
	if !pending.isClosed() {
		t.Fatal("Close did not close the owned deferred connection")
	}
}

// TestFinalAttachmentCloseFlushBoundedDespiteStaleDeadlineClear reproduces the
// QA-D3 shape at the attachment seam: the retained block is flushed through the
// deferred attempt, the established write blocks (deadline-blind, as the
// Windows overlapped send can), and a concurrent caller clears the wrapper
// write deadline while the flush is blocked. Close must still end on its own
// bound - the watchdog aborts the flush - and the owned attempt must be created
// exactly once with the first fragment as its TFO payload.
func TestFinalAttachmentCloseFlushBoundedDespiteStaleDeadlineClear(t *testing.T) {
	pending := newFinalPendingConn()
	pending.blockAfterFirst = true
	wrapped := finalAttach(t, pending)

	retained := finalRetainedPrefix()
	if written, err := wrapped.Write(retained); err != nil || written != len(retained) {
		t.Fatalf("retaining Write = %d,%v, want %d,nil", written, err, len(retained))
	}

	start := time.Now()
	closed := make(chan error, 1)
	go func() { closed <- wrapped.Close() }()

	select {
	case <-pending.blocked:
	case <-time.After(2 * time.Second):
		t.Fatal("the flush never reached the established deferred write")
	}
	// A publication computed by another caller before the flush installed its
	// bound can still land in the shared connection deadline slot last (QA-D3).
	// The wrapper's own publication cannot express that - it always caps by the
	// bound - so the stale write is applied to the connection slot directly, as
	// the final delegation of such a caller would.
	if err := pending.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("stale SetWriteDeadline = %v", err)
	}
	if deadline, ok := pending.lastDeadline(); !ok || !deadline.IsZero() {
		t.Fatalf("stale publication left %v in the connection slot, want a cleared deadline", deadline)
	}

	select {
	case err := <-closed:
		elapsed := time.Since(start)
		if err != nil {
			// The aborted flush reports the closed connection; the bound is
			// what this test asserts, so only a nil/hang distinction matters.
			t.Logf("Close reported the aborted flush: %v", err)
		}
		if elapsed < 200*time.Millisecond {
			t.Fatalf("Close returned in %v, before the 250 ms flush bound could be reached", elapsed)
		}
		if elapsed > 1500*time.Millisecond {
			t.Fatalf("Close took %v, want the 250 ms bound plus the watchdog grace", elapsed)
		}
		t.Logf("bounded Close after a stale clear: %v", elapsed)
	case <-time.After(3 * time.Second):
		t.Fatal("Close did not return after a stale deadline clear (the flush bound was defeated)")
	}

	activations, payload := pending.state()
	if activations != 1 {
		t.Fatalf("activations = %d, want exactly 1", activations)
	}
	if len(payload) == 0 || !bytes.Equal(payload, retained[:len(payload)]) {
		t.Fatalf("TFO payload = %x, want a prefix of the retained block %x", payload, retained)
	}
	if !pending.isClosed() {
		t.Fatal("the watchdog did not close the owned deferred connection")
	}
}

// TestFinalAttachmentDeferredPartialSendCountsOwnedBytesExactly covers the O2
// contract on the deferred first send: the TFO payload accepts one of the two
// first-fragment bytes, the wrapper forwards the unsent tail on the established
// connection, and Write reports exactly the caller bytes that are now on the
// wire. No byte is dropped, duplicated or counted twice.
func TestFinalAttachmentDeferredPartialSendCountsOwnedBytesExactly(t *testing.T) {
	pending := newFinalPendingConn()
	pending.firstAccept = func(int) (int, error) { return 1, nil }
	wrapped := finalAttach(t, pending)

	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = %d,%v, want %d,nil", written, err, len(input))
	}

	activations, payload := pending.state()
	if activations != 1 {
		t.Fatalf("activations = %d, want exactly 1", activations)
	}
	if string(payload) != "A" {
		t.Fatalf("accepted TFO payload = %q, want the one byte the first send took", payload)
	}
	if pending.Established() == nil {
		t.Fatal("the tail was not forwarded on the established connection")
	}
	if wire := finalWire(pending); !bytes.Equal(wire, input) {
		t.Fatalf("wire bytes = %q, want the caller bytes exactly once %q", wire, input)
	}

	// Close must not replay the already-counted block.
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if wire := finalWire(pending); !bytes.Equal(wire, input) {
		t.Fatalf("after Close wire bytes = %q, want no replay of %q", wire, input)
	}
}

// TestFinalAttachmentDeferredFirstSendErrorDoesNotClaimUnsentBytes is the
// failing first send half of the same contract. A plain split writes each
// fragment through the deferred connection, so a failing first write reports
// only the bytes that actually left: the wrapper does not claim the unsent
// remainder, the error is sticky and Close does not replay or complete the
// partially written fragment behind the caller's back.
func TestFinalAttachmentDeferredFirstSendErrorDoesNotClaimUnsentBytes(t *testing.T) {
	sendErr := errors.New("owned attempt first send failed")
	pending := newFinalPendingConn()
	pending.firstAccept = func(int) (int, error) { return 1, sendErr }
	wrapped := finalAttach(t, pending)

	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if !errors.Is(err, sendErr) {
		t.Fatalf("Write error = %v, want the first-send error", err)
	}
	if written != 1 {
		t.Fatalf("Write = %d, want 1 (only the byte that left the connection)", written)
	}
	if wire := finalWire(pending); !bytes.Equal(wire, input[:1]) {
		t.Fatalf("wire bytes = %q, want only the accepted prefix %q", wire, input[:1])
	}
	if written, err := wrapped.Write(input[1:]); !errors.Is(err, sendErr) || written != 0 {
		t.Fatalf("retry Write = %d,%v, want 0 and the sticky error", written, err)
	}

	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if wire := finalWire(pending); !bytes.Equal(wire, input[:1]) {
		t.Fatalf("after Close wire bytes = %q, want no silent completion of %q", wire, input)
	}
}

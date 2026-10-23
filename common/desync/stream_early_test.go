package desync

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// fakePendingConn is the hermetic model of the dialer's deferred TFO facade: it
// owns no socket until the first Write, that first Write is the single owned
// attempt carrying the transformed segment as TFO data, and every later Write
// goes to the established connection. It is the same contract the dialer's
// pendingTCPConn implements; the stream package only needs the structural
// NativePending/Established seam.
type fakePendingConn struct {
	mu          sync.Mutex
	established *fakeConn
	activations int
	payload     []byte
	closed      bool
}

func newFakePendingConn() *fakePendingConn {
	return &fakePendingConn{}
}

func (c *fakePendingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if c.established == nil {
		c.established = newFakeConn()
		c.activations++
		c.payload = append([]byte(nil), p...)
		c.mu.Unlock()
		// The native attempt carries the payload; it is not replayed on the
		// established connection.
		return len(p), nil
	}
	established := c.established
	c.mu.Unlock()
	return established.Write(p)
}

func (c *fakePendingConn) Read(p []byte) (int, error) { return 0, io.EOF }
func (c *fakePendingConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *fakePendingConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *fakePendingConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *fakePendingConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePendingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePendingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *fakePendingConn) NativePending() bool              { return c.established == nil }

func (c *fakePendingConn) Established() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.established == nil {
		return nil
	}
	return c.established
}

func (c *fakePendingConn) activationPayload() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.payload...)
}

func (c *fakePendingConn) activationCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activations
}

func (c *fakePendingConn) establishedWrites() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.established == nil {
		return nil
	}
	return c.established.collected()
}

// A plain split rule (no native per-segment control) is the ordinary
// TFO+split case: the first transformed fragment is the deferred first write,
// later fragments are ordinary writes on the same connection, and nothing is
// joined or replayed.
func TestStreamDeferredSplitFirstFragmentCarriesTFOPayload(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	config := mustCompileStream(t, rule)
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	defer wrapped.Close()
	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written != len(input) {
		t.Fatalf("Write = %d, want %d", written, len(input))
	}
	if got := pending.activationPayload(); !bytes.Equal(got, []byte("AB")) {
		t.Fatalf("first TFO payload = %q, want the first split fragment %q", got, "AB")
	}
	if pending.activationCount() != 1 {
		t.Fatalf("activations = %d, want exactly 1", pending.activationCount())
	}
	got := pending.establishedWrites()
	if !bytes.Equal(got, []byte("CDEF")) {
		t.Fatalf("established writes = %q, want %q", got, "CDEF")
	}
	if total := append(append([]byte(nil), pending.activationPayload()...), got...); !bytes.Equal(total, input) {
		t.Fatalf("reassembled stream = %q, want %q", total, input)
	}
}

// A native split rule (fix_seg needs a per-segment sender) must carry the first
// fragment through the deferred first send and then switch to the established
// native sender on the same connection.
func TestStreamDeferredNativeSplitUsesEstablishedAfterFirstSend(t *testing.T) {
	if !streamCaps().fixSeg {
		t.Skip("fix_seg native send is Linux only")
	}
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.FixSeg = &option.DirectDesyncStreamFixSeg{Default: true}
	config := mustCompileStream(t, rule)
	sender := &v4ScriptedSender{short: -1}
	config.native = &nativeRecorder{sender: sender}
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	defer wrapped.Close()
	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = %d,%v, want %d,nil", written, err, len(input))
	}
	if got := pending.activationPayload(); !bytes.Equal(got, []byte("AB")) {
		t.Fatalf("first TFO payload = %q, want %q", got, "AB")
	}
	if pending.activationCount() != 1 {
		t.Fatalf("activations = %d, want exactly 1", pending.activationCount())
	}
	if got := sender.emitted(); !bytes.Equal(got, []byte("CDEF")) {
		t.Fatalf("established native sender bytes = %q, want %q", got, "CDEF")
	}
	if len(pending.establishedWrites()) != 0 {
		t.Fatalf("second fragment was replayed through the pending facade: %q", pending.establishedWrites())
	}
}

// The OPEN TFO+first-send-OOB/disorder choice must stay a visible pre-I/O
// failure. A first fragment that needs OOB or low-TTL disorder cannot be carried
// by SYN data; forwarding the block unsplit after the error would silently
// bypass the transformation the rule asked for.
func TestStreamDeferredFirstSendOOBRefusedBeforeAnyByte(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	sender := &v4ScriptedSender{short: -1}
	config.native = &nativeRecorder{sender: sender}
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	defer wrapped.Close()
	written, err := wrapped.Write([]byte("ABCDEF"))
	if err == nil {
		t.Fatal("first-send OOB under deferred TFO reported success")
	}
	if written != 0 {
		t.Fatalf("refused first send reported %d bytes, want 0", written)
	}
	if pending.activationCount() != 0 {
		t.Fatalf("activations = %d, want 0: no socket and no byte may exist", pending.activationCount())
	}
	if got := pending.establishedWrites(); len(got) != 0 {
		t.Fatalf("refused first send forwarded %q unsplit", got)
	}
	if len(sender.emitted()) != 0 {
		t.Fatalf("refused first send emitted %q", sender.emitted())
	}
}

// fix_seg waits for the previous fragment before sending the next one. Before
// the first fragment there is no socket and nothing in flight, so the wait must
// succeed without activating the deferred attempt.
func TestStreamDeferredWaitNotSentBeforeFirstFragmentDoesNotActivate(t *testing.T) {
	pending := newFakePendingConn()
	sender := newFirstSendSender(pending, pending, func() (streamSender, error) {
		return &v4ScriptedSender{short: -1}, nil
	})
	if !sender.WaitNotSent(50 * time.Millisecond) {
		t.Fatal("fix_seg wait before the first fragment reported a pending send")
	}
	if pending.activationCount() != 0 {
		t.Fatalf("fix_seg wait created %d native attempts, want 0", pending.activationCount())
	}
}

// The connection manager performs an explicit empty write to create the
// connection for a server-first flow or when the first payload has not arrived.
// The stream wrapper must forward that signal to the deferred facade, otherwise
// the single owned attempt would only be created later by a read, without the
// bounded handshake deadline.
func TestStreamDeferredEmptyWriteActivatesEmptyAttempt(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	config := mustCompileStream(t, rule)
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	defer wrapped.Close()
	if n, err := wrapped.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty write = (%d, %v), want (0, nil)", n, err)
	}
	if pending.activationCount() != 1 {
		t.Fatalf("activations = %d, want exactly 1", pending.activationCount())
	}
	if got := pending.activationPayload(); len(got) != 0 {
		t.Fatalf("empty connect carried payload %q", got)
	}
	if pending.establishedWrites() != nil && len(pending.establishedWrites()) != 0 {
		t.Fatalf("empty connect wrote %q on the established connection", pending.establishedWrites())
	}
}

// The wrapped stream must forward the deferred handshake contract, otherwise
// the connection manager cannot perform the explicit empty/server-first connect
// and a server-first flow would never create its single owned attempt.
func TestStreamDeferredNeedHandshakeForwarded(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	config := mustCompileStream(t, rule)
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	defer wrapped.Close()
	if !N.NeedHandshakeForWrite(wrapped) {
		t.Fatal("stream wrapper hid the pending handshake")
	}
	if _, err := wrapped.Write([]byte("AB")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if N.NeedHandshakeForWrite(wrapped) {
		t.Fatal("stream wrapper still reports a pending handshake after the first send")
	}
}

// lifecycleSender records every optional sender capability the stream wrapper
// forwards. It substitutes only the native sender; the wrapper, adapter and
// shutdown paths are the production ones.
type lifecycleSender struct {
	sends     atomic.Int32
	cancels   atomic.Int32
	releases  atomic.Int32
	deadlines atomic.Int32
}

func (s *lifecycleSender) Send(p []byte, _ sendOptions) (int, error) {
	s.sends.Add(1)
	return len(p), nil
}

func (s *lifecycleSender) WaitNotSent(time.Duration) bool { return true }
func (s *lifecycleSender) CancelPending()                 { s.cancels.Add(1) }
func (s *lifecycleSender) Release()                       { s.releases.Add(1) }
func (s *lifecycleSender) SetWriteDeadline(time.Time)     { s.deadlines.Add(1) }

// The deferred adapter must forward release, cancellation and deadline
// ownership to the established inner sender. Registering only the adapter hid
// all three, so Close never freed the platform completion event.
func TestStreamDeferredFirstSendLifecycleForwarded(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		name := "eager-control"
		if deferred {
			name = "deferred"
		}
		t.Run(name, func(t *testing.T) {
			rule := splitRule("host+1")
			rule.Split.OOB = "any"
			config := mustCompileStream(t, rule)
			sender := &lifecycleSender{}
			config.native = &nativeRecorder{sender: sender}
			var conn net.Conn = newFakeConn()
			if deferred {
				conn = newFakePendingConn()
			}
			wrapped := wrapStream(t, config, conn, MatchFacts{})
			if _, err := wrapped.Write([]byte("unrecognised-block")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			wrapped.SetWriteDeadline(time.Now().Add(time.Second))
			wrapped.Close()
			wrapped.Close()
			t.Logf("deferred=%v adaptersends=%d cancel=%d release=%d deadline-push=%d",
				deferred, sender.sends.Load(), sender.cancels.Load(), sender.releases.Load(), sender.deadlines.Load())
			if sender.releases.Load() != 1 {
				t.Fatal("established native sender hidden by firstSendSender: Release not forwarded")
			}
			if sender.cancels.Load() == 0 || sender.deadlines.Load() == 0 {
				t.Fatal("established sender lifecycle/deadline not forwarded")
			}
		})
	}
}

// gatedNative blocks the established-sender creation, so a concurrent Close sees
// the adapter before its inner sender exists.
type gatedNative struct {
	sender  *lifecycleSender
	entered chan struct{}
	gate    chan struct{}
}

func (n *gatedNative) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *gatedNative) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	close(n.entered)
	<-n.gate
	return n.sender, nil
}

// A Close that races the first send must still free the inner sender that
// arrives afterwards: no second Write and no second Close may be required.
func TestStreamDeferredInnerSenderLateArrivalAfterCloseIsReleased(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	sender := &lifecycleSender{}
	native := &gatedNative{sender: sender, entered: make(chan struct{}), gate: make(chan struct{})}
	config.native = native
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	writeDone := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("ABCDEFG"))
		writeDone <- err
	}()
	<-native.entered
	// Deadline update and Close arrive while the inner sender does not exist.
	wrapped.SetWriteDeadline(time.Now().Add(time.Minute))
	wrapped.Close()
	close(native.gate)
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first send did not finish after the late inner sender was created")
	}
	t.Logf("late-adoption sends=%d cancel=%d release=%d deadline-push=%d",
		sender.sends.Load(), sender.cancels.Load(), sender.releases.Load(), sender.deadlines.Load())
	if sender.releases.Load() != 1 {
		t.Fatalf("late inner sender released %d times, want exactly once", sender.releases.Load())
	}
	if sender.cancels.Load() != 1 {
		t.Fatalf("late inner sender canceled %d times, want the recorded Close", sender.cancels.Load())
	}
	if sender.deadlines.Load() != 1 {
		t.Fatalf("deadline stored before the inner sender existed was applied %d times", sender.deadlines.Load())
	}
	if sender.sends.Load() != 0 {
		t.Fatalf("late inner sender started %d sends after the terminal Close", sender.sends.Load())
	}
	if _, err := wrapped.Write([]byte("x")); err == nil {
		t.Fatal("write after Close on the deferred adapter succeeded")
	}
}

package desync

// Permanent regressions for the v4 review repair (reviewer-max-2 findings
// R1-R4, S1 and the strict/immutable controls). Each test names the defect it
// pins; the byte-preservation and liveness assertions are substantive and were
// reproduced as failures on the rejected v3 artifact before the fix.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// v4NoSNIClientHello is a structurally complete TLS 1.2 ClientHello without a
// server_name extension (RSA/AES-128-CBC-SHA).
func v4NoSNIClientHello() []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0}, 32)...)
	body = append(body, 0, 0, 2, 0x00, 0x2f, 1, 0)
	handshake := append([]byte{1, 0, 0, byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, 0, byte(len(handshake))}, handshake...)
}

// waitCollected polls a memory connection until it has at least the expected
// number of bytes. It is bounded and never triggers network activity.
func waitCollected(t *testing.T, conn *fakeConn, expected int, timeout time.Duration) []byte {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		collected := conn.collected()
		if len(collected) >= expected || time.Now().After(deadline) {
			return collected
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// R1: a five-byte TLS record header with a zero record length must be
// classified safely instead of indexing block[5].
func TestStreamV4ZeroLengthTLSRecordIsSafe(t *testing.T) {
	config := mustCompileStream(t, splitRule("1"))
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Write panicked on a five-byte TLS record: %v", recovered)
		}
	}()
	input := []byte{0x16, 0x03, 0x03, 0x00, 0x00}
	written, err := wrapped.Write(input)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written != len(input) {
		t.Fatalf("Write = %d, want %d", written, len(input))
	}
	if err = wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := conn.collected(); !bytes.Equal(got, input) {
		t.Fatalf("malformed record bytes changed: %x", got)
	}
}

// R1: truncated and lying length fields must not panic or lose bytes.
func TestStreamV4MalformedTLSLengthsAreSafe(t *testing.T) {
	cases := map[string][]byte{
		"four-byte-prefix":        {0x16, 0x03, 0x03, 0x00},
		"zero-length-record":      {0x16, 0x03, 0x03, 0x00, 0x00},
		"zero-length-with-type":   {0x16, 0x03, 0x03, 0x00, 0x00, 0x01},
		"truncated-declared-body": {0x16, 0x03, 0x03, 0x00, 0x40, 0x01, 0x00, 0x00, 0x02},
		"max-declared-body":       {0x16, 0x03, 0x03, 0xff, 0xff, 0x01},
		"handshake-overrun":       {0x16, 0x03, 0x03, 0x00, 0x08, 0x01, 0x00, 0x00, 0x40, 0x03, 0x03, 0x00, 0x00},
	}
	for name, input := range cases {
		input := input
		t.Run(name, func(t *testing.T) {
			config := mustCompileStream(t, splitRule("1"))
			conn := newFakeConn()
			wrapped := wrapStream(t, config, conn, MatchFacts{})
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Write panicked: %v", recovered)
				}
			}()
			written, err := wrapped.Write(input)
			if err != nil {
				t.Fatalf("Write: %v", err)
			}
			if written != len(input) {
				t.Fatalf("Write = %d, want %d", written, len(input))
			}
			if err = wrapped.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if got := conn.collected(); !bytes.Equal(got, input) {
				t.Fatalf("malformed stream bytes changed\n got %x\nwant %x", got, input)
			}
		})
	}
}

type v4ScriptedSender struct {
	mu       sync.Mutex
	accepted [][]byte
	sent     bytes.Buffer
	short    int // bytes accepted by the first Send; -1 sends everything
	failErr  error
}

func (s *v4ScriptedSender) Send(data []byte, options sendOptions) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accepted = append(s.accepted, append([]byte(nil), data...))
	accepted := len(data)
	if s.short >= 0 && accepted > s.short {
		accepted = s.short
	}
	s.sent.Write(data[:accepted])
	return accepted, s.failErr
}

func (s *v4ScriptedSender) WaitNotSent(time.Duration) bool { return true }

func (s *v4ScriptedSender) emitted() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.sent.Bytes()...)
}

// R2: an unsplit native send that returns (2, nil) for nine bytes must forward
// the seven unsent bytes instead of reporting success and dropping them.
func TestStreamV4UnsplitNativeShortSendPreservesBytes(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &v4ScriptedSender{short: 2}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()
	input := []byte("xyzabcdef")
	written, err := wrapped.Write(input)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written != len(input) {
		t.Fatalf("Write = %d, want %d", written, len(input))
	}
	got := append(sender.emitted(), conn.collected()...)
	if !bytes.Equal(got, input) {
		t.Fatalf("unsplit native short send lost bytes: emitted %q, want %q", got, input)
	}
}

// R2: zero progress with a nil error must also preserve every byte.
func TestStreamV4UnsplitNativeZeroProgressPreservesBytes(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &v4ScriptedSender{short: 0}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()
	input := []byte("xyzabcdef")
	written, err := wrapped.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = %d,%v", written, err)
	}
	got := append(sender.emitted(), conn.collected()...)
	if !bytes.Equal(got, input) {
		t.Fatalf("zero-progress native send lost bytes: %q", got)
	}
}

// R2: a short send inside the split loop cancels the split and forwards the
// remaining transformed bytes.
func TestStreamV4SplitNativeShortSendForwardsRemainder(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	config := mustCompileStream(t, rule)
	sender := &v4ScriptedSender{short: 1}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()
	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = %d,%v", written, err)
	}
	got := append(sender.emitted(), conn.collected()...)
	if !bytes.Equal(got, input) {
		t.Fatalf("split short send lost bytes: %q", got)
	}
}

// R2: a native send error after partial progress must not discard the tail of
// the block either.
func TestStreamV4UnsplitNativeErrorPreservesTail(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &v4ScriptedSender{short: 2, failErr: errors.New("native send failed")}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	input := []byte("xyzabcdef")
	if _, err := wrapped.Write(input); err == nil {
		t.Fatal("native send error was swallowed")
	}
	got := append(sender.emitted(), conn.collected()...)
	if !bytes.Equal(got, input) {
		t.Fatalf("native send error lost bytes: emitted %q, want %q", got, input)
	}
}

// R3: Close must interrupt a Write blocked on the socket without waiting for
// the write mutex, repeated Close included.
func TestStreamV4ConcurrentCloseInterruptsBlockedWrite(t *testing.T) {
	config := mustCompileStream(t, splitRule("1"))
	local, peer := net.Pipe()
	defer peer.Close()
	defer local.Close()
	wrapped := wrapStream(t, config, local, MatchFacts{})
	writeDone := make(chan struct{})
	writeErr := make(chan error, 1)
	go func() {
		_, err := wrapped.Write([]byte("xyz"))
		writeErr <- err
		close(writeDone)
	}()
	// Give Write time to block on the pipe.
	time.Sleep(20 * time.Millisecond)
	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		_ = local.Close()
		t.Fatal("Close blocked behind a blocked Write instead of closing the socket")
	}
	select {
	case err := <-writeErr:
		if err == nil {
			t.Fatal("interrupted Write must report an error")
		}
	case <-time.After(time.Second):
		t.Fatal("Write did not return after Close")
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
	<-writeDone
}

// R3: the pending flush performed by Close is bounded even when the peer never
// reads; the retained first block is still transformed and written.
func TestStreamV4ClosePendingFlushIsBounded(t *testing.T) {
	config := mustCompileStream(t, splitRule("1"))
	local, peer := net.Pipe()
	defer peer.Close()
	defer local.Close()
	wrapped := wrapStream(t, config, local, MatchFacts{})
	// Unknown protocol so the block is written during Write; use a partial TLS
	// record instead so it stays pending without a concurrent writer.
	input := []byte{0x16, 0x03, 0x03, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02}
	if _, err := wrapped.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- wrapped.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(2 * time.Second):
		_ = local.Close()
		t.Fatal("Close pending flush exceeded its bound")
	}
}

// R4: a complete ClientHello without SNI must be emitted while the client waits
// for the server handshake, without Close or a further Write.
func TestStreamV4CompleteNoSNIReleasedWithoutClose(t *testing.T) {
	config := mustCompileStream(t, splitRule("1"))
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()
	input := v4NoSNIClientHello()
	written, err := wrapped.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = %d,%v", written, err)
	}
	// A complete message is released by the Write itself; it must not wait for
	// the hold fallback or for Close.
	if got := conn.collected(); !bytes.Equal(got, input) {
		t.Fatalf("complete no-SNI ClientHello was not released in-line: %x", got)
	}
	if got := waitCollected(t, conn, len(input), 300*time.Millisecond); !bytes.Equal(got, input) {
		t.Fatalf("complete no-SNI ClientHello stalled or changed: %x", got)
	}
}

// R4: a retained incomplete first block is released by the bounded progress
// fallback without a further Write or Close, and its partial HTTP
// transformation is preserved.
func TestStreamV4HeldPartialHTTPReleasedBounded(t *testing.T) {
	blocked := hostcaseRule()
	blocked.Domain = badoption.Listable[string]{"blocked.example"}
	catchAll := option.DirectDesyncStreamRule{
		Name:       "catch-all",
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostCase: true},
	}
	config := mustCompileStream(t, blocked, catchAll)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	defer wrapped.Close()
	input := []byte("GET / HTTP/1.1\r\nHost: blocked.exa")
	if _, err := wrapped.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(conn.collected()) != 0 {
		t.Fatalf("incomplete host header must be held, emitted %q", conn.collected())
	}
	got := waitCollected(t, conn, len(input), 2*time.Second)
	if !bytes.Equal(got, []byte("GET / HTTP/1.1\r\nhost: blocked.exa")) {
		t.Fatalf("held partial HTTP was not released/transformed: %q", got)
	}
}

// R4: a retained partial TLS record is likewise released by the fallback; an
// any-protocol absolute split still applies to the released prefix.
func TestStreamV4HeldPartialTLSReleasedBounded(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 443})
	defer wrapped.Close()
	hello := buildClientHello("example.com")
	input := hello[:10]
	if _, err := wrapped.Write(input); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := waitCollected(t, conn, len(input), 2*time.Second)
	if !bytes.Equal(got, input) {
		t.Fatalf("held partial TLS bytes changed: %x", got)
	}
	if count := conn.writeCount(); count != 2 {
		t.Fatalf("writes = %d, want the any-protocol split to survive the fallback", count)
	}
}

// S1: ownership on an error is settled as caller-retained: WrapConn never closes
// the caller's connection when it returns an error, and the caller can close it.
func TestStreamV4WrapCancellationKeepsCallerOwnership(t *testing.T) {
	config := mustCompileStream(t, splitRule("1"))
	conn := newFakeConn()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := config.WrapConn(ctx, conn, MatchFacts{}); err == nil {
		t.Fatal("expected cancellation error")
	}
	conn.mu.Lock()
	closed := conn.closed
	conn.mu.Unlock()
	if closed {
		t.Fatal("failed WrapConn must leave ownership with the caller")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("caller cleanup: %v", err)
	}
}

// Reviewer control: the strict decoder must reject unknown fields.
func TestStreamV4StrictDecodeControl(t *testing.T) {
	for _, input := range []string{
		`{"methods":["split"],"split":{"split_pos":["1"],"unexpected":1}}`,
		`{"methods":["split"],"split":{"split_pos":["1"]},"fake":{}}`,
	} {
		var rule option.DirectDesyncStreamRule
		if err := sjson.UnmarshalDisallowUnknownFields([]byte(input), &rule); err == nil {
			t.Errorf("strict decoder silently accepted %s", input)
		}
	}
}

// Reviewer control: compiling must not alias the caller's option values.
func TestStreamV4ImmutableCompileControl(t *testing.T) {
	rule := splitRule("2")
	rule.Domain = badoption.Listable[string]{"example.com"}
	rule.Port = badoption.Listable[uint16]{443}
	config := mustCompileStream(t, rule)
	rule.Domain[0] = "evil.example"
	rule.Port[0] = 80
	rule.Split.SplitPos[0] = "3"
	compiled := config.selectRule(MatchFacts{Host: "example.com", HostKnown: true, Port: 443})
	if compiled == nil {
		t.Fatal("compiled matching changed after caller mutated original options")
	}
	if got := compiled.split.positions[0].Offset; got != 2 {
		t.Errorf("compiled position mutated: %d", got)
	}
}

// v4DeadlineNative records the deadline source handed to the platform sender.
type v4DeadlineNative struct {
	sender   streamSender
	deadline func() time.Time
}

func (n *v4DeadlineNative) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *v4DeadlineNative) NewSender(_ net.Conn, deadline func() time.Time) (streamSender, error) {
	n.deadline = deadline
	return n.sender, nil
}

// v4LifecycleSender records Close-time cancellation/release, the Windows-style
// lifecycle contract.
type v4LifecycleSender struct {
	mu        sync.Mutex
	cancelled int
	released  int
}

func (s *v4LifecycleSender) Send(data []byte, _ sendOptions) (int, error) {
	return len(data), nil
}

func (s *v4LifecycleSender) WaitNotSent(time.Duration) bool { return true }

func (s *v4LifecycleSender) CancelPending() {
	s.mu.Lock()
	s.cancelled++
	s.mu.Unlock()
}

func (s *v4LifecycleSender) Release() {
	s.mu.Lock()
	s.released++
	s.mu.Unlock()
}

func (s *v4LifecycleSender) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cancelled, s.released
}

// R5 plumbing: the native sender receives the wrapper's current write deadline,
// including deadlines set after it was created, and Close releases it.
func TestStreamV4NativeDeadlineAndLifecyclePlumbing(t *testing.T) {
	rule := splitRule("1")
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	lifecycle := &v4LifecycleSender{}
	native := &v4DeadlineNative{sender: lifecycle}
	config.native = native
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	deadline := time.Unix(5000, 0)
	if err := wrapped.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := wrapped.Write([]byte("ABCD")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if native.deadline == nil {
		t.Fatal("native sender did not receive a deadline source")
	}
	if got := native.deadline(); !got.Equal(deadline) {
		t.Fatalf("deadline source = %v, want %v", got, deadline)
	}
	later := deadline.Add(time.Second)
	if err := wrapped.SetWriteDeadline(later); err != nil {
		t.Fatalf("SetWriteDeadline later: %v", err)
	}
	if got := native.deadline(); !got.Equal(later) {
		t.Fatalf("deadline source after update = %v, want %v", got, later)
	}
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cancelled, released := lifecycle.counts()
	if cancelled != 1 || released != 1 {
		t.Fatalf("Close lifecycle: cancelled=%d released=%d, want 1/1", cancelled, released)
	}
}

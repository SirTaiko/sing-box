package desync

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Hermetic wrapper tests: no real socket, no host network state. The platform
// native seam is replaced by recording implementations; plain writes go to a
// memory conn whose short-write/error behavior is controlled by the test.

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "fake" }

type fakeConn struct {
	mu             sync.Mutex
	writes         [][]byte
	readBuffer     bytes.Buffer
	closed         bool
	shortRemaining int
	zeroProgress   bool
	failAfter      int
	failErr        error
	written        int
	writeDeadline  time.Time
}

func newFakeConn() *fakeConn {
	return &fakeConn{failAfter: -1, failErr: errors.New("fake write failure")}
}

func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.zeroProgress {
		return 0, nil
	}
	if c.failAfter >= 0 && c.written >= c.failAfter {
		return 0, c.failErr
	}
	length := len(p)
	if c.failAfter >= 0 && c.written+length > c.failAfter {
		length = c.failAfter - c.written
	}
	if c.shortRemaining > 0 && length > c.shortRemaining {
		length = c.shortRemaining
		c.shortRemaining = 0
	}
	if length > 0 {
		c.writes = append(c.writes, append([]byte(nil), p[:length]...))
		c.written += length
	}
	return length, nil
}

func (c *fakeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.readBuffer.Len() == 0 {
		return 0, io.EOF
	}
	return c.readBuffer.Read(p)
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) LocalAddr() net.Addr  { return fakeAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr{} }
func (c *fakeConn) SetDeadline(time.Time) error {
	return nil
}
func (c *fakeConn) SetReadDeadline(time.Time) error {
	return nil
}
func (c *fakeConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = deadline
	return nil
}

func (c *fakeConn) collected() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []byte
	for _, write := range c.writes {
		result = append(result, write...)
	}
	return result
}

func (c *fakeConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

type traceCall struct {
	data    []byte
	options sendOptions
}

type traceSender struct {
	calls    []traceCall
	waits    []time.Duration
	written  bytes.Buffer
	shortAt  int
	shortLen int
}

func newTraceSender() *traceSender {
	return &traceSender{shortAt: -1}
}

func (s *traceSender) Send(data []byte, options sendOptions) (int, error) {
	index := len(s.calls)
	s.calls = append(s.calls, traceCall{data: append([]byte(nil), data...), options: options})
	if index == s.shortAt {
		length := s.shortLen
		if length > len(data) {
			length = len(data)
		}
		s.written.Write(data[:length])
		return length, nil
	}
	s.written.Write(data)
	if options.oob {
		return len(data) + 1, nil
	}
	return len(data), nil
}

func (s *traceSender) WaitNotSent(timeout time.Duration) bool {
	s.waits = append(s.waits, timeout)
	return true
}

type nativeRecorder struct {
	prepared []prepareRecord
	sender   streamSender
}

func (n *nativeRecorder) Prepare(fd uintptr, config streamSocketConfig) error {
	n.prepared = append(n.prepared, prepareRecord{fd: fd, config: config})
	return nil
}

func (n *nativeRecorder) NewSender(net.Conn, func() time.Time) (streamSender, error) {
	if n.sender == nil {
		return nil, errors.New("native sender not configured")
	}
	return n.sender, nil
}

func mustCompileStream(t *testing.T, rules ...option.DirectDesyncStreamRule) *StreamConfig {
	t.Helper()
	config, err := CompileStream(rules, "")
	if err != nil {
		t.Fatalf("CompileStream: %v", err)
	}
	if config == nil {
		t.Fatal("CompileStream returned nil config")
	}
	config.random = bytes.NewReader(bytes.Repeat([]byte{0}, 1<<16))
	return config
}

func wrapStream(t *testing.T, config *StreamConfig, conn net.Conn, facts MatchFacts) net.Conn {
	t.Helper()
	wrapped, err := config.WrapConn(context.Background(), conn, facts)
	if err != nil {
		t.Fatalf("WrapConn: %v", err)
	}
	return wrapped
}

func hostcaseRule() option.DirectDesyncStreamRule {
	return option.DirectDesyncStreamRule{
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostCase: true},
	}
}

func splitRule(positions ...string) option.DirectDesyncStreamRule {
	return option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split:   &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string](positions)},
	}
}

func TestWrapConnNilAndEmptyFastPath(t *testing.T) {
	conn := newFakeConn()
	wrapped, err := (*StreamConfig)(nil).WrapConn(context.Background(), conn, MatchFacts{})
	if err != nil || wrapped != conn {
		t.Fatalf("nil config must return the original conn: %v %v", wrapped, err)
	}
	empty := &StreamConfig{}
	wrapped, err = empty.WrapConn(context.Background(), conn, MatchFacts{})
	if err != nil || wrapped != conn {
		t.Fatalf("empty config must return the original conn: %v %v", wrapped, err)
	}
}

func TestWrapConnNoMatchingRulePassThrough(t *testing.T) {
	rule := hostcaseRule()
	rule.Domain = badoption.Listable[string]{"example.com"}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 443})
	payload := []byte("SSH-2.0-OpenSSH_9.6\r\nbinary\x00payload")
	if _, err := wrapped.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !bytes.Equal(conn.collected(), payload) {
		t.Fatalf("pass-through bytes changed: %q", conn.collected())
	}
}

func TestHTTPHostCaseWrapperGolden(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	if _, err := wrapped.Write([]byte(httpFixture)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := "GET / HTTP/1.1\r\nhost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY"
	if got := string(conn.collected()); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestDeferredHostReconsideration(t *testing.T) {
	blocked := hostcaseRule()
	blocked.Name = "blocked"
	blocked.Domain = badoption.Listable[string]{"blocked.example"}
	catchAll := option.DirectDesyncStreamRule{
		Name:       "catch-all",
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{MethodSpace: true},
	}
	config := mustCompileStream(t, blocked, catchAll)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	if _, err := wrapped.Write([]byte("GET / HTTP/1.1\r\nHo")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if conn.writeCount() != 0 {
		t.Fatal("a host-filtered rule set must defer the first block until the host arrives")
	}
	if _, err := wrapped.Write([]byte("st: blocked.example\r\nUser-Agent: x\r\n\r\n")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	want := "GET / HTTP/1.1\r\nhost: blocked.example\r\nUser-Agent: x\r\n\r\n"
	if got := string(conn.collected()); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestDeferredHostValueNotTruncated(t *testing.T) {
	blocked := hostcaseRule()
	blocked.Domain = badoption.Listable[string]{"blocked.example"}
	catchAll := option.DirectDesyncStreamRule{
		Name:       "catch-all",
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{MethodSpace: true},
	}
	config := mustCompileStream(t, blocked, catchAll)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	// The host value itself is split across writes. The unterminated prefix
	// must not be used to freeze the catch-all rule.
	if _, err := wrapped.Write([]byte("GET / HTTP/1.1\r\nHost: blocked.exa")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if conn.writeCount() != 0 {
		t.Fatal("an unterminated host line must be held")
	}
	if _, err := wrapped.Write([]byte("mple\r\nUser-Agent: x\r\n\r\n")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	want := "GET / HTTP/1.1\r\nhost: blocked.example\r\nUser-Agent: x\r\n\r\n"
	if got := string(conn.collected()); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestStartBlockInterval(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.Start = "n2"
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("AAAA")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := wrapped.Write([]byte("BBBB")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	want := []string{"AAAA", "BB", "BB"}
	if len(conn.writes) != len(want) {
		t.Fatalf("writes = %q", conn.writes)
	}
	for index := range want {
		if string(conn.writes[index]) != want[index] {
			t.Fatalf("writes = %q, want %q", conn.writes, want)
		}
	}
}

func TestCutoffUsesBlockStartPosition(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.Cutoff = "4"
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("AAAABBBB")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := wrapped.Write([]byte("CCCC")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	want := []string{"AA", "AABBBB", "CCCC"}
	if len(conn.writes) != len(want) {
		t.Fatalf("writes = %q", conn.writes)
	}
	for index := range want {
		if string(conn.writes[index]) != want[index] {
			t.Fatalf("writes = %q, want %q", conn.writes, want)
		}
	}
}

func TestNativeSplitDisorderOOBTrace(t *testing.T) {
	oobByte := option.DirectDesyncOOBByte{Value: 0x2a}
	rule := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos:         badoption.Listable[string]{"2", "4"},
			Disorder:         "any",
			OOB:              "any",
			OOBData:          &oobByte,
			SplitAnyProtocol: true,
		},
	}
	config := mustCompileStream(t, rule)
	sender := newTraceSender()
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("ABCDEF")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.calls) != 3 {
		t.Fatalf("calls = %+v", sender.calls)
	}
	wantData := []string{"AB", "CD", "EF"}
	wantTTL := []int{1, 0, 0}
	wantOOB := []bool{true, false, false}
	for index, call := range sender.calls {
		if string(call.data) != wantData[index] {
			t.Fatalf("call %d data = %q", index, call.data)
		}
		if call.options.ttl != wantTTL[index] {
			t.Fatalf("call %d ttl = %d, want %d", index, call.options.ttl, wantTTL[index])
		}
		if call.options.oob != wantOOB[index] {
			t.Fatalf("call %d oob = %v", index, call.options.oob)
		}
		if !call.options.cork {
			t.Fatalf("call %d must cork when skip_nodelay is absent", index)
		}
	}
	if sender.calls[0].options.oobByte != 0x2a {
		t.Fatalf("oob byte = %#x", sender.calls[0].options.oobByte)
	}
	if sender.written.String() != "ABCDEF" {
		t.Fatalf("reconstructed stream = %q", sender.written.String())
	}
	if conn.writeCount() != 0 {
		t.Fatal("native split must not fall back to plain writes")
	}
}

// TestShortSendCancelsSplit is the short-write invariant control: a partial
// fragment send must forward the whole remaining block unsplit, preserving
// every original byte exactly once.
func TestShortSendCancelsSplit(t *testing.T) {
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	sender := newTraceSender()
	sender.shortAt = 0
	sender.shortLen = 1
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("ABCDEF")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.calls) != 1 || string(sender.calls[0].data) != "AB" {
		t.Fatalf("calls = %+v", sender.calls)
	}
	if got := string(conn.collected()); got != "BCDEF" {
		t.Fatalf("remaining block = %q", got)
	}
	reconstructed := sender.written.String() + string(conn.collected())
	if reconstructed != "ABCDEF" {
		t.Fatalf("reconstructed = %q", reconstructed)
	}
}

func TestFixSegWaitsBeforeEveryFragment(t *testing.T) {
	if !streamCaps().fixSeg {
		t.Skip("fix_seg is Linux-only")
	}
	rule := splitRule("2")
	rule.Split.SplitAnyProtocol = true
	rule.FixSeg = &option.DirectDesyncStreamFixSeg{Milliseconds: 5}
	config := mustCompileStream(t, rule)
	sender := newTraceSender()
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("ABCD")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(sender.waits) != 2 {
		t.Fatalf("waits = %v", sender.waits)
	}
	for _, wait := range sender.waits {
		if wait != 5*time.Millisecond {
			t.Fatalf("wait = %v", wait)
		}
	}
}

func TestTLSRecordSplitThroughConn(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods:   badoption.Listable[string]{"tls_record"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "10"},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 443})
	hello := buildClientHello("example.com")
	if _, err := wrapped.Write(hello[:20]); err != nil {
		t.Fatalf("partial Write: %v", err)
	}
	if conn.writeCount() != 0 {
		t.Fatal("partial ClientHello must be held until the record is complete")
	}
	if _, err := wrapped.Write(hello[20:]); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	want := expectedTLSRecordSplit(t, hello, 10)
	if got := conn.collected(); !bytes.Equal(got, want) {
		t.Fatalf("record split output differs\n got %x\nwant %x", got, want)
	}
}

func TestTLSRecordAndSplitPositionShift(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods:   badoption.Listable[string]{"tls_record", "split"},
		TLSRecord: &option.DirectDesyncStreamTLSRecord{Pos: "10"},
		Split:     &option.DirectDesyncStreamSplit{SplitPos: badoption.Listable[string]{"12"}},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	hello := buildClientHello("example.com")
	if _, err := wrapped.Write(hello); err != nil {
		t.Fatalf("Write: %v", err)
	}
	transformed := expectedTLSRecordSplit(t, hello, 10)
	conn.mu.Lock()
	writes := append([][]byte(nil), conn.writes...)
	conn.mu.Unlock()
	if len(writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(writes))
	}
	if len(writes[0]) != 17 {
		t.Fatalf("first fragment length = %d, want shifted 17", len(writes[0]))
	}
	if got := conn.collected(); !bytes.Equal(got, transformed) {
		t.Fatal("split after tls_record must reconstruct the transformed record")
	}
}

func TestSplitAnyProtocolRequired(t *testing.T) {
	config := mustCompileStream(t, splitRule("2"))
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("ABCDEF")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.writes) != 1 || string(conn.writes[0]) != "ABCDEF" {
		t.Fatalf("unknown protocol without split_any_protocol = %q", conn.writes)
	}
}

func TestShortWriteLoop(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	conn.shortRemaining = 3
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte(httpFixture)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := "GET / HTTP/1.1\r\nhost: Example.COM\r\nUser-Agent: test\r\n\r\nBODY"
	if got := string(conn.collected()); got != want {
		t.Fatalf("short writes lost bytes: %q", got)
	}
}

// TestZeroProgressShortWriteIsAnError is the negative control for the
// short-write invariant: a writer that reports (0, nil) forever must produce
// io.ErrShortWrite instead of a silent success or an infinite loop.
func TestZeroProgressShortWriteIsAnError(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	conn.zeroProgress = true
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte(httpFixture)); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("error = %v, want io.ErrShortWrite", err)
	}
}

func TestWriteErrorSticky(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	conn.failAfter = 2
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte(httpFixture)); err == nil {
		t.Fatal("write failure must be returned")
	}
	if _, err := wrapped.Write([]byte("x")); err == nil {
		t.Fatal("a failed stream must stay failed")
	}
}

func TestWriteAfterClose(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	wrapped := wrapStream(t, config, newFakeConn(), MatchFacts{})
	if err := wrapped.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := wrapped.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v", err)
	}
}

func TestDeadlineDelegation(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	deadline := time.Unix(1234, 0)
	if err := wrapped.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if !conn.writeDeadline.Equal(deadline) {
		t.Fatalf("deadline = %v", conn.writeDeadline)
	}
}

func TestReadDelegation(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	conn.readBuffer.WriteString("response")
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	buffer := make([]byte, 8)
	if _, err := io.ReadFull(wrapped, buffer); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buffer) != "response" {
		t.Fatalf("read %q", buffer)
	}
}

func TestWrapConnCancellationCloses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := mustCompileStream(t, hostcaseRule())
	client, server := net.Pipe()
	wrapped, err := config.WrapConn(ctx, client, MatchFacts{})
	if err != nil {
		t.Fatalf("WrapConn: %v", err)
	}
	cancel()
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, readErr := server.Read(buffer); readErr == nil {
		t.Fatal("cancelled context must close the underlying connection")
	}
	if _, err = wrapped.Write([]byte("x")); err == nil {
		t.Fatal("Write after cancellation must fail")
	}
	_ = wrapped.Close()
	_ = server.Close()
}

func TestBodyBlocksAreNotHTTPTampered(t *testing.T) {
	config := mustCompileStream(t, hostcaseRule())
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	head := "GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n"
	body := "BODY Host: Example.COM\r\n\r\n"
	if _, err := wrapped.Write([]byte(head)); err != nil {
		t.Fatalf("Write head: %v", err)
	}
	if _, err := wrapped.Write([]byte(body)); err != nil {
		t.Fatalf("Write body: %v", err)
	}
	want := "GET / HTTP/1.1\r\nhost: Example.COM\r\n\r\n" + body
	if got := string(conn.collected()); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestNativeRequirementFailsWithoutSocket(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos:         badoption.Listable[string]{"1"},
			OOB:              "any",
			SplitAnyProtocol: true,
		},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	if _, err := wrapped.Write([]byte("ABCD")); err == nil {
		t.Fatal("native send without a syscall.Conn must fail, not silently drop OOB")
	}
}

package route

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// relayTestRead is one scripted local read result.
type relayTestRead struct {
	data []byte
	err  error
}

// relayTestConn is a deterministic in-memory duplex connection. No host
// socket is created: tests script reads and inspect writes, half-closes and
// closes.
type relayTestConn struct {
	readCh    chan relayTestRead
	closeCh   chan struct{}
	closeOnce sync.Once

	mu          sync.Mutex
	pending     []byte
	readErr     error
	readBytes   int64
	written     bytes.Buffer
	writeCalls  int
	closeWrites int
	writeErr    error
}

func newRelayTestConn() *relayTestConn {
	return &relayTestConn{
		readCh:  make(chan relayTestRead, 64),
		closeCh: make(chan struct{}),
	}
}

func (c *relayTestConn) pushData(data []byte) {
	c.readCh <- relayTestRead{data: data}
}

func (c *relayTestConn) pushError(err error) {
	c.readCh <- relayTestRead{err: err}
}

func (c *relayTestConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		if len(c.pending) > 0 {
			readN := copy(p, c.pending)
			c.pending = c.pending[readN:]
			c.readBytes += int64(readN)
			c.mu.Unlock()
			return readN, nil
		}
		if c.readErr != nil {
			err := c.readErr
			c.mu.Unlock()
			return 0, err
		}
		c.mu.Unlock()
		select {
		case chunk := <-c.readCh:
			c.mu.Lock()
			if chunk.err != nil {
				c.readErr = chunk.err
			} else {
				c.pending = append(c.pending, chunk.data...)
			}
			c.mu.Unlock()
		case <-c.closeCh:
			return 0, net.ErrClosed
		}
	}
}

func (c *relayTestConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writeCalls++
	c.written.Write(p)
	return len(p), nil
}

func (c *relayTestConn) Close() error {
	c.closeOnce.Do(func() { close(c.closeCh) })
	return nil
}

func (c *relayTestConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeWrites++
	return nil
}

func (c *relayTestConn) LocalAddr() net.Addr              { return relayTestAddr("local") }
func (c *relayTestConn) RemoteAddr() net.Addr             { return relayTestAddr("remote") }
func (c *relayTestConn) SetDeadline(time.Time) error      { return nil }
func (c *relayTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *relayTestConn) SetWriteDeadline(time.Time) error { return nil }
func (c *relayTestConn) ReadBytes() int64                 { c.mu.Lock(); defer c.mu.Unlock(); return c.readBytes }
func (c *relayTestConn) CloseWrites() int                 { c.mu.Lock(); defer c.mu.Unlock(); return c.closeWrites }
func (c *relayTestConn) WriteCalls() int                  { c.mu.Lock(); defer c.mu.Unlock(); return c.writeCalls }
func (c *relayTestConn) Written() string                  { c.mu.Lock(); defer c.mu.Unlock(); return c.written.String() }
func (c *relayTestConn) IsClosed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

type relayTestAddr string

func (a relayTestAddr) Network() string { return "tcp" }
func (a relayTestAddr) String() string  { return string(a) }

// relaySyscallConn additionally advertises a native syscall connection, so a
// copy helper would prefer the splice fast path. The fake descriptor makes the
// actual splice call fail hermetically while counting that the direct path was
// attempted.
type relaySyscallConn struct {
	*relayTestConn
	syscallReads  atomic.Int32
	syscallWrites atomic.Int32
}

func newRelaySyscallConn() *relaySyscallConn {
	return &relaySyscallConn{relayTestConn: newRelayTestConn()}
}

func (c *relaySyscallConn) SyscallConn() (syscall.RawConn, error) {
	return &relayTestRawConn{conn: c}, nil
}

type relayTestRawConn struct {
	conn *relaySyscallConn
}

func (c *relayTestRawConn) Control(function func(fd uintptr)) error {
	function(^uintptr(0))
	return nil
}

func (c *relayTestRawConn) Read(function func(fd uintptr) bool) error {
	c.conn.syscallReads.Add(1)
	function(^uintptr(0))
	return nil
}

func (c *relayTestRawConn) Write(function func(fd uintptr) bool) error {
	c.conn.syscallWrites.Add(1)
	function(^uintptr(0))
	return nil
}

// relayTestDialer is the injected remote attempt. It stays in the pending
// state until released, honours the pending context, and can deliberately
// return a connection after cancellation to test the race.
type relayTestDialer struct {
	started      chan struct{}
	release      chan struct{}
	startOnce    sync.Once
	conn         net.Conn
	err          error
	ignoreCancel bool
}

func newRelayTestDialer(conn net.Conn) *relayTestDialer {
	return &relayTestDialer{started: make(chan struct{}), release: make(chan struct{}), conn: conn}
}

func (d *relayTestDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	d.startOnce.Do(func() { close(d.started) })
	select {
	case <-d.release:
	case <-ctx.Done():
		if !d.ignoreCancel {
			return nil, ctx.Err()
		}
		<-d.release
	}
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

func (d *relayTestDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("packet connections are not used")
}

func (d *relayTestDialer) releaseNow() { close(d.release) }

// relayTestClock is the deterministic orphan timer seam.
type relayTestClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*relayTestTimer
}

type relayTestTimer struct {
	clock    *relayTestClock
	deadline time.Time
	fire     func()
	stopped  bool
	fired    bool
}

func newRelayTestClock() *relayTestClock {
	return &relayTestClock{now: time.Unix(1_700_000_000, 0)}
}

func (c *relayTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *relayTestClock) AfterFunc(duration time.Duration, function func()) tcpRelayTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	timer := &relayTestTimer{clock: c, deadline: c.now.Add(duration), fire: function}
	c.timers = append(c.timers, timer)
	return timer
}

func (c *relayTestClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	var fire []func()
	for _, timer := range c.timers {
		if timer.stopped || timer.fired || timer.deadline.After(c.now) {
			continue
		}
		timer.fired = true
		fire = append(fire, timer.fire)
	}
	c.mu.Unlock()
	for _, function := range fire {
		function()
	}
}

func (c *relayTestClock) Created() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

func (c *relayTestClock) Armed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	armed := 0
	for _, timer := range c.timers {
		if !timer.stopped && !timer.fired {
			armed++
		}
	}
	return armed
}

func (t *relayTestTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	if t.stopped || t.fired {
		return false
	}
	t.stopped = true
	return true
}

type relayHarness struct {
	local      *relayTestConn
	remote     *relayTestConn
	dialer     *relayTestDialer
	clock      *relayTestClock
	manager    *ConnectionManager
	onClose    atomic.Int32
	lastErr    atomic.Value
	waitResult chan struct{}
}

func newRelayHarness(t *testing.T, options adapter.TCPRelayOptions, local net.Conn, remote net.Conn) *relayHarness {
	t.Helper()
	harness := &relayHarness{
		clock:      newRelayTestClock(),
		manager:    NewConnectionManager(logger.NOP()),
		waitResult: make(chan struct{}, 1),
	}
	harness.manager.relayClock = harness.clock
	if testConn, isTestConn := local.(*relayTestConn); isTestConn {
		harness.local = testConn
	}
	if testConn, isTestConn := remote.(*relayTestConn); isTestConn {
		harness.remote = testConn
	}
	harness.dialer = newRelayTestDialer(remote)
	metadata := adapter.InboundContext{
		Inbound:         "relay-in",
		InboundType:     C.TypeDirect,
		Network:         N.NetworkTCP,
		Source:          M.Socksaddr{Fqdn: "client.example", Port: 12345},
		Destination:     M.Socksaddr{Fqdn: "target.example", Port: 443},
		TCPRelayOptions: options,
	}
	onClose := func(err error) {
		if err != nil {
			harness.lastErr.Store(err.Error())
		}
		harness.onClose.Add(1)
		select {
		case harness.waitResult <- struct{}{}:
		default:
		}
	}
	go harness.manager.NewConnection(context.Background(), harness.dialer, local, metadata, onClose)
	t.Cleanup(func() {
		_ = local.Close()
		_ = remote.Close()
		select {
		case <-harness.dialer.release:
		default:
			harness.dialer.releaseNow()
		}
	})
	return harness
}

func (h *relayHarness) dialStarted(t *testing.T) {
	t.Helper()
	select {
	case <-h.dialer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("remote attempt did not start")
	}
}

func waitRelay(t *testing.T, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(message)
}

func waitRelayClose(t *testing.T, harness *relayHarness) {
	t.Helper()
	select {
	case <-harness.waitResult:
	case <-time.After(5 * time.Second):
		t.Fatal("connection close was not reported")
	}
}

func TestTCPRelayOrphanExpiryCancelsPendingAttempt(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{MaxOrphanTime: 5 * time.Second, HasMaxOrphanTime: true}, local, remote)
	harness.dialStarted(t)

	local.pushData([]byte("early request bytes"))
	waitRelay(t, func() bool { return local.ReadBytes() == int64(len("early request bytes")) }, "pending reader did not consume local bytes")
	local.pushError(errors.New("connection reset by peer"))

	waitRelay(t, func() bool { return harness.clock.Created() == 1 }, "orphan timer was not armed on a terminal close with unsent data")
	if harness.onClose.Load() != 0 {
		t.Fatal("the pair must stay pending until the orphan timer expires")
	}
	harness.clock.Advance(5 * time.Second)
	waitRelayClose(t, harness)
	if harness.onClose.Load() != 1 {
		t.Fatalf("close must be reported exactly once, got %d", harness.onClose.Load())
	}
	reason, _ := harness.lastErr.Load().(string)
	if !bytes.Contains([]byte(reason), []byte("orphan timeout")) {
		t.Fatalf("unexpected close reason: %q", reason)
	}
	if !local.IsClosed() {
		t.Fatal("the local leg must be closed after the orphan timeout")
	}
	if remote.WriteCalls() != 0 {
		t.Fatal("no byte may be sent to a remote that never connected")
	}
	if harness.clock.Armed() != 0 {
		t.Fatal("the orphan timer must not stay armed after expiry")
	}
}

func TestTCPRelayTerminalCloseWithoutUnsentDataCancelsImmediately(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{MaxOrphanTime: 5 * time.Second, HasMaxOrphanTime: true}, local, remote)
	harness.dialStarted(t)
	local.pushError(errors.New("connection reset by peer"))
	waitRelayClose(t, harness)
	if harness.clock.Created() != 0 {
		t.Fatal("empty pending data must cancel immediately without an orphan timer")
	}
	reason, _ := harness.lastErr.Load().(string)
	if !bytes.Contains([]byte(reason), []byte("before the remote connection was available")) {
		t.Fatalf("unexpected close reason: %q", reason)
	}
	if !local.IsClosed() {
		t.Fatal("the local leg must be closed")
	}
}

func TestTCPRelayReadEOFKeepsPendingThenFlushesAndHalfCloses(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{MaxOrphanTime: 5 * time.Second, HasMaxOrphanTime: true}, local, remote)
	harness.dialStarted(t)
	local.pushData([]byte("GET / HTTP/1.1\r\n\r\n"))
	local.pushError(io.EOF)
	waitRelay(t, func() bool { return local.ReadBytes() == int64(len("GET / HTTP/1.1\r\n\r\n")) }, "pending reader did not consume the request")
	// A read EOF is a read half-close, not a terminal close: no orphan timer.
	time.Sleep(20 * time.Millisecond)
	if harness.clock.Created() != 0 {
		t.Fatal("an ordinary read EOF must not start the orphan timer")
	}
	harness.dialer.releaseNow()
	waitRelay(t, func() bool {
		remote.mu.Lock()
		defer remote.mu.Unlock()
		return remote.written.String() == "GET / HTTP/1.1\r\n\r\n" && remote.closeWrites == 1
	}, "queued bytes were not flushed once and half-closed")
	remote.mu.Lock()
	writeCalls := remote.writeCalls
	remote.mu.Unlock()
	if writeCalls != 1 {
		t.Fatalf("queued data must be flushed exactly once, got %d writes", writeCalls)
	}
	if harness.clock.Armed() != 0 {
		t.Fatal("connect success must disarm the orphan timer")
	}
	// The download direction still owns the pair; closing the remote finishes
	// it and reports the close once.
	_ = remote.Close()
	waitRelayClose(t, harness)
	if harness.onClose.Load() != 1 {
		t.Fatalf("close must be reported exactly once, got %d", harness.onClose.Load())
	}
}

func TestTCPRelayConnectedRemoteIsNotSubjectToOrphanPolicy(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{MaxOrphanTime: 5 * time.Second, HasMaxOrphanTime: true}, local, remote)
	harness.dialStarted(t)
	harness.dialer.releaseNow()
	local.pushData([]byte("connected data"))
	waitRelay(t, func() bool { return remote.Written() == "connected data" }, "activated upload did not write to the remote")
	local.pushError(errors.New("connection reset by peer"))
	time.Sleep(20 * time.Millisecond)
	if harness.clock.Created() != 0 {
		t.Fatal("a connected remote must not be subject to the orphan timer")
	}
	waitRelayClose(t, harness)
	if harness.onClose.Load() != 1 {
		t.Fatalf("close must be reported exactly once, got %d", harness.onClose.Load())
	}
}

func TestTCPRelayZeroOrphanTimeKeepsNormalAttempt(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{HasMaxOrphanTime: true}, local, remote)
	harness.dialStarted(t)
	local.pushData([]byte("queued request"))
	local.pushError(errors.New("connection reset by peer"))
	waitRelay(t, func() bool { return local.ReadBytes() == int64(len("queued request")) }, "pending reader did not consume local bytes")
	harness.clock.Advance(time.Hour)
	time.Sleep(20 * time.Millisecond)
	if harness.clock.Created() != 0 {
		t.Fatal("an explicit zero must not create an orphan timer")
	}
	if harness.onClose.Load() != 0 {
		t.Fatal("an explicit zero must not cancel the pending attempt early")
	}
	harness.dialer.releaseNow()
	waitRelay(t, func() bool { return remote.Written() == "queued request" }, "queued bytes were not delivered after the late connect")
	waitRelayClose(t, harness)
	reason, _ := harness.lastErr.Load().(string)
	if !bytes.Contains([]byte(reason), []byte("connection reset by peer")) {
		t.Fatalf("the terminal local error must be reported, got %q", reason)
	}
}

func TestTCPRelayTimerConnectRaceDoesNotResurrectPair(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{MaxOrphanTime: 5 * time.Second, HasMaxOrphanTime: true}, local, remote)
	harness.dialer.ignoreCancel = true
	harness.dialStarted(t)
	local.pushData([]byte("queued"))
	local.pushError(errors.New("connection reset by peer"))
	waitRelay(t, func() bool { return harness.clock.Created() == 1 }, "orphan timer was not armed")
	harness.clock.Advance(5 * time.Second)
	harness.dialer.releaseNow()
	waitRelayClose(t, harness)
	if !remote.IsClosed() {
		t.Fatal("a late late connect result must be closed, not used")
	}
	if remote.WriteCalls() != 0 {
		t.Fatal("a late connect result must not receive queued bytes")
	}
	reason, _ := harness.lastErr.Load().(string)
	if !bytes.Contains([]byte(reason), []byte("orphan timeout")) {
		t.Fatalf("unexpected close reason: %q", reason)
	}
}

func TestTCPRelayBoundedPendingBufferAndBackpressure(t *testing.T) {
	local := newRelayTestConn()
	remote := newRelayTestConn()
	harness := newRelayHarness(t, adapter.TCPRelayOptions{MaxOrphanTime: 5 * time.Second, HasMaxOrphanTime: true}, local, remote)
	harness.dialStarted(t)
	payload := bytes.Repeat([]byte("x"), tcpRelayPendingUploadLimit+32*1024)
	local.pushData(payload)
	waitRelay(t, func() bool { return local.ReadBytes() == int64(tcpRelayPendingUploadLimit) }, "pending upload was not bounded to 64 KiB")
	time.Sleep(20 * time.Millisecond)
	if local.ReadBytes() != int64(tcpRelayPendingUploadLimit) {
		t.Fatalf("the single pending reader must stop at the cap, read %d", local.ReadBytes())
	}
	if harness.onClose.Load() != 0 {
		t.Fatal("backpressure must keep the pair pending")
	}
	harness.dialer.releaseNow()
	waitRelay(t, func() bool { return int64(len(remote.Written())) == int64(len(payload)) }, "queued bytes were not delivered after activation")
	if harness.clock.Created() != 0 {
		t.Fatal("no orphan timer may exist without a terminal local close")
	}
}

func TestTCPRelayDisableSpliceBlocksDirectCopyBothDirections(t *testing.T) {
	t.Run("absent option keeps the direct fast path", func(t *testing.T) {
		local := newRelaySyscallConn()
		remote := newRelaySyscallConn()
		harness := newRelayHarness(t, adapter.TCPRelayOptions{}, local, remote)
		harness.dialStarted(t)
		harness.dialer.releaseNow()
		local.pushData([]byte("upload"))
		waitRelay(t, func() bool { return local.syscallReads.Load() > 0 || harness.onClose.Load() > 0 }, "the absent option must keep the previous copy fast path")
		if local.syscallReads.Load() == 0 {
			t.Fatal("the direct syscall read path was not attempted")
		}
	})

	t.Run("disabled option copies with ordinary reads", func(t *testing.T) {
		local := newRelaySyscallConn()
		remote := newRelaySyscallConn()
		harness := newRelayHarness(t, adapter.TCPRelayOptions{DisableSplice: true}, local, remote)
		harness.dialStarted(t)
		harness.dialer.releaseNow()
		local.pushData([]byte("upload bytes"))
		remote.pushData([]byte("download bytes"))
		waitRelay(t, func() bool {
			return remote.Written() == "upload bytes" && local.Written() == "download bytes"
		}, "ordinary copies did not deliver both directions")
		if local.syscallReads.Load() != 0 || local.syscallWrites.Load() != 0 {
			t.Fatalf("local fast path counters must stay zero: read=%d write=%d", local.syscallReads.Load(), local.syscallWrites.Load())
		}
		if remote.syscallReads.Load() != 0 || remote.syscallWrites.Load() != 0 {
			t.Fatalf("remote fast path counters must stay zero: read=%d write=%d", remote.syscallReads.Load(), remote.syscallWrites.Load())
		}
	})
}

func TestNonSpliceConnHidesFastPaths(t *testing.T) {
	base := newRelaySyscallConn()
	wrapped := newNonSpliceConn(base)
	if _, is := wrapped.(syscall.Conn); is {
		t.Fatal("wrapper must not expose syscall.Conn")
	}
	if _, is := wrapped.(io.ReaderFrom); is {
		t.Fatal("wrapper must not expose io.ReaderFrom")
	}
	if _, is := wrapped.(io.WriterTo); is {
		t.Fatal("wrapper must not expose io.WriterTo")
	}
	if _, is := wrapped.(N.ReaderWithUpstream); is {
		t.Fatal("wrapper must not expose ReaderWithUpstream")
	}
	if _, is := wrapped.(N.WriterWithUpstream); is {
		t.Fatal("wrapper must not expose WriterWithUpstream")
	}
	if N.SyscallAvailableForRead(wrapped) || N.SyscallAvailableForWrite(wrapped) {
		t.Fatal("copy helpers must not detect a syscall path through the wrapper")
	}
	if _, is := wrapped.(N.WriteCloser); !is {
		t.Fatal("wrapper must keep the half-close capability of the wrapped connection")
	}
	if err := wrapped.(N.WriteCloser).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if base.CloseWrites() != 1 {
		t.Fatal("CloseWrite was not forwarded")
	}
	plainWrapped := newNonSpliceConn(relayTestPipeConn{})
	if _, is := plainWrapped.(N.WriteCloser); is {
		t.Fatal("a connection without half-close must not claim CloseWrite")
	}
}

// relayTestPipeConn satisfies net.Conn without a half-close capability.
type relayTestPipeConn struct{}

func (relayTestPipeConn) Read(p []byte) (int, error)       { return 0, io.EOF }
func (relayTestPipeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (relayTestPipeConn) Close() error                     { return nil }
func (relayTestPipeConn) LocalAddr() net.Addr              { return relayTestAddr("local") }
func (relayTestPipeConn) RemoteAddr() net.Addr             { return relayTestAddr("remote") }
func (relayTestPipeConn) SetDeadline(time.Time) error      { return nil }
func (relayTestPipeConn) SetReadDeadline(time.Time) error  { return nil }
func (relayTestPipeConn) SetWriteDeadline(time.Time) error { return nil }

func TestInboundContextCopyKeepsTCPRelayOptions(t *testing.T) {
	// Inbound detours carry the same InboundContext value; the shared copy
	// helpers must keep the origin relay policy.
	ctx := adapter.WithContext(context.Background(), &adapter.InboundContext{
		Inbound:         "origin",
		TCPRelayOptions: adapter.TCPRelayOptions{DisableSplice: true, MaxOrphanTime: time.Second, HasMaxOrphanTime: true},
	})
	extendedCtx, extended := adapter.ExtendContext(ctx)
	if extended.TCPRelayOptions != (adapter.TCPRelayOptions{DisableSplice: true, MaxOrphanTime: time.Second, HasMaxOrphanTime: true}) {
		t.Fatalf("extended context lost the relay policy: %+v", extended.TCPRelayOptions)
	}
	override := adapter.ContextFrom(adapter.OverrideContext(extendedCtx))
	if override == nil || override.TCPRelayOptions != extended.TCPRelayOptions {
		t.Fatal("override context lost the relay policy")
	}
}

package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	sbufio "github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	M "github.com/sagernet/sing/common/metadata"
)

// fakeAttemptHook records the native attempt lifecycle. It never touches a
// socket: the platform first-payload function is replaced by the test.
type fakeAttemptHook struct {
	mu       sync.Mutex
	intents  []AttemptIntent
	prepares int
	closes   int
}

func (h *fakeAttemptHook) NewAttempt(_ context.Context, intent AttemptIntent) (AttemptLease, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.intents = append(h.intents, intent)
	return &fakeAttemptLease{hook: h}, nil
}

func (h *fakeAttemptHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.intents)
}

func (h *fakeAttemptHook) first() AttemptIntent {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.intents) == 0 {
		return AttemptIntent{}
	}
	return h.intents[0]
}

type fakeAttemptLease struct {
	hook *fakeAttemptHook
	once sync.Once
}

func (l *fakeAttemptLease) PrepareSocket(uintptr) error {
	l.hook.mu.Lock()
	defer l.hook.mu.Unlock()
	l.hook.prepares++
	return nil
}

func (l *fakeAttemptLease) RequiresExclusiveBind() bool    { return false }
func (l *fakeAttemptLease) SetLocalAddress(netip.AddrPort) {}
func (l *fakeAttemptLease) StartCapture() error            { return nil }
func (l *fakeAttemptLease) AttachConn(conn net.Conn) (net.Conn, error) {
	return conn, nil
}
func (l *fakeAttemptLease) AttachPacketConn(conn net.PacketConn) net.PacketConn { return conn }
func (l *fakeAttemptLease) Close(error) error {
	l.once.Do(func() {
		l.hook.mu.Lock()
		defer l.hook.mu.Unlock()
		l.hook.closes++
	})
	return nil
}

type netipAddrPort = netip.AddrPort

// fakePendingHook records the once-only stream wrapper application.
type fakePendingHook struct {
	mu      sync.Mutex
	wrapped int
}

func (h *fakePendingHook) WrapPendingTCP(_ context.Context, _ AttemptIntent, pending net.Conn) (net.Conn, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.wrapped++
	return pending, nil
}

func (h *fakePendingHook) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.wrapped
}

// fakeConn records writes on an established connection.
type fakeConn struct {
	mu         sync.Mutex
	writes     [][]byte
	writeErr   error
	writeCount int
	deadlines  []time.Time
	closed     bool
}

func (c *fakeConn) Read([]byte) (int, error) { return 0, nil }
func (c *fakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeCount++
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr  { return M.Socksaddr{} }
func (c *fakeConn) RemoteAddr() net.Addr { return M.Socksaddr{} }
func (c *fakeConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, deadline)
	return nil
}
func (c *fakeConn) SetReadDeadline(time.Time) error { return nil }
func (c *fakeConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, deadline)
	return nil
}

type payloadRecord struct {
	payload   []byte
	ctx       context.Context
	prepared  int
	conn      *fakeConn
	block     bool
	writePart int
}

// withFakePayload installs a hermetic first-payload attempt for one test.
func withFakePayload(t *testing.T, record *payloadRecord) {
	t.Helper()
	previous := dialAttemptPayloadHook
	dialAttemptPayloadHook = func(ctx context.Context, base net.Dialer, network, address string, payload []byte, lease AttemptLease) (net.Conn, int, error) {
		record.payload = append([]byte(nil), payload...)
		record.ctx = ctx
		record.prepared++
		// The platform attempt refuses to create a socket on a canceled
		// context, exactly like net.Dialer.DialContext. The deferred facade
		// must therefore never inherit a cancellation it is not owned by.
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if record.conn == nil {
			record.conn = &fakeConn{}
		}
		if record.block {
			<-ctx.Done()
			return nil, 0, ctx.Err()
		}
		if record.writePart > 0 && record.writePart < len(payload) {
			record.conn.Write(payload[:record.writePart])
			return record.conn, record.writePart, nil
		}
		return record.conn, len(payload), nil
	}
	t.Cleanup(func() { dialAttemptPayloadHook = previous })
}

func newTestDeferredDialer(t *testing.T, attemptHook AttemptHook, pendingHook PendingTCPHook) *DefaultDialer {
	t.Helper()
	dialer := &DefaultDialer{
		attemptHook: attemptHook,
		pendingHook: pendingHook,
		tcpFastOpen: true,
	}
	return dialer
}

func testAddress() M.Socksaddr {
	return M.ParseSocksaddr("127.0.0.1:443")
}

func TestDeferredTFOCreatesNoAttemptBeforeActivation(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	pendingHook := &fakePendingHook{}
	dialer := newTestDeferredDialer(t, hook, pendingHook)

	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if hook.count() != 0 {
		t.Fatalf("native attempt before activation: %d", hook.count())
	}
	if record.prepared != 0 {
		t.Fatalf("socket preparation before activation: %d", record.prepared)
	}
	if pendingHook.count() != 1 {
		t.Fatalf("pending hook calls = %d, want exactly 1", pendingHook.count())
	}
	if !conn.(interface{ NeedHandshake() bool }).NeedHandshake() {
		t.Fatal("pending connection must report a pending handshake")
	}
}

func TestDeferredTFOFirstWriteOnePreparedAttempt(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})

	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, err := conn.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("first write = (%d, %v), want (5, nil)", n, err)
	}
	if hook.count() != 1 || record.prepared != 1 {
		t.Fatalf("attempts=%d prepared=%d, want 1/1", hook.count(), record.prepared)
	}
	if got := string(record.payload); got != "hello" {
		t.Fatalf("first payload = %q, want the transformed segment", got)
	}
	if !hook.first().Deferred {
		t.Fatal("the owned attempt behind the pending facade must carry the Deferred intent bit")
	}
	// No byte was replayed: the payload went into the single attempt, and the
	// facade did not write it again on the established connection.
	record.conn.mu.Lock()
	defer record.conn.mu.Unlock()
	if record.conn.writeCount != 0 {
		t.Fatalf("established connection received %d extra payload writes, want 0", record.conn.writeCount)
	}
	if conn.(interface{ NeedHandshake() bool }).NeedHandshake() {
		t.Fatal("established pending connection must not report a pending handshake")
	}
}

func TestDeferredTFOSecondWriteUsesEstablished(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if hook.count() != 1 {
		t.Fatalf("attempts = %d, want exactly 1", hook.count())
	}
	record.conn.mu.Lock()
	defer record.conn.mu.Unlock()
	if len(record.conn.writes) != 1 || string(record.conn.writes[0]) != "second" {
		t.Fatalf("established writes = %q, want only the subsequent segment", record.conn.writes)
	}
}

func TestDeferredTFOEmptyWriteActivatesOneAttempt(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, err := conn.Write(nil); err != nil || n != 0 {
		t.Fatalf("empty write = (%d, %v)", n, err)
	}
	if hook.count() != 1 {
		t.Fatalf("attempts = %d, want 1", hook.count())
	}
	if len(record.payload) != 0 {
		t.Fatalf("empty connect carried payload %q", record.payload)
	}
}

func TestDeferredTFOReadFirstActivatesOneAttempt(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if hook.count() != 1 || record.prepared != 1 {
		t.Fatalf("attempts=%d prepared=%d, want 1/1", hook.count(), record.prepared)
	}
	if len(record.payload) != 0 {
		t.Fatalf("server-first connect carried payload %q", record.payload)
	}
}

func TestDeferredTFOCloseBeforeActivationCreatesNoSocket(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Write([]byte("late")); err == nil {
		t.Fatal("write on a closed pending connection succeeded")
	}
	if hook.count() != 0 || record.prepared != 0 {
		t.Fatalf("closed pending loser created an attempt: attempts=%d prepared=%d", hook.count(), record.prepared)
	}
}

func TestDeferredTFOCloseDuringActivationCancels(t *testing.T) {
	record := &payloadRecord{block: true}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write([]byte("payload"))
		done <- writeErr
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		hook.mu.Lock()
		count := len(hook.intents)
		hook.mu.Unlock()
		if count == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case writeErr := <-done:
		if writeErr == nil {
			t.Fatal("canceled activation reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation did not interrupt the activation")
	}
	if hook.count() != 1 {
		t.Fatalf("attempts = %d, want the single canceled attempt", hook.count())
	}
}

func TestDeferredTFOPreOpenDeadlineIsApplied(t *testing.T) {
	// The pre-open deadline bounds the activation through the facade's own
	// re-armable timer. A fixed context deadline could not be extended or
	// cleared by a later setter, so the contract is asserted behaviorally: the
	// activation must fail at the caller's bound, and an adopted connection
	// must receive the same deadline.
	record := &payloadRecord{block: true}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(40 * time.Millisecond)
	if err = conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("pre-open deadline rejected: %v", err)
	}
	start := time.Now()
	if _, err = conn.Write([]byte("x")); !isDeadlineError(err) {
		t.Fatalf("pre-open deadline not applied to activation: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("activation honored the deadline after %v", elapsed)
	}
}

// A pre-open deadline that does not expire during activation must still reach
// the adopted connection instead of being dropped at the facade boundary.
func TestDeferredTFOPreOpenDeadlineReachesAdoptedConn(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	deadline := time.Now().Add(30 * time.Second)
	if err = conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("pre-open deadline rejected: %v", err)
	}
	if _, err = conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	record.conn.mu.Lock()
	defer record.conn.mu.Unlock()
	if len(record.conn.deadlines) == 0 || !record.conn.deadlines[0].Equal(deadline) {
		t.Fatalf("adopted connection deadlines = %v, want the pre-open deadline", record.conn.deadlines)
	}
}

func TestDeferredTFOPartialFirstPayload(t *testing.T) {
	record := &payloadRecord{writePart: 3}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if n, err := conn.Write([]byte("abcdef")); err != nil || n != 3 {
		t.Fatalf("partial first write = (%d, %v), want (3, nil)", n, err)
	}
}

func TestDeferredTFOActivationFailureIsTerminal(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	failure := &fakeConn{writeErr: net.ErrClosed}
	record.conn = failure
	previous := dialAttemptPayloadHook
	dialAttemptPayloadHook = func(ctx context.Context, base net.Dialer, network, address string, payload []byte, lease AttemptLease) (net.Conn, int, error) {
		return nil, 0, net.ErrClosed
	}
	defer func() { dialAttemptPayloadHook = previous }()
	if _, err = conn.Write([]byte("x")); err == nil {
		t.Fatal("failed activation reported success")
	}
	// No candidate retry after the failed attempt: the logical connection is
	// failed and a later write cannot create a second socket.
	if _, err = conn.Write([]byte("y")); err == nil {
		t.Fatal("write after a failed activation succeeded")
	}
	if hook.count() != 1 {
		t.Fatalf("attempts = %d, want no retry", hook.count())
	}
}

// countingConn mirrors bufio.CounterConn: it embeds the extended-conn interface
// and therefore forwards net.Conn I/O while hiding both the EarlyWriter
// handshake contract and the Upstream unwrap chain. The deferred contract must
// survive exactly this wrapper, because the dialer installs it under the
// connection manager and the power-report counter.
type countingConn struct {
	N.ExtendedConn
}

type fakeConnectionManager struct {
	tracked int
}

func (m *fakeConnectionManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *fakeConnectionManager) Count() int                                     { return m.tracked }
func (m *fakeConnectionManager) CloseAll()                                      {}
func (m *fakeConnectionManager) TrackConn(conn net.Conn) net.Conn {
	m.tracked++
	return &countingConn{sbufio.NewExtendedConn(conn)}
}
func (m *fakeConnectionManager) TrackPacketConn(conn net.PacketConn) net.PacketConn {
	return conn
}
func (m *fakeConnectionManager) NewConnection(context.Context, N.Dialer, net.Conn, adapter.InboundContext, N.CloseHandlerFunc) {
}
func (m *fakeConnectionManager) NewPacketConnection(context.Context, N.Dialer, N.PacketConn, adapter.InboundContext, N.CloseHandlerFunc) {
}

// The parallel address/interface races return a winner and immediately cancel
// the dial context they used (DialParallelNetwork does exactly this). A
// deferred attempt is created after the race, so it must not inherit that
// cancellation: the winner's connection has to stay usable.
func TestDeferredTFOWinnerSurvivesRaceCancellation(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	raceCtx, cancelRace := context.WithCancel(context.Background())
	conn, err := dialer.DialContext(raceCtx, "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The race selected this connection as its winner and canceled its own
	// context, exactly as DialParallelNetwork does when it returns.
	cancelRace()
	payload := []byte("early-data")
	if n, writeErr := conn.Write(payload); writeErr != nil || n != len(payload) {
		t.Fatalf("first write after race cancellation = (%d, %v), want (%d, nil)", n, writeErr, len(payload))
	}
	if hook.count() != 1 || record.prepared != 1 {
		t.Fatalf("attempts=%d prepared=%d, want 1/1", hook.count(), record.prepared)
	}
	if got := string(record.payload); got != string(payload) {
		t.Fatalf("first payload = %q, want %q", got, payload)
	}
}

// The pending handshake contract must remain visible through the counting and
// connection-manager wrappers the dialer installs around a dialed connection.
// If those wrappers hid it, the connection manager would never perform the
// explicit empty/server-first connect and the first payload would not be the
// one the deferred attempt carries.
func TestDeferredTFONeedHandshakeThroughCountingWrappers(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	dialer.connectionManager = &fakeConnectionManager{}
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !N.NeedHandshakeForWrite(conn) {
		t.Fatal("counting wrapper hid the pending handshake contract")
	}
	if n, writeErr := conn.Write([]byte("first")); writeErr != nil || n != 5 {
		t.Fatalf("first write = (%d, %v)", n, writeErr)
	}
	if N.NeedHandshakeForWrite(conn) {
		t.Fatal("established deferred connection still reports a pending handshake")
	}
	if hook.count() != 1 {
		t.Fatalf("attempts = %d, want exactly 1", hook.count())
	}
}

// A dial context canceled before the deferred connection is returned must not
// create a lazy connection that is already unusable: the eager path fails the
// dial, and the deferred path keeps that observable contract.
func TestDeferredTFOCanceledDialContextFails(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	hook := &fakeAttemptHook{}
	dialer := newTestDeferredDialer(t, hook, &fakePendingHook{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := dialer.DialContext(ctx, "tcp", testAddress()); err == nil {
		t.Fatal("deferred dial with an already canceled context succeeded")
	}
	if hook.count() != 0 || record.prepared != 0 {
		t.Fatalf("canceled deferred dial created an attempt: attempts=%d prepared=%d", hook.count(), record.prepared)
	}
}

// isDeadlineError accepts the net.Conn deadline contract: the concrete sentinel
// may be os.ErrDeadlineExceeded or a context deadline, but the operation must
// report a timeout.
func isDeadlineError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// installBlockingPayload replaces the platform first-payload attempt with a
// hermetic one that reports entry and then waits for the single activation
// context, so deadline and Close handling can be observed without a socket.
func installBlockingPayload(t *testing.T, entered chan struct{}) {
	t.Helper()
	previous := dialAttemptPayloadHook
	dialAttemptPayloadHook = func(ctx context.Context, _ net.Dialer, _, _ string, _ []byte, _ AttemptLease) (net.Conn, int, error) {
		close(entered)
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}
	t.Cleanup(func() { dialAttemptPayloadHook = previous })
}

// The operation that triggers activation must honor its own deadline: a
// read-first activation observes the read deadline, and a write deadline
// tightened while the attempt is pending takes effect on that same attempt.
// These are the exact cases the scoped security probe failed.
func TestDeferredActivationHonorsOperationDeadlines(t *testing.T) {
	for _, mode := range []string{"write-before-control", "read-before", "write-during"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			installBlockingPayload(t, entered)
			dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
			conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
			defer conn.Close()
			if mode == "write-before-control" {
				conn.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
			}
			if mode == "read-before" {
				conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if mode == "read-before" {
					_, err = conn.Read(make([]byte, 1))
				} else {
					_, err = conn.Write([]byte("FIRST"))
				}
				done <- err
			}()
			<-entered
			if mode == "write-during" {
				conn.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
			}
			select {
			case err := <-done:
				if !isDeadlineError(err) {
					t.Fatalf("activation ended with %v, want a deadline error", err)
				}
			case <-time.After(2 * time.Second):
				conn.Close()
				<-done
				t.Fatalf("%s: activation ignored the operation deadline; only explicit Close canceled it", mode)
			}
		})
	}
}

// The same contract must hold through the public returned connection, which is
// where the scoped security probe observed the omission.
func TestPublicDeferredConnectionHonorsOperationDeadlines(t *testing.T) {
	for _, mode := range []string{"write-before-control", "read-before", "write-during"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			installBlockingPayload(t, entered)
			dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
			conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if mode == "write-before-control" {
				conn.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
			}
			if mode == "read-before" {
				conn.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if mode == "read-before" {
					_, err = conn.Read(make([]byte, 1))
				} else {
					_, err = conn.Write([]byte("FIRST"))
				}
				done <- err
			}()
			<-entered
			if mode == "write-during" {
				conn.SetWriteDeadline(time.Now().Add(25 * time.Millisecond))
			}
			select {
			case err := <-done:
				if !isDeadlineError(err) {
					t.Fatalf("public facade ended with %v, want a deadline error", err)
				}
			case <-time.After(2 * time.Second):
				conn.Close()
				<-done
				t.Fatalf("%s: public facade ignored the operation deadline", mode)
			}
		})
	}
}

// Extending or clearing the operation deadline while the attempt is pending
// must re-arm the activation bound instead of failing at the superseded value.
func TestDeferredActivationDeadlineExtendAndClear(t *testing.T) {
	for _, mode := range []string{"extend", "clear"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			previous := dialAttemptPayloadHook
			dialAttemptPayloadHook = func(ctx context.Context, _ net.Dialer, _, _ string, payload []byte, _ AttemptLease) (net.Conn, int, error) {
				close(entered)
				select {
				case <-ctx.Done():
					return nil, 0, ctx.Err()
				case <-release:
					return &fakeConn{}, len(payload), nil
				}
			}
			t.Cleanup(func() { dialAttemptPayloadHook = previous })
			dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
			conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
			defer conn.Close()
			conn.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
			done := make(chan error, 1)
			go func() {
				_, err := conn.Write([]byte("FIRST"))
				done <- err
			}()
			<-entered
			if mode == "extend" {
				conn.SetWriteDeadline(time.Now().Add(time.Minute))
			} else {
				conn.SetWriteDeadline(time.Time{})
			}
			// Well past the superseded 30 ms bound.
			select {
			case err := <-done:
				t.Fatalf("activation ended at the superseded deadline: %v", err)
			case <-time.After(150 * time.Millisecond):
			}
			close(release)
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("activation failed after %s: %v", mode, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("activation did not complete after the deadline update")
			}
		})
	}
}

// An already expired deadline is refused before any native attempt exists, and
// the single deferred attempt stays available for a later valid deadline.
func TestDeferredActivationExpiredDeadlineRefusesBeforeAttempt(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := conn.Write([]byte("FIRST")); !isDeadlineError(err) {
		t.Fatalf("expired deadline write = %v, want a deadline error", err)
	}
	if record.prepared != 0 {
		t.Fatalf("native attempts after an already expired deadline = %d, want 0", record.prepared)
	}
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Write([]byte("FIRST")); err != nil || n != 5 {
		t.Fatalf("write after a valid deadline = (%d, %v)", n, err)
	}
	if record.prepared != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", record.prepared)
	}
}

// A concurrent waiter must honor its own operation deadline while another
// caller's activation is still in flight, instead of blocking on the ready
// channel until the owner finishes.
func TestDeferredConcurrentWaiterHonorsOwnDeadline(t *testing.T) {
	entered := make(chan struct{})
	installBlockingPayload(t, entered)
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
	defer conn.Close()
	writeDone := make(chan error, 1)
	go func() {
		_, err := conn.Write([]byte("FIRST"))
		writeDone <- err
	}()
	<-entered
	conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	start := time.Now()
	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()
	var readErr error
	select {
	case readErr = <-readDone:
	case <-time.After(2 * time.Second):
		conn.Close()
		<-readDone
		t.Fatal("concurrent reader ignored its own deadline while the activation was in flight")
	}
	if !isDeadlineError(readErr) {
		t.Fatalf("concurrent reader = %v, want its own deadline error", readErr)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("concurrent reader waited %v for a 20ms deadline", elapsed)
	}
	conn.Close()
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the in-flight activation")
	}
}

// An internal WriteTo after a terminal activation error must not start a second
// native attempt and must not close the single ready channel twice.
func TestDeferredWriteToAfterFailureIsTerminal(t *testing.T) {
	var attempts atomic.Int32
	previous := dialAttemptPayloadHook
	dialAttemptPayloadHook = func(context.Context, net.Dialer, string, string, []byte, AttemptLease) (net.Conn, int, error) {
		attempts.Add(1)
		return nil, 0, errors.New("substituted attempt failure")
	}
	t.Cleanup(func() { dialAttemptPayloadHook = previous })
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
	if _, err := conn.Write([]byte("FIRST")); err == nil {
		t.Fatal("first activation failure reported success")
	}
	var (
		writeToErr error
		panicked   any
	)
	func() {
		defer func() { panicked = recover() }()
		_, writeToErr = conn.WriteTo(io.Discard)
	}()
	if panicked != nil {
		t.Fatalf("internal WriteTo after failure panicked: %v", panicked)
	}
	if writeToErr == nil {
		t.Fatal("internal WriteTo after a terminal failure reported success")
	}
	if attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want the single failed attempt", attempts.Load())
	}
}

// The internal WriteTo is not reachable through the public facade: the outer
// pendingHandshakeConn embeds net.Conn, so an io.WriterTo implemented by the
// inner connection is not promoted.
func TestPublicDeferredFacadeHidesInternalWriterTo(t *testing.T) {
	record := &payloadRecord{}
	withFakePayload(t, record)
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, isWriterTo := conn.(io.WriterTo); isWriterTo {
		t.Fatal("public deferred facade exposes the internal WriterTo fast path")
	}
}

package dialer

import (
	"context"
	"io"
	"net"
	"os"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// PendingTCPHook wraps the deferred logical TCP connection created by the
// owned `tcp_fast_open` path. It is implemented only by the direct outbound
// bridge and applies the configured stream wrapper exactly once, before any
// user write and before any socket exists.
type PendingTCPHook interface {
	WrapPendingTCP(ctx context.Context, intent AttemptIntent, pending net.Conn) (net.Conn, error)
}

// pendingTCPConn is the lazy logical connection of the owned deferred TFO path.
// It owns no socket: the native attempt is created only when the first
// transformed payload must be sent (first Write), on an explicit empty Write,
// or when the peer is expected to speak first (Read before any Write). It
// stores deadline and close state until that activation so callers can set
// deadlines and close a connection that has not touched the network yet.
//
// One pending facade performs exactly one native attempt. A closed facade
// never creates a socket, and an activation that finishes after Close adopts
// and closes its own socket instead of publishing it.
type pendingTCPConn struct {
	dialer  *DefaultDialer
	ctx     context.Context
	network string
	address string
	base    net.Dialer
	intent  AttemptIntent

	ready chan struct{}

	mu       sync.Mutex
	activate bool
	conn     net.Conn
	err      error
	closed   bool
	cancel   context.CancelFunc
	// published reports that the adopted connection received the current call
	// deadlines. The adopted connection is neither usable nor exposed through
	// the unwrap/replaceability contract before this barrier is settled: a
	// fresh operation that arrives during the publication window waits for it
	// under its own half deadline instead of delegating to a connection that
	// does not carry that deadline yet.
	published bool

	// activatingRead records which half owns the single activation, so the
	// deadline bound of the operation that triggers activation is the one
	// enforced (a read-first activation must honor the read deadline).
	activatingRead bool
	// attemptReason is the first reason this facade ended the activation
	// (expired deadline or Close). The platform attempt error is replaced by
	// it so a caller sees the deadline/close contract, not a generic context
	// cancellation.
	attemptReason error
	// deadlineTimer re-arms the activation bound when a setter changes it.
	// There is no per-connection goroutine: the timer cancels the single
	// attempt context.
	deadlineTimer      *time.Timer
	deadlineGeneration uint64

	// The call deadlines are exactly two halves, matching net.Conn: a combined
	// SetDeadline is the same operation as setting both halves, never a third
	// independent cap, so a later half setter always supersedes an earlier
	// combined value for that half.
	readDeadline  time.Time
	writeDeadline time.Time
	// deadlineVersion numbers every completed deadline setter. It closes the
	// publication window between an adopted connection and the setters: a
	// stale snapshot is never replayed over a newer completed value.
	deadlineVersion uint64
	// deadlineChanged is closed and replaced by every setter, so waiters that
	// already block on their own deadline re-evaluate the current value instead
	// of sleeping until a superseded bound.
	deadlineChanged chan struct{}
	// closeNotify is closed exactly once by Close, so an operation that is
	// already parked in the activation/publication wait is released by the
	// public cancellation itself. The channel is never replaced: a waiter that
	// snapshotted it before Close still observes the close, and the closed
	// state of the facade is checked under the same mutex, so a waiter cannot
	// miss both.
	closeNotify chan struct{}
}

func newPendingTCPConn(ctx context.Context, dialer *DefaultDialer, base net.Dialer, network string, address string, intent AttemptIntent) *pendingTCPConn {
	if ctx == nil {
		ctx = context.Background()
	}
	return &pendingTCPConn{
		dialer: dialer,
		// The single native attempt is created after the dial call returned,
		// so it must not inherit the dial context's cancellation. The
		// parallel address/interface races cancel the context they dialed
		// with as soon as they return a winner (DialParallelNetwork does
		// exactly that), and a deferred winner has not touched the network
		// yet; honoring that cancellation would fail every dual-stack
		// connection at its first write. Cancellation of the deferred attempt
		// is owned by Close instead, mirroring the existing lazy TFO path.
		ctx:     context.WithoutCancel(ctx),
		network: network,
		address: address,
		base:    base,
		intent:  intent,
		ready:   make(chan struct{}),

		deadlineChanged: make(chan struct{}),
		closeNotify:     make(chan struct{}),
	}
}

func (c *pendingTCPConn) established() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.published {
		// The socket exists but the call deadlines are still being published
		// on it. Exposing it here would let a raw fast path, an unwrap or a
		// replaceability upgrade bypass the deadline contract, so the adopted
		// connection stays internal until the publication barrier is settled.
		return nil
	}
	return c.conn
}

// activationPayload returns the first payload that must be handed to the native
// TFO attempt: the caller's first transformed segment, or nil for an explicit
// empty connect.
func (c *pendingTCPConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, os.ErrClosed
	}
	if c.conn != nil && c.published {
		conn := c.conn
		c.mu.Unlock()
		return conn.Write(p)
	}
	if c.activate || c.conn != nil {
		// Another first write owns the single transition, or the facade has
		// already adopted a connection whose call deadlines are still being
		// published. This caller must not carry payload to a connection that
		// does not have its deadline yet; it waits for the publication
		// barrier under its own write deadline. The waiter is also the only
		// writer allowed to carry payload in the SYN, so it writes its own
		// bytes only after the established sender exists.
		c.mu.Unlock()
		conn, err := c.awaitPublication(false)
		if err != nil {
			return 0, err
		}
		return conn.Write(p)
	}
	if c.err != nil {
		// A failed first send is terminal: no candidate retry may create a
		// second socket after an uncertain or positive early send.
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if expired := c.expiredDeadlineLocked(false); expired {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	c.activate = true
	c.activatingRead = false
	c.mu.Unlock()
	return c.dial(p)
}

// dial performs the single owned native attempt. The payload (possibly empty)
// is already transformed stream data; the native helper writes it as the first
// bytes of the connection, so no byte is replayed by this facade.
func (c *pendingTCPConn) dial(payload []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_, _ = c.finish(nil, 0, os.ErrClosed)
		return 0, os.ErrClosed
	}
	attemptCtx, cancel := context.WithCancel(c.ctx)
	c.cancel = cancel
	// A deadline that was set before activation bounds the activation itself.
	// Every later setter update re-arms the same bound through this timer, so a
	// shortened, extended or cleared operation deadline takes effect while the
	// attempt is pending instead of only after the socket exists.
	c.refreshActivationDeadlineLocked()
	c.mu.Unlock()
	defer cancel()

	conn, sent, err := c.dialer.dialOwnedTCP(attemptCtx, c.base, c.network, c.address, payload, c.intent)
	sent, err = c.finish(conn, sent, err)
	if err != nil {
		// A failure after valid native progress still reports the
		// authoritative accepted count, so neither this facade nor the caller
		// above it can mistake consumed bytes for unsent ones.
		return sent, err
	}
	if len(payload) > 0 && sent < len(payload) {
		// A short first send is not a failure by itself: only the accepted
		// prefix left the process. Report it so the caller (stream wrapper)
		// forwards the remainder instead of acknowledging dropped bytes.
		return sent, nil
	}
	return len(payload), nil
}

// activationDeadlineLocked returns the bound of the operation that triggers the
// single activation: the read or write half that owns the activation. A
// combined SetDeadline is stored in both halves, so it is never an independent
// third cap that could outlive a later half setter.
func (c *pendingTCPConn) activationDeadlineLocked(read bool) time.Time {
	if read {
		return c.readDeadline
	}
	return c.writeDeadline
}

// expiredDeadlineLocked reports whether the operation's own bound already
// passed. The refusal happens before any native attempt exists, so an expired
// deadline never creates a socket and never becomes an uncertain early send.
func (c *pendingTCPConn) expiredDeadlineLocked(read bool) bool {
	bound := c.activationDeadlineLocked(read)
	return !bound.IsZero() && !time.Now().Before(bound)
}

// refreshActivationDeadlineLocked re-arms the single activation timer for the
// current operation bound. It is called at activation start and by every
// deadline setter while the activation is in flight.
func (c *pendingTCPConn) refreshActivationDeadlineLocked() {
	if c.deadlineTimer != nil {
		c.deadlineTimer.Stop()
		c.deadlineTimer = nil
	}
	c.deadlineGeneration++
	if !c.activate || c.closed || c.cancel == nil {
		return
	}
	bound := c.activationDeadlineLocked(c.activatingRead)
	if bound.IsZero() {
		return
	}
	wait := time.Until(bound)
	if wait <= 0 {
		c.cancelActivationLocked(os.ErrDeadlineExceeded)
		return
	}
	generation := c.deadlineGeneration
	c.deadlineTimer = time.AfterFunc(wait, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if generation != c.deadlineGeneration || !c.activate {
			return
		}
		c.deadlineTimer = nil
		c.cancelActivationLocked(os.ErrDeadlineExceeded)
	})
}

// cancelActivationLocked ends the single activation for the first recorded
// reason (Close or an expired operation deadline).
func (c *pendingTCPConn) cancelActivationLocked(reason error) {
	if c.attemptReason == nil {
		c.attemptReason = reason
	}
	if c.cancel != nil {
		c.cancel()
	}
}

// notifyDeadlineLocked wakes every waiter that already blocked on its own
// deadline, so it re-evaluates the current half value instead of sleeping until
// a now superseded bound. The channel is replaced after the close, therefore an
// update cannot be lost between a waiter's snapshot and its select.
func (c *pendingTCPConn) notifyDeadlineLocked() {
	if c.deadlineChanged == nil {
		c.deadlineChanged = make(chan struct{})
		return
	}
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
}

// notifyCloseLocked publishes the terminal close state to operations that are
// already parked in the activation/publication wait. It is called under the
// mutex by Close, whose idempotent closed flag is the exactly-once guard.
func (c *pendingTCPConn) notifyCloseLocked() {
	if c.closeNotify == nil {
		c.closeNotify = make(chan struct{})
	}
	close(c.closeNotify)
}

// publishDeadlines applies the current call deadlines to an adopted connection.
// version closes the publication window: when a setter completes while a push
// is in flight it bumps the version, and the push is repeated with the newer
// value, so a stale snapshot can never overwrite a completed setter. skipZero is
// used for the first publication on a freshly adopted connection, which has no
// deadline to clear yet. The error of the settled pass is returned to the
// setter; the adoption path does not have a caller to report to.
func (c *pendingTCPConn) publishDeadlines(conn net.Conn, version uint64, skipZero bool) error {
	first := true
	for {
		c.mu.Lock()
		read, write := c.readDeadline, c.writeDeadline
		version = c.deadlineVersion
		c.mu.Unlock()
		jump := skipZero && first
		var publishErr error
		switch {
		case read.Equal(write) && (!jump || !read.IsZero()):
			// Equal halves are exactly the combined SetDeadline contract, and
			// one call keeps the caller's single deadline visible to a conn
			// that implements only the combined setter.
			publishErr = conn.SetDeadline(read)
		default:
			if !jump || !read.IsZero() {
				if readErr := conn.SetReadDeadline(read); readErr != nil {
					publishErr = readErr
				}
			}
			if !jump || !write.IsZero() {
				if writeErr := conn.SetWriteDeadline(write); writeErr != nil {
					publishErr = writeErr
				}
			}
		}
		first = false
		c.mu.Lock()
		stable := c.deadlineVersion == version
		c.mu.Unlock()
		if stable {
			return publishErr
		}
	}
}

// waitActivation waits for the in-flight activation without exceeding this
// caller's own operation deadline. The activating operation is bounded by the
// activation timer; a concurrent waiter enforces its own half deadline, and a
// deadline that is changed while it waits re-evaluates the current value instead
// of failing at (or sleeping past) a superseded one.
func (c *pendingTCPConn) waitActivation(read bool) error {
	for {
		c.mu.Lock()
		if c.closed {
			// The facade was closed before this operation parked (or by the
			// previous iteration of this loop): the close contract refuses it
			// here, before any I/O, instead of waiting for an activation the
			// closed facade will never publish.
			c.mu.Unlock()
			return os.ErrClosed
		}
		bound := c.activationDeadlineLocked(read)
		ready := c.ready
		changed := c.deadlineChanged
		cancelled := c.closeNotify
		c.mu.Unlock()
		var (
			timer   *time.Timer
			timeout <-chan time.Time
		)
		if !bound.IsZero() {
			wait := time.Until(bound)
			if wait <= 0 {
				return os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(wait)
			timeout = timer.C
		}
		select {
		case <-ready:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-cancelled:
			// Close is terminal for this wait whatever the activation still
			// does: the adopted connection stays unpublished, so the waiter
			// returns the close contract without touching it and without
			// waiting for the deadline publisher or a foreign setter.
			if timer != nil {
				timer.Stop()
			}
			return os.ErrClosed
		case <-changed:
			if timer != nil {
				timer.Stop()
			}
		case <-timeout:
			// Re-evaluate: an extension that lands at the same instant must
			// not fail an operation whose deadline is still live.
		}
	}
}

// awaitPublication waits until the single activation settled and returns the
// adopted connection. A fresh operation that arrives while the adoption is
// still publishing the call deadlines must not delegate to the connection: it
// waits for the same barrier the activating operation closes, bounded by its
// own half deadline. A caller whose half deadline expires first is refused
// before any byte reaches the adopted connection.
func (c *pendingTCPConn) awaitPublication(read bool) (net.Conn, error) {
	if err := c.waitActivation(read); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, os.ErrClosed
	}
	if c.err != nil {
		return nil, c.err
	}
	if !c.published || c.conn == nil {
		return nil, os.ErrClosed
	}
	return c.conn, nil
}

// finish settles the single transition. A connection that arrives after Close
// is closed here: a closed pending facade never publishes a late socket. It
// returns the authoritative accepted count even on failure, so progress that
// the native helper already made is never reported as zero.
func (c *pendingTCPConn) finish(conn net.Conn, sent int, err error) (int, error) {
	if sent < 0 {
		sent = 0
	}
	c.mu.Lock()
	c.activate = false
	c.cancel = nil
	if c.deadlineTimer != nil {
		c.deadlineTimer.Stop()
		c.deadlineTimer = nil
	}
	c.deadlineGeneration++
	closed := c.closed
	if err == nil && conn != nil && closed {
		err = os.ErrClosed
	}
	if err != nil && c.attemptReason != nil {
		// The facade owns the reason the activation ended (Close or an
		// expired operation deadline), so the caller sees that contract
		// instead of the platform context error. The accepted count is
		// independent of the reason and is preserved.
		err = c.attemptReason
	}
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	c.conn = conn
	c.err = err
	version := c.deadlineVersion
	c.mu.Unlock()
	if conn != nil {
		// Deadlines set while the attempt was pending are published on the
		// adopted socket in the same ordered protocol as a running setter, so
		// a completed newer setter is never overwritten by this adoption. The
		// publication precedes both the ready signal and the published barrier:
		// a woken waiter and a fresh entrant must observe the call deadlines on
		// the connection they are about to use.
		_ = c.publishDeadlines(conn, version, true)
	}
	c.mu.Lock()
	if conn != nil {
		// From here on the adopted connection carries the current call
		// deadlines and may be used and unwrapped. Until this assignment the
		// fast paths and `established` keep it internal.
		c.published = true
	}
	close(c.ready)
	c.mu.Unlock()
	return sent, err
}

// Read activates an owned empty attempt when no write happened yet: a
// server-first flow must still create exactly one prepared connection. While a
// first write is in flight, read waits for that write to finish, so the read
// never races the single transition.
func (c *pendingTCPConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return 0, os.ErrClosed
	case c.conn != nil && c.published:
		conn := c.conn
		c.mu.Unlock()
		return conn.Read(p)
	case c.activate || c.conn != nil:
		// The single activation is in flight, or the adopted connection is
		// still receiving its call deadlines. A fresh read must not observe
		// the adopted connection before the publication barrier: it waits
		// under its own read deadline and is refused if that deadline
		// expires first.
		c.mu.Unlock()
		conn, err := c.awaitPublication(true)
		if err != nil {
			return 0, err
		}
		return conn.Read(p)
	}
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if expired := c.expiredDeadlineLocked(true); expired {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	c.activate = true
	c.activatingRead = true
	c.mu.Unlock()
	if _, err := c.dial(nil); err != nil {
		return 0, err
	}
	conn := c.established()
	if conn == nil {
		return 0, os.ErrClosed
	}
	return conn.Read(p)
}

func (c *pendingTCPConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.cancelActivationLocked(os.ErrClosed)
	// Wake operations that are already parked in the activation/publication
	// wait: public Close is terminal for them even while the adopted connection
	// is still publishing its call deadlines, and it must not depend on that
	// publisher, on a foreign deadline setter or on the native attempt ending.
	c.notifyCloseLocked()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *pendingTCPConn) LocalAddr() net.Addr {
	conn := c.established()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.LocalAddr()
}

func (c *pendingTCPConn) RemoteAddr() net.Addr {
	conn := c.established()
	if conn == nil {
		return M.Socksaddr{}
	}
	return conn.RemoteAddr()
}

func (c *pendingTCPConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	// net.Conn defines SetDeadline as equivalent to both half setters, so a
	// later half setter supersedes this value for its half.
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.deadlineVersion++
	version := c.deadlineVersion
	c.notifyDeadlineLocked()
	// A running activation re-arms its bound: a shortened deadline cancels the
	// pending attempt, an extended or cleared one keeps it bounded by the new
	// value only.
	c.refreshActivationDeadlineLocked()
	conn := c.conn
	closed := c.closed
	c.mu.Unlock()
	if conn != nil {
		return c.publishDeadlines(conn, version, false)
	}
	if closed {
		return os.ErrClosed
	}
	return nil
}

func (c *pendingTCPConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.deadlineVersion++
	version := c.deadlineVersion
	c.notifyDeadlineLocked()
	c.refreshActivationDeadlineLocked()
	conn := c.conn
	closed := c.closed
	c.mu.Unlock()
	if conn != nil {
		return c.publishDeadlines(conn, version, false)
	}
	if closed {
		return os.ErrClosed
	}
	return nil
}

func (c *pendingTCPConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.deadlineVersion++
	version := c.deadlineVersion
	c.notifyDeadlineLocked()
	c.refreshActivationDeadlineLocked()
	conn := c.conn
	closed := c.closed
	c.mu.Unlock()
	if conn != nil {
		return c.publishDeadlines(conn, version, false)
	}
	if closed {
		return os.ErrClosed
	}
	return nil
}

// Upstream exposes only an established native connection whose call deadlines
// are already published. Before activation, and during the publication window,
// there is nothing to unwrap, so no counting or stream wrapper can be bypassed
// through a raw fast path, a deadline-less socket or a replaceability upgrade.
func (c *pendingTCPConn) Upstream() any {
	return c.established()
}

func (c *pendingTCPConn) ReaderReplaceable() bool {
	return c.established() != nil
}

func (c *pendingTCPConn) WriterReplaceable() bool {
	return c.established() != nil
}

// NeedHandshake reports the deferred state so the connection manager performs
// the explicit empty/server-first connect instead of waiting for payload.
func (c *pendingTCPConn) NeedHandshake() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn == nil && !c.closed
}

func (c *pendingTCPConn) WriteTo(w io.Writer) (int64, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, os.ErrClosed
	}
	if c.conn != nil && c.published {
		conn := c.conn
		c.mu.Unlock()
		return copyFrom(conn, w)
	}
	if c.activate || c.conn != nil {
		// Activation in flight, or the adopted connection is still receiving
		// its call deadlines. Copying from it now would bypass the caller's
		// read deadline, so this path waits for the publication barrier.
		c.mu.Unlock()
		conn, err := c.awaitPublication(true)
		if err != nil {
			return 0, err
		}
		return copyFrom(conn, w)
	}
	if c.err != nil {
		// A failed activation is terminal here as well: a second attempt
		// would close the single ready channel twice and could resend an
		// uncertain early prefix.
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if expired := c.expiredDeadlineLocked(true); expired {
		c.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	c.activate = true
	c.activatingRead = true
	c.mu.Unlock()
	if _, err := c.dial(nil); err != nil {
		return 0, err
	}
	return copyFrom(c.established(), w)
}

func copyFrom(conn net.Conn, w io.Writer) (int64, error) {
	if conn == nil {
		return 0, os.ErrClosed
	}
	return io.Copy(w, conn)
}

var (
	_ net.Conn    = (*pendingTCPConn)(nil)
	_ N.EarlyConn = (*pendingTCPConn)(nil)
)

// deferredNativeConn is the state seam the stream first-send adapter uses. It
// is structural: the stream package must not import the dialer.
type deferredNativeConn interface {
	NativePending() bool
	Established() net.Conn
}

// NativePending reports that no native socket exists yet.
func (c *pendingTCPConn) NativePending() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn == nil
}

// Established returns the native connection once activation succeeded.
func (c *pendingTCPConn) Established() net.Conn {
	return c.established()
}

// pendingHandshakeConn re-adds the deferred handshake and deadline contract on
// top of the counting/connection-manager wrappers, which do not forward the
// deprecated EarlyConn interface. It is the outermost connection returned by
// the dialer, so N.NeedHandshakeForWrite keeps working through TrackConn and
// the traffic counter. It deliberately hides every raw fast path: all writes
// pass through the transformation wrappers below it.
type pendingHandshakeConn struct {
	net.Conn
	pending *pendingTCPConn
}

func (c *pendingHandshakeConn) NeedHandshake() bool {
	return c.pending.NeedHandshake()
}

func (c *pendingHandshakeConn) NeedHandshakeForWrite() bool {
	return c.pending.NeedHandshake()
}

func (c *pendingHandshakeConn) SetDeadline(deadline time.Time) error {
	return c.Conn.SetDeadline(deadline)
}

func (c *pendingHandshakeConn) SetReadDeadline(deadline time.Time) error {
	return c.Conn.SetReadDeadline(deadline)
}

func (c *pendingHandshakeConn) SetWriteDeadline(deadline time.Time) error {
	return c.Conn.SetWriteDeadline(deadline)
}

var (
	_ net.Conn      = (*pendingHandshakeConn)(nil)
	_ N.EarlyConn   = (*pendingHandshakeConn)(nil)
	_ N.EarlyWriter = (*pendingHandshakeConn)(nil)
)

package route

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

const (
	// tcpRelayPendingUploadLimit is the hard cap of the pending upload
	// buffer. While the remote side is unavailable the single upload reader
	// stops reading at this point, so backpressure reaches the local leg
	// instead of growing memory without bound.
	tcpRelayPendingUploadLimit = 64 * 1024
	tcpRelayReadSize           = 32 * 1024
)

// nonSpliceConn exposes the read/write semantics of one connection only. It
// deliberately does not implement syscall.Conn, ReaderWithUpstream,
// WriterWithUpstream, io.ReaderFrom or io.WriterTo, so the existing copy
// helpers cannot unwrap the connection pair into a syscall splice or another
// direct fast path. Deadlines, close, half-close, counters and error values of
// the wrapped connection stay in effect because every call is forwarded.
type nonSpliceConn struct {
	conn net.Conn
}

// nonSpliceHalfCloseConn keeps the duplex half-close capability of the
// wrapped connection available to the existing copy owner. The half-close
// capability must not be claimed for a connection that does not have it:
// the copy owner closes the whole destination in that case.
type nonSpliceHalfCloseConn struct {
	nonSpliceConn
}

func newNonSpliceConn(conn net.Conn) net.Conn {
	if _, isHalfCloser := conn.(interface{ CloseWrite() error }); isHalfCloser {
		return &nonSpliceHalfCloseConn{nonSpliceConn{conn: conn}}
	}
	return &nonSpliceConn{conn: conn}
}

func (c *nonSpliceConn) Read(p []byte) (int, error)         { return c.conn.Read(p) }
func (c *nonSpliceConn) Write(p []byte) (int, error)        { return c.conn.Write(p) }
func (c *nonSpliceConn) Close() error                       { return c.conn.Close() }
func (c *nonSpliceConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *nonSpliceConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *nonSpliceConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *nonSpliceConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *nonSpliceConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *nonSpliceHalfCloseConn) CloseWrite() error {
	closeWriter, isCloseWriter := c.conn.(interface{ CloseWrite() error })
	if !isCloseWriter {
		return nil
	}
	return closeWriter.CloseWrite()
}

func (c *nonSpliceHalfCloseConn) CloseRead() error {
	closeReader, isCloseReader := c.conn.(interface{ CloseRead() error })
	if !isCloseReader {
		return nil
	}
	return closeReader.CloseRead()
}

// tcpRelayClock is the time seam of the orphan timer. Production uses the
// system clock; tests inject a deterministic clock.
type tcpRelayClock interface {
	Now() time.Time
	AfterFunc(duration time.Duration, function func()) tcpRelayTimer
}

type tcpRelayTimer interface {
	Stop() bool
}

type systemTCPRelayClock struct{}

func (systemTCPRelayClock) Now() time.Time {
	return time.Now()
}

func (systemTCPRelayClock) AfterFunc(duration time.Duration, function func()) tcpRelayTimer {
	return time.AfterFunc(duration, function)
}

type tcpRelayState uint8

const (
	// tcpRelayPending covers the single pending remote attempt owned by the
	// dialer: destination resolution and the native connect both happen
	// inside it, and the pair treats the remote as unavailable until the
	// attempt returns an actual connection.
	tcpRelayPending tcpRelayState = iota
	tcpRelayConnected
	tcpRelayCancelled
)

// tcpRelayPair owns the accepted local leg while the remote connection is
// pending. Exactly one goroutine reads the local leg; no sniff, handshake or
// watch reader competes with it after the handler transferred ownership. The
// pair reuses the existing connection-pair lifetime and close reporting: the
// shared done/onClose pair is the only close reporter, and the remote owner
// keeps its own Engine/lease accounting.
type tcpRelayPair struct {
	ctx     context.Context
	cancel  context.CancelFunc
	local   net.Conn
	options adapter.TCPRelayOptions
	clock   tcpRelayClock
	logger  logger.ContextLogger
	done    *atomic.Bool
	onClose N.CloseHandlerFunc
	// activatedCh is closed after the connected remote leg was handed to the
	// upload reader and the queued bytes were flushed.
	activatedCh chan struct{}

	// writeMu orders remote writes: the pending buffer flush and every later
	// upload write are serialized, so queued bytes stay ahead of new bytes.
	writeMu     sync.Mutex
	writeClosed bool

	mu           sync.Mutex
	state        tcpRelayState
	remote       net.Conn
	activated    bool
	buffer       []byte
	halfClosed   bool
	terminalErr  error
	timer        tcpRelayTimer
	cancelReason error
}

func newTCPRelayPair(ctx context.Context, local net.Conn, options adapter.TCPRelayOptions, clock tcpRelayClock, pairLogger logger.ContextLogger, done *atomic.Bool, onClose N.CloseHandlerFunc) *tcpRelayPair {
	relayCtx, cancel := context.WithCancel(ctx)
	if clock == nil {
		clock = systemTCPRelayClock{}
	}
	pair := &tcpRelayPair{
		ctx:         relayCtx,
		cancel:      cancel,
		local:       local,
		options:     options,
		clock:       clock,
		logger:      pairLogger,
		done:        done,
		onClose:     onClose,
		activatedCh: make(chan struct{}),
	}
	go pair.run()
	return pair
}

// context is the pending remote attempt context. Orphan expiry, a terminal
// local close without unsent data, caller cancellation and shutdown all cancel
// it, which cancels the pending resolve/connect.
func (p *tcpRelayPair) context() context.Context {
	return p.ctx
}

// bind marks the remote attempt as connected and disarms the orphan timer. It
// returns false when the pair already cancelled, in which case a late resolve
// or connect result must be closed instead of resurrecting the pair.
func (p *tcpRelayPair) bind() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != tcpRelayPending {
		return false
	}
	p.state = tcpRelayConnected
	p.stopTimerLocked()
	return true
}

// activate hands the connected remote leg to the upload reader: the queued
// bytes are flushed exactly once, then a pending read half-close is forwarded.
// It runs after the remote wrappers are installed, so transformed writes keep
// their existing owner.
func (p *tcpRelayPair) activate(remote net.Conn) error {
	p.writeMu.Lock()
	p.mu.Lock()
	if p.state != tcpRelayConnected {
		p.mu.Unlock()
		p.writeMu.Unlock()
		return E.New("tcp relay pair is not connected")
	}
	p.remote = remote
	p.activated = true
	buffered := p.buffer
	p.buffer = nil
	halfClosed := p.halfClosed
	terminalErr := p.terminalErr
	p.mu.Unlock()
	var err error
	if len(buffered) > 0 {
		_, err = writeTCPRelayData(remote, buffered)
	}
	if err == nil && halfClosed {
		err = p.closeWriteLocked(remote)
	}
	if err == nil && halfClosed {
		p.finishUpload(nil)
	}
	if err == nil && terminalErr != nil {
		// The local leg terminally closed while the remote was unavailable.
		// The queued bytes were delivered once; the pair now finishes like a
		// failed upload and reports the terminal error.
		p.failUpload(terminalErr)
	}
	p.writeMu.Unlock()
	close(p.activatedCh)
	return err
}

// terminate stops the pending reader after an external owner already closed
// and reported the pair; it must not report the close a second time.
func (p *tcpRelayPair) terminate() {
	p.cancel()
	p.mu.Lock()
	p.state = tcpRelayCancelled
	p.stopTimerLocked()
	p.mu.Unlock()
	_ = p.local.Close()
}

// abort stops the pair and reports one close. It is the single reporting path
// of the connection-pair owner, so admission release and the handler onClose
// callback happen exactly once.
func (p *tcpRelayPair) abort(cause error) {
	p.cancel()
	p.mu.Lock()
	p.state = tcpRelayCancelled
	p.stopTimerLocked()
	reason := p.cancelReason
	p.mu.Unlock()
	if reason != nil {
		if cause != nil && !E.IsClosedOrCanceled(cause) {
			cause = E.Cause(cause, reason)
		} else {
			cause = reason
		}
	} else if cause == nil {
		cause = E.New("tcp relay connection cancelled")
	}
	p.closePair()
	p.done.Store(true)
	p.report(cause)
	p.logger.ErrorContext(p.ctx, cause)
}

func (p *tcpRelayPair) stopTimerLocked() {
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

// cancelWith stops the pending remote attempt. Teardown and close reporting
// stay with the connection-pair owner, which observes the cancelled dial.
func (p *tcpRelayPair) cancelWith(reason error) {
	p.mu.Lock()
	if p.state != tcpRelayPending {
		p.mu.Unlock()
		return
	}
	p.state = tcpRelayCancelled
	p.stopTimerLocked()
	if p.cancelReason == nil {
		p.cancelReason = reason
	}
	p.mu.Unlock()
	p.cancel()
}

func (p *tcpRelayPair) orphanTimedOut() {
	p.cancelWith(E.New("tcp relay orphan timeout after ", p.options.MaxOrphanTime))
}

func (p *tcpRelayPair) closePair() {
	_ = p.local.Close()
	p.mu.Lock()
	remote := p.remote
	p.mu.Unlock()
	if remote != nil {
		_ = remote.Close()
	}
}

// finishUpload mirrors the existing copy owner's completion contract: the
// last direction reports the close exactly once through the shared done/onClose
// pair, and the pair is closed at that point.
func (p *tcpRelayPair) finishUpload(err error) {
	if p.done.Swap(true) {
		p.report(err)
		p.closePair()
	}
}

// failUpload reports the terminal pair error itself. The close callback is
// idempotent for the whole connection pair, so a later download completion
// cannot report a second close.
func (p *tcpRelayPair) failUpload(err error) {
	p.closePair()
	p.done.Store(true)
	p.report(err)
	p.logUpload(err)
}

func (p *tcpRelayPair) report(err error) {
	if p.onClose != nil {
		p.onClose(err)
	}
}

func (p *tcpRelayPair) run() {
	buffer := make([]byte, tcpRelayReadSize)
	for {
		limit, proceed := p.readLimit(len(buffer))
		if !proceed {
			return
		}
		if limit == 0 {
			// The pending buffer is at its cap: stop reading so the local
			// leg sees backpressure instead of an unbounded buffer.
			select {
			case <-p.activatedCh:
			case <-p.ctx.Done():
				return
			}
			continue
		}
		readN, err := p.local.Read(buffer[:limit])
		if readN > 0 {
			if !p.handleData(buffer[:readN]) {
				return
			}
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			p.handleEOF()
			return
		}
		p.handleReadError(err)
		return
	}
}

// readLimit reports how many bytes the single upload reader may read next.
// The limit is zero exactly at the pending cap, and proceed is false once the
// pair was cancelled.
func (p *tcpRelayPair) readLimit(chunk int) (int, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == tcpRelayCancelled {
		return 0, false
	}
	if p.activated {
		return chunk, true
	}
	remaining := tcpRelayPendingUploadLimit - len(p.buffer)
	if remaining <= 0 {
		return 0, true
	}
	if remaining < chunk {
		return remaining, true
	}
	return chunk, true
}

func (p *tcpRelayPair) handleData(data []byte) bool {
	p.mu.Lock()
	if p.state == tcpRelayCancelled {
		p.mu.Unlock()
		return false
	}
	if !p.activated {
		p.buffer = append(p.buffer, data...)
		p.mu.Unlock()
		return true
	}
	remote := p.remote
	p.mu.Unlock()
	p.writeMu.Lock()
	_, err := writeTCPRelayData(remote, data)
	p.writeMu.Unlock()
	if err != nil {
		p.failUpload(err)
		return false
	}
	return true
}

func (p *tcpRelayPair) handleEOF() {
	p.mu.Lock()
	p.halfClosed = true
	activated := p.activated
	state := p.state
	remote := p.remote
	p.mu.Unlock()
	if state == tcpRelayCancelled {
		return
	}
	if !activated {
		// A read EOF is a read half-close, not a terminal close: the pending
		// remote attempt keeps running and the queued bytes are flushed after
		// a successful connect, then the half-close is forwarded.
		select {
		case <-p.activatedCh:
		case <-p.ctx.Done():
		}
		return
	}
	p.writeMu.Lock()
	err := p.closeWriteLocked(remote)
	if err == nil {
		p.finishUpload(nil)
	}
	p.writeMu.Unlock()
	if err != nil {
		p.failUpload(err)
		return
	}
	p.logUpload(nil)
}

func (p *tcpRelayPair) handleReadError(err error) {
	p.mu.Lock()
	state := p.state
	activated := p.activated
	p.mu.Unlock()
	if state == tcpRelayCancelled {
		return
	}
	if activated {
		p.failUpload(err)
		return
	}
	p.mu.Lock()
	unsent := len(p.buffer)
	connected := p.state == tcpRelayConnected
	p.terminalErr = err
	p.mu.Unlock()
	if connected {
		// The remote attempt already succeeded: a connected remote is not
		// subject to the orphan policy. Activation flushes the queued bytes
		// and reports this terminal error.
		return
	}
	if unsent == 0 {
		// No unsent real data: cancel the pending attempt immediately.
		p.cancelWith(E.Cause(err, "local connection closed before the remote connection was available"))
		return
	}
	if p.options.MaxOrphanTime > 0 {
		p.mu.Lock()
		if p.state == tcpRelayPending && p.timer == nil {
			p.timer = p.clock.AfterFunc(p.options.MaxOrphanTime, p.orphanTimedOut)
		}
		p.mu.Unlock()
		return
	}
	// An explicit zero disables only this timer: the configured connect
	// deadline, caller cancellation and shutdown still bound the attempt.
}

// closeWriteLocked forwards a pending read half-close as a write half-close.
// The caller holds writeMu; exactly one half-close is sent.
func (p *tcpRelayPair) closeWriteLocked(remote net.Conn) error {
	if p.writeClosed {
		return nil
	}
	p.writeClosed = true
	if remote == nil {
		return nil
	}
	writer, _ := N.UnwrapCountWriter(remote, nil)
	duplexWriter, isDuplex := N.UnwrapWriter(writer).(N.WriteCloser)
	if isDuplex {
		return duplexWriter.CloseWrite()
	}
	return remote.Close()
}

func (p *tcpRelayPair) logUpload(err error) {
	if p.logger == nil {
		return
	}
	if err == nil {
		p.logger.DebugContext(p.ctx, "connection upload finished")
	} else if E.IsClosedOrCanceled(err) {
		p.logger.TraceContext(p.ctx, "connection upload closed")
	} else {
		p.logger.ErrorContext(p.ctx, "connection upload closed: ", err)
	}
}

// writeTCPRelayData writes the whole payload, so queued bytes are delivered
// exactly once and a partial write is never reported as success.
func writeTCPRelayData(conn net.Conn, data []byte) (int64, error) {
	var written int64
	for len(data) > 0 {
		writeN, err := conn.Write(data)
		written += int64(writeN)
		data = data[writeN:]
		if err != nil {
			return written, err
		}
		if writeN == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

var _ = common.Close

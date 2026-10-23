package desync

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Bounded liveness limits of the stream wrapper.
const (
	// streamFirstBlockHoldLimit bounds how long an incomplete HTTP/TLS first
	// block is retained while waiting for the bytes that carry the host. A
	// structurally complete message - including a ClientHello without SNI -
	// is released immediately; the timer only covers genuinely incomplete
	// prefixes, where waiting for a later Write or for Close would otherwise
	// stall a valid short exchange.
	streamFirstBlockHoldLimit = 200 * time.Millisecond
	// streamCloseFlushLimit bounds the pending-block flush performed by
	// Close, so Close on a peer that does not read cannot block forever.
	streamCloseFlushLimit = 250 * time.Millisecond
	// streamFlushWatchdogGrace delays the flush watchdog past the effective
	// deadline so the ordinary case - the connection and a caching platform
	// sender honour their published deadline - completes on its own. The
	// watchdog is the backstop for a deadline slot that a concurrent caller
	// publication has cleared or extended; it fires only after the deadline
	// had its chance, and aborting earlier would race the normal expiry.
	streamFlushWatchdogGrace = 25 * time.Millisecond
)

// streamConn is the per-connection tpws-equivalent wrapper. It owns the
// underlying net.Conn and serializes writes. It keeps no global state: the
// compiled StreamConfig is immutable and every mutable field belongs to this
// connection.
type streamConn struct {
	net.Conn
	config *StreamConfig
	facts  MatchFacts
	random *streamRandom
	cancel chan struct{}

	cancelOnce sync.Once
	closeOnce  sync.Once
	// flushAbortOnce runs the Close abort (cancel the pending native send,
	// close the underlying connection) at most once. The flush watchdog and
	// Close's own teardown both need it, and only one of them may fire it:
	// a watchdog that races the normal completion must not cancel the sender
	// a second time.
	flushAbortOnce sync.Once
	closeErr       error

	// closed is read by Write before it takes mu, so a concurrent Close can
	// prevent new writes even while an in-flight Write holds mu on a blocked
	// socket. mu is never required to observe or set it.
	closed atomic.Bool

	// writeDeadline is the deadline most recently set through the wrapper.
	// The Windows native sender reads it because a raw WSASend bypasses the
	// Go poller's deadline handling.
	writeDeadline atomic.Int64

	// flushDeadline is the upper bound installed once Close starts its
	// pending-block flush. It is never cleared: the connection is closed
	// immediately after that flush, and a later caller SetWriteDeadline must
	// not be able to extend the bound again. currentWriteDeadline reports the
	// earlier of this bound and the caller deadline, so every sender deadline
	// source (including a sender first constructed by the flush) observes the
	// same <= streamCloseFlushLimit limit. The value is delegated to the
	// underlying conn by publishWriteDeadline, which repeats the delegation
	// until the source generation it read is still current, so a caller update
	// whose effective value was computed before this store cannot be left
	// behind as the last deadline the conn sees. The bound is additionally
	// enforced on the connection lifetime by armFlushWatchdog, which does not
	// depend on this shared slot at all.
	flushDeadline atomic.Int64

	// deadlineGeneration orders deadline publications. Every store to
	// writeDeadline or flushDeadline increments it after the new value is
	// visible, so a publisher can tell whether the effective deadline changed
	// while its publication was in flight. A publication repeats until the
	// value it delivered was read after the last observed store and no newer
	// store followed the check; unlike a bounded number of verification passes
	// this cannot be exhausted by one more concurrent setter, so the deadline a
	// sender enforces converges on the current source instead of being left
	// stale. The counter is only compared for equality, so it never wraps in
	// practice.
	deadlineGeneration atomic.Uint64

	// senderMu guards the activeSender reference and the terminal sender
	// state. It is never held across socket I/O, so Close can cancel an
	// in-flight native send while Write is blocked.
	//
	// senderTerminal is the single ownership decision for platform sender
	// resources: it is set exactly once, by the first terminal shutdown, and
	// publication checks it under the same mutex. A sender whose factory
	// crossed Close is therefore either cancelled/released by the shutdown or
	// disposed by its publisher - never published into a shutdown that has
	// already run.
	senderMu       sync.Mutex
	activeSender   streamSender
	senderTerminal bool

	mu             sync.Mutex
	pending        []byte
	firstBlockDone bool
	stageResolved  bool
	passThrough    bool
	rule           *streamRule
	sender         streamSender
	protocol       Protocol
	blockIndex     uint64
	streamOffset   uint64
	writeErr       error
	holdTimer      *time.Timer
	holdGeneration uint64

	// Reply observation for hostlist-auto (upstream tamper_in/rst_in/hup_out).
	// It only reads a bounded copy of the first inbound block: connection bytes
	// are never modified and a reply is never consumed twice.
	observeBuf  []byte
	observed    bool
	learnRule   *streamRule
	learnHost   string
	learnActive bool
}

// WrapConn wraps a successfully attached TCP connection. Nil or empty config
// returns the original conn without allocating state.
//
// Ownership is settled once: on success the returned wrapper owns conn and
// Close closes it. On error nothing was wrapped and ownership stays with the
// caller, who must close conn itself; WrapConn never closes the caller's
// connection on a cancellation or configuration error, so a failed attempt
// cannot leak or double-close it.
func (c *StreamConfig) WrapConn(ctx context.Context, conn net.Conn, facts MatchFacts) (net.Conn, error) {
	if c == nil || len(c.snapshotRules()) == 0 {
		return conn, nil
	}
	if conn == nil {
		return nil, newStreamError("WrapConn with nil connection")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	source := c.random
	if source == nil {
		source = rand.Reader
	}
	facts.Transport = TransportTCP
	facts = c.annotateFacts(facts)
	wrapper := &streamConn{
		Conn:   conn,
		config: c,
		facts:  facts,
		random: &streamRandom{source: source},
		cancel: make(chan struct{}),
	}
	wrapper.rule = c.selectRule(facts)
	// F1: the preconnect Prepare set TCP_NODELAY=0, but Go's net package
	// re-enables NODELAY while constructing the connected TCPConn. Re-assert the
	// selected value on the adopted connection, before any wrapper state exists.
	if wrapper.rule != nil && wrapper.rule.skipNoDelay {
		if err := streamConfirmNoDelay(conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if done := ctx.Done(); done != nil {
		go func() {
			select {
			case <-done:
				// Cancellation is one more terminal shutdown owner. It must go
				// through the same once-guarded teardown as Close (cancel and
				// release the platform sender, close the underlying connection
				// exactly once) instead of closing the raw conn behind the
				// wrapper, which left the wrapper's state and sender untouched
				// and allowed a second underlying Close.
				wrapper.closed.Store(true)
				wrapper.abortFlush()
			case <-wrapper.cancel:
			}
		}()
	}
	return wrapper, nil
}

func newStreamError(message string) error {
	return streamError(message)
}

// newNativeSender builds the segment sender. A deferred TFO facade has no
// native socket before the first transformed write, so the first segment is
// sent through the pending Write (carrying the TFO data) and the established
// native sender is created immediately afterwards. No raw fast path is
// exposed in either case.
func (c *streamConn) newNativeSender() (streamSender, error) {
	if pending, isPending := earlySendConn(c.Conn); isPending {
		return newFirstSendSender(pending, c.Conn, func() (streamSender, error) {
			established := pending.Established()
			if established == nil {
				return nil, newStreamError("desync: deferred native sender requires an established connection")
			}
			return c.config.native.NewSender(established, c.currentWriteDeadline)
		}), nil
	}
	// A deferred facade can already be activated by a read-first or empty
	// write before the first transformed segment needs a native sender. In
	// that case the pending facade is no longer the native source: the
	// established connection (which carries the same attempt's lease
	// capability) is. Passing the facade itself would either hide the
	// admission owner or produce a second, unrelated socket.
	if pending, isDeferred := c.Conn.(deferredNativeConn); isDeferred {
		established := pending.Established()
		if established == nil {
			if pending.NativePending() {
				return nil, newStreamError("desync: deferred native sender requires an established connection")
			}
			// Activation is in flight or still publishing the call deadlines:
			// the established sender does not exist yet. Refuse before any
			// native effect instead of sending through the facade.
			return nil, newStreamError("desync: deferred native sender is not published yet")
		}
		return c.config.native.NewSender(established, c.currentWriteDeadline)
	}
	return c.config.native.NewSender(c.Conn, c.currentWriteDeadline)
}

// NeedHandshake forwards the deferred state of the wrapped connection. The
// stream wrapper must never hide a pending first send from the connection
// manager, otherwise a server-first flow would block without activating the
// single owned attempt. The deferred seam is enough on its own: a connection
// that only implements NativePending/Established is still a pending first send.
func (c *streamConn) NeedHandshake() bool {
	if earlyConn, ok := c.Conn.(interface{ NeedHandshake() bool }); ok {
		return earlyConn.NeedHandshake()
	}
	if pending, ok := c.Conn.(deferredNativeConn); ok {
		return pending.NativePending()
	}
	return false
}

// NeedHandshakeForWrite is the current early-writer interface.
func (c *streamConn) NeedHandshakeForWrite() bool {
	return c.NeedHandshake()
}

type streamError string

func (e streamError) Error() string { return string(e) }

func (r *streamRule) hasMethods() bool {
	return r != nil && (r.httpTamper != nil || r.tlsRecord != nil || r.split != nil)
}

func (r *streamRule) splitOOBByte() byte {
	if r == nil || r.split == nil {
		return 0
	}
	return r.split.oobByte
}

// Write consumes p into bounded blocks and sends every block that can be
// classified. A completely unrecognised prefix is sent immediately; HTTP and
// TLS prefixes are held only until a host/ClientHello is complete, until the
// bounded probe is exhausted or until the hold timer releases the prefix.
//
// The returned count reports how many bytes of p the wrapper now owns, which is
// exactly the set a caller must not send again:
//
//   - bytes whose block reached the connection are owned (through split
//     fragments, the OOB urgent byte, the disorder TTL or a transformation);
//   - bytes retained in the block buffer are owned too, because the hold timer,
//     the next Write or the bounded Close flush delivers them;
//   - bytes still unsent when a send error makes the buffer unfushable are not
//     owned, so they are reported as not written.
//
// Only original caller bytes are counted: bytes the wrapper adds on the wire
// (the single OOB byte) are never part of p. A block whose payload was
// rewritten into a different byte sequence (HTTP tamper, TLS record splice) is
// accounted as a unit - it counts when its whole transformed payload reached
// the connection, and contributes nothing when the send stopped inside it,
// because there is no byte boundary back into p. A block that is only split or
// OOB-marked keeps a byte-for-byte mapping, so a partial send of it is counted
// exactly. Any send error is sticky, so no counted byte is flushed or sent
// again afterwards.
func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	defer func() {
		// Keep the fallback timer in sync with the retained prefix. It is
		// only armed for an incomplete first block; a failed write has no
		// retained prefix left to release.
		if c.writeErr == nil && c.firstBlockHolding() {
			c.armHoldTimerLocked()
		} else if c.writeErr != nil {
			c.stopHoldTimerLocked()
		}
	}()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		// An explicit empty write is the connection manager's "connect now"
		// signal for a server-first flow or a flow whose payload has not
		// arrived. A deferred TFO connection must receive it, otherwise the
		// single owned attempt is created later by Read without the bounded
		// handshake deadline. Nothing is buffered or transformed here: the
		// pending facade only creates the empty owned attempt.
		if pending, isPending := c.Conn.(deferredNativeConn); isPending && pending.NativePending() && len(c.pending) == 0 && !c.firstBlockDone {
			return c.Conn.Write(p)
		}
		return 0, nil
	}
	// Accounting state. leftover is the buffered prefix owed to earlier calls:
	// it is delivered first, so a partial delivery pays it down before any byte
	// of p can be counted. removed counts bytes taken off the front of the
	// buffer as delivered and writtenDirect counts bytes of p written straight
	// from remaining on the pass-through path.
	remaining := p
	leftover := len(c.pending)
	writtenDirect := 0
	removed := 0
	owned := func() int {
		appended := len(p) - len(remaining) - writtenDirect
		delivered := removed - leftover
		if delivered < 0 {
			delivered = 0
		}
		if delivered > appended {
			delivered = appended
		}
		return writtenDirect + delivered
	}
	for {
		if c.passThrough {
			if len(c.pending) > 0 {
				written, err := writeFullN(c.Conn, c.pending)
				removed += written
				if err != nil {
					c.writeErr = err
					return owned(), err
				}
				c.pending = c.pending[:0]
			}
			if len(remaining) > 0 {
				written, err := writeFullN(c.Conn, remaining)
				writtenDirect += written
				remaining = remaining[written:]
				if err != nil {
					c.writeErr = err
					return owned(), err
				}
				remaining = nil
			}
			return len(p), nil
		}
		if len(remaining) > 0 {
			space := streamBlockSize - len(c.pending)
			if space == 0 {
				delivered, err := c.flushOneLocked()
				removed += delivered
				if err != nil {
					return owned(), err
				}
				continue
			}
			take := len(remaining)
			if take > space {
				take = space
			}
			c.pending = append(c.pending, remaining[:take]...)
			remaining = remaining[take:]
		}
		holding := c.firstBlockHolding()
		if !holding {
			flushed := false
			for len(c.pending) > 0 {
				if !c.firstBlockDone && c.firstBlockHolding() {
					break
				}
				delivered, err := c.flushOneLocked()
				removed += delivered
				if err != nil {
					return owned(), err
				}
				flushed = true
				if c.passThrough {
					break
				}
			}
			_ = flushed
		}
		if len(remaining) == 0 {
			return len(p), nil
		}
	}
}

// firstBlockHolding reports whether the first block must stay buffered until
// more bytes arrive. It is bounded by the tpws block size, the probe sizes and
// the hold timer; a structurally complete HTTP header or TLS ClientHello is
// never held, even when it carries no SNI.
func (c *streamConn) firstBlockHolding() bool {
	if c.firstBlockDone || len(c.pending) == 0 {
		return false
	}
	if len(c.pending) >= streamMaxFirstBlock {
		return false
	}
	protocol, needMore := classifyStreamBlock(c.pending)
	if needMore {
		return true
	}
	switch protocol {
	case ProtocolHTTP:
		if !c.config.dependsOnHost() {
			return false
		}
		if streamBlockFacts(ProtocolHTTP, c.pending).HostKnown {
			return false
		}
		// End of the header block: the host cannot appear later.
		if bytes.Contains(c.pending, []byte("\r\n\r\n")) || bytes.Contains(c.pending, []byte("\n\n")) {
			return false
		}
		return len(c.pending) < streamHTTPProbe
	case ProtocolTLS:
		// collectTLSHandshake reports framing completeness independently of
		// SNI presence, so a complete ClientHello without a server_name
		// extension is released instead of pending forever on a shared
		// parser that treats "no SNI" as "not complete".
		if _, _, complete := collectTLSHandshake(c.pending); complete {
			return false
		}
		return len(c.pending) < streamTLSProbe
	default:
		return false
	}
}

// armHoldTimerLocked starts the bounded release timer for a retained first
// block. Every new Write that makes progress restarts the deadline, so a
// slow-but-progressing client is not cut off, while a stalled one is released
// without requiring a further Write or Close.
func (c *streamConn) armHoldTimerLocked() {
	c.stopHoldTimerLocked()
	c.holdGeneration++
	generation := c.holdGeneration
	c.holdTimer = time.AfterFunc(streamFirstBlockHoldLimit, func() {
		c.releaseHeldBlock(generation)
	})
}

func (c *streamConn) stopHoldTimerLocked() {
	if c.holdTimer != nil {
		c.holdTimer.Stop()
		c.holdTimer = nil
	}
}

// releaseHeldBlock is the timer fallback: it flushes the retained prefix with
// the normal transformations and ordering, exactly like a Close flush, instead
// of dropping it or waiting for more client data.
func (c *streamConn) releaseHeldBlock(generation uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.holdGeneration {
		// Superseded by a newer Write; that write owns the current timer.
		return
	}
	c.holdTimer = nil
	if c.closed.Load() || c.writeErr != nil || c.firstBlockDone || len(c.pending) == 0 {
		return
	}
	if !c.firstBlockHolding() {
		return
	}
	for len(c.pending) > 0 {
		if _, err := c.flushOneLocked(); err != nil {
			c.writeErr = err
			return
		}
		if c.passThrough {
			break
		}
	}
}

// flushOneLocked processes exactly one ready block and reports how many bytes
// it delivered. The count is in block-buffer coordinates: the whole block when
// its payload reached the connection in full, the byte-for-byte prefix when an
// unchanged payload stopped early, and zero when the send failed before any
// byte of the block could be accounted (an error before the first send, or a
// partially sent rewritten payload with no offset mapping).
func (c *streamConn) flushOneLocked() (int, error) {
	if len(c.pending) == 0 {
		return 0, nil
	}
	length := len(c.pending)
	if length > streamBlockSize {
		length = streamBlockSize
	}
	block := c.pending[:length]
	delivered, err := c.processBlock(block)
	if err != nil {
		c.writeErr = err
		return delivered, err
	}
	if c.passThrough {
		written, err := writeFullN(c.Conn, c.pending)
		if err != nil {
			c.writeErr = err
			return written, err
		}
		c.pending = c.pending[:0]
		c.stopHoldTimerLocked()
		return written, nil
	}
	copy(c.pending, c.pending[length:])
	c.pending = c.pending[:len(c.pending)-length]
	c.firstBlockDone = true
	c.stopHoldTimerLocked()
	return length, nil
}

func (c *streamConn) processBlock(block []byte) (int, error) {
	originalLength := len(block)
	blockProtocol, _ := classifyStreamBlock(block)
	if !c.stageResolved {
		c.stageResolved = true
		c.protocol = blockProtocol
		facts := c.facts
		facts.Transport = TransportTCP
		facts.Protocol = blockProtocol
		if set := streamBlockFacts(blockProtocol, block); set.HostKnown {
			facts.Host = set.Host
			facts.HostKnown = true
		}
		c.rule = c.config.selectRule(facts)
		c.facts = facts
		c.prepareLearningObservation(c.rule, facts)
		if !c.rule.hasMethods() {
			c.passThrough = true
			return 0, nil
		}
		if c.rule.hasNativeSend() {
			sender, err := c.newNativeSender()
			if err != nil {
				return 0, err
			}
			// Publication is the ownership checkpoint: a factory that crossed
			// the terminal shutdown is refused here (and its resource released
			// exactly once) instead of being used for a send after Close.
			if !c.adoptSender(sender) {
				return 0, net.ErrClosed
			}
			c.sender = sender
		} else {
			c.sender = &plainSender{conn: c.Conn}
		}
	}
	blockNumber := c.blockIndex + 1
	if !c.rule.inRange(blockNumber, c.streamOffset) {
		written, err := writeFullN(c.Conn, block)
		if err != nil {
			return written, err
		}
		c.blockIndex++
		c.streamOffset += uint64(originalLength)
		return written, nil
	}
	data := make([]byte, len(block), streamBlockCapacity)
	copy(data, block)
	positionSet := streamBlockFacts(blockProtocol, block)
	var splitPositions []int
	if blockProtocol == ProtocolTLS && c.rule.split != nil {
		splitPositions = resolveStreamSplitPositions(c.rule.split.positions, positionSet, ProtocolTLS)
	}
	if blockProtocol == ProtocolHTTP && c.rule.httpTamper != nil {
		transformed, err := applyHTTPTamper(data, c.rule.httpTamper, c.random)
		if err != nil {
			return 0, err
		}
		data = transformed
	}
	if blockProtocol == ProtocolTLS && c.rule.tlsRecord != nil {
		data, splitPositions, _ = splitTLSRecord(data, c.rule.tlsRecord, positionSet, splitPositions)
	}
	if blockProtocol == ProtocolHTTP && c.rule.split != nil {
		splitPositions = resolveStreamSplitPositions(c.rule.split.positions,
			streamBlockFacts(ProtocolHTTP, data), ProtocolHTTP)
	}
	if blockProtocol == ProtocolUnknown && c.rule.split != nil && c.rule.split.anyProtocol {
		splitPositions = resolveStreamSplitPositions(c.rule.split.positions, positionSet, ProtocolUnknown)
	}
	valid := splitPositions[:0]
	for _, position := range splitPositions {
		if position > 0 && position < len(data) {
			valid = append(valid, position)
		}
	}
	written, err := c.sendBlock(data, valid, blockProtocol)
	if err != nil {
		// A rewritten payload has no byte boundary back into the caller
		// buffer, so a send that stopped inside it accounts for nothing; an
		// unchanged payload maps byte for byte and reports its prefix.
		if len(data) == originalLength && bytes.Equal(data, block) {
			return written, err
		}
		return 0, err
	}
	c.blockIndex++
	c.streamOffset += uint64(originalLength)
	return originalLength, nil
}

// sendBlock sends transformed bytes, applying tpws fragment order, low-TTL
// disorder and the single OOB byte on the first fragment. It returns the number
// of bytes of data that reached the connection; the OOB urgent byte is an extra
// wire byte and is never part of that count.
func (c *streamConn) sendBlock(data []byte, positions []int, blockProtocol Protocol) (int, error) {
	rule := c.rule
	if rule == nil {
		return writeFullN(c.Conn, data)
	}
	native := rule.hasNativeSend()
	if len(positions) == 0 {
		// tpws applies fix-seg only inside the multisplit loop
		// (tpws_conn.c:1289-1307); an unsplit block never waits.
		if !native {
			return writeFullN(c.Conn, data)
		}
		sent, err := c.sender.Send(data, sendOptions{cork: !rule.skipNoDelay})
		// A native send may be short under backpressure (or make no progress
		// at all). The unsent tail is real stream data: forward it on the
		// same connection instead of acknowledging bytes that were dropped.
		// This mirrors tpws send_or_buffer in the unsplit branch.
		return c.forwardUnsent(data, 0, sent, err)
	}
	from := 0
	for index := 0; index <= len(positions); index++ {
		to := len(data)
		if index < len(positions) {
			to = positions[index]
		}
		if to <= from {
			continue
		}
		disorder := index%2 == 0 && index < len(positions) && rule.effectiveDisorder(blockProtocol)
		oob := index == 0 && rule.effectiveOOB(blockProtocol)
		segment := data[from:to]
		if !native {
			written, err := writeFullN(c.Conn, segment)
			if err != nil {
				return from + written, err
			}
			from = to
			continue
		}
		if rule.fixSegSet && !c.sender.WaitNotSent(rule.fixSeg) {
			// Upstream reports a segmentation failure and continues.
		}
		options := sendOptions{oob: oob, oobByte: rule.splitOOBByte(), cork: !rule.skipNoDelay}
		if disorder {
			options.ttl = 1
		}
		if index == 0 {
			// The first fragment is the deferred TFO payload. A rule that
			// cannot be carried by the first send is refused here, before any
			// byte of the block exists; forwarding it through the short-send
			// path would send the block unsplit and drop the transformation.
			if guard, isGuarded := c.sender.(firstSendGuard); isGuarded {
				if guardErr := guard.refuseFirstSend(options); guardErr != nil {
					return from, guardErr
				}
			}
		}
		sent, err := c.sender.Send(segment, options)
		if err != nil || sent < len(segment) {
			// tpws cancels the split when a fragment cannot be sent
			// immediately and forwards the remaining bytes unsplit.
			return c.forwardUnsent(data, from, sent, err)
		}
		from = to
	}
	return len(data), nil
}

// forwardUnsent preserves the bytes of a block that a native send did not
// consume. offset is the block position the send started at; sent counts only
// bytes of that fragment, so the tail begins at offset+sent. The original send
// error, if any, is returned after the bytes are preserved, and the returned
// count covers the block prefix that is on the connection - the failed fragment
// progress plus everything the forwarding write accepted.
//
// A send whose terminal completion could not be established is the exception:
// the provider may have transmitted an unknown prefix of the block, so the
// remaining bytes are not "unsent" and forwarding them here would duplicate
// stream data. Such a send reports only the block prefix that is provably on
// the connection and its unchanged error; the operation keeps its own
// completion owner until the provider proves the terminal state.
func (c *streamConn) forwardUnsent(data []byte, offset int, sent int, sendErr error) (int, error) {
	if errors.Is(sendErr, ErrAdmissionRefused) {
		// A refused admission denies the protected native effect from this
		// point on, so the tail is never forwarded: that would be I/O on an
		// attempt whose admission gate already closed. The fragment itself can
		// still carry proven progress - the deferred first write delivers its
		// TFO data before the established factory is refused - so the block
		// prefix stays offset+sent and no count is invented for an uncounted
		// receipt.
		if sent < 0 {
			sent = 0
		}
		if remaining := len(data) - offset; sent > remaining {
			sent = remaining
		}
		return offset + sent, sendErr
	}
	if streamCompletionUnproven(sendErr) {
		return offset, sendErr
	}
	if sent < 0 {
		sent = 0
	}
	if remaining := len(data) - offset; sent > remaining {
		sent = remaining
	}
	tail := data[offset+sent:]
	written := offset + sent
	if len(tail) > 0 {
		forwarded, err := writeFullN(c.Conn, tail)
		written += forwarded
		if err != nil {
			return written, err
		}
	}
	return written, sendErr
}

func (c *streamConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.observeInbound(p[:n])
	} else if err != nil {
		c.observeInboundFailure()
	}
	return n, err
}

// prepareLearningObservation decides the upstream b_ah_check applicability for
// this connection: the rule carries rule.learning, the host is known, it is not
// excluded and it is not already in the engine-owned learned set. It is called
// once, after the first outbound block resolved the rule.
func (c *streamConn) prepareLearningObservation(rule *streamRule, facts MatchFacts) {
	if rule == nil || rule.learning == nil || !facts.HostKnown {
		return
	}
	value, err := normalizeLearnedHost(facts.Host)
	if err != nil {
		return
	}
	if rule.match.DomainsExclude.matches(value) {
		return
	}
	if c.config.engine != nil && c.config.engine.HostLearned(value) {
		return
	}
	c.learnRule = rule
	c.learnHost = value
	c.learnActive = true
}

// observeInbound ports tamper_in for the first inbound block. It copies at most
// one tpws receive block, never modifies the caller's bytes, and marks the
// observation cut off after the first decision. A non-HTTP first block resets
// the fail counter exactly like upstream (it is not a DPI redirect).
func (c *streamConn) observeInbound(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observed || !c.learnActive {
		return
	}
	if room := streamBlockSize - len(c.observeBuf); room > 0 {
		if len(data) > room {
			data = data[:room]
		}
		c.observeBuf = append(c.observeBuf, data...)
	}
	buffer := c.observeBuf
	if isHTTPReply(buffer) {
		if !httpReplyHeadersComplete(buffer) && len(buffer) < streamBlockSize {
			// Wait for the header block; the bound is one tpws receive block.
			return
		}
		c.observed = true
		if httpReplyLooksLikeDPIRedirect(buffer, c.learnHost) {
			c.recordLearningFailure()
			return
		}
		c.recordLearningSuccess()
		return
	}
	if isHTTPReplyPrefix(buffer) && len(buffer) < 15 {
		return
	}
	// Unknown first inbound data: upstream stops monitoring and resets the
	// counter, because a non-HTTP reply is not a DPI redirect.
	c.observed = true
	c.recordLearningSuccess()
}

// observeInboundFailure ports rst_in/hup_out: a read failure before the first
// inbound block is a failed host (server RST or a dropped connection). It is
// never applied after tamper_in has observed a block.
func (c *streamConn) observeInboundFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.observed || !c.learnActive {
		return
	}
	c.observed = true
	c.recordLearningFailure()
}

func (c *streamConn) recordLearningFailure() {
	if !c.learnActive || c.config.engine == nil {
		return
	}
	c.config.engine.recordStreamFailure(c.learnRule, c.learnHost)
}

func (c *streamConn) recordLearningSuccess() {
	if !c.learnActive || c.config.engine == nil {
		return
	}
	c.config.engine.RecordHostSuccess(c.learnHost)
}

func httpReplyHeadersComplete(data []byte) bool {
	return bytes.Contains(data, []byte("\r\n\r\n")) || bytes.Contains(data, []byte("\n\n"))
}

// isHTTPReplyPrefix reports whether data is a prefix of a plausible HTTP/1.x
// status line, so a short first read is not misclassified as unknown data.
func isHTTPReplyPrefix(data []byte) bool {
	const prefix = "HTTP/1.0 200 OK\r\n"
	if len(data) == 0 || len(data) > len(prefix) {
		return false
	}
	return bytes.HasPrefix([]byte(prefix), data)
}

// SetWriteDeadline records the deadline for native senders and delegates to
// the underlying connection. A raw WSASend on Windows cannot observe the Go
// poller deadline, so the Windows sender uses the recorded value itself. The
// value delegated is the effective deadline: while Close's bounded flush is
// running, a later caller deadline is capped by the flush bound, and a later
// caller update can never clear that bound.
func (c *streamConn) SetWriteDeadline(deadline time.Time) error {
	c.storeWriteDeadline(deadline)
	return c.publishWriteDeadline()
}

// SetDeadline records the write half for native senders and delegates both
// halves to the underlying connection. net.Conn requires every method to be
// safe for concurrent use, so a caller SetDeadline that is in flight while
// Close flushes must not be able to lift the flush bound either: the combined
// call is followed by the same capped write publication SetWriteDeadline uses,
// which leaves the effective (capped) value as the connection's write
// deadline. The read deadline is not part of the flush bound and is delegated
// unchanged.
func (c *streamConn) SetDeadline(deadline time.Time) error {
	c.storeWriteDeadline(deadline)
	combinedErr := c.Conn.SetDeadline(deadline)
	if combinedErr != nil {
		return combinedErr
	}
	return c.publishWriteDeadline()
}

// storeWriteDeadline records the caller deadline in the wrapper source. Zero
// means "no caller deadline"; the Close flush bound, when present, still
// applies through currentWriteDeadlineNanos. The value is stored before the
// generation is advanced, so a publisher that observes the new generation also
// observes this value.
func (c *streamConn) storeWriteDeadline(deadline time.Time) {
	if deadline.IsZero() {
		c.writeDeadline.Store(0)
	} else {
		c.writeDeadline.Store(deadline.UnixNano())
	}
	c.deadlineGeneration.Add(1)
}

// storeFlushDeadline installs the Close flush bound in the caller source's
// ordering: the value is visible before the generation advances.
func (c *streamConn) storeFlushDeadline(deadline time.Time) {
	c.flushDeadline.Store(deadline.UnixNano())
	c.deadlineGeneration.Add(1)
}

// currentWriteDeadline is the deadline source handed to a native sender. It is
// called by the platform sender on every segment, including senders created
// after the deadline was set, and returns the earlier of the caller deadline
// and the Close flush bound so no source can extend the flush past its limit.
func (c *streamConn) currentWriteDeadline() time.Time {
	return deadlineFromNanos(c.currentWriteDeadlineNanos())
}

// currentWriteDeadlineNanos returns the effective write deadline as UnixNano,
// with 0 meaning "no deadline" (later than every finite deadline).
func (c *streamConn) currentWriteDeadlineNanos() int64 {
	value := c.writeDeadline.Load()
	if flush := c.flushDeadline.Load(); flush != 0 && (value == 0 || flush < value) {
		value = flush
	}
	return value
}

// deadlineFromNanos converts a UnixNano deadline back to a time.Time; 0 is the
// zero time, i.e. no deadline.
func deadlineFromNanos(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value)
}

// publishWriteDeadline publishes the effective write deadline to every
// consumer: a platform sender that caches its own copy and the underlying
// connection.
//
// Computing an effective deadline and delivering it is not atomic, so the
// publication is ordered by the source generation instead of a fixed number of
// verification passes: after delegating, the source is read again and a value
// that changed while it was being delivered is delegated again, until the
// generation read before the last delivery is still current. A caller
// SetWriteDeadline/SetDeadline that computed its effective value before Close's
// flush installed the bound (and cleared or extended the deadline afterwards)
// can therefore never remain the last deadline on the connection, and the
// reversed update - a stricter caller deadline arriving while the flush
// publishes its bound - is corrected the same way.
func (c *streamConn) publishWriteDeadline() error {
	for {
		generation := c.deadlineGeneration.Load()
		c.publishSenderDeadline()
		if err := c.Conn.SetWriteDeadline(deadlineFromNanos(c.currentWriteDeadlineNanos())); err != nil {
			// The connection refused the value (normally because it is already
			// closed). The sender publication above has still converged on the
			// current source, so the error is reported without another
			// delegation attempt.
			return err
		}
		if c.deadlineGeneration.Load() == generation {
			return nil
		}
	}
}

// publishSenderDeadline is the single publication protocol for the active
// platform sender: adoption and every caller deadline update go through it, so
// there is exactly one ordered sequence in which sender deadlines are written.
// It is safe to call from the write path (adoption) and from concurrent
// SetWriteDeadline/SetDeadline callers: no lock is held across the publication,
// so a sender implementation that blocks cannot deadlock the connection, and
// Close never waits for it.
//
// Ordering comes from the source generation, not from a pass bound: the loop
// records the generation, publishes the effective value, and repeats when the
// generation moved, which proves that a newer deadline was stored while the
// publication was in flight. The value delivered last was therefore read after
// the last store the loop observed, and a publication never returns while it
// knows that a delivered value is stale. Any number of concurrent completed
// setters therefore ends with the sender enforcing the current effective
// deadline, while each iteration requires an actual source change, so the loop
// finishes as soon as the callers stop.
func (c *streamConn) publishSenderDeadline() {
	for {
		generation := c.deadlineGeneration.Load()
		if aware, ok := c.activeSenderSnapshot().(streamDeadlineSender); ok {
			aware.SetWriteDeadline(deadlineFromNanos(c.currentWriteDeadlineNanos()))
		}
		if c.deadlineGeneration.Load() == generation {
			return
		}
	}
}

// activeSenderSnapshot returns the published sender. The reference is only
// used for a deadline publication; a sender that a terminal shutdown has
// already released ignores later publications itself.
func (c *streamConn) activeSenderSnapshot() streamSender {
	c.senderMu.Lock()
	sender := c.activeSender
	c.senderMu.Unlock()
	return sender
}

// adoptSender publishes a freshly created sender unless the connection has
// already entered its terminal sender state. Publication and the terminal
// transition are decided under the same mutex, so a sender whose creation
// crosses Close is either owned by that shutdown (published before it) or
// disposed by this call (published after it) - it can never be published after
// the single shutdown already ran, which is what left the resource unreleased.
//
// The rejected sender is released immediately with its own idempotent Release
// and is never used for a send. adoptSender never blocks on the write mutex, so
// Close keeps its bounded, non-blocking teardown property.
func (c *streamConn) adoptSender(sender streamSender) bool {
	c.senderMu.Lock()
	if c.senderTerminal {
		c.senderMu.Unlock()
		disposeStreamSender(sender)
		return false
	}
	c.activeSender = sender
	c.senderMu.Unlock()
	// Publish the effective deadline once at registration as well. A platform
	// sender normally receives the live source at construction, but a sender
	// first constructed by Close's bounded flush must observe the flush bound
	// even if it caches the deadline instead of reading the source lazily.
	// The publication is the same generation-ordered protocol every caller
	// deadline update uses, so it cannot leave the sender with a value older
	// than a deadline setter that completed while the factory was running: the
	// publication repeats until the value it delivered is current, before the
	// sender is used for the first send.
	c.publishSenderDeadline()
	return true
}

// disposeStreamSender frees a sender that must not be used. The platform
// sender's Release is idempotent, so a resource can never be freed twice even
// when the shutdown and the arriving factory both reach it.
func disposeStreamSender(sender streamSender) {
	if releaser, ok := sender.(streamSenderReleaser); ok {
		releaser.Release()
	}
}

// shutdownSender is the single terminal sender transition: it aborts an
// in-flight overlapped send (release a Write blocked in it) and frees the
// platform resource exactly once. It runs at most once per connection because
// the terminal flag is checked and set under senderMu, and it never waits for
// the write mutex.
func (c *streamConn) shutdownSender() {
	c.senderMu.Lock()
	if c.senderTerminal {
		c.senderMu.Unlock()
		return
	}
	c.senderTerminal = true
	sender := c.activeSender
	c.activeSender = nil
	c.senderMu.Unlock()
	if canceler, ok := sender.(streamSenderCanceler); ok {
		canceler.CancelPending()
	}
	if releaser, ok := sender.(streamSenderReleaser); ok {
		releaser.Release()
	}
}

// Close releases the connection. It never waits for the write mutex: if a
// Write is blocked on the socket, Close first closes the underlying connection
// (and cancels a native overlapped send) to interrupt it. The pending-block
// flush only runs when Close can take the write mutex immediately, and it is
// bounded by streamCloseFlushLimit so a peer that stopped reading cannot
// deadlock Close. Repeated Close calls are safe and return the same result.
func (c *streamConn) Close() error {
	first := c.closed.CompareAndSwap(false, true)
	c.cancelOnce.Do(func() { close(c.cancel) })
	if first && c.mu.TryLock() {
		c.stopHoldTimerLocked()
		c.flushOnCloseLocked()
		c.mu.Unlock()
	}
	// The watchdog may have aborted the flush already; aborting is
	// idempotent and also covers the ordinary path where no flush ran. It is
	// also the single terminal sender transition (cancel + release), so Close
	// no longer releases the sender a second time here.
	c.abortFlush()
	return c.closeUnderlying()
}

// abortFlush performs the Close abort at most once: it cancels and releases the
// platform sender and closes the underlying connection, which releases a
// blocked plain write or overlapped send. Close uses it for its normal
// teardown, the flush watchdog uses it when the flush outlives its bound, and
// context cancellation uses it instead of closing the raw conn itself; the
// once keeps a racing owner from cancelling or releasing twice.
func (c *streamConn) abortFlush() {
	c.flushAbortOnce.Do(func() {
		c.shutdownSender()
		_ = c.closeUnderlying()
	})
}

// armFlushWatchdog bounds the lifetime of the Close flush itself and returns
// the stop function for the normal path.
//
// The bound cannot be enforced through the write-deadline slot alone. That slot
// is shared with every SetWriteDeadline/SetDeadline caller, net.Conn allows
// such calls concurrently with Close, and a caller that computed its effective
// value before flushDeadline was stored can still delegate that stale value
// after the flush published the bound: the connection is then left with a
// cleared or later deadline while the flush is blocked. Any finite number of
// verification passes can be defeated by one more stale writer, so the
// watchdog does not depend on the slot at all. It is armed with the effective
// deadline (the earlier of the caller deadline and the flush bound, so a
// stricter caller deadline is still honoured) plus streamFlushWatchdogGrace,
// and it performs the same abortFlush that Close performs for a blocked Write:
// the cancelled native send and closed connection release the flush no matter
// which deadline value the other writers left behind. The grace lets the
// ordinary case - a deadline the I/O layer actually observes - expire on its
// own first, so the watchdog only aborts a flush whose deadline was defeated.
func (c *streamConn) armFlushWatchdog() func() {
	deadline := c.currentWriteDeadline()
	if deadline.IsZero() {
		// Unreachable: flushDeadline is stored before this call, so the
		// effective deadline is always finite.
		return func() {}
	}
	timer := time.AfterFunc(time.Until(deadline)+streamFlushWatchdogGrace, c.abortFlush)
	return func() { timer.Stop() }
}

// flushOnCloseLocked performs the bounded graceful part of Close. It is only
// called with the write mutex held, i.e. when no Write can be in flight.
func (c *streamConn) flushOnCloseLocked() {
	if c.writeErr != nil || len(c.pending) == 0 {
		return
	}
	// Bound the flush so a blocked peer cannot hold Close forever. The bound
	// must reach every deadline source a platform sender can consult, not only
	// the underlying conn: the Windows overlapped sender reads the wrapper
	// deadline source and waits INFINITE on a zero deadline, and the sender
	// may first be constructed by this very flush. Publishing the bound in
	// flushDeadline makes currentWriteDeadline (and therefore any sender
	// created here) return the earlier of the caller deadline and this limit.
	// An earlier caller deadline stays stricter; the connection is closed
	// immediately afterwards, so the bound has no later effect.
	//
	// Two mechanisms cooperate, and only the second one carries the bound:
	//
	//   - the effective deadline (caller deadline or this bound, whichever is
	//     earlier) is published to a deadline-caching platform sender and to
	//     the underlying conn, so the I/O layer normally stops the write at
	//     the bound on its own;
	//   - the flush watchdog enforces the same deadline on the connection
	//     lifetime. When it fires it runs abortFlush - the cancel-and-close
	//     Close itself performs for a blocked Write - which releases the
	//     blocked write or send whatever value the shared deadline slot
	//     currently holds.
	//
	// The watchdog is what makes the bound independent of other deadline
	// writers. net.Conn allows SetWriteDeadline/SetDeadline concurrently with
	// Close, so any number of callers may publish a value they computed before
	// this store, in any order, and one of those publications can be the last
	// deadline the connection sees. The generation-ordered publication above
	// repairs that (every publisher repeats until its delivery is current, so a
	// finite pass bound cannot be exhausted), but a lifetime abort does not need
	// to depend on any deadline slot at all.
	c.storeFlushDeadline(time.Now().Add(streamCloseFlushLimit))
	stopWatchdog := c.armFlushWatchdog()
	defer func() {
		stopWatchdog()
		// Re-assert the effective deadline for observers. This clamp is not
		// what bounds Close: a stale publication still in flight can land
		// after it. Every publication that starts after the store above reads
		// the bound, and this clamp repairs the ordinary adversarial case
		// where the stale publication landed while the flush was blocked.
		_ = c.publishWriteDeadline()
	}()
	_ = c.publishWriteDeadline()
	if c.passThrough {
		if err := writeFull(c.Conn, c.pending); err != nil {
			c.writeErr = err
			return
		}
		c.pending = c.pending[:0]
		return
	}
	length := len(c.pending)
	if length > streamBlockSize {
		length = streamBlockSize
	}
	if _, err := c.processBlock(c.pending[:length]); err != nil {
		c.writeErr = err
		return
	}
	if c.passThrough {
		if err := writeFull(c.Conn, c.pending); err != nil {
			c.writeErr = err
			return
		}
		c.pending = c.pending[:0]
		return
	}
	copy(c.pending, c.pending[length:])
	c.pending = c.pending[:len(c.pending)-length]
	for len(c.pending) > 0 {
		if _, err := c.flushOneLocked(); err != nil {
			return
		}
	}
}

func (c *streamConn) closeUnderlying() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

var _ net.Conn = (*streamConn)(nil)
var _ io.Reader = (*streamConn)(nil)

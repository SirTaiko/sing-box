//go:build windows

package desync

import (
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/windows"
)

// Windows keeps ordinary tpws stream behavior: OOB and disorder are available
// through WSASend, TCP_NODELAY is available through setsockopt. TCP_MAXSEG,
// TCP_CORK and the TCP_INFO fix-seg wait have no Windows equivalent in tpws and
// are rejected at compile time (U3 source applicability); OOB+disorder is
// explicitly unsupported upstream outside Linux and rejected the same way.
//
// A raw send on Windows cannot rely on syscall.RawConn.Write: the Go
// implementation calls the callback without poller or deadline preparation, so
// WSAEWOULDBLOCK would surface as an error instead of waiting and an expired
// write deadline would be ignored. Native segments therefore use an overlapped
// WSASend with a completion event: an already expired deadline is rejected
// before the call, readiness is a bounded wait on that event, deadline updates
// pushed by the wrapper retime the abort of a still-pending operation (so a
// shorten, extend or clear takes effect on the pending send), the submitted
// backing store stays reachable until the terminal completion, and Close
// cancels the pending operation. An authoritative count comes from a
// successful WSAGetOverlappedResult and is forwarded as the unsent stream tail
// by the wrapper. A failed count query - including the aborted status that
// cancelling the operation produces - establishes that the operation reached a
// terminal state but does not establish a transferred prefix: the wrapper is
// told the prefix is unknown and must not replay the block.

func platformStreamCaps() streamCapsInfo {
	return streamCapsInfo{
		mss:         false,
		fixSeg:      false,
		oob:         true,
		disorder:    true,
		oobDisorder: false,
		skipNoDelay: true,
	}
}

func newPlatformStreamNative() streamNative {
	return windowsStreamNative{}
}

type windowsStreamNative struct{}

func (windowsStreamNative) Prepare(fd uintptr, config streamSocketConfig) error {
	if config.mss > 0 {
		return E.New("desync: mss is not implemented on Windows")
	}
	if config.skipNoDelay {
		err := windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_NODELAY, 0)
		if err != nil {
			return E.Cause(err, "set TCP_NODELAY=0")
		}
	}
	return nil
}

func (windowsStreamNative) NewSender(conn net.Conn, deadline func() time.Time) (streamSender, error) {
	// The sender factory is a native effect: it acquires its admission
	// reference before creating the completion event, so a factory that races
	// Close is either refused before any native resource exists or owns the
	// already-charged attempt until Release and its last operation retire.
	source, holder, release, err := acquireStreamNativeSource(conn)
	if err != nil {
		return nil, err
	}
	syscallConn, ok := source.(syscall.Conn)
	if !ok {
		release()
		return nil, E.New("desync: stream native send requires a syscall.Conn")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		release()
		return nil, E.Cause(err, "obtain raw stream socket")
	}
	var handle windows.Handle
	if controlErr := raw.Control(func(fd uintptr) { handle = windows.Handle(fd) }); controlErr != nil {
		release()
		return nil, E.Cause(controlErr, "obtain raw stream socket")
	}
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		release()
		return nil, E.Cause(err, "create stream send completion event")
	}
	sender := &windowsSender{
		handle:          handle,
		event:           event,
		family:          streamRemoteFamily(source),
		deadline:        deadline,
		source:          deadline,
		holder:          holder,
		resourceRelease: release,
	}
	sender.overlapped.HEvent = event
	return sender, nil
}

// Injected seams: the Windows-only unit tests replace these to exercise the
// deadline/cancellation/partial-count lifecycle without a real socket. They are
// package variables, never changed in production.
var (
	windowsWSASend                = windows.WSASend
	windowsWSAGetOverlappedResult = windows.WSAGetOverlappedResult
	windowsCancelIoEx             = windows.CancelIoEx
	// windowsWaitForSingleObject is the completion-event wait. It is a seam for
	// the completion-ownership tests: a wait that fails says nothing about the
	// operation, and a real failure cannot be provoked without an invalid event
	// handle.
	windowsWaitForSingleObject = windows.WaitForSingleObject
)

type windowsSender struct {
	handle   windows.Handle
	event    windows.Handle
	family   int
	deadline func() time.Time

	// holder is the admission capability of the already admitted attempt this
	// sender was built on. Every native submission takes one operation
	// reference through it before touching the socket; a refused acquisition
	// means the attempt's admission gate closed and no I/O may start.
	holder nativeAdmissionHolder
	// resourceRelease discharges the sender-resource reference acquired before
	// the completion event existed. It runs exactly once, after Release was
	// requested and the last pending operation retired.
	resourceRelease func()
	// opRelease discharges the operation reference of the current submission.
	// Ordinary terminal retirement releases it; an unknown terminal status
	// keeps it with the autonomous completion owner.
	opRelease func()

	// source is the live connection deadline this sender was constructed with.
	// NewSender receives the wrapper's deadline function, not a snapshot, and a
	// publication never replaces this reference. A submission can therefore
	// always be checked against the authoritative value: a stale publication
	// that is still in flight can no longer permit I/O after the caller's
	// expired deadline setter completed. The published value in deadline stays
	// authoritative for the pending wait and the abort timer, so an extension
	// or a clear still applies to an operation already on the wire.
	source func() time.Time

	mu          sync.Mutex
	overlapped  windows.Overlapped
	sending     bool
	completed   bool
	canceled    bool
	released    bool
	eventClosed bool

	// completionUnproven records that the terminal completion of the submitted
	// operation could not be established. finishSend then hands the operation
	// to the autonomous completion owner instead of retiring it.
	completionUnproven bool

	// retained is true while the autonomous completion owner holds the exact
	// submitted allocation, the OVERLAPPED and the completion event of an
	// operation whose terminal receipt is still outstanding. The sender
	// refuses new sends meanwhile, so the single OVERLAPPED can never be
	// reused and admission stays bounded by one retained operation.
	retained bool

	// submitted is the exact backing store handed to WSASend, including the
	// private OOB allocation the caller cannot root. It is set before the
	// submission and cleared only once a terminal completion has been
	// established: WSASend requires the buffer to stay valid for the whole
	// asynchronous operation, and a local slice variable is not a GC root while
	// this goroutine is blocked in WaitForSingleObject. Without a retained
	// reference the private OOB copy can be finalized, and its storage reused,
	// while the kernel still owns the buffer.
	submitted []byte

	// deadlineFired records that the deadline watcher aborted the outstanding
	// operation, so its authoritative completion count is still reported and
	// the error is os.ErrDeadlineExceeded rather than the raw abort status.
	deadlineFired bool

	// deadlineTimer retimes the pending operation's abort when the caller
	// shortens, extends or clears the write deadline. It exists because the
	// wait itself cannot observe an update: net.Conn allows SetWriteDeadline
	// concurrently with a pending Write, and a wait computed from one snapshot
	// would otherwise ignore every later value.
	deadlineTimer *time.Timer
}

func (s *windowsSender) Send(data []byte, options sendOptions) (int, error) {
	s.mu.Lock()
	if s.released || s.canceled || s.sending {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	expired := s.deadlineExpiredLocked()
	s.mu.Unlock()
	if expired {
		// An already expired deadline must keep the bytes out of the socket:
		// submitting them would be I/O the caller never authorised.
		return 0, os.ErrDeadlineExceeded
	}
	// The operation reference is the admission gate of this submission: it is
	// taken before any socket option or WSASend, and a refusal (closed engine
	// or closed attempt) returns the refusal instead of falling back to plain
	// I/O. It references the already charged attempt, never a new slot.
	if s.holder == nil {
		return 0, E.New("desync: native stream send requires an admission owner")
	}
	opRelease, err := s.holder.AcquireNativeHold()
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	if s.released || s.canceled || s.sending {
		s.mu.Unlock()
		opRelease()
		return 0, net.ErrClosed
	}
	s.sending = true
	s.completionUnproven = false
	s.opRelease = opRelease
	s.mu.Unlock()
	defer s.finishSend()

	if options.cork {
		// TCP_CORK does not exist on Windows; tpws does not cork there either.
		options.cork = false
	}
	// The submitted allocation is captured by the operation owner before
	// submission: an operation that outlives the caller keeps exactly this
	// backing store, so a later send cannot change what was handed to WSASend.
	// The stream wrapper always passes a per-block copy, so the storage it
	// submits is owned by this operation and is never reused.
	buffer := data
	if options.oob {
		buffer = make([]byte, len(data)+1)
		copy(buffer, data)
		buffer[len(data)] = options.oobByte
	}
	return s.sendBuffer(buffer, options)
}

// deadlineExpiredLocked reports whether either deadline authority says the
// write deadline has passed. The published value is what the pending wait and
// the abort timer use; the live source is the connection's authoritative value
// and closes the window in which a stale publication could still permit I/O
// after the caller's setter completed. The check only ever tightens: waits are
// still timed from the published value, so a shortened, extended or cleared
// deadline reaches an already pending operation.
func (s *windowsSender) deadlineExpiredLocked() bool {
	if windowsDeadlineExpired(s.deadline) {
		return true
	}
	if s.source != nil {
		return windowsDeadlineExpired(s.source)
	}
	return false
}

// sendBuffer performs one overlapped WSASend and returns the bytes the kernel
// reports as transferred, with the deadline mapped to os.ErrDeadlineExceeded.
func (s *windowsSender) sendBuffer(buffer []byte, options sendOptions) (int, error) {
	ttlLevel, ttlOption, previousTTL, ttlChanged, err := windowsPrepareTTL(s.handle, options.ttl, s.family)
	if err != nil {
		return 0, err
	}
	defer func() {
		if ttlChanged {
			_ = windows.SetsockoptInt(s.handle, ttlLevel, ttlOption, previousTTL)
		}
	}()
	if len(buffer) == 0 {
		return 0, nil
	}
	if err = windows.ResetEvent(s.event); err != nil {
		return 0, err
	}
	var (
		wsabuf windows.WSABuf
		flags  uint32
	)
	wsabuf.Len = uint32(len(buffer))
	wsabuf.Buf = &buffer[0]
	if options.oob {
		flags = windows.MSG_OOB
	}
	s.mu.Lock()
	if s.released || s.canceled {
		s.mu.Unlock()
		return 0, net.ErrClosed
	}
	// Re-check immediately before the submission: the deadline may have
	// expired while the socket options and the completion event were prepared.
	if s.deadlineExpiredLocked() {
		s.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	s.overlapped.Internal = 0
	s.overlapped.InternalHigh = 0
	s.overlapped.Offset = 0
	s.overlapped.OffsetHigh = 0
	s.submitted = buffer
	s.deadlineFired = false
	s.completed = false
	sendErr := windowsWSASend(s.handle, &wsabuf, 1, nil, flags, &s.overlapped, nil)
	s.mu.Unlock()
	if sendErr == nil {
		// WSASend reported the completed operation synchronously, so the
		// terminal state is established and only the count is queried.
		return s.collectCompletion(true)
	}
	if sendErr != windows.ERROR_IO_PENDING {
		return 0, sendErr
	}
	return s.waitPending()
}

// waitPending waits for the outstanding overlapped send to reach its terminal
// completion. The wait is split by the current deadline and re-reads it after
// every slice, while the deadline watcher cancels the operation as soon as the
// deadline expires. Together they make a shortened deadline abort the pending
// send, and an extended or cleared deadline keep it alive without losing the
// authoritative completion count.
func (s *windowsSender) waitPending() (int, error) {
	for {
		s.mu.Lock()
		if s.canceled {
			s.mu.Unlock()
			_ = windowsCancelIoEx(s.handle, &s.overlapped)
			// The cancellation was decided while the operation had not been
			// observed as complete, so only the blocking query can establish
			// the terminal state.
			return s.collectCompletion(false)
		}
		timeout, expired := windowsSendTimeout(s.deadline)
		if expired {
			s.mu.Unlock()
			_ = windowsCancelIoEx(s.handle, &s.overlapped)
			// This path owns the terminal decision: stop the watcher so a timer
			// that fires afterwards cannot claim an operation that is already
			// being reaped.
			s.finishDeadline()
			// No completion notification was observed on this path, so the
			// blocking query has to establish the terminal state itself.
			return s.deadlineCompletion(false)
		}
		s.armDeadlineTimerLocked()
		s.mu.Unlock()
		event, waitErr := windowsWaitForSingleObject(s.event, timeout)
		if waitErr != nil {
			// A failing wait says nothing about the operation. Abort it, then
			// harvest its terminal state: a WSASend that completed successfully
			// while the wait failed carries an authoritative prefix, and
			// reporting it as zero would make the wrapper forward those bytes
			// again. A harvest that cannot even prove the terminal state keeps
			// the operation owned.
			s.finishDeadline()
			_ = windowsCancelIoEx(s.handle, &s.overlapped)
			return s.completionResult(s.queryCompletion(true), waitErr)
		}
		if event == uint32(windows.WAIT_TIMEOUT) {
			// The wait slice ended. Either the deadline has expired or a
			// concurrent SetWriteDeadline extended or cleared it; re-read the
			// value instead of assuming the deadline won.
			continue
		}
		// The completion event was signalled and this wait consumed the single
		// auto-reset signal: the operation is terminal from here on, whatever
		// the caller-cause selection below decides.
		return s.collectCompletion(true)
	}
}

// collectCompletion turns the completion state into the send result. terminal
// is true when the terminal completion was already established: the completion
// event was signalled, or WSASend returned synchronously. The deadline and
// cancellation decisions are snapshotted under the same mutex that the watcher
// and Close use, so exactly one of them owns this completion, and the
// established terminal fact is passed on: a caller-cause selection may decide
// which error the caller sees, but it may not discard a receipt the provider
// already delivered.
func (s *windowsSender) collectCompletion(terminal bool) (int, error) {
	deadlineFired, canceled := s.finishDeadline()
	if deadlineFired {
		return s.deadlineCompletion(terminal)
	}
	if canceled {
		return s.cancelCompletion(terminal)
	}
	query := s.providerQuery(terminal)
	// The completion was observed, but the provider may have refused to report
	// the transferred prefix. completionResult marks that case instead of
	// reporting "zero bytes accepted": the operation is retired (it is
	// finished), while the wrapper is told that the prefix is unknown and must
	// not be replayed.
	return s.completionResult(query, query.err)
}

// deadlineCompletion reaps an operation aborted by the write deadline. The
// authoritative count is reported with os.ErrDeadlineExceeded. When the
// provider cannot prove the terminal status, the count is unknown: the
// operation is handed to the autonomous completion owner instead of being
// retired, because an unproven query is not evidence that the kernel is
// finished with the submitted buffers. terminal reports whether the terminal
// completion was already observed, in which case only the count is queried.
func (s *windowsSender) deadlineCompletion(terminal bool) (int, error) {
	return s.completionResult(s.providerQuery(terminal), os.ErrDeadlineExceeded)
}

// cancelCompletion is the cancelled counterpart of deadlineCompletion: the
// authoritative count survives the Close cancel, and an unproven query keeps
// the operation owned until a real completion receipt arrives.
func (s *windowsSender) cancelCompletion(terminal bool) (int, error) {
	return s.completionResult(s.providerQuery(terminal), net.ErrClosed)
}

// providerQuery asks the provider about one operation and keeps an already
// established terminal completion established. When terminal is true the
// completion event was signalled (or WSASend returned synchronously), which is
// the documented terminal-completion notification of exactly this operation,
// so no blocking query is issued and a failed count query cannot demote the
// receipt into "not terminal": the operation is retired with an unknown
// prefix, never retained for a second event signal that the auto-reset event
// no longer holds. The one exception is ERROR_IO_INCOMPLETE, which asserts that
// the operation is still in progress: that contradiction is resolved in favour
// of ownership (the provider may still reference the submitted buffers), so it
// remains unproven.
func (s *windowsSender) providerQuery(terminal bool) streamCompletionQuery {
	query := s.queryCompletion(!terminal)
	if terminal && !errors.Is(query.err, windows.ERROR_IO_INCOMPLETE) {
		query.terminal = true
	}
	return query
}

// markCompletionUnproven records that the terminal completion of the submitted
// operation could not be established, so finishSend hands it to the autonomous
// completion owner.
func (s *windowsSender) markCompletionUnproven() {
	s.mu.Lock()
	s.completionUnproven = true
	s.mu.Unlock()
}

// finishDeadline stops the watcher and reports which terminal owner decided
// this operation. It also marks the operation completed so a timer that fires
// concurrently cannot claim an operation that already finished.
func (s *windowsSender) finishDeadline() (deadlineFired bool, canceled bool) {
	s.mu.Lock()
	s.completed = true
	s.stopDeadlineTimerLocked()
	deadlineFired, canceled = s.deadlineFired, s.canceled
	s.mu.Unlock()
	return deadlineFired, canceled
}

// armDeadlineTimerLocked (re)schedules the deadline watcher for the pending
// operation. Called with mu held; a cleared deadline disarms it, a later
// deadline retimes it.
func (s *windowsSender) armDeadlineTimerLocked() {
	s.stopDeadlineTimerLocked()
	if s.deadline == nil {
		return
	}
	value := s.deadline()
	if value.IsZero() {
		return
	}
	s.deadlineTimer = time.AfterFunc(time.Until(value), s.onDeadline)
}

// stopDeadlineTimerLocked disarms the deadline watcher. Called with mu held.
func (s *windowsSender) stopDeadlineTimerLocked() {
	if s.deadlineTimer != nil {
		s.deadlineTimer.Stop()
		s.deadlineTimer = nil
	}
}

// onDeadline aborts an outstanding overlapped send whose deadline expired. It
// re-reads the deadline under the mutex, so an extension or a clear that lands
// before the callback keeps the operation alive, and an operation that already
// completed is never reported as a deadline abort.
func (s *windowsSender) onDeadline() {
	s.mu.Lock()
	if !s.sending || s.completed || s.released {
		s.mu.Unlock()
		return
	}
	if !windowsDeadlineExpired(s.deadline) {
		s.armDeadlineTimerLocked()
		s.mu.Unlock()
		return
	}
	s.deadlineFired = true
	s.deadlineTimer = nil
	s.mu.Unlock()
	_ = windowsCancelIoEx(s.handle, &s.overlapped)
}

// streamCompletionQuery is what the provider reported about one submitted
// operation. The outcomes are deliberately distinct:
//   - terminal and counted: the operation finished and transferred is the
//     authoritative prefix;
//   - terminal but not counted: the operation finished (the completion event
//     was signalled, the submission returned synchronously, or the provider
//     reported the operation aborted), so its buffers, OVERLAPPED and event may
//     be retired, but no count was reported, so the prefix that reached the
//     wire is unknown;
//   - not terminal: nothing about the operation was established, so the
//     provider may still reference the submitted buffers.
type streamCompletionQuery struct {
	transferred int
	err         error
	terminal    bool
	counted     bool
}

// queryCompletion asks the provider for the terminal byte count and classifies
// the answer.
//
// A blocking query (wait=true) establishes the terminal state only when it
// returns a status: either the count, or the aborted-operation status that
// CancelIoEx itself produces. Any other failure, and WSAGetOverlappedResult's
// "still pending" status, is a failure to determine the status, not a
// completion receipt - Microsoft documents those cases separately - so the
// provider may still reference the submitted buffers.
//
// A non-blocking query (wait=false) is only issued after the completion was
// observed: the completion event was signalled by the provider, or WSASend
// returned synchronously. The operation is finished in both cases, but a failed
// query still leaves the transferred prefix unknown. It must not be reported as
// zero: WSAGetOverlappedResult does not promise a count when it fails, and the
// wrapper treats "zero accepted" as "the whole block is unsent" and replays it.
//
// ERROR_OPERATION_ABORTED is terminal - the operation was cancelled and is no
// longer outstanding - but it is not a counted receipt. The result output is
// documented as not updated when WSAGetOverlappedResult fails, so an aborted
// operation can have transferred any prefix; reporting the initialized count
// would authorise a replay of bytes that already reached the wire.
func (s *windowsSender) queryCompletion(wait bool) streamCompletionQuery {
	var (
		count uint32
		flags uint32
	)
	err := windowsWSAGetOverlappedResult(s.handle, &s.overlapped, &count, wait, &flags)
	switch {
	case err == nil:
		return streamCompletionQuery{transferred: int(count), terminal: true, counted: true}
	case errors.Is(err, windows.ERROR_OPERATION_ABORTED):
		return streamCompletionQuery{err: err, terminal: true}
	case errors.Is(err, windows.ERROR_IO_INCOMPLETE):
		return streamCompletionQuery{err: err}
	case wait:
		return streamCompletionQuery{err: err}
	default:
		return streamCompletionQuery{err: err, terminal: true}
	}
}

// completionResult turns a provider answer into the Send result. cause is the
// caller-visible error of this path: the query error on the ordinary path, the
// deadline or Close error on an abort path, or the wait error.
//
// When the terminal state could not be established the operation is handed to
// the autonomous completion owner (markCompletionUnproven) and the result is an
// unknown-completion marker. When the operation is terminal but its count is
// unavailable the result is the same marker - the wrapper must not replay a
// block whose prefix may have reached the wire - but the operation is retired,
// because a finished operation is exactly what the provider reported and its
// resources must not be kept alive for a count that will never arrive.
func (s *windowsSender) completionResult(query streamCompletionQuery, cause error) (int, error) {
	if !query.terminal {
		s.markCompletionUnproven()
		return 0, newStreamUnknownCompletionError(cause)
	}
	if !query.counted {
		return 0, newStreamUnknownCompletionError(cause)
	}
	return query.transferred, cause
}

// windowsDeadlineExpired reports whether the deadline source is set and has
// already passed. An expired deadline must not produce any socket I/O.
func windowsDeadlineExpired(deadline func() time.Time) bool {
	if deadline == nil {
		return false
	}
	value := deadline()
	return !value.IsZero() && !time.Now().Before(value)
}

// windowsSendTimeout converts the wrapper deadline into a wait timeout.
// expired is true when the deadline already passed; 0 means no deadline.
func windowsSendTimeout(deadline func() time.Time) (timeout uint32, expired bool) {
	if deadline == nil {
		return windows.INFINITE, false
	}
	value := deadline()
	if value.IsZero() {
		return windows.INFINITE, false
	}
	remaining := time.Until(value)
	if remaining <= 0 {
		return 0, true
	}
	millis := remaining / time.Millisecond
	if millis <= 0 {
		millis = 1
	}
	if millis > time.Duration(^uint32(0)-1) {
		return ^uint32(0) - 1, false
	}
	return uint32(millis), false
}

// CancelPending aborts an in-flight overlapped send. It is called by Close
// without the write mutex, so a blocked Write can be released.
func (s *windowsSender) CancelPending() {
	s.mu.Lock()
	s.canceled = true
	pending := s.sending
	s.mu.Unlock()
	if pending {
		_ = windowsCancelIoEx(s.handle, &s.overlapped)
	}
}

// SetWriteDeadline records a deadline pushed by the wrapper. The wrapper
// delegates every caller update and also pushes the effective value when a
// sender is registered, so a Close-flush bound reaches a sender that was first
// constructed by that flush. A pending overlapped send is retimed here: net.Conn
// allows SetWriteDeadline concurrently with a Write, so a shortened deadline
// must abort the outstanding operation, and an extended or cleared deadline
// must let it continue. The submitted buffer and the completion count are not
// affected by any of these updates.
func (s *windowsSender) SetWriteDeadline(deadline time.Time) {
	s.mu.Lock()
	s.deadline = func() time.Time { return deadline }
	if s.sending && !s.completed && !s.released && !s.canceled && !s.deadlineFired {
		s.armDeadlineTimerLocked()
	}
	s.mu.Unlock()
}

// finishSend ends one Send call. When the terminal completion of the submitted
// operation was never established, ownership of the operation passes to the
// autonomous completion owner: the exact submitted allocation, the OVERLAPPED
// and the completion event stay alive until the provider reports the
// completion, and no later Write or Close is needed to release them. Otherwise
// the operation is retired here, which releases the submitted store and - when
// the sender was already released - closes the completion event exactly once.
func (s *windowsSender) finishSend() {
	s.mu.Lock()
	if s.completionUnproven && s.submitted != nil {
		s.retained = true
		// completed keeps the deadline watcher from claiming an operation the
		// reaper now owns, and sending stays set so Release defers the event
		// close and a new send is refused. The operation reference stays with
		// the reaper until the terminal receipt discharges it.
		s.completed = true
		s.stopDeadlineTimerLocked()
		s.mu.Unlock()
		go s.reapRetainedCompletion()
		return
	}
	release := s.retireLocked()
	s.mu.Unlock()
	if release != nil {
		release()
	}
}

// retireLocked releases one operation's resources. Called with mu held, exactly
// once per operation: either by the caller-side path when the terminal receipt
// was established, or by the autonomous completion owner. It returns the
// operation's admission release callback, which the caller must invoke after
// unlocking (callbacks perform bounded accounting only, never I/O).
func (s *windowsSender) retireLocked() (release func()) {
	s.sending = false
	s.completed = false
	s.deadlineFired = false
	s.completionUnproven = false
	s.retained = false
	// The asynchronous operation is over: the submitted backing store no
	// longer needs to stay reachable.
	s.submitted = nil
	s.stopDeadlineTimerLocked()
	release = s.opRelease
	s.opRelease = nil
	if s.released {
		if resourceRelease := s.closeEventLocked(); resourceRelease != nil {
			if release == nil {
				release = resourceRelease
			} else {
				first := release
				release = func() {
					first()
					resourceRelease()
				}
			}
		}
	}
	return
}

// streamRetainedCompletionSlice bounds one wait of the autonomous completion
// owner. The owner never issues an unlimited native wait of its own: it
// re-checks the operation between slices, keeps Close independent of it, and
// adds no global queue or daemon - one retained operation per sender.
const streamRetainedCompletionSlice = 250 * time.Millisecond

// reapRetainedCompletion is the autonomous completion owner of one retained
// operation. It holds the exact submitted allocation, the OVERLAPPED and the
// completion event until the provider signals the completion event - the
// documented terminal-completion notification - and only then retires them,
// exactly once. A query error on the abort path is not treated as a receipt: a
// closed socket cannot answer for an operation it no longer owns. If the
// provider never signals the event, the operation stays owned and this sender
// keeps refusing new sends, so the retained population is bounded by one
// operation per connection; that residual platform risk is explicit rather
// than silently resolved by freeing memory the kernel may still reference.
func (s *windowsSender) reapRetainedCompletion() {
	for {
		event, waitErr := windowsWaitForSingleObject(s.event, uint32(streamRetainedCompletionSlice/time.Millisecond))
		if waitErr == nil && event != uint32(windows.WAIT_TIMEOUT) {
			s.mu.Lock()
			var release func()
			if s.retained {
				release = s.retireLocked()
			}
			s.mu.Unlock()
			if release != nil {
				release()
			}
			return
		}
		time.Sleep(streamRetainedCompletionSlice)
	}
}

// Release frees the completion event once no send can use it. A release that
// races with an in-flight send defers the handle close - and the sender-resource
// admission release - to the terminal retirement of that operation.
func (s *windowsSender) Release() {
	s.mu.Lock()
	var release func()
	if !s.released {
		s.released = true
		if !s.sending {
			release = s.closeEventLocked()
		}
	}
	s.mu.Unlock()
	if release != nil {
		release()
	}
}

// closeEventLocked closes the completion event and returns the sender-resource
// admission release. Called with mu held; the caller invokes the release after
// unlocking. The event closed flag makes both actions happen exactly once.
func (s *windowsSender) closeEventLocked() (release func()) {
	if s.eventClosed {
		return nil
	}
	s.eventClosed = true
	_ = windows.CloseHandle(s.event)
	release = s.resourceRelease
	s.resourceRelease = nil
	return
}

// windowsPrepareTTL saves and applies IP_TTL/IPV6_UNICAST_HOPS for one send,
// retrying the other family when the socket was created for the opposite one
// (same behavior as the Linux sender).
func windowsPrepareTTL(fd windows.Handle, ttl int, family int) (level int, option int, previous int, changed bool, err error) {
	if ttl == 0 {
		return 0, 0, 0, false, nil
	}
	tryLevel, tryOption := int(windows.IPPROTO_IP), int(windows.IP_TTL)
	if family == 6 {
		tryLevel, tryOption = int(windows.IPPROTO_IPV6), int(windows.IPV6_UNICAST_HOPS)
	}
	previous, err = windows.GetsockoptInt(fd, tryLevel, tryOption)
	if err != nil {
		if tryLevel == int(windows.IPPROTO_IP) {
			tryLevel, tryOption = int(windows.IPPROTO_IPV6), int(windows.IPV6_UNICAST_HOPS)
		} else {
			tryLevel, tryOption = int(windows.IPPROTO_IP), int(windows.IP_TTL)
		}
		previous, err = windows.GetsockoptInt(fd, tryLevel, tryOption)
		if err != nil {
			return 0, 0, 0, false, err
		}
	}
	if err = windows.SetsockoptInt(fd, tryLevel, tryOption, ttl); err != nil {
		return 0, 0, 0, false, err
	}
	return tryLevel, tryOption, previous, true, nil
}

func (s *windowsSender) WaitNotSent(time.Duration) bool {
	// Windows has no tpws fix-seg equivalent.
	return true
}

var _ streamDeadlineSender = (*windowsSender)(nil)
var _ streamSenderCanceler = (*windowsSender)(nil)
var _ streamSenderReleaser = (*windowsSender)(nil)

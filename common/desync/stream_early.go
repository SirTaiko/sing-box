package desync

import (
	"net"
	"os"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// deferredNativeConn is the structural seam of the dialer's lazy TFO facade.
// The stream package deliberately does not import the dialer: it only needs to
// know whether a native socket exists yet and, once it does, which connection
// the established native sender must be built from.
type deferredNativeConn interface {
	NativePending() bool
	Established() net.Conn
}

// earlySendConn reports whether conn selects the deferred first-send path.
func earlySendConn(conn net.Conn) (deferredNativeConn, bool) {
	pending, ok := conn.(deferredNativeConn)
	if !ok || !pending.NativePending() {
		return nil, false
	}
	return pending, true
}

// firstSendSender carries the first transformed segment of a rule through the
// deferred pending write, which creates the single owned native attempt with
// that segment as TFO data. Every later segment, and every send after the
// connection is established, uses the ordinary established native sender.
//
// The first segment is never joined with the following split pieces: the split
// loop calls Send once per fragment, so exactly one fragment is the initial
// buffer. A first send that needs OOB or a low-TTL/disorder send is refused
// before any byte is written: the Windows ConnectEx initial buffer and a SYN
// data packet cannot carry those semantics, and the U4 compatibility choice for
// that cross product is still open. TFO is not silently disabled and the flow
// is not silently converted to an empty handshake.
//
// The established sender only exists after the first send, so the wrapper is
// also its owner: release, cancellation and deadline updates received while the
// inner sender does not exist yet are recorded here and applied to it at
// adoption. A Close that races the first send therefore frees the inner sender
// without requiring a second Write, and a late inner sender never sends on a
// terminal wrapper.
type firstSendSender struct {
	pending deferredNativeConn
	conn    net.Conn
	resolve func() (streamSender, error)

	mu          sync.Mutex
	inner       streamSender
	released    bool
	canceled    bool
	deadline    time.Time
	deadlineSet bool
	// deadlineVersion numbers every completed write-deadline setter; adoption
	// uses it to detect that the value it is publishing is already superseded.
	deadlineVersion uint64
}

func newFirstSendSender(pending deferredNativeConn, conn net.Conn, resolve func() (streamSender, error)) *firstSendSender {
	return &firstSendSender{pending: pending, conn: conn, resolve: resolve}
}

func (s *firstSendSender) Send(data []byte, options sendOptions) (int, error) {
	s.mu.Lock()
	released := s.released
	inner := s.inner
	s.mu.Unlock()
	if released {
		// The wrapper is terminal: no native send may start after close.
		return 0, os.ErrClosed
	}
	if inner != nil {
		return inner.Send(data, options)
	}
	if err := s.refuseFirstSend(options); err != nil {
		return 0, err
	}
	sent, err := writeFullN(s.conn, data)
	if err != nil {
		return sent, err
	}
	// The pending write established the native connection. Later segments use
	// the established sender on that same connection.
	established := s.pending.Established()
	if established == nil {
		return sent, E.New("desync: deferred first send produced no established connection")
	}
	inner, err = s.resolve()
	if err != nil {
		return sent, err
	}
	s.adopt(inner)
	return sent, nil
}

// adopt publishes the inner sender and settles every lifecycle action that
// arrived before it existed. It is called by the first send that created it, so
// cleanup never depends on another Write.
//
// The write deadline is published with a version check rather than a plain
// snapshot: a setter that completes while the push is in flight bumps the
// version, and the push is repeated with the newer value. A deferred adoption
// therefore never overwrites a deadline whose setter already returned.
func (s *firstSendSender) adopt(inner streamSender) {
	s.mu.Lock()
	s.inner = inner
	s.mu.Unlock()
	s.publishDeadline(inner)
	s.mu.Lock()
	canceled, released := s.canceled, s.released
	s.mu.Unlock()
	if canceled {
		if canceler, isCanceler := inner.(streamSenderCanceler); isCanceler {
			canceler.CancelPending()
		}
	}
	if released {
		if releaser, isReleaser := inner.(streamSenderReleaser); isReleaser {
			releaser.Release()
		}
	}
}

// publishDeadline pushes the current write deadline of the wrapper to a sender
// that may not have existed when the setter ran.
func (s *firstSendSender) publishDeadline(inner streamSender) {
	aware, isAware := inner.(streamDeadlineSender)
	if !isAware {
		return
	}
	for {
		s.mu.Lock()
		deadline, deadlineSet, version := s.deadline, s.deadlineSet, s.deadlineVersion
		s.mu.Unlock()
		if !deadlineSet {
			return
		}
		aware.SetWriteDeadline(deadline)
		s.mu.Lock()
		stable := s.deadlineVersion == version
		s.mu.Unlock()
		if stable {
			return
		}
	}
}

// WaitNotSent applies only to an established socket. Before activation there is
// no send queue to inspect, so nothing is pending and the split loop continues.
func (s *firstSendSender) WaitNotSent(timeout time.Duration) bool {
	s.mu.Lock()
	inner := s.inner
	s.mu.Unlock()
	if inner == nil {
		return true
	}
	return inner.WaitNotSent(timeout)
}

// Release forwards the inner sender release and records the terminal state, so
// an inner sender created later is released by adopt instead of leaking the
// platform completion event.
func (s *firstSendSender) Release() {
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return
	}
	s.released = true
	inner := s.inner
	s.mu.Unlock()
	if inner != nil {
		if releaser, isReleaser := inner.(streamSenderReleaser); isReleaser {
			releaser.Release()
		}
	}
}

// CancelPending forwards cancellation to an established sender and records it
// for one that is still being created, so Close can still interrupt the first
// overlapped send.
func (s *firstSendSender) CancelPending() {
	s.mu.Lock()
	s.canceled = true
	inner := s.inner
	s.mu.Unlock()
	if inner != nil {
		if canceler, isCanceler := inner.(streamSenderCanceler); isCanceler {
			canceler.CancelPending()
		}
	}
}

// SetWriteDeadline forwards the effective write deadline to an established
// sender and stores it for one that does not exist yet. The platform sender
// caches its own copy, so the value has to be pushed rather than only read from
// the wrapper source. The version lets a concurrent adoption detect that a
// completed setter is newer than the value it is about to publish.
func (s *firstSendSender) SetWriteDeadline(deadline time.Time) {
	s.mu.Lock()
	s.deadline = deadline
	s.deadlineSet = true
	s.deadlineVersion++
	inner := s.inner
	s.mu.Unlock()
	if inner != nil {
		if aware, isAware := inner.(streamDeadlineSender); isAware {
			aware.SetWriteDeadline(deadline)
		}
	}
}

// firstSendGuard is implemented by senders whose first send creates the native
// socket. The split loop asks it before writing the first fragment, so an
// impossible first send (OOB or low-TTL disorder, the OPEN TFO+first-send
// compatibility choice) fails before any byte exists instead of after a failed
// send, where the ordinary short-send handling would forward the block unsplit
// and silently bypass the configured transformation.
type firstSendGuard interface {
	refuseFirstSend(options sendOptions) error
}

func (s *firstSendSender) refuseFirstSend(options sendOptions) error {
	s.mu.Lock()
	inner := s.inner
	released := s.released
	s.mu.Unlock()
	if released {
		return os.ErrClosed
	}
	if inner != nil {
		return nil
	}
	if options.oob || options.ttl != 0 {
		return E.New("desync: tcp_fast_open cannot carry a first-send OOB/disorder rule; this combination is an open compatibility choice")
	}
	return nil
}

var (
	_ streamSender         = (*firstSendSender)(nil)
	_ streamSenderReleaser = (*firstSendSender)(nil)
	_ streamSenderCanceler = (*firstSendSender)(nil)
	_ streamDeadlineSender = (*firstSendSender)(nil)
	_ firstSendGuard       = (*firstSendSender)(nil)
)

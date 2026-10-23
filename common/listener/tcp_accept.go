package listener

import (
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// tcpAdmission is the single accepted-connection budget of one logical
// inbound. Every bind socket of that inbound shares this counter.
type tcpAdmission struct {
	limit int64
	count atomic.Int64
}

func newTCPAdmission(limit int) *tcpAdmission {
	if limit <= 0 {
		return nil
	}
	return &tcpAdmission{limit: int64(limit)}
}

func (a *tcpAdmission) acquire() bool {
	for {
		current := a.count.Load()
		if current >= a.limit {
			return false
		}
		if a.count.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

func (a *tcpAdmission) release() {
	a.count.Add(-1)
}

// tcpAcceptHandler performs the post-Accept work shared by the legacy single
// listener and the multi-bind listener: the admission token is acquired
// before any handler is published, excess connections are closed before
// dispatch, and accepted socket controls are applied and verified.
type tcpAcceptHandler struct {
	socketOptions option.TCPOptions
	admission     *tcpAdmission
	logger        logger.ContextLogger
}

func (h *tcpAcceptHandler) active() bool {
	return h != nil && (!h.socketOptions.Empty() || h.admission != nil)
}

// accept returns a connection ready for dispatch, or false when the accepted
// connection was closed without dispatch (admission limit or socket control
// failure). It never returns an error: an accept-level failure must not tear
// down the whole inbound.
func (h *tcpAcceptHandler) accept(conn net.Conn) (net.Conn, bool) {
	if h.admission != nil {
		if !h.admission.acquire() {
			if h.logger != nil {
				h.logger.Warn("tcp connection limit reached, closing accepted connection")
			}
			_ = conn.Close()
			return nil, false
		}
	}
	if !h.socketOptions.Empty() {
		if err := ensureAcceptedTCPSocketOptions(conn, h.socketOptions); err != nil {
			if h.logger != nil {
				h.logger.Error(err, ", closing accepted TCP connection")
			}
			_ = conn.Close()
			h.release()
			return nil, false
		}
	}
	if h.admission == nil {
		return conn, true
	}
	return newAdmissionConn(conn, h.admission), true
}

func (h *tcpAcceptHandler) release() {
	if h.admission != nil {
		h.admission.release()
	}
}

// admissionConn ties the admission token to the accepted connection lifetime.
// Release is idempotent across Close and the handler onClose callback, and the
// wrapper forwards the native capabilities existing routing relies on.
type admissionConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func newAdmissionConn(conn net.Conn, admission *tcpAdmission) *admissionConn {
	return &admissionConn{
		Conn: conn,
		release: func() {
			admission.release()
		},
	}
}

func (c *admissionConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// AdmissionCloseHandler is consumed by the shared accept loop so the existing
// onClose lifecycle also releases the token exactly once.
func (c *admissionConn) AdmissionCloseHandler() N.CloseHandlerFunc {
	return func(error) {
		c.once.Do(c.release)
	}
}

func (c *admissionConn) SyscallConn() (syscall.RawConn, error) {
	syscallConn, isSyscallConn := c.Conn.(syscall.Conn)
	if !isSyscallConn {
		return nil, E.New("accepted connection does not expose a native socket")
	}
	return syscallConn.SyscallConn()
}

func (c *admissionConn) CloseWrite() error {
	if closeWriter, isCloseWriter := c.Conn.(interface{ CloseWrite() error }); isCloseWriter {
		return closeWriter.CloseWrite()
	}
	return nil
}

func (c *admissionConn) CloseRead() error {
	if closeReader, isCloseReader := c.Conn.(interface{ CloseRead() error }); isCloseReader {
		return closeReader.CloseRead()
	}
	return nil
}

// tcpAcceptListener applies the post-Accept work to a single listener. It is
// an ordinary net.Listener so every existing ListenTCP caller keeps working.
type tcpAcceptListener struct {
	net.Listener
	handler *tcpAcceptHandler
}

func (l *tcpAcceptListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		admitted, ok := l.handler.accept(conn)
		if ok {
			return admitted, nil
		}
	}
}

// tcpMultiListener accepts from every bind socket of one inbound and exposes
// them as one net.Listener, so the existing accept/handler owner is reused
// unchanged. The underlying listeners are created (and rolled back) by the
// caller before this value is published.
type tcpMultiListener struct {
	listeners []net.Listener
	handler   *tcpAcceptHandler
	results   chan tcpAcceptResult
	done      chan struct{}
	closeOnce sync.Once
}

type tcpAcceptResult struct {
	conn net.Conn
	err  error
}

func newTCPMultiListener(listeners []net.Listener, handler *tcpAcceptHandler) *tcpMultiListener {
	multiListener := &tcpMultiListener{
		listeners: listeners,
		handler:   handler,
		results:   make(chan tcpAcceptResult),
		done:      make(chan struct{}),
	}
	for _, listener := range listeners {
		go multiListener.serve(listener)
	}
	return multiListener
}

func (l *tcpMultiListener) serve(listener net.Listener) {
	var acceptDelay time.Duration
	for {
		conn, err := listener.Accept()
		if err != nil {
			if l.isClosed() {
				return
			}
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay = min(2*acceptDelay, time.Second)
				}
				timer := time.NewTimer(acceptDelay)
				select {
				case <-timer.C:
				case <-l.done:
					timer.Stop()
					return
				}
				continue
			}
			l.send(tcpAcceptResult{err: err})
			return
		}
		acceptDelay = 0
		if !l.send(tcpAcceptResult{conn: conn}) {
			_ = conn.Close()
			return
		}
	}
}

func (l *tcpMultiListener) send(result tcpAcceptResult) bool {
	select {
	case l.results <- result:
		return true
	case <-l.done:
		return false
	}
}

func (l *tcpMultiListener) isClosed() bool {
	select {
	case <-l.done:
		return true
	default:
		return false
	}
}

func (l *tcpMultiListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		case result := <-l.results:
			if result.err != nil {
				return nil, result.err
			}
			admitted, ok := l.handler.accept(result.conn)
			if ok {
				return admitted, nil
			}
		}
	}
}

func (l *tcpMultiListener) Close() error {
	var closeErr error
	l.closeOnce.Do(func() {
		close(l.done)
		for _, listener := range l.listeners {
			closeErr = E.Errors(closeErr, listener.Close())
		}
	})
	return closeErr
}

func (l *tcpMultiListener) Addr() net.Addr {
	if len(l.listeners) == 0 {
		return nil
	}
	return l.listeners[0].Addr()
}

// wrapTCPListener installs the post-Accept handler only when something is
// configured; the option-absent path returns the exact previous listener.
func wrapTCPListener(base net.Listener, handler *tcpAcceptHandler) net.Listener {
	if !handler.active() {
		return base
	}
	return &tcpAcceptListener{Listener: base, handler: handler}
}

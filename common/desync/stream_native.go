package desync

import (
	"errors"
	"io"
	"net"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// streamNative is the platform seam for the native socket controls of tpws.
// It is injectable: tests replace StreamConfig.native with a recording
// implementation and never touch a real socket or host network state.
type streamNative interface {
	// Prepare applies preconnect socket controls. fd is owned by the dialer.
	Prepare(fd uintptr, config streamSocketConfig) error
	// NewSender returns a per-connection segment sender. deadline reports the
	// connection's current write deadline; platform senders that bypass the Go
	// poller (Windows overlapped sends) apply it themselves.
	NewSender(conn net.Conn, deadline func() time.Time) (streamSender, error)
}

// streamSender writes one already transformed segment. It mirrors tpws
// send_oob/send_with_ttl: an OOB send transmits data plus one trailing OOB
// byte, and ttl is applied only around that send.
type streamSender interface {
	Send(data []byte, options sendOptions) (int, error)
	// WaitNotSent implements the Linux fix-seg wait. timeout==0 performs only
	// the upstream explicit-zero inspection (no sleep); a bare `--fix-seg`
	// is compiled to the upstream 50 ms default instead, so it never reaches
	// this method with a zero timeout.
	WaitNotSent(timeout time.Duration) bool
}

type streamSocketConfig struct {
	mss         int
	skipNoDelay bool
}

// streamNoDelayConn is implemented by Go TCP connections. Go's net.newTCPConn
// enables TCP_NODELAY after a successful dial, overwriting the preconnect value
// of `skip_nodelay`; the option is therefore re-asserted on the connected
// socket. A selected upstream option that cannot be applied is an error, never
// a silent optimization bypass.
type streamNoDelayConn interface {
	SetNoDelay(bool) error
}

var _ streamNoDelayConn = (*net.TCPConn)(nil)

// streamConfirmNoDelay re-applies TCP_NODELAY=0 after connect/adoption for the
// attached Go TCP entrypoints. It is only called when the selected rule sets
// skip_nodelay, so an ordinary rule never touches the socket option.
func streamConfirmNoDelay(conn net.Conn) error {
	setter, ok := conn.(streamNoDelayConn)
	if !ok {
		return E.New("desync: skip_nodelay selected but the connection does not support TCP_NODELAY")
	}
	if err := setter.SetNoDelay(false); err != nil {
		return E.Cause(err, "desync: re-assert TCP_NODELAY=0 after connect")
	}
	return nil
}

type sendOptions struct {
	ttl     int
	oob     bool
	oobByte byte
	cork    bool
}

// streamDeadlineSender is implemented by senders that must enforce the
// connection write deadline themselves because their I/O bypasses the Go
// poller (Windows overlapped WSASend).
//
// The value is the connection's effective deadline at publication time. A
// sender that reads a live source instead of caching one may keep using that
// source; the wrapper's publication is generation-ordered either way (see
// streamConn.publishSenderDeadline), so a publication that was computed before
// a completed deadline setter cannot remain the last value a sender sees.
type streamDeadlineSender interface {
	SetWriteDeadline(deadline time.Time)
}

// streamUnknownCompletionError marks a native send whose transferred prefix
// could not be established. The marker matters to the stream wrapper: the
// remaining bytes of the block are not known to be unsent, so forwarding them
// would replay data the provider may already have transmitted. It unwraps to
// the error the caller would otherwise have received, so the net.Conn error
// contract (for example net.ErrClosed or os.ErrDeadlineExceeded) is preserved.
type streamUnknownCompletionError struct {
	cause error
}

func newStreamUnknownCompletionError(cause error) error {
	return &streamUnknownCompletionError{cause: cause}
}

func (e *streamUnknownCompletionError) Error() string {
	return "desync: stream send completion unproven: " + e.cause.Error()
}

func (e *streamUnknownCompletionError) Unwrap() error { return e.cause }

// streamCompletionUnproven reports whether err marks a native send whose
// transferred prefix is unknown.
func streamCompletionUnproven(err error) bool {
	var target *streamUnknownCompletionError
	return errors.As(err, &target)
}

// streamSenderCanceler is implemented by senders that can abort an in-flight
// overlapped send so Close can interrupt a blocked Write.
type streamSenderCanceler interface {
	CancelPending()
}

// streamSenderReleaser is implemented by senders that own platform resources
// (for example a completion event handle) which must be freed on Close.
type streamSenderReleaser interface {
	Release()
}

// streamCapsInfo describes the source platform applicability of tpws native
// controls implemented by this build.
type streamCapsInfo struct {
	mss         bool
	fixSeg      bool
	oob         bool
	disorder    bool
	oobDisorder bool
	skipNoDelay bool
}

// plainSender is used when a rule does not need native per-segment control.
// It refuses native-only options instead of silently dropping them.
type plainSender struct {
	conn net.Conn
}

func (s *plainSender) Send(data []byte, options sendOptions) (int, error) {
	if options.ttl != 0 || options.oob || options.oobByte != 0 || options.cork {
		return 0, E.New("desync: native stream send required but not available")
	}
	return s.conn.Write(data)
}

func (s *plainSender) WaitNotSent(time.Duration) bool { return true }

// nativeAdmissionHolder is the structural admission capability of a connection
// that carries an already admitted native attempt. The platform sender factory
// and every native submission acquire a reference through it before touching
// the socket; the reference charges no second slot. It is implemented by the
// direct bridge's leaseConn and forwarded to the attempt's desync.Lease.
type nativeAdmissionHolder interface {
	AcquireNativeHold() (release func(), err error)
}

// nativeStreamSource exposes the already-owned underlying connection of an
// admission-carrying wrapper. It never creates, dials or adopts a socket: the
// platform factory only needs the socket that the attempt already owns.
type nativeStreamSource interface {
	NativeStreamConn() net.Conn
}

// acquireStreamNativeSource resolves the native socket source of one platform
// sender and acquires its admission reference. The capability is mandatory
// before a production native effect: a connection without an admission owner is
// an explicit error, never an unaccounted native operation and never a
// permissive fallback (tests adapt their fixtures instead).
func acquireStreamNativeSource(conn net.Conn) (source net.Conn, holder nativeAdmissionHolder, release func(), err error) {
	if conn == nil {
		return nil, nil, nil, E.New("desync: native stream send requires a connection")
	}
	holder, ok := conn.(nativeAdmissionHolder)
	if !ok {
		return nil, nil, nil, E.New("desync: native stream send requires an admission owner")
	}
	release, err = holder.AcquireNativeHold()
	if err != nil {
		return nil, nil, nil, err
	}
	if release == nil {
		return nil, nil, nil, E.New("desync: native stream admission returned no release")
	}
	source = conn
	if provider, isSource := conn.(nativeStreamSource); isSource {
		native := provider.NativeStreamConn()
		if native == nil {
			release()
			return nil, nil, nil, E.New("desync: native stream admission exposes no native connection")
		}
		source = native
	}
	return source, holder, release, nil
}

// streamRemoteFamily returns 4 or 6 for a TCP remote address, 0 when unknown.
func streamRemoteFamily(conn net.Conn) int {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && addr.IP != nil {
		if addr.IP.To4() != nil {
			return 4
		}
		return 6
	}
	return 0
}

// writeFull sends all bytes, tolerating short writes with nil error.
func writeFull(writer io.Writer, data []byte) error {
	_, err := writeFullN(writer, data)
	return err
}

// writeFullN sends all bytes and also reports how many of them reached the
// writer before the first error. A short write with no error is retried, so the
// count is always a positive prefix of data; a writer that accepts nothing
// returns io.ErrShortWrite instead of spinning. Send accounting uses the count
// to report caller bytes that are already on the wire, so a failure after full
// delivery is distinguishable from a failure before any progress.
func writeFullN(writer io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		written, err := writer.Write(data[total:])
		if written > 0 {
			total += written
		}
		if err != nil {
			return total, err
		}
		if written == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func streamCaps() streamCapsInfo { return platformStreamCaps() }

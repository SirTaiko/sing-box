//go:build windows

package dialer

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/windows"
)

func dialAttempt(ctx context.Context, base net.Dialer, network, address string, lease AttemptLease) (net.Conn, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return dialAttemptControl(ctx, base, network, address, lease)
	}
	conn, _, err := dialConnectEx(ctx, base, network, address, lease, nil)
	return conn, err
}

// dialAttemptControl is the safe pre-bind path for UDP on Windows. ConnectEx is
// required for TCP because ordinary net.Dialer.Control runs before Bind and
// ConnectEx binds again when the local sockaddr is nil.
func dialAttemptControl(ctx context.Context, base net.Dialer, network, address string, lease AttemptLease) (net.Conn, error) {
	perAttempt := base
	if lease.RequiresExclusiveBind() {
		perAttempt.LocalAddr = nil
	}
	perAttempt.Control = control.Append(perAttempt.Control, func(network, address string, rawConn syscall.RawConn) error {
		var prepareErr error
		if controlErr := rawConn.Control(func(fd uintptr) {
			prepareErr = lease.PrepareSocket(fd)
		}); controlErr != nil {
			return controlErr
		}
		return prepareErr
	})
	return perAttempt.DialContext(ctx, network, address)
}

// rawConn adapts a Winsock handle to syscall.RawConn so the existing controls
// (interface binding, routing mark, protection) can run on the native socket.
type rawConn struct {
	handle windows.Handle
}

func (c *rawConn) Control(f func(fd uintptr)) error {
	f(uintptr(c.handle))
	return nil
}

func (c *rawConn) Read(f func(fd uintptr) (done bool)) error {
	return E.New("desync: raw control read is not used")
}

func (c *rawConn) Write(f func(fd uintptr) (done bool)) error {
	return E.New("desync: raw control write is not used")
}

// nativeHoldLease is the optional admission capability of an attempt lease.
// The retaining helper consumes it structurally; an enabled owned attempt must
// provide it before the native connect exists, otherwise the operation would be
// an unaccounted native effect.
type nativeHoldLease interface {
	AcquireNativeHold() (release func(), err error)
}

// dialConnectEx is the enabled-only native connect lifecycle: create a
// non-inheritable overlapped socket, apply the TFO socket option for a
// non-empty initial buffer, run the existing controls, bind the exclusive
// local port once, register capture, perform a cancellable ConnectEx with the
// selected initial data, then adopt the connected socket through the public
// net.FileConn path.
//
// The caller's completion wait is bounded by the earliest of the attempt
// context deadline, the caller deadline and the dialer connect timeout. A
// canceled or expired wait cancels the overlapped operation and observes it for
// a bounded grace; when completion does not arrive in that grace the
// per-attempt owner retains the OVERLAPPED, event, socket and initial payload
// until the kernel reports terminal completion. The authoritative byte count is
// taken from the path that actually completed the operation: a short initial
// send only writes the remainder on the same connection, so no payload byte is
// replayed and no alternate socket is created.
func dialConnectEx(ctx context.Context, base net.Dialer, network, address string, lease AttemptLease, payload []byte) (conn net.Conn, accepted int, err error) {
	destination := M.ParseSocksaddr(address)
	if destination.IsDomain() || !destination.IsValid() {
		return nil, 0, E.New("desync: native connect requires a resolved address")
	}
	// The operation's admission reference is taken before the socket, the
	// event and the OVERLAPPED exist. A refused acquisition (closed engine or
	// closed attempt) therefore starts no native effect at all; it never falls
	// back to a plain connect.
	holder, ok := lease.(nativeHoldLease)
	if !ok {
		return nil, 0, E.New("desync: native connect requires an admission owner")
	}
	holdRelease, err := holder.AcquireNativeHold()
	if err != nil {
		return nil, 0, err
	}
	if holdRelease == nil {
		return nil, 0, E.New("desync: native connect admission returned no release")
	}
	holdOwned := true
	defer func() {
		if holdOwned {
			holdRelease()
		}
	}()
	family := int32(windows.AF_INET)
	if destination.IsIPv6() {
		family = windows.AF_INET6
	}
	handle, err := windows.WSASocket(family, windows.SOCK_STREAM, windows.IPPROTO_TCP, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return nil, 0, E.Cause(err, "desync: create native socket")
	}
	retained := false
	defer func() {
		// The original handle is owned by this function for the whole
		// adoption sequence: on success the connection owns its own
		// duplicate, on failure nothing was transferred, and a retained
		// operation keeps the socket until the kernel reports terminal
		// completion (the retention owner closes it). It is therefore
		// released exactly once, and always through the Winsock API.
		//
		// A failed retirement is not a successful attempt: an already adopted
		// connection is rolled back, the failure is reported with the
		// attempt's own error, and an unproven release keeps this attempt's
		// admission charge. There is no blind numeric retry, no second owner
		// and no replacement attempt.
		if retained {
			return
		}
		state := attemptRetirement{handle: handle, conn: conn, holdOwned: holdOwned, err: err}
		state.retire()
		conn, err, holdOwned = state.conn, state.err, state.holdOwned
	}()
	// Match the socket defaults net.Dialer would have applied.
	_ = windows.SetsockoptInt(handle, windows.IPPROTO_TCP, windows.TCP_NODELAY, 1)
	// TFO is requested only when this attempt carries initial data. An
	// unsupported stack is an actionable error, never a silent plaintext
	// switch: Windows 10 1607+ is required for ConnectEx initial data.
	if len(payload) > 0 {
		if err = windows.SetsockoptInt(handle, windows.IPPROTO_TCP, windows.TCP_FASTOPEN, 1); err != nil {
			return nil, 0, E.Cause(err, "desync: setsockopt(TCP_FASTOPEN)")
		}
	}
	if base.Control != nil {
		if err = base.Control(network, address, &rawConn{handle: handle}); err != nil {
			return nil, 0, E.Cause(err, "desync: apply socket controls")
		}
	}
	var bindAddress windows.Sockaddr
	if destination.IsIPv6() {
		bind := &windows.SockaddrInet6{}
		if local, ok := base.LocalAddr.(*net.TCPAddr); ok && local.IP != nil {
			if ip4 := local.IP.To4(); ip4 != nil {
				return nil, 0, E.New("desync: IPv4 bind address for an IPv6 destination")
			}
			copy(bind.Addr[:], local.IP.To16())
			if local.Zone != "" {
				iface, zoneErr := net.InterfaceByName(local.Zone)
				if zoneErr != nil {
					return nil, 0, E.Cause(zoneErr, "desync: resolve IPv6 zone")
				}
				bind.ZoneId = uint32(iface.Index)
			}
		}
		bindAddress = bind
	} else {
		bind := &windows.SockaddrInet4{}
		if local, ok := base.LocalAddr.(*net.TCPAddr); ok && local.IP != nil {
			ip4 := local.IP.To4()
			if ip4 == nil {
				return nil, 0, E.New("desync: IPv6 bind address for an IPv4 destination")
			}
			copy(bind.Addr[:], ip4)
		}
		bindAddress = bind
	}
	if err = windows.Bind(handle, bindAddress); err != nil {
		return nil, 0, E.Cause(err, "desync: bind exclusive local port")
	}
	if err = lease.PrepareSocket(uintptr(handle)); err != nil {
		return nil, 0, err
	}
	var remote windows.Sockaddr
	if destination.IsIPv6() {
		remote = &windows.SockaddrInet6{Port: int(destination.Port), Addr: destination.Addr.As16()}
	} else {
		remote = &windows.SockaddrInet4{Port: int(destination.Port), Addr: destination.Addr.As4()}
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, 0, E.Cause(err, "desync: create connect event")
	}
	// The payload handed to the kernel is the operation's own storage. A
	// deferred attempt can outlive the caller's Write (the completion owner
	// retains it), and the caller may reuse its buffer immediately after
	// returning, so the caller slice must never be submitted.
	if len(payload) > 0 {
		owned := make([]byte, len(payload))
		copy(owned, payload)
		payload = owned
	}
	overlapped := new(windows.Overlapped)
	overlapped.HEvent = event
	var initialData *byte
	if len(payload) > 0 {
		initialData = &payload[0]
	}
	operation := newOutstandingConnect(handle, event, overlapped, payload, lease)
	// The operation owns the admission reference from here on. The caller's
	// deferred release is disabled only when the operation is retained: the
	// retention goroutine then discharges it after the terminal receipt and
	// after the socket is retired.
	operation.nativeHold = holdRelease
	var sent uint32
	err = windows.ConnectEx(handle, remote, initialData, uint32(len(payload)), &sent, overlapped)
	var completion uint32
	asynchronous := err == windows.ERROR_IO_PENDING
	switch {
	case err == nil:
		// Synchronous success: the initiation out parameter is the documented
		// accepted count and no completion is outstanding.
		operation.releaseResources()
	case asynchronous:
		completion, err = operation.awaitConnectCompletion(ctx, connectDeadline(ctx, base))
		if err != nil {
			if operation.retained {
				// The kernel still owns the OVERLAPPED, event and initial
				// payload. The per-attempt owner retains them and frees them
				// after terminal completion; this caller must not close the
				// socket underneath that operation, and it must not close the
				// attempt lease either: the retained owner keeps the existing
				// admission charged until the kernel is done. The admission
				// reference acquired before the socket also belongs to that
				// owner now.
				retained = true
				holdOwned = false
				return nil, 0, &retainedAttemptError{err: err}
			}
			return nil, connectTransferred(true, 0, completion, len(payload)), err
		}
	default:
		// ConnectEx failed synchronously: no operation was issued and the
		// event/overlapped ownership can be freed at once.
		operation.releaseResources()
		return nil, 0, E.Cause(err, "desync: ConnectEx")
	}
	// The accepted count is authoritative from the path that completed the
	// operation, so it is resolved before the post-completion steps: a failing
	// socket-context update or descriptor adoption happens after valid native
	// progress and must report that progress, not zero.
	written := connectTransferred(asynchronous, sent, completion, len(payload))
	if err = windows.Setsockopt(handle, windows.SOL_SOCKET, windows.SO_UPDATE_CONNECT_CONTEXT, nil, 0); err != nil {
		return nil, written, E.Cause(err, "desync: SO_UPDATE_CONNECT_CONTEXT")
	}
	if err = waitConnectedContext(handle); err != nil {
		return nil, written, E.Cause(err, "desync: observe connected socket context")
	}
	conn, err = adoptConnectedSocket(handle)
	if err != nil {
		return nil, written, E.Cause(err, "desync: adopt connected socket")
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// Go's net package re-enables transport options while constructing the
		// adopted conn; the configured values are re-asserted here.
		_ = tcpConn.SetNoDelay(true)
		if base.KeepAlive >= 0 {
			_ = tcpConn.SetKeepAlive(true)
			if base.KeepAlive > 0 {
				_ = tcpConn.SetKeepAlivePeriod(base.KeepAlive)
			}
			if base.KeepAliveConfig.Enable {
				_ = tcpConn.SetKeepAliveConfig(base.KeepAliveConfig)
			}
		} else {
			_ = tcpConn.SetKeepAlive(false)
		}
	}
	// Only the path that actually completed the operation reports the accepted
	// bytes: a pending ConnectEx reports zero at initiation time, so reusing
	// that value would replay the whole initial payload on this same socket.
	if written < len(payload) {
		rest, writeErr := conn.Write(payload[written:])
		written += rest
		if writeErr != nil {
			conn.Close()
			return nil, written, writeErr
		}
	}
	return conn, written, nil
}

// adoptionFile is the carrier file the single net.FileConn adoption runs on.
// Production wraps the real socket-aware *os.File; the interface is a narrow
// seam so the ownership sequence is regression-tested with fake calls, not just
// by source inspection.
type adoptionFile interface {
	adopt() (net.Conn, error)
	close() error
}

type osAdoptionFile struct {
	file *os.File
}

func (f *osAdoptionFile) adopt() (net.Conn, error) { return net.FileConn(f.file) }

func (f *osAdoptionFile) close() error { return f.file.Close() }

var (
	// duplicateForAdoption creates the carrier duplicate through the public
	// Winsock duplication API.
	duplicateForAdoption = duplicateConnectedSocket
	// newAdoptionFile wraps one carrier handle in the socket-aware File the
	// single adoption needs. os.NewFile is not usable here: its Close and its
	// finalizer call CloseHandle, which is not a valid disposal API for a
	// Winsock descriptor. The constructor is the version-qualified one from
	// attempt_windows_adoption_ctor.go.
	newAdoptionFile = newSocketAdoptionFile
	// closeCarrierSocket is the only socket disposal used for the carrier and
	// readiness-probe descriptors, whose socket-aware File was already closed
	// or was never constructed. It is a seam so the close-error contract is
	// exercised with fake handles.
	closeCarrierSocket = func(handle windows.Handle) error { return windows.Closesocket(handle) }
	// closeOriginalSocket is the single disposal API of the original native
	// socket. It is a seam so the original-retirement contract is exercised
	// with fake handles; the original is never wrapped in an os.File.
	closeOriginalSocket = func(handle windows.Handle) error { return windows.Closesocket(handle) }
	// duplicateProbe creates one bounded readiness observation duplicate.
	duplicateProbe = duplicateConnectedSocket
)

const (
	// carrierRetireRetryPause is the pause between closesocket retries of a
	// descriptor the documented WSAEWOULDBLOCK outcome left valid.
	carrierRetireRetryPause = 10 * time.Millisecond
	// carrierRetireRetries bounds those retries. An unresolved retirement is
	// reported instead of being retried indefinitely or hidden.
	carrierRetireRetries = 3
)

// unresolvedSocketRetirement reports a socket descriptor whose release is not
// proven. It keeps the numeric handle only as an account of the charge that
// remains open on this attempt; the value is never closed blindly afterwards,
// because an ambiguous close error may already have released or even reused it.
type unresolvedSocketRetirement struct {
	handle windows.Handle
	err    error
}

func (e *unresolvedSocketRetirement) Error() string {
	// The descriptor is a windows.Handle: a defined uintptr type, not the
	// predeclared uintptr sing's format.ToString accepts. Passing the value
	// itself therefore panics with "unknown value" while the message is built,
	// and exceptions.Errors builds every joined message eagerly, so that panic
	// escaped three production paths instead of surfacing the retirement
	// failure. The diagnostic renders the underlying integer; the original
	// close error stays joined through Unwrap and the descriptor accounting is
	// unchanged.
	return E.New("desync: socket retirement unresolved for descriptor ", uintptr(e.handle), ": ", e.err).Error()
}

func (e *unresolvedSocketRetirement) Unwrap() error { return e.err }

// retireSocketDescriptor closes one socket descriptor that no socket-aware File
// owns any more and applies the documented close-error contract to it: only
// WSAEWOULDBLOCK proves the descriptor is still valid and may be closed again by
// its single remaining owner; any other failure is an unresolved retirement and
// is reported instead of retried. closeSocket is the one disposal API the
// descriptor's owner selected, never a generic File close.
func retireSocketDescriptor(handle windows.Handle, closeErr error, closeSocket func(windows.Handle) error) error {
	if !errors.Is(closeErr, windows.WSAEWOULDBLOCK) {
		return &unresolvedSocketRetirement{handle: handle, err: closeErr}
	}
	lastErr := closeErr
	for retry := 0; retry < carrierRetireRetries; retry++ {
		time.Sleep(carrierRetireRetryPause)
		lastErr = closeSocket(handle)
		if lastErr == nil {
			// The retry released the descriptor: invalidate the cleanup token
			// before the caller performs any further work.
			return nil
		}
		if !errors.Is(lastErr, windows.WSAEWOULDBLOCK) {
			break
		}
	}
	return &unresolvedSocketRetirement{handle: handle, err: lastErr}
}

// retireOriginalSocket retires the original native socket with the only valid
// socket API and applies the documented close-error contract: a proven release
// returns nil, a documented WSAEWOULDBLOCK outcome is retried by the same
// owner, and an ambiguous result returns an unresolved-retirement error instead
// of a blind retry of the numeric handle.
func retireOriginalSocket(handle windows.Handle) error {
	_, err := retireOriginalSocketOutcome(handle)
	return err
}

// retireOriginalSocketOutcome applies the same close-error contract and also
// reports whether the native release is proven. The deferred attempt path only
// needs the error; the retained operation needs the proof as well, because only
// a proven release may discharge its admission charge. A would-block outcome
// that is released by the owner's own retry is a proven release that still
// reports the transient close error, exactly like the deferred attempt path: a
// close error is never dropped.
func retireOriginalSocketOutcome(handle windows.Handle) (bool, error) {
	closeErr := closeOriginalSocket(handle)
	if closeErr == nil {
		return true, nil
	}
	cause := E.Cause(closeErr, "desync: retire original socket")
	if residual := retireSocketDescriptor(handle, closeErr, closeOriginalSocket); residual != nil {
		return false, E.Errors(cause, residual)
	}
	return true, cause
}

// attemptRetirement is the final retirement of one attempt's original native
// socket. The deferred call site records the attempt outcome, retires the
// descriptor exactly once through its selected socket API, and then:
//
//   - rolls back an already adopted connection when retirement fails, so a
//     connection is never published while its original socket is unretired;
//   - keeps the attempt's admission charge when the release is unproven, so a
//     possibly valid descriptor can never look like a released, charge-free
//     attempt that a new native operation may replace;
//   - keeps both the attempt error and the retirement error visible.
type attemptRetirement struct {
	handle    windows.Handle
	conn      net.Conn
	holdOwned bool
	err       error
}

func (r *attemptRetirement) retire() {
	retireErr := retireOriginalSocket(r.handle)
	// A proven release of the original descriptor is not proof that the whole
	// attempt retired: a readiness probe, an adoption carrier or a failed
	// duplicate of this same attempt may still be unresolved in the attempt
	// error. Every application-visible O/P/C obligation must be proven before
	// this attempt discharges its admission charge, so an unresolved temporary
	// descriptor keeps the charge exactly like an unproven original release and
	// the adopted connection is rolled back instead of being published.
	attemptUnresolved := hasUnresolvedRetirement(r.err)
	if retireErr == nil && !attemptUnresolved {
		return
	}
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	var unresolved *unresolvedSocketRetirement
	if attemptUnresolved || (retireErr != nil && errors.As(retireErr, &unresolved)) {
		// The descriptor may still be valid and is not closed again: the
		// attempt keeps the charge instead of pretending it was released.
		r.holdOwned = false
	}
	if retireErr != nil {
		r.err = E.Errors(r.err, retireErr)
	}
}

// hasUnresolvedRetirement reports whether err carries an unproven socket
// retirement of one attempt. The retirement decision needs the same
// classification the deferred original-socket path uses, so a temporary
// descriptor of this attempt is never mistaken for a proven release.
func hasUnresolvedRetirement(err error) bool {
	var unresolved *unresolvedSocketRetirement
	return err != nil && errors.As(err, &unresolved)
}

// adoptConnectedSocket hands a connected Winsock socket to the net package
// exactly once and returns the adopted connection.
//
// net.FileConn needs an *os.File and duplicates the socket it is given; the
// returned connection owns that duplicate and releases it through the net
// package's socket-aware close (closesocket). The *os.File is only a carrier:
// it must wrap a dedicated duplicate of the connected socket, never the
// original handle, and it must be constructed by the socket-aware constructor so
// that both File.Close and the File finalizer call closesocket instead of
// CloseHandle. The carrier is retired deterministically before this function
// returns; the caller keeps sole ownership of the original and releases it with
// windows.Closesocket.
//
// Retirement failures are not hidden. A carrier that cannot be retired prevents
// publication of the adopted connection (which is rolled back) and is reported
// together with any adoption or rollback error.
func adoptConnectedSocket(handle windows.Handle) (net.Conn, error) {
	carrier, err := duplicateForAdoption(handle)
	if err != nil {
		return nil, err
	}
	file, err := newAdoptionFile(carrier)
	if err != nil {
		// No wrapper was created, so this helper is still the carrier's only
		// owner: it is retired here and never handed to a constructor that
		// rejects it.
		constructErr := E.Cause(err, "desync: construct adoption carrier file")
		if closeErr := closeCarrierSocket(carrier); closeErr != nil {
			return nil, E.Errors(constructErr, &unresolvedSocketRetirement{handle: carrier, err: closeErr})
		}
		return nil, constructErr
	}
	conn, adoptErr := file.adopt()
	closeErr := file.close()
	var retireErr error
	if closeErr != nil {
		// A deterministic Close invalidates the socket-aware File even when it
		// reports an error: its poll descriptor is invalidated and its
		// finalizer is cleared, so this helper is the remaining cleanup owner.
		// The error is never dropped, not even when the documented
		// WSAEWOULDBLOCK retry below releases the descriptor: the adoption is
		// not published as a clean one after a close failure.
		retireErr = E.Cause(closeErr, "desync: retire adoption carrier")
		if residual := retireSocketDescriptor(carrier, closeErr, closeCarrierSocket); residual != nil {
			retireErr = E.Errors(retireErr, residual)
		}
	}
	if adoptErr != nil {
		// The duplication failed and retirement of the carrier may have failed
		// as well: both errors stay visible.
		return nil, E.Errors(adoptErr, retireErr)
	}
	if retireErr != nil {
		var rollbackErr error
		if conn != nil {
			rollbackErr = conn.Close()
		}
		return nil, E.Errors(retireErr, rollbackErr)
	}
	return conn, nil
}

// newOutstandingConnect builds the terminal-completion owner of one ConnectEx
// operation. The closures plus the retained payload keep the event, the
// OVERLAPPED and the submitted buffer valid for as long as the operation is
// owned, including after the caller's bounded wait returns. The attempt lease
// is the operation's existing admission charge: a retained operation discharges
// it only after terminal completion.
func newOutstandingConnect(handle windows.Handle, event windows.Handle, overlapped *windows.Overlapped, payload []byte, lease AttemptLease) *outstandingConnect {
	return &outstandingConnect{
		wait: func(timeout time.Duration) (bool, error) {
			milliseconds := uint32(windows.INFINITE)
			if timeout >= 0 {
				milliseconds = uint32(timeout / time.Millisecond)
				if milliseconds == 0 {
					milliseconds = 1
				}
			}
			status, waitErr := windows.WaitForSingleObject(event, milliseconds)
			if waitErr != nil {
				return false, E.Cause(waitErr, "desync: wait for connect")
			}
			switch status {
			case uint32(windows.WAIT_OBJECT_0), uint32(windows.WAIT_ABANDONED):
				return true, nil
			case uint32(windows.WAIT_TIMEOUT):
				return false, nil
			default:
				return false, E.New("desync: unexpected connect wait status")
			}
		},
		result: func() (uint32, error) {
			var transferred uint32
			if resultErr := windows.GetOverlappedResult(handle, overlapped, &transferred, false); resultErr != nil {
				// A failed operation has no authoritative transferred count:
				// the provider's out value is undefined when the connect did
				// not complete, so returning it would claim initial-payload
				// bytes that can never be delivered on a connection that does
				// not exist. Only a completed operation reports progress.
				return 0, E.Cause(resultErr, "desync: ConnectEx result")
			}
			return transferred, nil
		},
		cancel: func() error {
			// Cancellation is a request; the completion is observed through
			// the event. ERROR_NOT_FOUND means the operation already
			// completed, which the bounded grace harvests below.
			return windows.CancelIoEx(handle, overlapped)
		},
		release: func() {
			_ = windows.CloseHandle(event)
		},
		retireSocket: func() (bool, error) {
			// The retained operation owns the original socket from the
			// retention marker on, so its terminal release uses the same
			// single socket API and the same documented close-error contract
			// as the deferred attempt path: a would-block descriptor stays
			// valid and is retried by this owner, an ambiguous error keeps the
			// descriptor and the admission charge, and no numeric handle is
			// ever closed twice by a different owner.
			return retireOriginalSocketOutcome(handle)
		},
		buffer: payload,
		lease:  lease,
	}
}

// connectDeadline is the earliest of the attempt context deadline and the
// dialer connect timeout. There is deliberately no second independent timer.
func connectDeadline(ctx context.Context, base net.Dialer) time.Time {
	deadline, _ := ctx.Deadline()
	if base.Timeout > 0 {
		timeoutDeadline := time.Now().Add(base.Timeout)
		if deadline.IsZero() || timeoutDeadline.Before(deadline) {
			deadline = timeoutDeadline
		}
	}
	return deadline
}

const (
	// adoptContextBudget bounds how long the connected context of a just
	// completed ConnectEx socket may take to become visible to a duplicate.
	adoptContextBudget = 20 * time.Millisecond
	// adoptContextPause is the pause between two context observations. It is
	// not a delay before adoption: every iteration observes the actual socket
	// state and adoption is attempted as soon as it is observable.
	adoptContextPause = 200 * time.Microsecond
)

// waitConnectedContext observes the socket until a duplicate of it exposes the
// connected context (local and remote address). It is a no-op when the context
// is already visible.
//
// Native evidence (Windows Server 2022, first adoption in a fresh process): a
// WSADuplicateSocket + WSASocket duplicate created immediately after a
// completed overlapped ConnectEx can still be unconnected — Getsockname returns
// WSAEINVAL and Getpeername returns WSAENOTCONN — even though the original
// socket already reports both addresses and SO_UPDATE_CONNECT_CONTEXT was set.
// Go's net.FileConn duplicates the handle internally and derives the address
// family from syscall.Getsockname of that duplicate, discarding the error, so
// this transient state surfaces as EPROTONOSUPPORT ("protocol not supported")
// although the connect succeeded. The window closes within microseconds; this
// helper waits for the observable precondition instead of guessing a delay. It
// never re-issues the connect, never resends payload bytes and never adopts
// twice: net.FileConn below stays the single adoption, and its result (success
// or error) is authoritative.
//
// A probe whose retirement cannot be proven ends the sequence with an error: a
// failed closesocket must not be hidden by starting another probe, and no
// carrier may be created while an earlier probe descriptor is unresolved.
func waitConnectedContext(handle windows.Handle) error {
	deadline := time.Now().Add(adoptContextBudget)
	for {
		ready, err := probeConnectedContext(handle)
		if err != nil {
			var unresolved *unresolvedSocketRetirement
			if errors.As(err, &unresolved) {
				return err
			}
			// The connected context was not observable yet: the duplicate was
			// retired and this is the bounded precondition wait, not an
			// adoption result.
		} else if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(adoptContextPause)
	}
}

// probeConnectedContext observes one readiness duplicate and retires it with
// the only valid socket API. Readiness is an observation, not an adoption
// guarantee: the single net.FileConn result stays authoritative. A probe whose
// retirement is not proven stays an unresolved descriptor of this attempt; it
// is never hidden by starting another probe.
func probeConnectedContext(handle windows.Handle) (bool, error) {
	probe, err := duplicateProbe(handle)
	if err != nil {
		return false, err
	}
	if closeErr := closeCarrierSocket(probe); closeErr != nil {
		cause := E.Cause(closeErr, "desync: retire readiness probe")
		if residual := retireSocketDescriptor(probe, closeErr, closeCarrierSocket); residual != nil {
			return false, E.Errors(cause, residual)
		}
		return false, cause
	}
	return true, nil
}

// retireFailedDuplicate retires a duplicate that failed address validation. A
// failed retirement is reported instead of being hidden, so the caller cannot
// continue as if the descriptor had been released.
func retireFailedDuplicate(handle windows.Handle, cause error) error {
	if closeErr := closeCarrierSocket(handle); closeErr != nil {
		return E.Errors(cause, &unresolvedSocketRetirement{handle: handle, err: closeErr})
	}
	return cause
}

// duplicateConnectedSocket duplicates one socket and requires the duplicate to
// expose both a local and a remote address. The returned handle is owned by the
// caller and closed exactly once.
func duplicateConnectedSocket(handle windows.Handle) (windows.Handle, error) {
	var info windows.WSAProtocolInfo
	if err := windows.WSADuplicateSocket(handle, windows.GetCurrentProcessId(), &info); err != nil {
		return 0, E.Cause(err, "desync: duplicate connected socket")
	}
	duplicate, err := windows.WSASocket(-1, -1, -1, &info, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		return 0, E.Cause(err, "desync: duplicate connected socket handle")
	}
	if _, err = windows.Getsockname(duplicate); err != nil {
		return 0, retireFailedDuplicate(duplicate, E.Cause(err, "desync: duplicated socket has no local address"))
	}
	if _, err = windows.Getpeername(duplicate); err != nil {
		return 0, retireFailedDuplicate(duplicate, E.Cause(err, "desync: duplicated socket has no peer address"))
	}
	return duplicate, nil
}

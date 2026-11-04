//go:build windows

package dialer

import (
	"context"
	"errors"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is Winsock's SO_EXCLUSIVEADDRUSE, which winsock2.h defines
// as (int)(~SO_REUSEADDR). x/sys/windows does not export it.
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

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
// selected initial data, then consume the connected socket into the standard
// library's netFD/TCPConn through the direct-owned adoption bridge.
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
	// A packet-enabled attempt owns its local endpoint exclusively. Winsock
	// applies SO_EXCLUSIVEADDRUSE only before bind, and an ordinary Bind does
	// not exclude a foreign SO_REUSEADDR contender on the same port. The
	// option is applied after the caller's controls (which may still adjust
	// socket state) and before Bind, and only on the packet path: stream-only
	// leases keep the ordinary dialer bind behavior.
	if lease != nil && lease.RequiresExclusiveBind() {
		if err = windows.SetsockoptInt(handle, windows.SOL_SOCKET, soExclusiveAddrUse, 1); err != nil {
			return nil, 0, E.Cause(err, "desync: setsockopt(SO_EXCLUSIVEADDRUSE)")
		}
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
	written, err = writeAdoptedRemainder(conn, payload, written)
	if err != nil {
		return nil, written, err
	}
	return conn, written, nil
}

// writeAdoptedRemainder writes only the suffix the connect did not accept on
// the same adopted connection. The actual native accepted count plus the real
// remainder progress stays authoritative on both success and error. A write
// error rolls the adopted connection back exactly once through the existing
// helper, and a bad rollback Close keeps its opaque retirement charge; there is
// no reconnect and no replay.
func writeAdoptedRemainder(conn net.Conn, payload []byte, written int) (int, error) {
	if written >= len(payload) {
		return written, nil
	}
	rest, writeErr := conn.Write(payload[written:])
	written += rest
	if writeErr != nil {
		return written, errors.Join(writeErr, rollbackAdoptedConn(conn))
	}
	return written, nil
}

var (
	// duplicateForAdoption creates the readiness carrier through the public
	// Winsock duplication API.
	duplicateForAdoption = duplicateConnectedSocket
	// adoptOwnedCarrier is the direct-owned adoption bridge of
	// attempt_windows_adoption_ctor.go. It consumes a valid readiness-verified
	// carrier on entry, on success and on error, and returns the genuine
	// *net.TCPConn the standard library built around the same descriptor. The
	// caller never closes the carrier after this call.
	adoptOwnedCarrier = newOwnedSocketConn
	// closeCarrierSocket is the only socket disposal used for the carrier and
	// readiness-probe descriptors, whose socket-aware File was already closed
	// or was never constructed. It is a seam so the close-error contract is
	// exercised with fake handles.
	closeCarrierSocket = func(handle windows.Handle) error { return windows.Closesocket(handle) }
	// closeOriginalSocket is the single disposal API of the original native
	// socket. It is a seam so the original-retirement contract is exercised
	// with fake handles; the original is never handed to the adoption bridge.
	closeOriginalSocket = func(handle windows.Handle) error { return windows.Closesocket(handle) }
	// adoptNow and adoptSleep are the clock and pause of the bounded adoption
	// carrier acquisition. They exist so the fake-API tests can place a
	// carrier entry or a ready carrier on either side of the shared budget
	// deterministically, instead of depending on real scheduler delay; they
	// are not a general timer abstraction. Production uses the standard
	// functions.
	adoptNow   = time.Now
	adoptSleep = time.Sleep
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

// Opaque adoption-retirement stages. Each stage names a descriptor boundary
// whose descriptor existed but whose numeric identity is not available to this
// package, so its charge is recorded without inventing a handle.
const (
	adoptionRetirementStageAdoptedRollback = "adopted-connection-rollback"
)

// opaqueUnprovenAdoptionRetirement reports a descriptor of the adoption
// boundary whose release is not proven while its numeric identity is not
// exposed to this package: an adopted connection whose one-shot rollback Close
// did not report success. The error deliberately has no handle field: putting
// the original, the carrier or zero there would present a foreign or invented
// identity as if it were that descriptor, and a numeric close of an unproven
// handle is exactly what this accounting must not do. The marker is a
// conservative charge only; it never retries a Close, keeps the attempt's
// existing native hold/tombstone, and its cause stays inspectable through
// Unwrap.
type opaqueUnprovenAdoptionRetirement struct {
	stage string
	cause error
}

func (e *opaqueUnprovenAdoptionRetirement) Error() string {
	return E.New("desync: unproven adoption retirement at ", e.stage, ": ", e.cause).Error()
}

func (e *opaqueUnprovenAdoptionRetirement) Unwrap() error { return e.cause }

// rollbackAdoptedConn closes one adopted connection exactly once. The caller
// must not close it again afterwards. A nil connection had nothing to roll
// back, and a nil Close result proves this boundary release. A nonnil Close
// result becomes the opaque unproven-adoption-retirement marker of the rollback
// stage: a failed Close is not proof that the adopted descriptor was released,
// and no numeric handle may be substituted for it.
func rollbackAdoptedConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}
	if closeErr := conn.Close(); closeErr != nil {
		return &opaqueUnprovenAdoptionRetirement{stage: adoptionRetirementStageAdoptedRollback, cause: closeErr}
	}
	return nil
}

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
//   - rolls back an already adopted connection when retirement is not clean, so
//     a connection is never published while its original socket is unretired;
//   - charges a failed adopted rollback through the same opaque marker as the
//     adoption boundary, because its release is not proven;
//   - keeps the attempt's admission charge when any release is unproven, so a
//     possibly valid descriptor can never look like a released, charge-free
//     attempt that a new native operation may replace;
//   - keeps the attempt error, the original-retirement error and the rollback
//     error visible before the hold classification.
type attemptRetirement struct {
	handle    windows.Handle
	conn      net.Conn
	holdOwned bool
	err       error
}

func (r *attemptRetirement) retire() {
	retireErr := retireOriginalSocket(r.handle)
	// The early return is allowed only when the original descriptor was proven
	// released and the attempt carries no existing obligation. Every other
	// outcome takes the rollback path so nothing is discharged on an unproven
	// boundary.
	if retireErr == nil && !hasUnresolvedRetirement(r.err) {
		return
	}
	// A proven release of the original descriptor is not proof that the whole
	// attempt retired: a readiness probe, an adoption carrier, a failed
	// duplicate or an internal FileConn duplicate of this same attempt may
	// still be unresolved in the attempt error. The adopted connection is
	// rolled back through the one-shot helper and its result is joined into
	// the attempt error before the charge is classified, so an unproven
	// rollback can never be dropped or discharged.
	var rollbackErr error
	if r.conn != nil {
		rollbackErr = rollbackAdoptedConn(r.conn)
		r.conn = nil
	}
	// The prior attempt error is joined as the original object, not flattened:
	// the attempt aggregate and every leaf cause keep their identity for
	// errors.Is/errors.As, so the retirement decision and the caller observe
	// the exact obligation this attempt recorded. E.Errors would rebuild the
	// aggregate wrapper and drop the unresolved marker object even when no
	// rollback error was added. The retirement and rollback diagnostics stay
	// in the same chain.
	r.err = errors.Join(r.err, retireErr, rollbackErr)
	if hasUnresolvedRetirement(r.err) {
		// A descriptor may still be valid and is not closed again: the attempt
		// keeps the charge instead of pretending it was released.
		r.holdOwned = false
	}
}

// hasUnresolvedRetirement reports whether err carries an unproven descriptor
// release of one attempt: a socket descriptor with a known handle, or an
// opaque adoption-boundary descriptor with no known handle. The retirement
// decision needs the same classification the deferred original-socket path
// uses, so a temporary descriptor of this attempt is never mistaken for a
// proven release.
func hasUnresolvedRetirement(err error) bool {
	if err == nil {
		return false
	}
	var unresolved *unresolvedSocketRetirement
	if errors.As(err, &unresolved) {
		return true
	}
	var opaque *opaqueUnprovenAdoptionRetirement
	return errors.As(err, &opaque)
}

// adoptConnectedSocket hands a connected Winsock socket to the net package
// through the direct-owned adoption bridge and returns the genuine TCP
// connection the standard library built around a readiness-verified carrier.
//
// The carrier is acquired only after its own duplicated context reports both
// addresses, so the descriptor that was observed is the descriptor that is
// adopted. The carrier is consumed by the bridge: on success the standard
// netFD/TCPConn owns it, and on failure the bridge has already retired the raw
// descriptor or the unpublished netFD exactly once. The caller keeps sole
// ownership of the original socket and releases it with the existing original
// retirement contract.
//
// Retirement failures are not hidden. Every raw-carrier close and every
// unpublished FD.Close result becomes visible in the returned error, and an
// unproven release keeps the attempt's admission charge. No failure is retried.
func adoptConnectedSocket(handle windows.Handle) (net.Conn, error) {
	deadline := adoptNow().Add(adoptContextBudget)
	return adoptConnectedSocketOnce(handle, deadline)
}

// adoptConnectedSocketOnce performs the single adoption attempt: one
// readiness-verified carrier, one consume-on-entry bridge call and the
// deterministic ownership transfer or cleanup of that descriptor. Every
// outcome is final for the attempt.
func adoptConnectedSocketOnce(handle windows.Handle, deadline time.Time) (net.Conn, error) {
	carrier, err := acquireConnectedCarrier(handle, deadline)
	if err != nil {
		return nil, err
	}
	// A valid acquired carrier is consumed on entry, on success and on error.
	// The bridge is the only caller-side owner from this point on.
	return adoptOwnedCarrier(carrier, deadline)
}

// socketAdoptionAPI is the six-function boundary of the direct adoption
// bridge. Production binds exactly the five qualified net symbols plus the
// carrier address observation; the inert tests script the same routine with
// allocated Go tokens and net.Pipe connections instead of overlaying stdlib.
type socketAdoptionAPI struct {
	addresses func(windows.Handle) (int, *net.TCPAddr, *net.TCPAddr, error)
	newFD     func(syscall.Handle, int, int, string) (unsafe.Pointer, error)
	initFD    func(unsafe.Pointer) error
	setAddr   func(unsafe.Pointer, net.Addr, net.Addr)
	tcpConn   func(unsafe.Pointer) net.Conn
	closeFD   func(unsafe.Pointer) error
}

// bridgeOwnedCarrier consumes one valid readiness-verified carrier and builds
// the standard-library connection around that same descriptor. Ownership moves
// raw carrier -> netFD, at net.newFD's nonnil descriptor, and then FD ->
// TCPConn, at net.newTCPConn. Exactly one owner closes the descriptor on each
// path:
//
//   - address/deadline/newFD failure before an FD exists: one raw carrier
//     close through the documented retirement helper;
//   - init (or defensive newFD) failure with an FD: one FD.Close, never a raw
//     close afterwards;
//   - late success: one rollback Close of the connection;
//   - timely success: no carrier close, the TCPConn owns it.
//
// The FD pointer is never dereferenced, never converted through uintptr and is
// kept visible to the garbage collector until the last internal call.
func bridgeOwnedCarrier(api socketAdoptionAPI, carrier windows.Handle, deadline time.Time) (net.Conn, error) {
	if carrier == 0 || carrier == windows.InvalidHandle {
		// Invalid sentinels are rejected without a close: no descriptor was
		// ever transferred to this boundary.
		return nil, E.New("desync: adoption carrier handle is invalid")
	}
	family, local, remote, err := api.addresses(carrier)
	if err != nil {
		return nil, retireFailedDuplicate(carrier, err)
	}
	// Entry admission of the FD construction group: an expired shared budget
	// closes the raw carrier and never enters init.
	if !adoptNow().Before(deadline) {
		return nil, retireFailedDuplicate(carrier, adoptionBudgetError(nil))
	}
	fd, newFDErr := api.newFD(syscall.Handle(carrier), family, syscall.SOCK_STREAM, "tcp")
	if fd == nil {
		// The pinned body always returns a nonnil FD; a defensive nil leaves
		// the raw carrier with this bridge as its only owner.
		cause := E.New("desync: allocate adopted socket")
		if newFDErr != nil {
			cause = E.Cause(newFDErr, "desync: allocate adopted socket")
		}
		return nil, retireFailedDuplicate(carrier, cause)
	}
	// The nonnil FD owns the carrier from here on, even if newFD also reported
	// an error. Only the FD may be closed; the raw carrier must not be.
	if newFDErr != nil {
		closeErr := api.closeFD(fd)
		runtime.KeepAlive(fd)
		return nil, errors.Join(E.Cause(newFDErr, "desync: allocate adopted socket"), adoptedFDCloseFailure(carrier, closeErr))
	}
	if err := api.initFD(fd); err != nil {
		// Init failure: exactly one FD.Close and no raw numeric retry
		// afterwards. A nil close result proves this unpublished FD boundary;
		// a nonnil one becomes the known-carrier unresolved obligation.
		closeErr := api.closeFD(fd)
		runtime.KeepAlive(fd)
		return nil, errors.Join(E.Cause(err, "desync: init adopted socket"), adoptedFDCloseFailure(carrier, closeErr))
	}
	api.setAddr(fd, local, remote)
	conn := api.tcpConn(fd)
	runtime.KeepAlive(fd)
	// A success observed after the shared budget is rolled back and never
	// published: the TCPConn now owns the carrier, so this one Close is the
	// only carrier cleanup.
	if !adoptNow().Before(deadline) {
		return nil, errors.Join(adoptionLateError(), rollbackAdoptedConn(conn))
	}
	return conn, nil
}

// adoptedFDCloseFailure classifies the Close result of an unpublished netFD.
// A nil result proves the boundary release. A nonnil result becomes the
// existing known-handle unresolved obligation for the carrier, because the
// failed FD.Close is not proof that the descriptor was released. The descriptor
// is never closed again through its numeric handle.
func adoptedFDCloseFailure(carrier windows.Handle, closeErr error) error {
	if closeErr == nil {
		return nil
	}
	return &unresolvedSocketRetirement{handle: carrier, err: closeErr}
}

// adoptionLateError reports an adoption success that completed only after the
// shared admission budget expired. The adopted descriptor is rolled back by the
// bridge and is never published.
func adoptionLateError() error {
	return E.New("desync: adoption completed after the adoption budget expired")
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
	// adoptContextBudget bounds how long the adoption carrier may take to expose
	// the connected context (local and peer address) of a just completed
	// ConnectEx socket. The same absolute budget admits the carrier
	// acquisition, the single adoption entry and the acceptance of an adoption
	// success, so neither a duplicate nor a late FileConn can extend the
	// attempt.
	adoptContextBudget = 20 * time.Millisecond
	// adoptContextPause is the pause between two carrier observations. It is
	// not a delay before adoption: every iteration observes the actual carrier
	// context and the sequence ends as soon as a carrier exposes it.
	adoptContextPause = 200 * time.Microsecond
)

// acquireConnectedCarrier creates the adoption carrier and returns it only when
// the carrier itself exposes both the local and the peer address of the
// connected socket, all under the caller's absolute adoption deadline.
//
// The carrier is the readiness boundary: the descriptor whose own context is
// verified is the descriptor the adoption consumes, so a readiness observation
// can never be separated from the carrier that is adopted. Native evidence
// (Windows Server 2022): a duplicate created after a completed overlapped
// ConnectEx can still be unconnected while the original already reports both
// addresses and SO_UPDATE_CONNECT_CONTEXT was set, and such a duplicate can stay
// unconnected for its whole life (Getsockname returns WSAEINVAL, Getpeername
// returns WSAENOTCONN). A carrier born in that state is retired exactly once
// through the socket API and replaced inside the same bounded budget; an
// unverified carrier is never handed to the adoption bridge, and budget
// exhaustion is reported instead of continuing to adoption.
//
// A carrier whose retirement cannot be proven stops the sequence immediately: no
// second carrier may be created while the earlier descriptor is unresolved, and
// the token keeps the attempt's admission charge. A duplication failure that is
// not an address observation acquired no descriptor, so it ends the attempt with
// its cause and nothing is closed for it.
func acquireConnectedCarrier(handle windows.Handle, deadline time.Time) (windows.Handle, error) {
	var lastErr error
	for {
		// Admission of the acquisition entry, including every replacement:
		// once the shared budget is spent, no further native descriptor is
		// created for this attempt.
		if !adoptNow().Before(deadline) {
			return 0, adoptionBudgetError(lastErr)
		}
		carrier, err := duplicateForAdoption(handle)
		if err == nil {
			// Success is admitted under the same deadline. A carrier that
			// becomes ready only after the budget is retired exactly once
			// through the carrier close contract and is never handed to
			// the adoption bridge, so no adoption can outlive the attempt
			// budget.
			if !adoptNow().Before(deadline) {
				return 0, retireFailedDuplicate(carrier, adoptionBudgetError(lastErr))
			}
			return carrier, nil
		}
		var unresolved *unresolvedSocketRetirement
		if errors.As(err, &unresolved) {
			return 0, err
		}
		var notVisible *connectedContextNotVisible
		if !errors.As(err, &notVisible) {
			return 0, err
		}
		lastErr = err
		if !adoptNow().Before(deadline) {
			return 0, adoptionBudgetError(lastErr)
		}
		adoptSleep(adoptContextPause)
	}
}

// adoptionBudgetError is the single expiry error of the shared carrier budget.
// It keeps the last connected-context observation as its cause when one was
// made, so the exact Winsock observation is not replaced by the budget
// message.
func adoptionBudgetError(lastErr error) error {
	const message = "desync: connected socket context not observable within the adoption budget"
	if lastErr != nil {
		return E.Cause(lastErr, message)
	}
	return E.New(message)
}

// retireFailedDuplicate retires a duplicated carrier that must not be adopted:
// one that failed address validation, or a carrier that became ready only after
// the shared acquisition budget expired. A failed retirement is reported
// instead of being hidden, so the caller cannot continue as if the descriptor
// had been released.
func retireFailedDuplicate(handle windows.Handle, cause error) error {
	if closeErr := closeCarrierSocket(handle); closeErr != nil {
		return E.Errors(cause, &unresolvedSocketRetirement{handle: handle, err: closeErr})
	}
	return cause
}

// connectedContextNotVisible reports that a freshly duplicated socket does not
// expose the connected context yet: the descriptor exists, its retirement is
// accounted for by the caller, and the socket itself is connected. It is the
// only duplication outcome that the bounded acquisition may replace, because a
// duplicate born in this state can stay unconnected for its whole life. The
// message is the underlying address observation, so the diagnostic keeps the
// exact Winsock cause.
type connectedContextNotVisible struct {
	cause error
}

func (e *connectedContextNotVisible) Error() string { return e.cause.Error() }

func (e *connectedContextNotVisible) Unwrap() error { return e.cause }

// duplicateConnectedSocket duplicates one socket and requires the duplicate to
// expose both a local and a remote address. The returned handle is owned by the
// caller and closed exactly once. A duplicate whose own context is not visible
// is retired before this function returns and is reported as
// connectedContextNotVisible; every other failure is final for the attempt.
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
		return 0, retireFailedDuplicate(duplicate, &connectedContextNotVisible{cause: E.Cause(err, "desync: duplicated socket has no local address")})
	}
	if _, err = windows.Getpeername(duplicate); err != nil {
		return 0, retireFailedDuplicate(duplicate, &connectedContextNotVisible{cause: E.Cause(err, "desync: duplicated socket has no peer address")})
	}
	return duplicate, nil
}

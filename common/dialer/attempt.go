package dialer

import (
	"context"
	"net"
	"net/netip"

	boxlistener "github.com/sagernet/sing-box/common/listener"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// AttemptIntent describes one native socket attempt before any side effect.
// Source is the effective bind address requested by the dialer options and
// Destination is already resolved to an IP address. Interface is the device
// this dialer actually binds every attempt to (bind_interface); it is an
// attempt fact, never a per-connection guess, and is empty when the dialer
// binds no device.
type AttemptIntent struct {
	Network     string
	Source      netip.AddrPort
	Destination M.Socksaddr
	Interface   string
	NetNs       string
	// Deferred marks an actual native attempt reached through the already
	// wrapped pending TFO facade. The direct bridge transfers packet-lease
	// ownership for these attempts but must not apply the stream wrapper a
	// second time: it was applied to the pending facade before any write.
	// This bit is internal and never maps to user JSON.
	Deferred bool
}

// AttemptHook creates one independently closable lease per native socket
// attempt, including losing parallel attempts. It must not import or know
// desync rule matching; the direct outbound implements this bridge.
type AttemptHook interface {
	NewAttempt(ctx context.Context, intent AttemptIntent) (AttemptLease, error)
}

// AttemptLease is the native lifecycle of one attempt. PrepareSocket runs
// after all existing interface/mark/namespace controls and before the first
// connect or send; on Linux it establishes the exclusive local port and
// capture ownership when RequiresExclusiveBind is true. AttachConn and
// AttachPacketConn transfer ownership to the returned object exactly once and
// are called only for successful attempts. An AttachConn failure is terminal:
// the dialer closes the native connection and fails the attempt, it never
// falls back to an unwrapped connection. Close is idempotent and is called for
// failed or losing attempts.
type AttemptLease interface {
	PrepareSocket(fd uintptr) error
	// RequiresExclusiveBind reports whether PrepareSocket binds the requested
	// local address itself, so the dialer must not let net.Dialer bind it
	// first. Packet capture leases own the exclusive local port; stream-only
	// leases do not and keep the ordinary dialer bind path.
	RequiresExclusiveBind() bool
	SetLocalAddress(address netip.AddrPort)
	StartCapture() error
	AttachConn(conn net.Conn) (net.Conn, error)
	AttachPacketConn(conn net.PacketConn) net.PacketConn
	Close(reason error) error
}

func localAddrPort(address net.Addr) netip.AddrPort {
	switch value := address.(type) {
	case *net.TCPAddr:
		return value.AddrPort()
	case *net.UDPAddr:
		return value.AddrPort()
	default:
		return netip.AddrPort{}
	}
}

// dialAttemptPayloadHook is the platform first-payload attempt. It is a
// variable only so hermetic lifecycle tests can observe the prepared-attempt
// ordering without creating a host socket or sending host packets; production
// always uses the platform implementation.
var dialAttemptPayloadHook = dialAttemptPayload

// FirstPayloadAttempt is the platform seam of the owned deferred first-payload
// attempt: it prepares exactly one native socket and submits the first
// transformed payload as TFO data on it.
type FirstPayloadAttempt func(ctx context.Context, base net.Dialer, network, address string, payload []byte, lease AttemptLease) (net.Conn, int, error)

// attemptPayload returns this dialer's platform first-payload attempt.
func (d *DefaultDialer) attemptPayload() FirstPayloadAttempt {
	if d.firstPayload != nil {
		return d.firstPayload
	}
	return dialAttemptPayloadHook
}

// dialOwnedTCP is the single owned native attempt behind the deferred TFO
// facade. It runs inside the selected network namespace, so deferred execution
// does not escape the namespace the logical dialer was created for. Exactly one
// lease exists per actual socket; the lease prepares the socket (bind, capture,
// stream preconnect controls) before the first connect/send, and packet-lease
// ownership is attached to the returned connection afterwards with the
// internal Deferred intent bit, which suppresses the second stream wrapper.
func (d *DefaultDialer) dialOwnedTCP(ctx context.Context, base net.Dialer, network, address string, payload []byte, intent AttemptIntent) (net.Conn, int, error) {
	if d.attemptHook == nil {
		return nil, 0, E.New("desync: deferred TFO requires a native attempt hook")
	}
	intent.Deferred = true
	// Admission precedes both the operation-owned payload copy and any native
	// effect: a refused admission must not copy or submit the caller's buffer.
	lease, err := d.attemptHook.NewAttempt(ctx, intent)
	if err != nil {
		return nil, 0, err
	}
	if len(payload) > 0 {
		// The deferred attempt may outlive the caller's Write: a retained
		// native operation keeps the submitted buffer after Write returned,
		// and the caller is free to reuse its own storage as soon as it does.
		// The operation therefore needs independent, operation-owned payload
		// storage acquired before any native submission and after admission;
		// copying later (for example inside the retention path) is too late
		// because the kernel already references the caller's bytes.
		owned := make([]byte, len(payload))
		copy(owned, payload)
		payload = owned
	}
	var sent int
	conn, err := boxlistener.ListenNetworkNamespace[net.Conn](ctx, d.netns, func() (net.Conn, error) {
		attemptConn, attemptSent, attemptErr := d.attemptPayload()(ctx, base, network, address, payload, lease)
		sent = attemptSent
		return attemptConn, attemptErr
	})
	if err != nil {
		// A retained operation still owns its native socket and keeps the
		// attempt's admission charged; its completion owner discharges it.
		if !retainedOperation(err) {
			_ = lease.Close(err)
		}
		return nil, sent, err
	}
	conn, err = lease.AttachConn(conn)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		_ = lease.Close(err)
		return nil, sent, err
	}
	return conn, sent, nil
}

// pendingIntent freezes the attempt facts reported to the hook. The pending
// facade reuses them verbatim: source address, zone, interface and namespace
// are attempt facts, never re-guessed at first write.
func (d *DefaultDialer) pendingIntent(base net.Dialer, network, address string) AttemptIntent {
	return AttemptIntent{
		Network:     network,
		Source:      localAddrPort(base.LocalAddr),
		Destination: M.ParseSocksaddr(address),
		Interface:   d.bindInterface,
		NetNs:       d.netns,
	}
}

// deferTCP reports whether this logical dial must be deferred so the first
// transformed payload can carry TFO data on an owned, prepared socket.
func (d *DefaultDialer) deferTCP(network string) bool {
	return d.tcpFastOpen && d.attemptHook != nil && d.pendingHook != nil && N.NetworkName(network) == N.NetworkTCP
}

// dialPendingTCP creates the lazy logical connection and applies the bridge's
// stream wrapper exactly once, before any user write and before any socket.
//
// A context canceled before this point keeps the eager dial contract: no
// connection is returned. Only cancellations that happen after the dial call
// returned (the parallel race winner case) are not inherited by the deferred
// attempt, which is why the pending facade stores a non-cancelable base.
func (d *DefaultDialer) dialPendingTCP(ctx context.Context, base net.Dialer, network string, address string) (net.Conn, *pendingTCPConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	intent := d.pendingIntent(base, network, address)
	pending := newPendingTCPConn(ctx, d, base, network, address, intent)
	wrapped, err := d.pendingHook.WrapPendingTCP(ctx, intent, pending)
	if err != nil {
		_ = pending.Close()
		return nil, nil, err
	}
	if wrapped == nil {
		_ = pending.Close()
		return nil, nil, E.New("desync: pending TFO hook returned no connection")
	}
	return wrapped, pending, nil
}

// dialNativeAttempt is the platform native dial behind dialAttempt. It is a
// variable only so hermetic lifecycle tests can substitute an owned transport
// without creating a host socket; production always uses the platform helper.
var dialNativeAttempt = dialAttempt

// dialAttempt performs one native dial; a nil hook is the exact existing path.
func (d *DefaultDialer) dialAttempt(ctx context.Context, base net.Dialer, network string, address string) (net.Conn, error) {
	if d.attemptHook == nil {
		return base.DialContext(ctx, network, address)
	}
	// A context that is already canceled or expired when the dial is called is
	// refused here, before the attempt hook, the per-attempt lease, the capture
	// registration and the native socket exist. The platform path cannot carry
	// this guarantee by itself: a synchronous ConnectEx success never consults
	// the context, so an attempt admitted after a completed cancellation would
	// still reach the peer and be returned as a live connection.
	//
	// This is the eager-dial entry point only. The deferred facade owns its own
	// refusal (dialPendingTCP) and runs its single attempt on a non-cancelable
	// base, so a family race that cancels the context it won with cannot fail an
	// already established winner; nothing below this point is re-checked, so
	// completion progress racing a later cancellation is never rejected.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lease, err := d.attemptHook.NewAttempt(ctx, AttemptIntent{
		Network:     network,
		Source:      localAddrPort(base.LocalAddr),
		Destination: M.ParseSocksaddr(address),
		Interface:   d.bindInterface,
		NetNs:       d.netns,
	})
	if err != nil {
		return nil, err
	}
	conn, err := dialNativeAttempt(ctx, base, network, address, lease)
	if err != nil {
		// A retained native operation keeps its own admission charge until the
		// kernel reports terminal completion.
		if !retainedOperation(err) {
			_ = lease.Close(err)
		}
		return nil, err
	}
	conn, err = lease.AttachConn(conn)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		_ = lease.Close(err)
		return nil, err
	}
	return conn, nil
}

// attachListener registers capture ownership for a bound UDP listener before
// the socket is published or used for the first send.
func (d *DefaultDialer) attachListener(ctx context.Context, conn net.PacketConn, err error) (net.PacketConn, error) {
	if err != nil || d.attemptHook == nil {
		return conn, err
	}
	local := localAddrPort(conn.LocalAddr())
	lease, hookErr := d.attemptHook.NewAttempt(ctx, AttemptIntent{
		Network:   N.NetworkUDP,
		Source:    local,
		Interface: d.bindInterface,
		NetNs:     d.netns,
	})
	if hookErr != nil {
		conn.Close()
		return nil, hookErr
	}
	lease.SetLocalAddress(local)
	if hookErr = lease.StartCapture(); hookErr != nil {
		conn.Close()
		_ = lease.Close(hookErr)
		return nil, hookErr
	}
	return lease.AttachPacketConn(conn), nil
}

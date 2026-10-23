package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// streamAttachment is the compiled stream configuration contract used by the
// per-attempt bridge. *desync.StreamConfig is the only production
// implementation; the interface is the seam that lets the attachment
// lifecycle be exercised hermetically without OS sockets. It is not a second
// attachment API: configuration is still direct.desync.stream_rules.
type streamAttachment interface {
	PrepareSocket(ctx context.Context, fd uintptr, facts desync.MatchFacts) error
	WrapConn(ctx context.Context, conn net.Conn, facts desync.MatchFacts) (net.Conn, error)
}

var _ streamAttachment = (*desync.StreamConfig)(nil)

// desyncHook bridges the dialer's per-attempt lifecycle to one engine lease
// (packet capture, when configured), the compiled stream snapshot and the
// connection ownership wrapper. The dialer never sees rules; neither the
// engine nor the stream snapshot creates sockets.
type desyncHook struct {
	engine *desync.Engine
	stream streamAttachment
	// lifetime bounds the stream wrapper. It must outlive the attempt:
	// parallel race contexts are canceled when the winner is returned, so an
	// attempt context can never be used for connection-lifetime cancellation.
	lifetime context.Context
	// logger is the direct outbound's existing production logger. A retained
	// operation outlives its caller, so this logger is the operator-visible
	// boundary that stays alive after the caller returned; it is not a new
	// logging registry or a second diagnostic owner.
	logger logger.ContextLogger
}

// desyncLease is the per-native-attempt lifecycle. Every attempt, including
// losing parallel attempts and Windows ConnectEx attempts, owns exactly one.
type desyncLease struct {
	lease  *desync.Lease
	stream streamAttachment
	intent dialer.AttemptIntent
	facts  desync.MatchFacts
	// ctx is the attempt context: PrepareSocket may be canceled with the dial.
	ctx context.Context
	// lifetime is the connection context passed to WrapConn.
	lifetime context.Context
	// logger is the outbound's existing operator-visible boundary for a
	// retained operation that fails after its caller returned.
	logger logger.ContextLogger
	// listener marks a bound UDP listener lease: no destination is known yet
	// and the peer is the later flow discriminator.
	listener bool

	mu       sync.Mutex
	attached bool
}

func (h *desyncHook) NewAttempt(ctx context.Context, intent dialer.AttemptIntent) (dialer.AttemptLease, error) {
	destination := intent.Destination
	transport := desync.TransportTCP
	if N.NetworkName(intent.Network) == N.NetworkUDP {
		transport = desync.TransportUDP
	}
	// A bound UDP listener has no destination yet: its lease is scoped by the
	// local endpoint, and each peer becomes a flow discriminator later. TCP
	// attempts and destination-less non-listener attempts still require a
	// resolved destination.
	listener := false
	if !destination.IsIP() {
		if transport != desync.TransportUDP || !intent.Source.IsValid() || intent.Source.Port() == 0 {
			return nil, E.New("desync: native attempt requires a resolved destination")
		}
		listener = true
	}
	facts := h.attemptFacts(ctx, intent, transport, listener)
	lifetime := h.lifetime
	if lifetime == nil {
		// A hook built without a service lifetime (tests) must never cancel
		// the wrapper when the dial attempt ends.
		lifetime = context.WithoutCancel(ctx)
	}
	lease := &desyncLease{
		stream:   h.stream,
		intent:   intent,
		ctx:      ctx,
		lifetime: lifetime,
		logger:   h.logger,
		listener: listener,
		facts:    facts,
	}
	if h.ownsAdmission(transport) {
		engineLease, err := h.engine.NewAttempt(desync.Intent{
			Family:      facts.Family,
			Transport:   transport,
			Source:      intent.Source,
			Interface:   intent.Interface,
			Destination: netip.AddrPortFrom(destination.Addr, destination.Port),
			Host:        facts.Host,
		})
		if err != nil {
			return nil, err
		}
		lease.lease = engineLease
	}
	return lease, nil
}

// ownsAdmission reports whether this attempt has desync work that the engine
// admission pool must charge. A TCP attempt always owns the stream wrapper and
// the native retention capability of the same attempt, and a packet-capable
// engine additionally owns its capture. A state-only engine has no packet
// backend, so a UDP attempt or a bound UDP listener owns ordinary UDP I/O only:
// charging it would consume the stream pool for traffic that has no stream,
// capture or native-retention work, and its returned connection would carry no
// owner that could ever discharge that charge.
func (h *desyncHook) ownsAdmission(transport desync.Transport) bool {
	if h.engine == nil {
		return false
	}
	if h.engine.PacketEnabled() {
		return true
	}
	return transport == desync.TransportTCP
}

// attemptFacts derives the rule-matching facts of one native attempt. It is
// shared by the eager attempt lease and the deferred pending-TFO wrapper so a
// deferred flow is matched by exactly the same facts as an eager one.
func (h *desyncHook) attemptFacts(ctx context.Context, intent dialer.AttemptIntent, transport desync.Transport, listener bool) desync.MatchFacts {
	destination := intent.Destination
	family := desync.FamilyIPv4
	switch {
	case destination.IsIPv6():
		family = desync.FamilyIPv6
	case listener && intent.Source.Addr().Is6() && !intent.Source.Addr().Is4In6():
		family = desync.FamilyIPv6
	}
	domain := ""
	_, metadata := adapter.ExtendContext(ctx)
	if metadata != nil {
		domain = metadata.Domain
	}
	return desync.MatchFacts{
		Family:      family,
		Transport:   transport,
		Destination: destination.Addr,
		Port:        destination.Port,
		Host:        domain,
		HostKnown:   domain != "",
	}
}

// WrapPendingTCP applies the compiled stream wrapper to the deferred logical
// TCP connection exactly once, before any user write and before any socket
// exists. A nil stream configuration is the packet-only case: the pending
// facade itself is returned unchanged, because packet capture is attached to
// the actual socket through the attempt lease, not through a stream wrapper.
func (h *desyncHook) WrapPendingTCP(ctx context.Context, intent dialer.AttemptIntent, pending net.Conn) (net.Conn, error) {
	if pending == nil {
		return nil, E.New("desync: pending TFO connection is nil")
	}
	if h.stream == nil {
		return pending, nil
	}
	facts := h.attemptFacts(ctx, intent, desync.TransportTCP, false)
	lifetime := h.lifetime
	if lifetime == nil {
		lifetime = context.WithoutCancel(ctx)
	}
	wrapped, err := h.stream.WrapConn(lifetime, pending, facts)
	if err != nil {
		return nil, err
	}
	if wrapped == nil {
		return nil, E.New("desync: stream wrapper returned no pending connection")
	}
	return wrapped, nil
}

// isTCP reports whether this attempt owns a TCP stream. Stream rules never
// apply to UDP attempts or to bound UDP listeners.
func (l *desyncLease) isTCP() bool {
	return N.NetworkName(l.intent.Network) == N.NetworkTCP
}

// PrepareSocket applies the packet lease's native controls first and then the
// stream preconnect controls, on every owned TCP native attempt. The fd stays
// owned by the dialer.
//
// The native attempt's actual interface fact is resolved here, after the
// socket exists: the socket-reported device wins, the dialer-supplied bind
// interface is the second actual fact. It scopes the stream preconnect ip-cache
// lookup to that interface, so a host learned on another device is never used
// as a cross-device fallback. Attempts with no interface fact keep the
// outbound-scoped lookup (nothing is crossed).
func (l *desyncLease) PrepareSocket(fd uintptr) error {
	interfaceFact := l.intent.Interface
	if l.lease != nil {
		// Admission and packet capability are separate: only a packet-capable
		// engine owns the capture/bind preparation. A stream-only state lease
		// keeps the ordinary dialer bind path and never opens a capture.
		if l.lease.PacketEnabled() {
			if err := l.lease.PrepareSocket(fd); err != nil {
				return err
			}
		}
		if device := l.lease.CaptureInterface(); device != "" {
			interfaceFact = device
		}
	}
	l.applyPreconnectInterface(interfaceFact)
	if l.stream != nil && l.isTCP() {
		return l.stream.PrepareSocket(l.ctx, fd, l.facts)
	}
	return nil
}

// applyPreconnectInterface records the attempt's interface fact and resolves the
// preconnect host on that interface through the engine-owned ip cache. It never
// creates a second cache: the lookup is the same Engine.CachedHostOn entry the
// packet flows populate, and an interface-scoped miss is a miss (no fallback to
// a host learned on another device).
func (l *desyncLease) applyPreconnectInterface(interfaceFact string) {
	if interfaceFact == "" {
		return
	}
	l.facts.Interface = interfaceFact
	if l.lease == nil || l.facts.HostKnown || !l.facts.Destination.IsValid() {
		return
	}
	if host, hostIsIP, ok := l.lease.PreconnectHost(); ok {
		l.facts.Host = host
		l.facts.HostKnown = true
		l.facts.HostIsIP = hostIsIP
	}
}

// RequiresExclusiveBind is true exactly when the packet lease binds the local
// address itself inside PrepareSocket. Stream-only attempts keep the ordinary
// dialer bind path: their lease is admission only, never packet capability.
func (l *desyncLease) RequiresExclusiveBind() bool {
	return l.lease != nil && l.lease.PacketEnabled()
}

func (l *desyncLease) SetLocalAddress(address netip.AddrPort) {
	if l.lease != nil {
		l.lease.SetLocalAddress(address)
	}
}

func (l *desyncLease) StartCapture() error {
	if l.lease != nil && l.lease.PacketEnabled() {
		return l.lease.StartCapture()
	}
	return nil
}

// AcquireNativeHold forwards the admission reference capability to the
// attempt's engine lease. The dialer retaining helper uses it structurally
// before a native ConnectEx effect; a stream-only lease forwards the same
// already charged slot, never a second one.
func (l *desyncLease) AcquireNativeHold() (func(), error) {
	if l.lease == nil {
		return nil, desync.RefuseAdmission(E.New("desync: native attempt has no admission owner"))
	}
	return l.lease.AcquireNativeHold()
}

// AttachConn transfers ownership exactly once. TCP connections run through
// the configured stream wrapper (before kernel serialization, so packet
// capture observes the transformed packets) and then through a wrapper that
// closes the packet capture lease with the connection. A wrapping failure is
// terminal: no unwrapped connection is returned.
func (l *desyncLease) AttachConn(conn net.Conn) (net.Conn, error) {
	if conn == nil {
		return nil, E.New("desync: attach nil connection")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.attached {
		return nil, E.New("desync: native attempt attached more than once")
	}
	l.attached = true
	if !l.isTCP() {
		return conn, nil
	}
	if l.intent.Deferred {
		// The stream wrapper was applied to the pending facade before any
		// user write. This actual attempt only transfers packet-lease
		// ownership: applying the wrapper again would double-transform the
		// first segment that the pending Write already carries as TFO data.
		if l.lease != nil {
			conn = &leaseConn{Conn: conn, lease: l.lease}
		}
		return conn, nil
	}
	if l.stream != nil {
		// The admission-carrying wrapper is created first, so the native
		// sender factory of the stream wrapper can acquire the attempt's
		// native reference through the connection it owns. The transformation
		// wrapper stays outside it: capture observes the transformed bytes and
		// no second lease wrapper or raw replacement path exists.
		if l.lease != nil {
			conn = &leaseConn{Conn: conn, lease: l.lease}
		}
		wrapped, err := l.stream.WrapConn(l.lifetime, conn, l.facts)
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if wrapped == nil {
			_ = conn.Close()
			return nil, E.New("desync: stream wrapper returned no connection")
		}
		conn = wrapped
	} else if l.lease != nil {
		conn = &leaseConn{Conn: conn, lease: l.lease}
	}
	return conn, nil
}

// AttachPacketConn registers no stream work: stream rules are TCP-only and
// UDP behavior is unchanged.
func (l *desyncLease) AttachPacketConn(conn net.PacketConn) net.PacketConn {
	return conn
}

func (l *desyncLease) Close(reason error) error {
	if l.lease != nil {
		return l.lease.Close(reason)
	}
	return nil
}

// ReportNativeFailure forwards the retained operation's terminal socket
// retirement failure to this attempt's engine lease diagnostic. The dialer uses
// it only when the native operation outlived its caller, so there is no caller
// error to join; the admission charge stays with the same lease and is not
// modified here.
//
// A retained operation fails after its caller already returned, so the attempt
// lease's private record is not an operator-visible boundary. The same failure
// is therefore published exactly once through the direct outbound's existing
// logger, with the original causes unchanged. The lease join above returns
// before the report, so no lease lock is held across it, and this method never
// touches the engine lock or the admission charge.
func (l *desyncLease) ReportNativeFailure(err error) {
	if err == nil {
		return
	}
	if l.lease != nil {
		l.lease.ReportNativeFailure(err)
	}
	if l.logger == nil {
		return
	}
	reportContext := l.ctx
	if reportContext == nil {
		reportContext = context.Background()
	} else {
		// The attempt context may already be canceled when the retained
		// operation finishes. This report is not attempt work, so it must not
		// be dropped because of that cancellation.
		reportContext = context.WithoutCancel(reportContext)
	}
	l.logger.ErrorContext(reportContext, "desync: retained native socket retirement failed: ", err)
}

// The dialer's retained-operation owner consumes this structural capability:
// the lease is the existing per-attempt diagnostic sink of a retention that
// failed to retire its socket after the caller returned.
var _ interface{ ReportNativeFailure(error) } = (*desyncLease)(nil)

// leaseConn ties packet capture ownership to the TCP connection lifetime. The
// capture must observe the whole connection and is released exactly once when
// the connection closes, including losing parallel attempts.
type leaseConn struct {
	net.Conn
	lease *desync.Lease

	closeOnce sync.Once
	closeErr  error
}

// AcquireNativeHold is the optional connection capability the platform sender
// factory and the dialer retaining helper consume. It forwards to the exact
// admission lease of this connection: no second lease, pool or registry.
func (c *leaseConn) AcquireNativeHold() (func(), error) {
	if c.lease == nil {
		return nil, desync.RefuseAdmission(E.New("desync: connection has no admission owner"))
	}
	return c.lease.AcquireNativeHold()
}

// NativeStreamConn exposes only the already-owned underlying connection to the
// internal platform sender factory. It never creates, dials or adopts a socket.
func (c *leaseConn) NativeStreamConn() net.Conn { return c.Conn }

func (c *leaseConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = errors.Join(c.Conn.Close(), c.lease.Close(nil))
	})
	return c.closeErr
}

// checkLegacyConflict rejects combining the new desync attachment with a
// legacy per-connection TLS transformation on the same connection, before any
// user data. The legacy options remain available on other outbounds and
// routes. It applies to packet capture, stream rules and their combination.
func (h *Outbound) checkLegacyConflict(ctx context.Context) error {
	if h.desync == nil && h.stream == nil {
		return nil
	}
	_, metadata := adapter.ExtendContext(ctx)
	if metadata == nil {
		return nil
	}
	switch {
	case metadata.TLSDesync != nil:
		return E.New("desync: cannot be combined with route tls_desync on the same connection")
	case metadata.TLSFragment || metadata.TLSRecordFragment:
		return E.New("desync: cannot be combined with route tls_fragment on the same connection")
	case metadata.TLSSpoof != "":
		return E.New("desync: cannot be combined with route tls_spoof on the same connection")
	}
	return nil
}

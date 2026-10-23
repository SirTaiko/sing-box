package socks

import (
	std_bufio "bufio"
	"context"
	"net"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	singUot "github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.SocksInboundOptions](registry, C.TypeSOCKS, NewInbound)
}

var _ adapter.TCPInjectableInbound = (*Inbound)(nil)

type Inbound struct {
	inbound.Adapter
	router         adapter.ConnectionRouterEx
	logger         logger.ContextLogger
	listener       *listener.Listener
	packetListener socks.PacketListener
	authenticator  *auth.Authenticator
	udpTimeout     time.Duration
	noResolve      bool
	resolver       *destinationResolver
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SocksInboundOptions) (adapter.Inbound, error) {
	var udpTimeout time.Duration
	if options.UDPTimeout != 0 {
		udpTimeout = time.Duration(options.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	resolver, err := newDestinationResolver(ctx, options)
	if err != nil {
		return nil, err
	}
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeSOCKS, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		authenticator: auth.NewAuthenticator(options.Users),
		udpTimeout:    udpTimeout,
		noResolve:     options.NoResolve,
		resolver:      resolver,
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	inbound.packetListener = inbound.listener
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	err := socks.HandleConnectionEx(ctx, conn, std_bufio.NewReader(conn), h.authenticator, adapter.NewUpstreamHandler(metadata, h.newUserConnection, h.streamUserPacketConnection), h.packetListener, h.udpTimeout, metadata.Source, onClose)
	N.CloseOnHandshakeFailure(conn, onClose, err)
	if err != nil {
		if E.IsClosedOrCanceled(err) {
			h.logger.DebugContext(ctx, "connection closed: ", err)
		} else {
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
		}
	}
}

func (h *Inbound) newUserConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	if !h.prepareDestination(ctx, conn, &metadata, onClose) {
		return
	}
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
		h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	h.logger.InfoContext(ctx, "[", user, "] inbound connection to ", metadata.Destination)
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

// prepareDestination applies the inbound destination policy of no_resolve and
// the bounded resolver before route rules, sniffing or dialing are consulted.
// It returns false when the request was already answered with the protocol
// failure response.
func (h *Inbound) prepareDestination(ctx context.Context, conn net.Conn, metadata *adapter.InboundContext, onClose N.CloseHandlerFunc) bool {
	requestMetadata, hasProvenance := requestMetadataFromConn(conn)
	if isUOTMagicAddress(metadata.Destination.Fqdn) {
		// UoT control requests carry a synthetic domain instead of a real
		// destination: they are transport requests, not resolvable hosts, so
		// the existing UDP-over-TCP extension stays untouched.
		return true
	}
	if h.noResolve {
		if !validRequestProvenance(requestMetadata, hasProvenance, metadata.Destination) {
			err := E.New("socks: rejected connection to ", metadata.Destination, ": missing or inconsistent wire provenance")
			return h.rejectConnection(ctx, conn, onClose, err)
		}
		if requestMetadata.DestinationFamily == M.AddressFamilyFqdn {
			// syscall.EPERM is the error the existing sing SOCKS response
			// mapping turns into the ruleset-denied reply code, so the real
			// lazy handshake error path is used instead of a parser fork or a
			// guessed errno.
			err := E.Cause(syscall.EPERM, "socks: rejected domain destination ", metadata.Destination, ": no_resolve is enabled")
			return h.rejectConnection(ctx, conn, onClose, err)
		}
		return true
	}
	if !metadata.Destination.IsDomain() {
		return true
	}
	if h.resolver == nil {
		return true
	}
	addresses, err := h.resolver.lookup(ctx, metadata, metadata.Destination.Fqdn)
	if err != nil {
		err = E.Cause(err, "socks: resolve destination ", metadata.Destination)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		_ = conn.Close()
		h.logger.ErrorContext(ctx, err)
		return false
	}
	metadata.DestinationAddresses = addresses
	h.logger.DebugContext(ctx, "resolved ", metadata.Destination.Fqdn, " to ", addresses)
	return true
}

func (h *Inbound) rejectConnection(ctx context.Context, conn net.Conn, onClose N.CloseHandlerFunc, err error) bool {
	N.CloseOnHandshakeFailure(conn, onClose, err)
	_ = conn.Close()
	h.logger.DebugContext(ctx, err)
	return false
}

// requestMetadataFromConn reads the optional wire provenance capability of the
// connection handed over by the shared SOCKS handshake. It performs no read or
// write on the connection and works through the existing upstream wrappers.
func requestMetadataFromConn(conn net.Conn) (socks.RequestMetadata, bool) {
	provider, loaded := common.Cast[socks.RequestMetadataProvider](conn)
	if !loaded {
		return socks.RequestMetadata{}, false
	}
	return provider.RequestMetadata()
}

// validRequestProvenance reports whether a no_resolve admission decision can
// rely on the observed wire form. Missing or inconsistent provenance fails
// closed instead of being treated as a literal destination.
//
// The consistency check must compare against the shapes the shared parser can
// actually publish. An ATYP=4 request is either a native IPv6 address or a
// 16-byte IPv4-mapped address that the shared serializer normalizes with
// Socksaddr.Unwrap into a plain IPv4 address, so both IP shapes are valid
// outputs of the IPv6 wire family and the normalized mapped literal keeps
// flowing as the IPv4 literal it denotes. Domains are never valid for an IP
// wire family, and the Fqdn family keeps its original-wire denial below.
func validRequestProvenance(requestMetadata socks.RequestMetadata, hasProvenance bool, destination M.Socksaddr) bool {
	if !hasProvenance {
		return false
	}
	switch requestMetadata.Version {
	case 4:
		// SOCKS4 has no ATYP byte: its destination classification is either
		// the IPv4 literal form or the SOCKS4a hostname form.
		if requestMetadata.DestinationFamily == M.AddressFamilyIPv6 {
			return false
		}
	case 5:
	default:
		return false
	}
	switch requestMetadata.DestinationFamily {
	case M.AddressFamilyIPv4:
		return destination.Addr.Is4()
	case M.AddressFamilyIPv6:
		return destination.Addr.Is6() || destination.Addr.Is4()
	case M.AddressFamilyFqdn:
		// The shared parsers normalize an IP-looking domain into a literal
		// address, so both a kept hostname and a normalized address are
		// consistent with a domain-form request.
		return destination.IsValid()
	default:
		return false
	}
}

func isUOTMagicAddress(domain string) bool {
	return domain == singUot.MagicAddress || domain == singUot.LegacyMagicAddress
}

func (h *Inbound) streamUserPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		if !metadata.Destination.IsValid() {
			h.logger.InfoContext(ctx, "inbound packet connection")
		} else {
			h.logger.InfoContext(ctx, "inbound packet connection to ", metadata.Destination)
		}
		h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	metadata.User = user
	if !metadata.Destination.IsValid() {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection")
	} else {
		h.logger.InfoContext(ctx, "[", user, "] inbound packet connection to ", metadata.Destination)
	}
	h.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

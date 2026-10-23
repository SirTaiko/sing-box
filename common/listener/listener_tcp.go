package listener

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/redir"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"github.com/database64128/tfo-go/v2"
)

// tcpListenFunc creates one native TCP listen socket. It is a seam for the
// multi-bind rollback test; production uses defaultTCPListenFunc.
type tcpListenFunc func(ctx context.Context, config *net.ListenConfig, tcpFastOpen bool, network string, address string) (net.Listener, error)

func defaultTCPListenFunc(ctx context.Context, config *net.ListenConfig, tcpFastOpen bool, network string, address string) (net.Listener, error) {
	if tcpFastOpen {
		var tfoConfig tfo.ListenConfig
		tfoConfig.ListenConfig = *config
		return tfoConfig.Listen(ctx, network, address)
	}
	return config.Listen(ctx, network, address)
}

func (l *Listener) listenerFunc() tcpListenFunc {
	if l.listenFunc != nil {
		return l.listenFunc
	}
	return defaultTCPListenFunc
}

func (l *Listener) ListenTCP() (net.Listener, error) {
	//nolint:staticcheck
	if l.listenOptions.ProxyProtocol || l.listenOptions.ProxyProtocolAcceptNoHeader {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	tcpOptions, err := l.buildTCPSocketOptions()
	if err != nil {
		return nil, err
	}
	admission, err := l.buildTCPAdmission()
	if err != nil {
		return nil, err
	}
	relayOptions, err := l.buildTCPRelayOptions()
	if err != nil {
		return nil, err
	}
	l.tcpRelayOptions = relayOptions
	bindings := l.listenOptions.TCPBindings()
	if len(bindings) > 0 {
		if l.listenOptions.Listen != nil {
			return nil, E.New("tcp_listen_bindings conflicts with the legacy listen field")
		}
		if l.setSystemProxy {
			return nil, E.New("tcp_listen_bindings conflicts with set_system_proxy: one unambiguous endpoint is required")
		}
		if common.Contains(l.network, N.NetworkUDP) {
			return nil, E.New("tcp_listen_bindings is TCP-only and cannot configure a UDP-listening inbound")
		}
		if err = option.ValidateTCPListenBindings(bindings); err != nil {
			return nil, err
		}
	}
	listenConfig := l.buildTCPListenConfig(tcpOptions)
	handler := &tcpAcceptHandler{
		socketOptions: tcpOptions,
		admission:     admission,
		logger:        l.logger,
	}
	var tcpListener net.Listener
	if len(bindings) > 0 {
		tcpListener, err = l.listenTCPBindings(listenConfig, bindings, handler)
	} else {
		tcpListener, err = l.listenTCPLegacy(listenConfig, handler)
	}
	if err != nil {
		return nil, err
	}
	l.tcpListener = tcpListener
	return tcpListener, nil
}

func (l *Listener) buildTCPSocketOptions() (option.TCPOptions, error) {
	if l.listenOptions.TCPSocketOptions == nil {
		return option.TCPOptions{}, nil
	}
	return l.listenOptions.TCPSocketOptions.Build()
}

func (l *Listener) buildTCPAdmission() (*tcpAdmission, error) {
	limit := l.listenOptions.TCPMaxConnectionLimit()
	if l.listenOptions.TCPMaxConnections != nil && (limit < 1 || limit > 10000) {
		return nil, E.New("tcp_max_connections must be between 1 and 10000, got ", limit)
	}
	return newTCPAdmission(limit), nil
}

// buildTCPRelayOptions validates the relay policy of this listening inbound.
// The value is only transport policy for the existing connection-pair owner.
func (l *Listener) buildTCPRelayOptions() (adapter.TCPRelayOptions, error) {
	policy, err := l.listenOptions.TCPRelayPolicy()
	if err != nil {
		return adapter.TCPRelayOptions{}, err
	}
	if policy.Empty() {
		return adapter.TCPRelayOptions{}, nil
	}
	return adapter.TCPRelayOptions{
		DisableSplice:    policy.DisableSplice,
		MaxOrphanTime:    policy.MaxOrphanTime,
		HasMaxOrphanTime: policy.HasMaxOrphanTime,
	}, nil
}

// newTCPInboundMetadata builds the metadata of one accepted TCP connection.
// The relay policy of this acceptor travels with the metadata value, so an
// inbound detour keeps the origin policy and the origin admission token
// instead of deriving either one again.
func (l *Listener) newTCPInboundMetadata(conn net.Conn) adapter.InboundContext {
	var metadata adapter.InboundContext
	//nolint:staticcheck
	metadata.InboundDetour = l.listenOptions.Detour
	metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.TCPRelayOptions = l.tcpRelayOptions
	return metadata
}

func (l *Listener) buildTCPListenConfig(tcpOptions option.TCPOptions) net.ListenConfig {
	var listenConfig net.ListenConfig
	if l.listenOptions.BindInterface != "" {
		listenConfig.Control = control.Append(listenConfig.Control, control.BindToInterface(service.FromContext[adapter.NetworkManager](l.ctx).InterfaceFinder(), l.listenOptions.BindInterface, -1))
	}
	if l.listenOptions.RoutingMark != 0 {
		listenConfig.Control = control.Append(listenConfig.Control, control.RoutingMark(uint32(l.listenOptions.RoutingMark)))
	}
	if l.listenOptions.ReuseAddr {
		listenConfig.Control = control.Append(listenConfig.Control, control.ReuseAddr())
	}
	if l.listenOptions.DisableTCPKeepAlive {
		listenConfig.KeepAlive = -1
		listenConfig.KeepAliveConfig.Enable = false
	} else {
		keepIdle := time.Duration(l.listenOptions.TCPKeepAlive)
		if keepIdle == 0 {
			keepIdle = C.TCPKeepAliveInitial
		}
		keepInterval := time.Duration(l.listenOptions.TCPKeepAliveInterval)
		if keepInterval == 0 {
			keepInterval = C.TCPKeepAliveInterval
		}
		listenConfig.KeepAliveConfig = net.KeepAliveConfig{
			Enable:   true,
			Idle:     keepIdle,
			Interval: keepInterval,
		}
	}
	if l.listenOptions.TCPMultiPath {
		listenConfig.SetMultipathTCP(true)
	}
	if l.tproxy {
		listenConfig.Control = control.Append(listenConfig.Control, func(network, address string, conn syscall.RawConn) error {
			return control.Raw(conn, func(fd uintptr) error {
				return redir.TProxy(fd, !strings.HasSuffix(network, "4"), false)
			})
		})
	}
	if !tcpOptions.Empty() {
		// Socket options run first so T3 observes option calls before the
		// interface/mark/reuse controls and before bind.
		listenConfig.Control = control.Append(TCPControl(tcpOptions), listenConfig.Control)
	}
	return listenConfig
}

func (l *Listener) listenTCPLegacy(listenConfig net.ListenConfig, handler *tcpAcceptHandler) (net.Listener, error) {
	bindAddr := M.SocksaddrFrom(l.listenOptions.Listen.Build(netip.AddrFrom4([4]byte{127, 0, 0, 1})), l.listenOptions.ListenPort)
	tcpListener, err := ListenNetworkNamespace[net.Listener](l.ctx, l.listenOptions.NetNs, func() (net.Listener, error) {
		return l.listenerFunc()(l.ctx, &listenConfig, l.listenOptions.TCPFastOpen, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
	})
	if err != nil {
		return nil, err
	}
	l.logger.Info("tcp server started at ", tcpListener.Addr())
	return wrapTCPListener(tcpListener, handler), nil
}

func (l *Listener) listenTCPBindings(listenConfig net.ListenConfig, bindings option.TCPListenBindingList, handler *tcpAcceptHandler) (net.Listener, error) {
	return ListenNetworkNamespace[net.Listener](l.ctx, l.listenOptions.NetNs, func() (net.Listener, error) {
		resolved, err := ResolveTCPBindings(l.ctx, bindings, l.tcpBindInterfaceSource(), l.tcpBindClock())
		if err != nil {
			return nil, err
		}
		baseListeners := make([]net.Listener, 0, len(resolved))
		for index := range resolved {
			tcpListener, listenErr := l.listenResolvedBinding(&listenConfig, bindings[index], resolved[index])
			if listenErr != nil {
				// Allocate all bind sockets under rollback ownership before
				// the inbound reports ready. A later failure closes only the
				// sockets this inbound already acquired.
				var closeErr error
				for _, baseListener := range baseListeners {
					closeErr = E.Errors(closeErr, baseListener.Close())
				}
				return nil, E.Errors(E.Cause(listenErr, "tcp_listen_bindings[", index, "]"), closeErr)
			}
			l.logger.Info("tcp server started at ", tcpListener.Addr())
			baseListeners = append(baseListeners, tcpListener)
		}
		return newTCPMultiListener(baseListeners, handler), nil
	})
}

func (l *Listener) listenResolvedBinding(listenConfig *net.ListenConfig, binding option.TCPListenBinding, resolved ResolvedTCPBinding) (net.Listener, error) {
	address := M.SocksaddrFrom(resolved.Address, l.listenOptions.ListenPort)
	network := M.NetworkFromNetAddr(N.NetworkTCP, resolved.Address)
	var (
		tcpListener net.Listener
		err         error
	)
	if binding.Address != nil && binding.WaitIP > 0 {
		// An explicit address may appear after startup. Retry
		// EADDRNOTAVAIL only inside the declared wait-IP budget; selected
		// addresses already consumed that budget during resolution.
		clock := l.tcpBindClock()
		deadline := clock.Now().Add(time.Duration(binding.WaitIP))
		for {
			tcpListener, err = l.listenerFunc()(l.ctx, listenConfig, l.listenOptions.TCPFastOpen, network, address.String())
			if err == nil || !errors.Is(err, syscall.EADDRNOTAVAIL) {
				break
			}
			now := clock.Now()
			if !now.Before(deadline) {
				break
			}
			wait := tcpBindPollInterval
			if remaining := deadline.Sub(now); remaining < wait {
				wait = remaining
			}
			if waitErr := clock.Wait(l.ctx, wait); waitErr != nil {
				return nil, E.Errors(err, waitErr)
			}
		}
	} else {
		tcpListener, err = l.listenerFunc()(l.ctx, listenConfig, l.listenOptions.TCPFastOpen, network, address.String())
	}
	if err != nil {
		return nil, err
	}
	return tcpListener, nil
}

func (l *Listener) loopTCPIn() {
	tcpListener := l.tcpListener
	var (
		metadata    adapter.InboundContext
		acceptDelay time.Duration
	)
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			if l.shutdown.Load() && E.IsClosed(err) {
				return
			}
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				if acceptDelay == 0 {
					acceptDelay = 5 * time.Millisecond
				} else {
					acceptDelay = min(2*acceptDelay, time.Second)
				}
				l.logger.Error(err, ", retrying in ", acceptDelay)
				time.Sleep(acceptDelay)
				continue
			}
			tcpListener.Close()
			l.logger.Error("tcp listener closed: ", err)
			return
		}
		acceptDelay = 0
		metadata = l.newTCPInboundMetadata(conn)
		ctx := log.ContextWithNewID(l.ctx)
		l.logger.InfoContext(ctx, "inbound connection from ", metadata.Source)
		var onClose N.CloseHandlerFunc
		if closeHandler, hasCloseHandler := conn.(interface{ AdmissionCloseHandler() N.CloseHandlerFunc }); hasCloseHandler {
			onClose = closeHandler.AdmissionCloseHandler()
		}
		go l.connHandler.NewConnection(ctx, conn, metadata, onClose)
	}
}

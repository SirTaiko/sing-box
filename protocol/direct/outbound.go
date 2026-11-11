package direct

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"reflect"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/zapret"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/ping"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.DirectOutboundOptions](registry, C.TypeDirect, NewOutbound)
}

var (
	_ N.ParallelDialer                = (*Outbound)(nil)
	_ dialer.ParallelNetworkDialer    = (*Outbound)(nil)
	_ dialer.DirectDialer             = (*Outbound)(nil)
	_ adapter.FlowOutbound            = (*Outbound)(nil)
	_ adapter.InterfaceUpdateListener = (*Outbound)(nil)
)

type Outbound struct {
	outbound.Adapter
	ctx             context.Context
	logger          logger.ContextLogger
	network         adapter.NetworkManager
	dialer          dialer.ParallelInterfaceDialer
	domainStrategy  C.DomainStrategy
	fallbackDelay   time.Duration
	isEmpty         bool
	myAddresses     common.TypedValue[[]netip.Prefix]
	icmpPort        *ping.Port
	zapret          *zapret.Manager
	zapretInterface string
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.Detour != "" {
		return nil, E.New("`detour` is not supported in direct context")
	}
	var (
		zapretManager   *zapret.Manager
		socketOwner     dialer.SocketOwner
		zapretProfile   string
		zapretInterface string
	)
	if options.Zapret != nil {
		if options.Zapret.Profile == "" {
			return nil, E.New("zapret: `profile` is required in `zapret`")
		}
		if options.BindInterface == "" {
			return nil, E.New("zapret: `bind_interface` is required for a direct outbound with `zapret`")
		}
		if options.NetworkStrategy != nil {
			return nil, E.New("zapret: `network_strategy` is not supported for a direct outbound with `zapret` because the physical egress must be pinned by `bind_interface`")
		}
		if options.RoutingMark != 0 {
			return nil, E.New("zapret: `routing_mark` is not supported for a direct outbound with `zapret`: the unique ownership SO_MARK is managed by sing-box, and a user routing mark on the same sockets would be overwritten")
		}
		if options.NetNs != "" {
			return nil, E.New("zapret: `netns` is not supported for a direct outbound with `zapret` in this slice: the ownership nftables table is installed in the sing-box network namespace, so sockets created in another namespace would not be captured")
		}
		networkManager := service.FromContext[adapter.NetworkManager](ctx)
		if networkManager != nil {
			if defaultMark := networkManager.DefaultOptions().RoutingMark; defaultMark != 0 {
				return nil, E.New("zapret: `route.default_mark` is not supported with `zapret`: the unique ownership SO_MARK is managed by sing-box, and the default routing mark would be overwritten")
			}
			if networkManager.AutoRedirectOutputMark() != 0 {
				return nil, E.New("zapret: `tun.auto_redirect` is not supported together with `zapret` in this slice: auto-redirect manages its own socket mark; use `auto_route` without `auto_redirect`")
			}
		}
		zapretProfile = options.Zapret.Profile
		if !filepath.IsAbs(zapretProfile) {
			configDirectory := adapter.ConfigDirectoryFromContext(ctx)
			if configDirectory == "" {
				return nil, E.New("zapret: relative `profile` ", zapretProfile, " requires a loaded configuration directory; use an absolute path for programmatic use")
			}
			zapretProfile = filepath.Join(configDirectory, zapretProfile)
		}
		zapretInterface = options.BindInterface
		var err error
		zapretManager, err = zapret.NewManager(zapret.Options{
			Tag:           tag,
			ProfilePath:   zapretProfile,
			BindInterface: zapretInterface,
			Logger:        logger,
		})
		if err != nil {
			return nil, err
		}
		socketOwner = zapretManager
	}
	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
		DirectOutbound: true,
		SocketOwner:    socketOwner,
	})
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeDirect, tag, []string{N.NetworkTCP, N.NetworkUDP, N.NetworkICMP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		network: service.FromContext[adapter.NetworkManager](ctx),
		//nolint:staticcheck
		domainStrategy: C.DomainStrategy(options.DomainStrategy),
		fallbackDelay:  time.Duration(options.FallbackDelay),
		dialer:         outboundDialer.(dialer.ParallelInterfaceDialer),
		isEmpty: options.Zapret == nil && reflect.DeepEqual(options.DialerOptions, option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{UDPFragmentDefault: true},
		}),
		zapret:          zapretManager,
		zapretInterface: zapretInterface,
	}
	//nolint:staticcheck
	if options.ProxyProtocol != 0 {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	if defaultDialer, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer); isDefaultDialer {
		icmpControl := defaultDialer.ICMPControl()
		outbound.icmpPort = ping.NewPort(ctx, logger, func(destination netip.Addr) control.Func {
			return icmpControl
		}, 0)
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if h.zapret != nil {
			scope.Add(h.zapret.Close)
		}
		if h.icmpPort != nil {
			scope.Add(h.icmpPort.Close)
		}
	case adapter.StartStateStart:
		if h.zapret != nil {
			err := h.startZapret()
			if err != nil {
				return err
			}
		}
	case adapter.StartStatePostStart, adapter.StartStateStarted:
		if len(h.myAddresses.Load()) == 0 {
			h.fetchMyAddresses()
		}
	}
	return nil
}

func (h *Outbound) startZapret() error {
	if h.network == nil {
		return E.New("zapret: outbound ", h.Tag(), ": missing network manager")
	}
	if h.network.AutoRedirectOutputMark() != 0 {
		return E.New("zapret: outbound ", h.Tag(), ": `tun.auto_redirect` is not supported together with `zapret` in this slice: auto-redirect manages its own socket mark; use `auto_route` without `auto_redirect`")
	}
	if defaultMark := h.network.DefaultOptions().RoutingMark; defaultMark != 0 {
		return E.New("zapret: outbound ", h.Tag(), ": `route.default_mark` is not supported with `zapret`: the unique ownership SO_MARK is managed by sing-box, and the default routing mark would be overwritten")
	}
	networkInterface, err := h.network.InterfaceFinder().ByName(h.zapretInterface)
	if err != nil {
		return E.Cause(err, "zapret: outbound ", h.Tag(), ": find bind_interface ", h.zapretInterface)
	}
	if networkInterface.Index <= 0 {
		return E.New("zapret: outbound ", h.Tag(), ": bind_interface ", h.zapretInterface, " has no valid interface index")
	}
	return h.zapret.Start(h.ctx, networkInterface.Index)
}

func (h *Outbound) checkZapretInterface() {
	if h.zapret == nil || h.zapret.State() != zapret.StateReady {
		return
	}
	if h.network == nil {
		h.zapret.Fail(E.New("zapret: outbound ", h.Tag(), ": network manager unavailable after interface update"))
		return
	}
	networkInterface, err := h.network.InterfaceFinder().ByName(h.zapretInterface)
	if err != nil {
		h.zapret.Fail(E.Cause(err, "zapret: outbound ", h.Tag(), ": bind_interface ", h.zapretInterface, " disappeared"))
		return
	}
	if networkInterface.Index != h.zapret.InterfaceIndex() {
		h.zapret.Fail(E.New("zapret: outbound ", h.Tag(), ": bind_interface ", h.zapretInterface, " index changed from ", h.zapret.InterfaceIndex(), " to ", networkInterface.Index, "; refusing to continue with a stale capture filter"))
	}
}

func (h *Outbound) fetchMyAddresses() {
	interfaceMonitor := h.network.InterfaceMonitor()
	if interfaceMonitor == nil {
		return
	}
	myInterfaceNames := interfaceMonitor.MyInterfaces()
	if len(myInterfaceNames) == 0 {
		return
	}
	var (
		myAddresses []netip.Prefix
		found       bool
	)
	for _, myInterfaceName := range myInterfaceNames {
		myInterface, err := h.network.InterfaceFinder().ByName(myInterfaceName)
		if err != nil {
			continue
		}
		found = true
		myAddresses = append(myAddresses, myInterface.Addresses...)
	}
	if !found {
		return
	}
	h.myAddresses.Store(myAddresses)
}

func (h *Outbound) InterfaceUpdated(ctx context.Context) {
	h.fetchMyAddresses()
	if h.icmpPort != nil {
		h.icmpPort.Close()
	}
	h.checkZapretInterface()
}

func (h *Outbound) isMyLoopbackAddress(addresses ...netip.Addr) bool {
	for _, prefix := range h.myAddresses.Load() {
		for _, address := range addresses {
			if !C.IsDarwin && prefix.Addr() == address {
				continue
			}
			if prefix.Contains(address) {
				return true
			}
		}
	}
	return false
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	return h.dialer.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.isMyLoopbackAddress(destination.Addr) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, err := h.dialer.ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (h *Outbound) PreMatchFlow(network string, destination netip.Addr) adapter.PreMatchAction {
	if network == N.NetworkICMP && h.icmpPort != nil {
		if h.isMyLoopbackAddress(destination) {
			h.logger.Error("reject ", network, " connection to ", destination, ": loopback connection to TUN range")
			return adapter.PreMatchReject
		}
		return adapter.PreMatchFlow
	}
	return adapter.PreMatchContinue
}

func (h *Outbound) PortAddresses() (netip.Addr, netip.Addr) {
	return h.icmpPort.PortAddresses()
}

func (h *Outbound) PortMTU() uint32 {
	return h.icmpPort.PortMTU()
}

func (h *Outbound) AttachReturn(returnPath tun.Return) error {
	return h.icmpPort.AttachReturn(returnPath)
}

func (h *Outbound) DetachReturn(returnPath tun.Return) error {
	return h.icmpPort.DetachReturn(returnPath)
}

func (h *Outbound) WritePackets(packets [][]byte) error {
	return h.icmpPort.WritePackets(packets)
}

func (h *Outbound) DialParallel(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	return dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), nil, nil, nil, h.fallbackDelay)
}

func (h *Outbound) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	network = N.NetworkName(network)
	switch network {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	}
	if fallbackDelay == 0 {
		fallbackDelay = h.fallbackDelay
	}
	return dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
}

func (h *Outbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, netip.Addr{}, E.New("loopback connection to TUN range")
	}
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection")
	conn, newDestination, err := dialer.ListenSerialNetworkPacket(ctx, h.dialer, destination, destinationAddresses, networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	return conn, newDestination, nil
}

func (h *Outbound) IsEmpty() bool {
	return h.isEmpty
}

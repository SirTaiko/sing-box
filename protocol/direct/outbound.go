package direct

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
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
	"github.com/sagernet/sing/service/filemanager"
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
	ctx            context.Context
	logger         logger.ContextLogger
	network        adapter.NetworkManager
	dialer         dialer.ParallelInterfaceDialer
	domainStrategy C.DomainStrategy
	fallbackDelay  time.Duration
	isEmpty        bool
	myAddresses    common.TypedValue[[]netip.Prefix]
	icmpPort       *ping.Port
	// desync is nil for absent/disabled packet configurations: no engine,
	// capture, reassembly or extra goroutines are allocated in that case.
	desync *desync.Engine
	// stream is nil for absent/disabled stream configurations. Non-nil only
	// means the immutable compiled snapshot exists; no socket work happens
	// until an owned TCP attempt is created.
	stream *desync.StreamConfig
	// desyncStarted records that the outbound reached its lifecycle start.
	// Diagnostics reports not_started before that; it never forces activation.
	desyncStarted atomic.Bool
}

func anyEnabledPacketRule(rules []option.DirectDesyncRule) bool {
	for index := range rules {
		if !rules[index].Disabled {
			return true
		}
	}
	return false
}

func anyEnabledStreamRule(rules []option.DirectDesyncStreamRule) bool {
	for index := range rules {
		if !rules[index].Disabled {
			return true
		}
	}
	return false
}

// compileDirectDesync compiles the packet and stream halves of one
// direct.desync object independently. The two rule lists are never merged:
// packet rules are compiled into a capture engine, stream rules into an
// immutable StreamConfig. A stream-only configuration is valid: it creates the
// existing state-only engine (admission, ip cache, learner) and needs no packet
// backend, capture privileges or packet socket preparation.
func compileDirectDesync(options *option.DirectDesyncOptions, basePath string) (*desync.Engine, *desync.StreamConfig, error) {
	if options == nil {
		return nil, nil, nil
	}
	if options.Enabled != nil && !*options.Enabled {
		return nil, nil, nil
	}
	packetEnabled := anyEnabledPacketRule(options.Rules)
	streamEnabled := anyEnabledStreamRule(options.StreamRules)
	if !packetEnabled && !streamEnabled {
		if len(options.Rules) == 0 && len(options.StreamRules) == 0 {
			return nil, nil, E.New("desync: enabled without rules")
		}
		return nil, nil, E.New("desync: enabled without enabled rules")
	}
	if !packetEnabled {
		// capture/limits bound the packet engine only. They are rejected for
		// a stream-only object instead of being accepted as silent no-ops.
		if options.Capture != nil {
			return nil, nil, E.New("desync: capture requires packet rules")
		}
		if options.Limits != nil {
			return nil, nil, E.New("desync: limits require packet rules")
		}
	}
	var (
		engine       *desync.Engine
		streamConfig *desync.StreamConfig
	)
	// One state for both halves: current.json is read once per canonical
	// bundle root and packet/stream rules share the pinned generation and the
	// per-outbound selection budget.
	listState := desync.NewListBuildState()
	if packetEnabled {
		desyncConfig, err := desync.CompileWithState(options, basePath, listState)
		if err != nil {
			return nil, nil, err
		}
		if desyncConfig != nil {
			engine, err = desync.NewEngine(desyncConfig, desync.NewNativeBackend())
			if err != nil {
				return nil, nil, err
			}
		}
	}
	if streamEnabled {
		var err error
		streamConfig, err = desync.CompileStreamWithState(options.StreamRules, basePath, listState)
		if err != nil {
			return nil, nil, err
		}
		if streamConfig != nil {
			if engine == nil {
				// A stream-only object still needs the single per-outbound
				// state owner for the ip cache and hostlist-auto learner.
				// The state backend owns no capture and opens no native handle.
				engine, err = desync.NewStateEngine(options, options.StreamRules)
				if err != nil {
					return nil, nil, err
				}
			}
			if err = streamConfig.AttachEngine(engine); err != nil {
				return nil, nil, err
			}
		}
	}
	if engine == nil && streamConfig == nil {
		return nil, nil, E.New("desync: enabled without enabled rules")
	}
	if engine != nil {
		engine.SetBundleGenerations(listState.BundleGenerations())
	}
	return engine, streamConfig, nil
}

// checkDesyncDialerConflicts rejects dialer combinations whose ownership the
// attachment cannot guarantee. It covers the packet engine and stream rules so
// an enabled configuration never silently loses a configured dialer behavior.
func checkDesyncDialerConflicts(dialerOptions option.DialerOptions, engine *desync.Engine, stream *desync.StreamConfig) error {
	if engine == nil && stream == nil {
		return nil
	}
	if engine != nil && engine.PacketEnabled() {
		// These combinations need packet ownership that this increment does
		// not implement. They are rejected explicitly instead of silently
		// accepting a configuration that does nothing. A stream-only state
		// engine owns no packet socket, so these dialer options stay valid.
		if dialerOptions.TCPMultiPath {
			return E.New("desync: tcp_multipath conflicts with enabled packet desync (additional subflow ownership is an outstanding parity gap)")
		}
		if dialerOptions.BindAddressNoPort {
			return E.New("desync: bind_address_no_port conflicts with enabled packet desync (an exclusive early local port is required)")
		}
	}
	return nil
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.DirectOutboundOptions) (adapter.Outbound, error) {
	options.UDPFragmentDefault = true
	if options.Detour != "" {
		return nil, E.New("`detour` is not supported in direct context")
	}
	var (
		outboundEngine *desync.Engine
		streamConfig   *desync.StreamConfig
	)
	if options.Desync != nil {
		// Payload and list paths resolve through the established configuration
		// path context (filemanager), exactly like other sing-box file options.
		// Without a manager this is the process-relative path, preserving the
		// previous behaviour for callers that do not install one.
		basePath := filemanager.BasePath(ctx, "")
		var err error
		outboundEngine, streamConfig, err = compileDirectDesync(options.Desync, basePath)
		if err != nil {
			return nil, err
		}
	}
	desyncEnabled := outboundEngine != nil || streamConfig != nil
	if conflictErr := checkDesyncDialerConflicts(options.DialerOptions, outboundEngine, streamConfig); conflictErr != nil {
		return nil, conflictErr
	}
	dialerOptions := dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: true,
		DirectOutbound: true,
	}
	if desyncEnabled {
		hook := &desyncHook{
			engine:   outboundEngine,
			stream:   streamConfig,
			lifetime: ctx,
			logger:   logger,
		}
		dialerOptions.AttemptHook = hook
		// With `tcp_fast_open` the native dial must be deferred to the first
		// transformed write so the single prepared owned attempt can carry
		// the TFO data. The same hook supplies the once-only stream wrapper
		// for the pending facade.
		dialerOptions.PendingTCPHook = hook
	}
	outboundDialer, err := dialer.NewWithOptions(dialerOptions)
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
		isEmpty: reflect.DeepEqual(options.DialerOptions, option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{UDPFragmentDefault: true},
		}),
		desync: outboundEngine,
		stream: streamConfig,
	}
	if desyncEnabled {
		// Enabled desync must never be treated as an empty direct outbound by
		// detour validation or optimization.
		outbound.isEmpty = false
	}
	//nolint:staticcheck
	if options.ProxyProtocol != 0 {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	if defaultDialer, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer); isDefaultDialer {
		outbound.icmpPort = ping.NewPort(ctx, logger, func(destination netip.Addr) control.Func {
			return defaultDialer.DialerForICMPDestination(destination).Control
		}, 0)
	}
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	switch stage {
	case adapter.StartStateInitialize:
		if h.icmpPort != nil {
			scope.Add(h.icmpPort.Close)
		}
		if h.desync != nil {
			scope.Add(h.desync.Close)
		}
	case adapter.StartStatePostStart, adapter.StartStateStarted:
		if h.desync != nil || h.stream != nil {
			h.desyncStarted.Store(true)
		}
		if len(h.myAddresses.Load()) == 0 {
			h.fetchMyAddresses()
		}
	}
	return nil
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
	if err := h.checkLegacyConflict(ctx); err != nil {
		return nil, err
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
	if err := h.checkLegacyConflict(ctx); err != nil {
		return nil, err
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
	if err := h.checkLegacyConflict(ctx); err != nil {
		return nil, err
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
	if err := h.checkLegacyConflict(ctx); err != nil {
		return nil, err
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
	return dialer.DialParallelNetwork(ctx, h.dialer, network, destination, destinationAddresses, len(destinationAddresses) > 0 && destinationAddresses[0].Is6(), networkStrategy, networkType, fallbackNetworkType, fallbackDelay)
}

func (h *Outbound) ListenSerialNetworkPacket(ctx context.Context, destination M.Socksaddr, destinationAddresses []netip.Addr, networkStrategy *C.NetworkStrategy, networkType []C.InterfaceType, fallbackNetworkType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, netip.Addr, error) {
	if h.isMyLoopbackAddress(destinationAddresses...) {
		return nil, netip.Addr{}, E.New("loopback connection to TUN range")
	}
	if err := h.checkLegacyConflict(ctx); err != nil {
		return nil, netip.Addr{}, err
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

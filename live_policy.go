package box

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/service"
)

type policyNetwork struct {
	adapter.NetworkManager
	defaults adapter.NetworkOptions
	zapret   bool
}

func (n policyNetwork) DefaultOptions() adapter.NetworkOptions { return n.defaults }
func (n policyNetwork) AutoRedirectOutputMark() uint32 {
	if n.zapret {
		return 0
	}
	return n.NetworkManager.AutoRedirectOutputMark()
}

// The desktop policy has no Wi-Fi-dependent rule sets.
func (n policyNetwork) Initialize([]adapter.RuleSet) {}

func withoutInterrupt(ob []option.Outbound) []option.Outbound {
	normalized := slices.Clone(ob)
	for i, it := range normalized {
		switch v := it.Options.(type) {
		case *option.SelectorOutboundOptions:
			copy := *v
			copy.InterruptExistConnections = false
			normalized[i].Options = &copy
		case *option.URLTestOutboundOptions:
			copy := *v
			copy.InterruptExistConnections = false
			normalized[i].Options = &copy
		}
	}
	return normalized
}

func (h *liveRuntime) preparePolicy(request context.Context, old *routingPolicy, opts option.Options) (_ *routingPolicy, err error) {
	p := &routingPolicy{live: h, config: opts, assets: make(map[any]*policyAsset), drained: make(chan struct{})}
	p.refs.Store(1)
	var reuse map[liveResourceKey]bool
	defer func() {
		if err != nil {
			err = p.abort(err)
		}
	}()
	ctx := service.ExtendContext(h.box.scope.Context())
	ro := common.PtrValueOrDefault(opts.Route)
	do := common.PtrValueOrDefault(opts.DNS)
	oldRoute := common.PtrValueOrDefault(old.config.Route)
	shared := old.healthy() && reflect.DeepEqual(opts.DNS, old.config.DNS) && reflect.DeepEqual(opts.Endpoints, old.config.Endpoints) &&
		reflect.DeepEqual(withoutInterrupt(opts.Outbounds), withoutInterrupt(old.config.Outbounds)) &&
		reflect.DeepEqual(ro.RuleSet, oldRoute.RuleSet) && ro.Final == oldRoute.Final && reflect.DeepEqual(ro.DefaultDomainResolver, oldRoute.DefaultDomainResolver)
	defaults := h.box.network.DefaultOptions()
	resolver := common.PtrValueOrDefault(ro.DefaultDomainResolver)
	defaults.DomainResolver = resolver.Server
	defaults.DomainResolveOptions = adapter.DNSQueryOptions{Strategy: C.DomainStrategy(resolver.Strategy), Timeout: time.Duration(resolver.Timeout), DisableCache: resolver.DisableCache, DisableOptimisticCache: resolver.DisableOptimisticCache, RewriteTTL: resolver.RewriteTTL, ClientSubnet: resolver.ClientSubnet.Build(netip.Prefix{})}
	zapret := false
	for _, ob := range opts.Outbounds {
		if d, ok := ob.Options.(*option.DirectOutboundOptions); ok && d.Zapret != nil {
			zapret = true
		}
	}
	service.MustRegister[adapter.NetworkManager](ctx, policyNetwork{h.box.network, defaults, zapret})
	if shared {
		p.resources = old.resources
		p.flows.Store(old.flows.Load())
		p.out, p.end, p.transports, p.dns = old.out, old.end, old.transports, old.dns
		for obj := range old.assets {
			if obj != old.router {
				p.borrow(old, obj)
			}
		}
		if reflect.DeepEqual(ro, oldRoute) {
			p.router = old.router
			p.borrow(old, old.router)
			return p, nil
		}
	} else {
		p.resources = describeLiveResources(opts)
		reuse = p.resources.reusable(old, reflect.DeepEqual(dnsPolicyOptions(do), dnsPolicyOptions(common.PtrValueOrDefault(old.config.DNS))))
		p.end = endpoint.NewManager(service.FromContext[adapter.EndpointRegistry](ctx))
		p.out = outbound.NewManager(service.FromContext[adapter.OutboundRegistry](ctx), p.end, ro.Final)
		p.transports = dns.NewTransportManager(service.FromContext[adapter.DNSTransportRegistry](ctx), p.out, do.Final)
	}
	service.MustRegister[adapter.OutboundManager](ctx, p.out)
	service.MustRegister[adapter.EndpointManager](ctx, p.end)
	service.MustRegister[adapter.DNSTransportManager](ctx, p.transports)
	var sets map[string]bool
	shareDNS := shared
	if !shared {
		sets = reusableRuleSets(old, p, reuse)
		shareDNS = sameDNSBindings(old, p, reuse, sets)
	}
	if !shared && shareDNS {
		p.dns = old.dns
		p.borrow(old, old.dns)
	}
	if !shareDNS {
		p.dns, err = dns.NewRouter(ctx, h.box.logFactory, do)
		if err != nil {
			return nil, err
		}
		p.own(p.dns, adapter.NewScope(ctx, h.box.logger))
	}
	service.MustRegister[adapter.DNSRouter](ctx, p.dns)
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, p.dns)
	p.router = route.NewRouter(ctx, h.box.logFactory, ro, do)
	h.box.router.CopyTrackersTo(p.router)
	p.own(p.router, adapter.NewScope(ctx, h.box.logger))
	service.MustRegister[adapter.Router](ctx, p.router)
	if err = p.router.InitializeLive(ro.Rules, ro.RuleSet, p.assets[p.router].scope, old.router, func(tag string) bool {
		// A source with a different DNS validator must be rebuilt when either
		// validator uses DNS rules. Both empty validators are equivalent.
		return shared || (sets[tag] && (shareDNS || (len(do.Rules) == 0 && len(common.PtrValueOrDefault(old.config.DNS).Rules) == 0)))
	}); err != nil {
		return nil, err
	}
	var resources []adapter.Lifecycle
	if !shared {
		resources, err = h.buildPolicyResources(ctx, old, p, reuse)
		if err != nil {
			return nil, err
		}
		if !shareDNS {
			if err = p.dns.Initialize(do.Rules); err != nil {
				return nil, err
			}
		}
	}
	for _, stage := range adapter.ListStartStages {
		if err = request.Err(); err != nil {
			return nil, err
		}
		if stage == adapter.StartStateStart {
			for _, ob := range old.config.Outbounds {
				d, ok := ob.Options.(*option.DirectOutboundOptions)
				if !ok || d.Zapret == nil {
					continue
				}
				existing, _ := old.out.Outbound(ob.Tag)
				if _, used := p.assets[existing]; used {
					continue
				}
				engine := existing.(interface{ SuspendRuntimeEngine() (func() error, error) })
				restore, stopErr := engine.SuspendRuntimeEngine()
				if stopErr != nil {
					return nil, stopErr
				}
				p.restoreEngines = append(p.restoreEngines, restore)
			}
		}
		for _, component := range resources {
			if err = component.Start(stage, p.assets[component].scope); err != nil {
				return nil, fmt.Errorf("start runtime component: %w", err)
			}
		}
		if err = p.router.Start(stage, p.assets[p.router].scope); err != nil {
			return nil, err
		}
		if !shareDNS {
			if err = p.dns.Start(stage, p.assets[p.dns].scope); err != nil {
				return nil, err
			}
		}
	}
	if !shared {
		p.indexFlowAssets()
	}
	return p, nil
}

// Start dependencies before groups. The options have already passed the same
// decoder and tag uniqueness checks as a cold startup.
func orderedResources[T interface {
	Tag() string
	Dependencies() []string
}](items []T) ([]T, error) {
	pending := slices.Clone(items)
	var ordered []T
	for len(pending) > 0 {
		before := len(pending)
		for i := 0; i < len(pending); {
			item := pending[i]
			wait := slices.ContainsFunc(pending, func(other T) bool { return slices.Contains(item.Dependencies(), other.Tag()) })
			if wait {
				i++
				continue
			}
			ordered = append(ordered, item)
			pending = slices.Delete(pending, i, i+1)
		}
		if len(pending) == before {
			return nil, errors.New("circular runtime dependency")
		}
	}
	return ordered, nil
}

func (h *liveRuntime) buildPolicyResources(ctx context.Context, old, p *routingPolicy, reuse map[liveResourceKey]bool) ([]adapter.Lifecycle, error) {
	var start []adapter.Lifecycle
	logger := h.box.logFactory
	resourceCtx := service.ExtendContext(ctx)
	service.MustRegister[adapter.DNSRouter](resourceCtx, liveDNS{p.dns, h})
	ingress := &liveIngress{Router: p.router, live: h}
	// Dialer construction resolves explicit DNS transport tags immediately.
	// Populate the staged transport registry before constructing any endpoint or outbound.
	do := common.PtrValueOrDefault(p.config.DNS)
	servers := desktopDNSServers(do)
	for _, t := range servers {
		if t.Type == C.DNSTypeFakeIP && old.transports.FakeIP() != nil {
			existing := old.transports.FakeIP()
			if existing.Tag() != t.Tag {
				return nil, errors.New("cannot change the live fake-IP pool")
			}
			if err := p.transports.Add(existing); err != nil {
				return nil, err
			}
			p.borrow(old, existing)
		} else if reuse[transportKey(t.Tag)] {
			existing, _ := old.transports.Transport(t.Tag)
			if err := p.transports.Add(existing); err != nil {
				return nil, err
			}
			p.borrow(old, existing)
		} else if err := p.transports.Create(ctx, logger.NewLogger("dns/"+t.Tag), t.Tag, t.Type, t.Options); err != nil {
			return nil, err
		}
	}
	// OS and browsers may still use addresses issued before switching to legacy DNS.
	if previous := old.transports.FakeIP(); previous != nil && p.transports.FakeIP() == nil {
		if err := p.transports.Add(previous); err != nil {
			return nil, err
		}
		p.borrow(old, previous)
	}
	for _, e := range p.config.Endpoints {
		if e.Type != C.TypeOpenConnect {
			return nil, errors.New("unsupported desktop endpoint")
		}
		if reuse[outboundKey(e.Tag)] {
			existing, _ := old.end.Get(e.Tag)
			if err := p.end.Add(existing); err != nil {
				return nil, err
			}
			p.borrow(old, existing)
		} else if err := p.end.Create(resourceCtx, ingress, logger.NewLogger("endpoint/"+e.Tag), e.Tag, e.Type, e.Options); err != nil {
			return nil, err
		}
	}
	for _, ob := range p.config.Outbounds {
		if !slices.Contains([]string{C.TypeDirect, C.TypeVLESS, C.TypeHysteria2, C.TypeSelector, C.TypeURLTest}, ob.Type) {
			return nil, errors.New("unsupported desktop outbound")
		}
		existing, _ := old.out.Outbound(ob.Tag)
		if reuse[outboundKey(ob.Tag)] {
			if err := p.out.Add(existing); err != nil {
				return nil, err
			}
			p.borrow(old, existing)
		} else if err := p.out.Create(resourceCtx, p.router, logger.NewLogger("outbound/"+ob.Tag), ob.Tag, ob.Type, ob.Options); err != nil {
			return nil, err
		}
	}
	outbounds := slices.Clone(p.out.Outbounds())
	for _, ep := range p.end.Endpoints() {
		outbounds = append(outbounds, ep)
	}
	ordered, err := orderedResources(outbounds)
	if err != nil {
		return nil, err
	}
	for _, ob := range ordered {
		for _, dep := range ob.Dependencies() {
			if _, found := p.out.Outbound(dep); !found {
				return nil, fmt.Errorf("missing outbound %q", dep)
			}
		}
		if _, exists := p.assets[ob]; exists {
			continue
		}
		var scope *adapter.Scope
		if life, ok := ob.(adapter.Lifecycle); ok {
			scope = adapter.NewScope(ctx, h.box.logger)
			start = append(start, life)
		}
		p.own(ob, scope)
	}
	if p.out.Default() == nil {
		return nil, errors.New("missing default outbound")
	}
	transports, err := orderedResources(p.transports.Transports())
	if err != nil {
		return nil, err
	}
	for _, t := range transports {
		if _, exists := p.assets[t]; exists {
			continue
		}
		p.own(t, adapter.NewScope(ctx, h.box.logger))
		start = append(start, t)
	}
	if p.transports.Default() == nil {
		return nil, errors.New("missing default DNS transport")
	}
	return start, nil
}

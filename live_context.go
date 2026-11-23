package box

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

// A reusable object can resolve its candidate's dependencies during startup.
// Publication switches the view to the process routing service. The view never
// has a back-reference to the revision in which that object was created afterwards.
type policyView struct {
	live    *liveRuntime
	staged  atomic.Pointer[routingPolicy]
	mu      sync.Mutex
	pending []*outboundBinding
}

// A detour may be dialed for the first time after its owning policy retires.
// Bind that one tag before publication, without retaining the whole manager.
type outboundBinding struct {
	tag    string
	target atomic.Pointer[adapter.Outbound]
}

func (b *outboundBinding) lookup(p *routingPolicy) (adapter.Outbound, bool) {
	if b.tag != "" {
		return p.out.Outbound(b.tag)
	}
	ob := p.out.Default()
	return ob, ob != nil
}
func (b *outboundBinding) bind(p *routingPolicy) { ob, _ := b.lookup(p); b.target.Store(&ob) }
func newPolicyView(h *liveRuntime) *policyView {
	return &policyView{live: h, pending: make([]*outboundBinding, 0)}
}
func (v *policyView) finishBindings(p *routingPolicy) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, b := range v.pending {
		b.bind(p)
	}
	v.pending = nil
}
func (v liveOutbounds) BindOutbound(tag string) func() (adapter.Outbound, bool) {
	b := &outboundBinding{tag: tag}
	v.mu.Lock()
	if v.pending != nil {
		v.pending = append(v.pending, b)
	} else {
		b.bind(v.current())
	}
	v.mu.Unlock()
	return func() (adapter.Outbound, bool) {
		if t := b.target.Load(); t != nil {
			return *t, *t != nil
		}
		return b.lookup(v.current())
	}
}

func (v *policyView) current() *routingPolicy {
	if p := v.staged.Load(); p != nil {
		return p
	}
	return v.live.active.Load()
}
func (v *policyView) take() (*routingPolicy, context.Context) {
	v.live.readers.RLock()
	p := v.staged.Load()
	var preparing context.Context
	if p == nil {
		p = v.live.active.Load()
	} else {
		preparing = p.preparing
	}
	p.refs.Add(1)
	v.live.readers.RUnlock()
	return p, preparing
}

func (v *policyView) acquire() (*routingPolicy, func()) {
	p, _ := v.take()
	return p, sync.OnceFunc(p.dropReader)
}

// A background DNS lookup started by a candidate may still be waiting on I/O
// when another component fails startup. Abort must cancel it before draining.
func (v *policyView) acquireQuery(ctx context.Context) (*routingPolicy, context.Context, func()) {
	p, preparing := v.take()
	if preparing == nil {
		return p, ctx, sync.OnceFunc(p.dropReader)
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(preparing, cancel)
	return p, ctx, sync.OnceFunc(func() { stop(); cancel(); p.dropReader() })
}

func (v *policyView) register(ctx context.Context) {
	service.MustRegister[adapter.Router](ctx, &liveIngress{v})
	service.MustRegister[adapter.EndpointManager](ctx, liveEndpoints{v})
	service.MustRegister[adapter.OutboundManager](ctx, liveOutbounds{v})
	service.MustRegister[adapter.DNSTransportManager](ctx, liveTransports{v})
	service.MustRegister[adapter.DNSRouter](ctx, liveDNS{v})
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, liveDNS{v})
}

// The parent contains only process services. Keep late registrations such as
// the cache file visible at cold start without retaining a previous revision.
type policyRegistry struct {
	service.Registry
	parent service.Registry
}

func (r policyRegistry) Get(key any) any {
	if value := r.Registry.Get(key); value != nil {
		return value
	}
	return r.parent.Get(key)
}
func (r policyRegistry) Clone() service.Registry {
	return policyRegistry{r.Registry.Clone(), r.parent.Clone()}
}
func policyContext(parent context.Context) context.Context {
	return service.ContextWithRegistry(parent, policyRegistry{service.NewRegistry(), service.RegistryFromContext(parent)})
}

// DNS requests must keep the transports and rule sets selected by their own
// DNS policy, including while a newer policy is being published.
type dnsRuleSets struct {
	adapter.Router
	sets map[string]adapter.RuleSet
}

func (r dnsRuleSets) RuleSet(tag string) (adapter.RuleSet, bool) {
	s, ok := r.sets[tag]
	return s, ok
}
func bindDNSRuleSets(ctx context.Context, stable adapter.Router, p *routingPolicy, rules []option.DNSRule) {
	tags := make(map[string]bool)
	dnsRuleSetTags(rules, tags)
	sets := make(map[string]adapter.RuleSet, len(tags))
	for tag := range tags {
		if set, ok := p.router.RuleSet(tag); ok {
			sets[tag] = set
		}
	}
	service.MustRegister[adapter.Router](ctx, dnsRuleSets{stable, sets})
}

type ruleSetValidator struct{ router *dns.Router }

func (v ruleSetValidator) ValidateRuleSetMetadataUpdate(tag string, m adapter.RuleSetMetadata) error {
	if v.router == nil {
		return nil
	}
	return v.router.ValidateRuleSetMetadataUpdate(tag, m)
}
func ruleSetContext(ctx context.Context, p *routingPolicy, rules []option.DNSRule) context.Context {
	ctx = policyContext(ctx)
	var v ruleSetValidator
	if len(rules) != 0 {
		v.router = p.dns
	}
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, v)
	return ctx
}

func (v liveDNS) ValidateRuleSetMetadataUpdate(tag string, m adapter.RuleSetMetadata) error {
	p, done := v.acquire()
	defer done()
	return p.dns.ValidateRuleSetMetadataUpdate(tag, m)
}

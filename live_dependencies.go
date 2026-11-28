package box

import (
	"cmp"
	"net/netip"
	"net/url"
	"reflect"
	"slices"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

type liveResourceKey struct {
	dns bool
	tag string
}

func outboundKey(tag string) liveResourceKey  { return liveResourceKey{tag: tag} }
func transportKey(tag string) liveResourceKey { return liveResourceKey{dns: true, tag: tag} }

type liveResource struct {
	definition        any
	dependencies      []liveResourceKey
	resolver          *option.DomainResolveOptions
	implicitDNS       bool
	usesDNS           bool
	unknownDependency bool
	interceptionMark  bool
}

type liveResources map[liveResourceKey]liveResource

func desktopDNSServers(config option.DNSOptions) []option.DNSServerOptions {
	if len(config.Servers) > 0 {
		return config.Servers
	}
	return []option.DNSServerOptions{{Tag: "local", Type: C.DNSTypeLocal, Options: &option.LocalDNSServerOptions{}}}
}

func implicitTransports(dns option.DNSOptions, servers []option.DNSServerOptions) []string {
	defaultTag := dns.Final
	if defaultTag == "" {
		defaultTag = servers[0].Tag
	}
	tags := []string{defaultTag}
	if dns.DirectModeServer != "" {
		tags = append(tags, dns.DirectModeServer)
	}
	var collect func([]option.DNSRule)
	collect = func(rules []option.DNSRule) {
		for _, rule := range rules {
			action := rule.DefaultOptions.DNSRuleAction
			if rule.Type == C.RuleTypeLogical {
				action = rule.LogicalOptions.DNSRuleAction
				collect(rule.LogicalOptions.Rules)
			}
			switch action.Action {
			case "", C.RuleActionTypeRoute:
				if action.RouteOptions.Server != "" {
					tags = append(tags, action.RouteOptions.Server)
				}
			case C.RuleActionTypeEvaluate:
				if action.EvaluateOptions.Server != "" {
					tags = append(tags, action.EvaluateOptions.Server)
				}
			case C.RuleActionTypeRouteOptions, C.RuleActionTypeRespond, C.RuleActionTypeReject, "predefined":
			default:
				for _, server := range servers {
					tags = append(tags, server.Tag)
				}
			}
		}
	}
	collect(dns.Rules)
	slices.Sort(tags)
	return slices.Compact(tags)
}

func dnsPolicyOptions(config option.DNSOptions) option.DNSOptions {
	config.Servers = nil
	return config
}

func describeLiveResources(config option.Options) liveResources {
	routeOptions := common.PtrValueOrDefault(config.Route)
	dnsOptions := common.PtrValueOrDefault(config.DNS)
	servers := desktopDNSServers(dnsOptions)
	implicitTags := implicitTransports(dnsOptions, servers)
	resources := make(liveResources, len(servers)+len(config.Outbounds)+len(config.Endpoints))
	zapret := common.Any(config.Outbounds, func(o option.Outbound) bool {
		d, ok := o.Options.(*option.DirectOutboundOptions)
		return ok && d.Zapret != nil
	})
	add := func(key liveResourceKey, definition, options any) {
		resource := liveResource{definition: definition}
		addOutbound := func(tag string) {
			if tag != "" {
				resource.dependencies = append(resource.dependencies, outboundKey(tag))
			}
		}
		addDNS := func(tag string) {
			if tag != "" {
				resource.dependencies = append(resource.dependencies, transportKey(tag))
			}
		}
		implicit := func() {
			resource.usesDNS = true
			resource.implicitDNS = true
			for _, tag := range implicitTags {
				if tag == "" {
					resource.unknownDependency = true
				} else {
					addDNS(tag)
				}
			}
		}
		if wrapper, ok := options.(option.DialerOptionsWrapper); ok {
			dialer := wrapper.TakeDialerOptions()
			resource.interceptionMark = zapret
			addOutbound(dialer.Detour)
			needsResolver := !key.dns
			if server, ok := options.(option.ServerOptionsWrapper); ok {
				needsResolver = server.TakeServerOptions().ServerIsDomain()
			}
			if dialer.DomainResolver != nil || needsResolver {
				resource.resolver = dialer.DomainResolver
				if resource.resolver == nil {
					resource.resolver = routeOptions.DefaultDomainResolver
				}
				if resource.resolver != nil && resource.resolver.Server != "" {
					resource.usesDNS = true
					addDNS(resource.resolver.Server)
				} else if needsResolver {
					implicit()
				}
			}
		}
		switch opts := options.(type) {
		case *option.OpenConnectDNSServerOptions:
			addOutbound(opts.Endpoint)
		case *option.OpenVPNDNSServerOptions:
			addOutbound(opts.Endpoint)
		case *option.TailscaleDNSServerOptions:
			addOutbound(opts.Endpoint)
		case *option.SelectorOutboundOptions:
			for _, tag := range opts.Outbounds {
				addOutbound(tag)
			}
		case *option.URLTestOutboundOptions:
			for _, tag := range opts.Outbounds {
				addOutbound(tag)
			}
			for _, r := range opts.ProbeDomainResolvers {
				if r.Server == "" {
					implicit()
				} else {
					resource.usesDNS = true
					addDNS(r.Server)
				}
			}
		}
		slices.SortFunc(resource.dependencies, func(a, b liveResourceKey) int {
			if a.dns != b.dns {
				if a.dns {
					return 1
				}
				return -1
			}
			return cmp.Compare(a.tag, b.tag)
		})
		resource.dependencies = slices.Compact(resource.dependencies)
		resources[key] = resource
	}
	for _, t := range servers {
		add(transportKey(t.Tag), t, t.Options)
	}
	for _, e := range config.Endpoints {
		add(outboundKey(e.Tag), e, e.Options)
	}
	for _, o := range withoutInterrupt(config.Outbounds) {
		add(outboundKey(o.Tag), o, o.Options)
	}
	return resources
}

func (p *routingPolicy) resource(key liveResourceKey) any {
	if key.dns {
		t, _ := p.transports.Transport(key.tag)
		return t
	}
	o, _ := p.out.Outbound(key.tag)
	return o
}

// Adapters also expose resolved dependencies that are specific to their type.
func resourceDependencies(key liveResourceKey, spec liveResource, obj any) []liveResourceKey {
	deps := slices.Clone(spec.dependencies)
	if declared, ok := obj.(interface{ Dependencies() []string }); ok {
		for _, tag := range declared.Dependencies() {
			deps = append(deps, liveResourceKey{dns: key.dns, tag: tag})
		}
	}
	if refs, ok := obj.(interface{ References() []string }); ok {
		for _, tag := range refs.References() {
			deps = append(deps, outboundKey(tag))
		}
	}
	return deps
}

// Remove a resource from the reusable set if any of its dependencies changed.
// Cycles of identical dependencies stay together.
func (next liveResources) reusable(old *routingPolicy, sameDNSPolicy bool) map[liveResourceKey]bool {
	reusable := make(map[liveResourceKey]bool, len(next))
	dependents := make(map[liveResourceKey][]liveResourceKey)
	for key, spec := range next {
		prev, ok := old.resources[key]
		if !ok || spec.unknownDependency || (spec.implicitDNS && !sameDNSPolicy) || !reflect.DeepEqual(spec, prev) {
			continue
		}
		obj := old.resource(key)
		if obj == nil || old.assets[obj] == nil {
			continue
		}
		if ready, ok := obj.(interface{ RuntimeReady() bool }); ok && !ready.RuntimeReady() {
			continue
		}
		reusable[key] = true
		for _, dep := range resourceDependencies(key, spec, obj) {
			dependents[dep] = append(dependents[dep], key)
		}
	}
	var changed []liveResourceKey
	for dep := range dependents {
		if !reusable[dep] {
			changed = append(changed, dep)
		}
	}
	for len(changed) > 0 {
		dep := changed[len(changed)-1]
		changed = changed[:len(changed)-1]
		for _, key := range dependents[dep] {
			if reusable[key] {
				delete(reusable, key)
				changed = append(changed, key)
			}
		}
	}
	return reusable
}

func dnsRuleSetTags(rules []option.DNSRule, tags map[string]bool) {
	for _, rule := range rules {
		for _, tag := range rule.DefaultOptions.RuleSet {
			tags[tag] = true
		}
		dnsRuleSetTags(rule.LogicalOptions.Rules, tags)
	}
}

// An explicitly routed download depends on its detour and resolver. The default
// HTTP transport may use the core's default DNS and outbound bindings.
func reusableRuleSets(old, next *routingPolicy, reuse map[liveResourceKey]bool) map[string]bool {
	sets := make(map[string]bool)
	before, after := common.PtrValueOrDefault(old.config.Route), common.PtrValueOrDefault(next.config.Route)
	oldSets := map[string]option.RuleSet{}
	for _, set := range before.RuleSet {
		tags := set.Tag
		set.Tag = nil
		for _, tag := range tags {
			oldSets[tag] = set
		}
	}
	allBindings := before.Final == after.Final && reflect.DeepEqual(before.DefaultDomainResolver, after.DefaultDomainResolver) && reflect.DeepEqual(old.config.DNS, next.config.DNS) && len(old.resources) == len(next.resources) && len(reuse) == len(next.resources)
	for _, set := range after.RuleSet {
		usable := true
		if set.Type == C.RuleSetTypeRemote {
			options := set.RemoteOptions
			detour := options.DownloadDetour
			client := options.HTTPClient
			if client != nil && client.Tag != "" {
				for _, configured := range next.config.HTTPClients {
					if configured.Tag == client.Tag {
						value := configured.Options()
						client = &value
						break
					}
				}
			}
			if client != nil {
				detour = client.Detour
			}
			if detour == "" {
				usable = allBindings
			} else {
				usable = reuse[outboundKey(detour)]
				if client != nil && client.DomainResolver != nil && client.DomainResolver.Server != "" {
					usable = usable && reuse[transportKey(client.DomainResolver.Server)]
				} else if endpoint, err := url.Parse(options.URL); err != nil || !isIPHost(endpoint.Hostname()) {
					usable = usable && reflect.DeepEqual(before.DefaultDomainResolver, after.DefaultDomainResolver) && reflect.DeepEqual(old.config.DNS, next.config.DNS)
				}
			}
		}
		if usable {
			tags := set.Tag
			set.Tag = nil
			for _, tag := range tags {
				previous, ok := oldSets[tag]
				sets[tag] = ok && reflect.DeepEqual(previous, set) && old.router.ReusableRuleSet(tag)
			}
		}
	}
	return sets
}

func isIPHost(host string) bool { _, err := netip.ParseAddr(host); return err == nil }

func sameDNSBindings(old, next *routingPolicy, reuse map[liveResourceKey]bool, sets map[string]bool) bool {
	if !reflect.DeepEqual(old.config.DNS, next.config.DNS) {
		return false
	}
	for key := range next.resources {
		if key.dns && !reuse[key] {
			return false
		}
	}
	tags := make(map[string]bool)
	dnsRuleSetTags(common.PtrValueOrDefault(next.config.DNS).Rules, tags)
	for tag := range tags {
		if !sets[tag] {
			return false
		}
	}
	return true
}

func (p *routingPolicy) flowAssets(key liveResourceKey) ([]*policyAsset, bool) {
	seen := map[liveResourceKey]bool{}
	var assets []*policyAsset
	add := func(a *policyAsset) {
		if a.scope != nil && !slices.Contains(assets, a) {
			assets = append(assets, a)
		}
	}
	var visit func(liveResourceKey) bool
	visit = func(k liveResourceKey) bool {
		if seen[k] {
			return true
		}
		seen[k] = true
		spec, ok := p.resources[k]
		if !ok || spec.unknownDependency {
			return false
		}
		obj := p.resource(k)
		a := p.assets[obj]
		if a == nil {
			return false
		}
		add(a)
		if spec.usesDNS {
			a = p.assets[p.dns]
			if a == nil {
				return false
			}
			add(a)
		}
		for _, dep := range resourceDependencies(k, spec, obj) {
			if !visit(dep) {
				return false
			}
		}
		return true
	}
	ok := visit(key)
	return assets, ok
}

type flowAssetIndex map[adapter.Outbound][]*policyAsset

func (p *routingPolicy) indexFlowAssets() {
	flows := make(flowAssetIndex)
	for key := range p.resources {
		if key.dns {
			continue
		}
		ob, _ := p.out.Outbound(key.tag)
		if ob != nil {
			if assets, ok := p.flowAssets(key); ok {
				flows[ob] = assets
			}
		}
	}
	p.flows.Store(&flows)
}

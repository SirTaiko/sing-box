package box

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The listeners and the authenticated API keep their lifetimes. Each accepted
// flow holds the matching policy during lookup and its outbound dependencies during I/O.
type liveIngress struct {
	*policyView
}

// The close callback can run concurrently with handoff, including on an error.
type flowLease struct {
	mu      sync.Mutex
	release func()
}

func (l *flowLease) replace(next func()) {
	l.mu.Lock()
	previous := l.release
	if previous != nil {
		l.release = next
	}
	l.mu.Unlock()
	if previous != nil {
		previous()
	} else if next != nil {
		next()
	}
}

func (p *routingPolicy) leaseForFlow(onClose N.CloseHandlerFunc) (N.CloseHandlerFunc, func([]adapter.Outbound)) {
	p.refs.Add(1)
	lease := &flowLease{release: p.dropReader}
	closeFlow := N.OnceClose(N.AppendClose(onClose, func(error) { lease.replace(nil) }))
	return closeFlow, func(chain []adapter.Outbound) {
		index := p.flows.Load()
		if index == nil || len(chain) == 0 {
			return
		}
		assets, known := (*index)[chain[0]]
		if !known {
			return
		}
		for _, a := range assets {
			a.flows.Add(1)
		}
		lease.replace(func() {
			for _, a := range assets {
				a.dropFlow()
			}
		})
	}
}

func (r *liveIngress) RouteConnectionEx(ctx context.Context, conn net.Conn, md adapter.InboundContext, onClose N.CloseHandlerFunc) {
	p, done := r.live.acquire()
	defer done()
	closeFlow, handoff := p.leaseForFlow(onClose)
	p.router.RouteConnectionWithHandoff(ctx, conn, md, closeFlow, handoff)
}

func (r *liveIngress) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, md adapter.InboundContext, onClose N.CloseHandlerFunc) {
	p, done := r.live.acquire()
	defer done()
	closeFlow, handoff := p.leaseForFlow(onClose)
	p.router.RoutePacketConnectionWithHandoff(ctx, conn, md, closeFlow, handoff)
}

func (r *liveIngress) RouteConnection(ctx context.Context, conn net.Conn, md adapter.InboundContext) error {
	done := make(chan struct{})
	r.RouteConnectionEx(ctx, conn, md, func(error) { close(done) })
	select {
	case <-done:
	case <-r.live.stop:
	}
	return nil
}

func (r *liveIngress) RoutePacketConnection(ctx context.Context, conn N.PacketConn, md adapter.InboundContext) error {
	done := make(chan struct{})
	r.RoutePacketConnectionEx(ctx, conn, md, func(error) { close(done) })
	select {
	case <-done:
	case <-r.live.stop:
	}
	return nil
}

func (r *liveIngress) PreMatch(md adapter.InboundContext, packet []byte) adapter.PreMatchResult {
	p, done := r.live.acquire()
	defer done()
	return p.router.PreMatch(md, packet)
}

func (r *liveIngress) HijackDNSPacket(ctx context.Context, payload []byte, w N.PacketWriter, md adapter.InboundContext) {
	p, done := r.live.acquire()
	p.router.HijackDNSPacketWithCompletion(ctx, payload, w, md, done)
}

func (r *liveIngress) ResetNetwork() {
	p, done := r.live.acquire()
	defer done()
	p.router.ResetNetwork()
}

type liveOutbounds struct {
	*policyView
}

func (v liveOutbounds) Outbounds() []adapter.Outbound { return v.current().out.Outbounds() }
func (v liveOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	return v.current().out.Outbound(tag)
}
func (v liveOutbounds) Default() adapter.Outbound { return v.current().out.Default() }

type liveEndpoints struct {
	*policyView
}

func (v liveEndpoints) Endpoints() []adapter.Endpoint { return v.current().end.Endpoints() }
func (v liveEndpoints) Get(tag string) (adapter.Endpoint, bool) {
	return v.current().end.Get(tag)
}

type liveTransports struct {
	*policyView
}

func (v liveTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	return v.current().transports.Transport(tag)
}
func (v liveTransports) Transports() []adapter.DNSTransport {
	return v.current().transports.Transports()
}
func (v liveTransports) Default() adapter.DNSTransport {
	return v.current().transports.Default()
}
func (v liveTransports) FakeIP() adapter.FakeIPTransport {
	return v.current().transports.FakeIP()
}

type liveDNS struct {
	*policyView
}

func currentDNSOptions(p *routingPolicy, o adapter.DNSQueryOptions) (adapter.DNSQueryOptions, error) {
	if o.Transport != nil {
		tag := o.Transport.Tag()
		target, ok := p.transports.Transport(tag)
		if !ok {
			return o, fmt.Errorf("unknown DNS transport %q", tag)
		}
		o.Transport = target
	}
	return o, nil
}
func (v liveDNS) Lookup(ctx context.Context, name string, o adapter.DNSQueryOptions) ([]netip.Addr, error) {
	p, ctx, done := v.acquireQuery(ctx)
	defer done()
	o, err := currentDNSOptions(p, o)
	if err != nil {
		return nil, err
	}
	return p.dns.Lookup(ctx, name, o)
}
func (v liveDNS) Exchange(ctx context.Context, msg *mdns.Msg, o adapter.DNSQueryOptions) (*mdns.Msg, error) {
	p, ctx, done := v.acquireQuery(ctx)
	defer done()
	o, err := currentDNSOptions(p, o)
	if err != nil {
		return nil, err
	}
	return p.dns.Exchange(ctx, msg, o)
}
func (v liveDNS) ExchangeAsync(ctx context.Context, msg *mdns.Msg, o adapter.DNSQueryOptions, cb func(*mdns.Msg, error)) {
	p, ctx, done := v.acquireQuery(ctx)
	o, err := currentDNSOptions(p, o)
	if err != nil {
		done()
		cb(nil, err)
		return
	}
	p.dns.ExchangeAsync(ctx, msg, o, func(msg *mdns.Msg, err error) { defer done(); cb(msg, err) })
}
func (v liveDNS) LookupReverseMapping(ip netip.Addr) (string, bool) {
	p, done := v.acquire()
	defer done()
	return p.dns.LookupReverseMapping(ip)
}
func (v liveDNS) ClearCache()   { p, done := v.acquire(); defer done(); p.dns.ClearCache() }
func (v liveDNS) ResetNetwork() { p, done := v.acquire(); defer done(); p.dns.ResetNetwork() }

func (h *liveRuntime) ServiceContext(ctx context.Context) context.Context {
	ctx = service.ExtendContext(ctx)
	h.view.register(ctx)
	return ctx
}

func (h *liveRuntime) acquire() (*routingPolicy, func()) {
	h.readers.RLock()
	p := h.active.Load()
	p.refs.Add(1)
	h.readers.RUnlock()
	return p, sync.OnceFunc(p.dropReader)
}

func (r *liveIngress) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return r.current().router.Start(stage, scope)
}
func (r *liveIngress) RuleSet(tag string) (adapter.RuleSet, bool) {
	return r.current().router.RuleSet(tag)
}
func (r *liveIngress) Rules() []adapter.Rule  { return r.current().router.Rules() }
func (r *liveIngress) NeedFindProcess() bool  { return r.current().router.NeedFindProcess() }
func (r *liveIngress) NeedFindNeighbor() bool { return r.current().router.NeedFindNeighbor() }
func (r *liveIngress) NeighborResolver() adapter.NeighborResolver {
	return r.current().router.NeighborResolver()
}
func (r *liveIngress) AppendTracker(t adapter.ConnectionTracker) { r.current().router.AppendTracker(t) }
func (v liveDNS) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return v.current().dns.Start(stage, scope)
}
func (v liveOutbounds) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return v.current().out.Start(stage, scope)
}
func (v liveOutbounds) Create(ctx context.Context, r adapter.Router, l log.ContextLogger, tag, kind string, opts any) error {
	return v.current().out.Create(ctx, r, l, tag, kind, opts)
}
func (v liveEndpoints) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return v.current().end.Start(stage, scope)
}
func (v liveEndpoints) StartEndpoint(e adapter.Endpoint) error {
	return v.current().end.StartEndpoint(e)
}
func (v liveEndpoints) Create(ctx context.Context, r adapter.Router, l log.ContextLogger, tag, kind string, opts any) error {
	return v.current().end.Create(ctx, r, l, tag, kind, opts)
}
func (v liveTransports) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	return v.current().transports.Start(stage, scope)
}
func (v liveTransports) Create(ctx context.Context, l log.ContextLogger, tag, kind string, opts any) error {
	return v.current().transports.Create(ctx, l, tag, kind, opts)
}

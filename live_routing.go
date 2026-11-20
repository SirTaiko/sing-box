package box

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// The listeners and the authenticated API keep their lifetimes. Each accepted
// flow pins its routing policy until the connection manager calls onClose.
type liveIngress struct {
	adapter.Router
	live *liveRuntime
}

func (r *liveIngress) RouteConnectionEx(ctx context.Context, conn net.Conn, md adapter.InboundContext, onClose N.CloseHandlerFunc) {
	p, done := r.live.acquire()
	p.router.RouteConnectionEx(ctx, conn, md, N.OnceClose(N.AppendClose(onClose, func(error) { done() })))
}

func (r *liveIngress) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, md adapter.InboundContext, onClose N.CloseHandlerFunc) {
	p, done := r.live.acquire()
	p.router.RoutePacketConnectionEx(ctx, conn, md, N.OnceClose(N.AppendClose(onClose, func(error) { done() })))
}

func (r *liveIngress) RouteConnection(ctx context.Context, conn net.Conn, md adapter.InboundContext) error {
	p, done := r.live.acquire()
	defer done()
	return p.router.RouteConnection(ctx, conn, md)
}

func (r *liveIngress) RoutePacketConnection(ctx context.Context, conn N.PacketConn, md adapter.InboundContext) error {
	p, done := r.live.acquire()
	defer done()
	return p.router.RoutePacketConnection(ctx, conn, md)
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
	adapter.OutboundManager
	live *liveRuntime
}

func (v liveOutbounds) Outbounds() []adapter.Outbound { return v.live.active.Load().out.Outbounds() }
func (v liveOutbounds) Outbound(tag string) (adapter.Outbound, bool) {
	return v.live.active.Load().out.Outbound(tag)
}
func (v liveOutbounds) Default() adapter.Outbound { return v.live.active.Load().out.Default() }

type liveEndpoints struct {
	adapter.EndpointManager
	live *liveRuntime
}

func (v liveEndpoints) Endpoints() []adapter.Endpoint { return v.live.active.Load().end.Endpoints() }
func (v liveEndpoints) Get(tag string) (adapter.Endpoint, bool) {
	return v.live.active.Load().end.Get(tag)
}

type liveTransports struct {
	adapter.DNSTransportManager
	live *liveRuntime
}

func (v liveTransports) Transport(tag string) (adapter.DNSTransport, bool) {
	return v.live.active.Load().transports.Transport(tag)
}
func (v liveTransports) Transports() []adapter.DNSTransport {
	return v.live.active.Load().transports.Transports()
}
func (v liveTransports) Default() adapter.DNSTransport {
	return v.live.active.Load().transports.Default()
}
func (v liveTransports) FakeIP() adapter.FakeIPTransport {
	return v.live.active.Load().transports.FakeIP()
}

type liveDNS struct {
	adapter.DNSRouter
	live *liveRuntime
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
	p, done := v.live.acquire()
	defer done()
	o, err := currentDNSOptions(p, o)
	if err != nil {
		return nil, err
	}
	return p.dns.Lookup(ctx, name, o)
}
func (v liveDNS) Exchange(ctx context.Context, msg *mdns.Msg, o adapter.DNSQueryOptions) (*mdns.Msg, error) {
	p, done := v.live.acquire()
	defer done()
	o, err := currentDNSOptions(p, o)
	if err != nil {
		return nil, err
	}
	return p.dns.Exchange(ctx, msg, o)
}
func (v liveDNS) ExchangeAsync(ctx context.Context, msg *mdns.Msg, o adapter.DNSQueryOptions, cb func(*mdns.Msg, error)) {
	p, done := v.live.acquire()
	o, err := currentDNSOptions(p, o)
	if err != nil {
		done()
		cb(nil, err)
		return
	}
	p.dns.ExchangeAsync(ctx, msg, o, func(msg *mdns.Msg, err error) { defer done(); cb(msg, err) })
}
func (v liveDNS) LookupReverseMapping(ip netip.Addr) (string, bool) {
	p, done := v.live.acquire()
	defer done()
	return p.dns.LookupReverseMapping(ip)
}
func (v liveDNS) ClearCache()   { p, done := v.live.acquire(); defer done(); p.dns.ClearCache() }
func (v liveDNS) ResetNetwork() { p, done := v.live.acquire(); defer done(); p.dns.ResetNetwork() }

func (h *liveRuntime) ServiceContext(ctx context.Context) context.Context {
	ctx = service.ExtendContext(ctx)
	p := h.active.Load()
	service.MustRegister[adapter.EndpointManager](ctx, liveEndpoints{p.end, h})
	service.MustRegister[adapter.OutboundManager](ctx, liveOutbounds{p.out, h})
	service.MustRegister[adapter.DNSTransportManager](ctx, liveTransports{p.transports, h})
	service.MustRegister[adapter.DNSRouter](ctx, liveDNS{p.dns, h})
	return ctx
}

func (h *liveRuntime) acquire() (*routingPolicy, func()) {
	h.readers.RLock()
	p := h.active.Load()
	p.refs.Add(1)
	h.readers.RUnlock()
	return p, sync.OnceFunc(p.dropReader)
}

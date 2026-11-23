package box

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/sagernet/sing-box/route"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

type liveRuntime struct {
	ctx         context.Context
	path        string
	box         *Box
	mu          sync.Mutex
	readers     sync.RWMutex
	active      atomic.Pointer[routingPolicy]
	closed      bool
	initialized bool
	lastDigest  []byte
	tunScope    *adapter.Scope
	stop        chan struct{}
	cleanup     sync.WaitGroup
}

type routingPolicy struct {
	live           *liveRuntime
	config         option.Options
	router         *route.Router
	dns            *dns.Router
	out            *outbound.Manager
	end            *endpoint.Manager
	transports     *dns.TransportManager
	refs           atomic.Int64
	drained        chan struct{}
	assets         map[any]*policyAsset
	resources      liveResources
	flows          atomic.Pointer[flowAssetIndex]
	restoreEngines []func() error
}

// An unchanged transport (especially FakeIP), endpoint or outbound may be
// referenced by several routing revisions. Its lifetime ends with its last user.
type policyAsset struct {
	scope   *adapter.Scope
	users   atomic.Int32
	flows   atomic.Int64
	drained chan struct{}
}

func (p *routingPolicy) own(obj any, scope *adapter.Scope) {
	a := &policyAsset{scope: scope}
	if scope != nil {
		a.drained = make(chan struct{})
	}
	a.users.Store(1)
	p.assets[obj] = a
}
func (p *routingPolicy) borrow(old *routingPolicy, obj any) {
	a := old.assets[obj]
	a.users.Add(1)
	p.assets[obj] = a
}

// Mark retirement in the same atomic word as the flow count: a transient
// zero while policies can still accept flows must never signal final drain.
const retiredAsset int64 = 1 << 62

func (a *policyAsset) dropFlow() {
	if a.flows.Add(-1) == retiredAsset {
		close(a.drained)
	}
}

func (p *routingPolicy) release() {
	for _, asset := range p.assets {
		if asset.users.Add(-1) != 0 || asset.scope == nil {
			continue
		}
		if asset.flows.Add(retiredAsset) == retiredAsset {
			_ = asset.scope.Close()
			continue
		}
		live := p.live
		select {
		case <-live.stop:
			_ = asset.scope.Close()
		default:
			// Closing an outbound can wait for I/O. Keep it off the flow's
			// own close callback and retain only this asset while waiting.
			live.cleanup.Add(1)
			go func(a *policyAsset) {
				defer live.cleanup.Done()
				select {
				case <-a.drained:
				case <-live.stop:
				}
				_ = a.scope.Close()
			}(asset)
		}
	}
}
func (p *routingPolicy) abort(cause error) error {
	p.release()
	for _, restore := range p.restoreEngines {
		cause = errors.Join(cause, restore())
	}
	return cause
}
func newLiveRuntime(ctx context.Context, path string, o option.Options, r *route.Router, d *dns.Router, out *outbound.Manager, end *endpoint.Manager, transports *dns.TransportManager) *liveRuntime {
	h := &liveRuntime{ctx: ctx, path: path, stop: make(chan struct{})}
	service.MustRegisterPtr(ctx, new(group.RuntimeInterrupts))
	p := &routingPolicy{live: h, config: o, router: r, dns: d, out: out, end: end, transports: transports, assets: make(map[any]*policyAsset)}
	p.drained = make(chan struct{})
	p.refs.Store(1)
	h.active.Store(p)
	return h
}
func (h *liveRuntime) adoptInitial(p *routingPolicy) {
	root := h.box.scope
	p.own(p.router, root.Child(p.router))
	p.own(p.dns, root.Child(p.dns))
	add := func(manager adapter.Lifecycle, obj any) {
		var scope *adapter.Scope
		if life, ok := obj.(adapter.Lifecycle); ok {
			if parent := root.Child(manager); parent != nil {
				scope = parent.Child(life)
			}
		}
		p.own(obj, scope)
	}
	for _, ob := range p.out.Outbounds() {
		add(p.out, ob)
	}
	for _, ep := range p.end.Endpoints() {
		add(p.end, ep)
	}
	for _, t := range p.transports.Transports() {
		add(p.transports, t)
	}
	p.resources = describeLiveResources(p.config)
	p.indexFlowAssets()
	h.initialized = true
}
func (p *routingPolicy) dropReader() {
	if p.refs.Add(-1) == 0 {
		close(p.drained)
	}
}

func (h *liveRuntime) shutdown() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	close(h.stop)
	if h.tunScope != nil {
		_ = h.tunScope.Close()
	}
}

func (h *liveRuntime) finishShutdown() {
	h.cleanup.Wait()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.initialized {
		h.active.Load().release()
		h.initialized = false
	}
}

// Only the desktop data plane is mutable. API credentials, listening sockets,
// cache location and all unrelated services remain under startup ownership.
func fixedOptions(o option.Options) option.Options {
	o.RawMessage = nil
	o.CommentsSet = nil
	o.DNS = nil
	o.Route = nil
	o.Endpoints = nil
	o.Outbounds = nil
	o.Inbounds = nil
	if o.Log != nil {
		l := *o.Log
		l.DisableColor = false
		o.Log = &l
	}
	return o
}
func fixedRoute(o *option.RouteOptions) option.RouteOptions {
	r := common.PtrValueOrDefault(o)
	r.Final = ""
	r.Rules = nil
	r.RuleSet = nil
	r.DefaultDomainResolver = nil
	return r
}

func (p *routingPolicy) healthy() bool {
	for _, ob := range p.out.Outbounds() {
		if engine, ok := ob.(interface{ RuntimeReady() bool }); ok && !engine.RuntimeReady() {
			return false
		}
	}
	return true
}

func (h *liveRuntime) RuntimeRevision() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return bytes.Clone(h.lastDigest)
}

func (h *liveRuntime) ApplyRuntimeConfig(ctx context.Context, digest []byte, selected string) (err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	content, err := os.ReadFile(h.path + ".pending")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	if !bytes.Equal(sum[:], digest) {
		return errors.New("configuration file changed before apply")
	}
	if bytes.Equal(h.lastDigest, digest) && h.active.Load().healthy() {
		return nil
	}
	next, err := json.UnmarshalExtendedContext[option.Options](h.ctx, content)
	if err != nil {
		return fmt.Errorf("parse runtime configuration: %w", err)
	}
	old := h.active.Load()
	if !reflect.DeepEqual(fixedOptions(old.config), fixedOptions(next)) || !reflect.DeepEqual(fixedRoute(old.config.Route), fixedRoute(next.Route)) {
		return errors.New("unsupported change outside desktop routing configuration")
	}
	if selected != "" && !common.Any(next.Outbounds, func(ob option.Outbound) bool {
		g, ok := ob.Options.(*option.SelectorOutboundOptions)
		return ok && ob.Tag == "vpn-select" && common.Contains(g.Outbounds, selected)
	}) {
		return errors.New("requested server is not in vpn-select")
	}
	tunChange, err := h.prepareTun(old.config.Inbounds, next.Inbounds)
	if err != nil {
		return err
	}
	if !h.initialized {
		h.adoptInitial(old)
	}
	p, err := h.preparePolicy(ctx, old, next)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			err = p.abort(err)
		}
	}()
	sel, _ := p.out.Outbound("vpn-select")
	selector, ok := sel.(*group.Selector)
	if selected != "" && (!ok || !common.Contains(selector.All(), selected)) {
		return errors.New("requested server is not in vpn-select")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if tunChange != nil {
		if err = tunChange(); err != nil {
			return err
		}
	}
	for _, ob := range next.Outbounds {
		current, _ := p.out.Outbound(ob.Tag)
		switch o := ob.Options.(type) {
		case *option.SelectorOutboundOptions:
			current.(*group.Selector).SetInterruptExisting(o.InterruptExistConnections)
		case *option.URLTestOutboundOptions:
			current.(*group.URLTest).SetInterruptExisting(o.InterruptExistConnections)
		}
	}
	if selected != "" {
		previousTag := ""
		if previous, found := old.out.Outbound("vpn-select"); found {
			if g, ok := previous.(*group.Selector); ok && g.Selected("tcp") != nil {
				previousTag = g.Selected("tcp").Tag()
			}
		}
		selector.SelectRuntimeOutbound(selected, previousTag)
	}
	h.readers.Lock()
	h.active.Store(p)
	h.readers.Unlock()
	h.closeReroutedConnections(old, p)
	if p.dns != old.dns {
		p.dns.ClearCache()
	}
	h.box.referenceManager.Reconfigure(h.ServiceContext(h.ctx), next)
	// A retired corporate login or packet-interception process must stop even
	// if another, unrelated connection still pins the previous routing rules.
	for _, ob := range old.out.Outbounds() {
		if g, ok := ob.(*group.URLTest); ok {
			if _, shared := p.assets[ob]; !shared {
				g.Retire()
			}
		}
	}
	for _, ep := range old.end.Endpoints() {
		if _, kept := p.assets[ep]; !kept && old.assets[ep].scope != nil {
			_ = old.assets[ep].scope.Close()
		}
	}
	for _, ob := range old.config.Outbounds {
		if d, ok := ob.Options.(*option.DirectOutboundOptions); ok && d.Zapret != nil {
			obj, _ := old.out.Outbound(ob.Tag)
			if _, kept := p.assets[obj]; !kept && old.assets[obj].scope != nil {
				_ = old.assets[obj].scope.Close()
			}
		}
	}
	h.lastDigest = append([]byte(nil), digest...)
	p.restoreEngines = nil
	committed = true
	old.dropReader()
	h.cleanup.Add(1)
	go func() {
		defer h.cleanup.Done()
		select {
		case <-old.drained:
		case <-h.stop:
		}
		old.release()
	}()
	if history := service.PtrFromContext[urltest.HistoryStorage](h.ctx); history != nil {
		history.NotifyUpdated()
	}
	return nil
}

func (h *liveRuntime) closeReroutedConnections(old, next *routingPolicy) {
	if reflect.DeepEqual(old.config.Route, next.config.Route) {
		return
	}
	manager := service.PtrFromContext[trafficcontrol.Manager](h.ctx)
	if manager == nil {
		return
	}
	for _, flow := range manager.Connections() {
		if len(flow.Chain) == 0 {
			continue
		}
		// Compare logical route tags. A server switch inside vpn-select has
		// its own interruption policy.
		activeTag := flow.Chain[len(flow.Chain)-1]
		oldTag, known := old.router.TrackedOutboundTag(h.ctx, flow.Metadata)
		if !known || oldTag != activeTag {
			continue
		}
		newTag, known := next.router.TrackedOutboundTag(h.ctx, flow.Metadata)
		if known && newTag != activeTag {
			if tracked := manager.Connection(flow.ID); tracked != nil {
				_ = tracked.Close()
			}
		}
	}
}

package socks

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

type fakeLookup struct {
	domain  string
	options adapter.DNSQueryOptions
}

// fakeDNSRouter implements only Lookup; every other DNSRouter method panics if
// some unexpected code path starts using it.
type fakeDNSRouter struct {
	adapter.DNSRouter
	lookupFunc func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error)
	started    chan struct{}
	access     sync.Mutex
	lookups    []fakeLookup
}

func (r *fakeDNSRouter) Lookup(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
	r.access.Lock()
	r.lookups = append(r.lookups, fakeLookup{domain: domain, options: options})
	lookupFunc := r.lookupFunc
	started := r.started
	r.access.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if lookupFunc != nil {
		return lookupFunc(ctx, domain, options)
	}
	return nil, nil
}

func (r *fakeDNSRouter) lookupCount() int {
	r.access.Lock()
	defer r.access.Unlock()
	return len(r.lookups)
}

func (r *fakeDNSRouter) lookupAt(index int) fakeLookup {
	r.access.Lock()
	defer r.access.Unlock()
	return r.lookups[index]
}

type fakeDNSTransport struct {
	adapter.DNSTransport
	tag string
}

func (t *fakeDNSTransport) Type() string { return "test" }
func (t *fakeDNSTransport) Tag() string  { return t.tag }

type fakeTransportManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
	defaultTag string
}

func (m *fakeTransportManager) Transport(tag string) (adapter.DNSTransport, bool) {
	transport, loaded := m.transports[tag]
	return transport, loaded
}

func (m *fakeTransportManager) Default() adapter.DNSTransport {
	return m.transports[m.defaultTag]
}

func (m *fakeTransportManager) Transports() []adapter.DNSTransport {
	transports := make([]adapter.DNSTransport, 0, len(m.transports))
	for _, transport := range m.transports {
		transports = append(transports, transport)
	}
	return transports
}

type fakeNetworkManager struct {
	adapter.NetworkManager
	options adapter.NetworkOptions
}

func (m *fakeNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return m.options
}

type resolverServices struct {
	router     *fakeDNSRouter
	transports *fakeTransportManager
	network    *fakeNetworkManager
}

func newResolverServices() *resolverServices {
	return &resolverServices{
		router: &fakeDNSRouter{},
		transports: &fakeTransportManager{
			transports: map[string]adapter.DNSTransport{},
			defaultTag: "default-dns",
		},
		network: &fakeNetworkManager{},
	}
}

func (s *resolverServices) context() context.Context {
	ctx := service.ContextWithDefaultRegistry(context.Background())
	ctx = service.ContextWith[adapter.DNSRouter](ctx, s.router)
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, s.transports)
	ctx = service.ContextWith[adapter.NetworkManager](ctx, s.network)
	return ctx
}

func ptrValue[T any](value T) *T {
	return &value
}

func TestDestinationResolverAbsent(t *testing.T) {
	resolver, err := newDestinationResolver(context.Background(), option.SocksInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if resolver != nil {
		t.Fatal("resolver must stay absent without resolver_concurrency")
	}
}

func TestDestinationResolverConcurrencyValidation(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	for _, value := range []uint16{0, 301, 65535} {
		_, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
			ResolverConcurrency: ptrValue(value),
		})
		if err == nil {
			t.Fatalf("resolver_concurrency=%d must be rejected", value)
		}
	}
	for _, value := range []uint16{1, 300} {
		resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
			ResolverConcurrency: ptrValue(value),
		})
		if err != nil {
			t.Fatalf("resolver_concurrency=%d must be accepted: %v", value, err)
		}
		if resolver == nil || cap(resolver.slots) != int(value) {
			t.Fatalf("resolver_concurrency=%d produced wrong slot capacity", value)
		}
	}
}

func TestDestinationResolverDomainResolverWiring(t *testing.T) {
	services := newResolverServices()
	localTransport := &fakeDNSTransport{tag: "dns-local"}
	otherTransport := &fakeDNSTransport{tag: "dns-other"}
	services.transports.transports["dns-local"] = localTransport
	services.transports.transports["dns-other"] = otherTransport
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	rewriteTTL := uint32(60)
	clientSubnet := badoption.Prefixable(netip.MustParsePrefix("192.0.2.0/24"))
	resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(4)),
		DomainResolver: &option.DomainResolveOptions{
			Server:                 "dns-local",
			Strategy:               option.DomainStrategy(C.DomainStrategyIPv4Only),
			Timeout:                badoption.Duration(3 * time.Second),
			DisableCache:           true,
			DisableOptimisticCache: true,
			RewriteTTL:             &rewriteTTL,
			ClientSubnet:           &clientSubnet,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.queryOptions.Transport != localTransport {
		t.Fatalf("domain_resolver server was not selected: %v", resolver.queryOptions.Transport)
	}
	if resolver.queryOptions.Strategy != C.DomainStrategyIPv4Only {
		t.Fatalf("domain_resolver strategy was not wired: %v", resolver.queryOptions.Strategy)
	}
	if resolver.queryOptions.Timeout != 3*time.Second {
		t.Fatalf("domain_resolver timeout was not wired: %v", resolver.queryOptions.Timeout)
	}
	if !resolver.queryOptions.DisableCache || !resolver.queryOptions.DisableOptimisticCache {
		t.Fatal("domain_resolver cache flags were not wired")
	}
	if resolver.queryOptions.RewriteTTL == nil || *resolver.queryOptions.RewriteTTL != rewriteTTL {
		t.Fatal("domain_resolver rewrite_ttl was not wired")
	}
	if resolver.queryOptions.ClientSubnet != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("domain_resolver client_subnet was not wired: %v", resolver.queryOptions.ClientSubnet)
	}
}

func TestDestinationResolverMissingDomainResolver(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	_, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
		DomainResolver:      &option.DomainResolveOptions{Server: "missing-dns"},
	})
	if err == nil {
		t.Fatal("an unknown domain_resolver server must be rejected")
	}
}

func TestDestinationResolverDefaultSelection(t *testing.T) {
	services := newResolverServices()
	defaultTransport := &fakeDNSTransport{tag: "default-dns"}
	services.transports.transports["default-dns"] = defaultTransport
	services.network.options = adapter.NetworkOptions{
		DomainResolver:       "default-dns",
		DomainResolveOptions: adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv6Only},
	}
	resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(2)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.queryOptions.Transport != defaultTransport {
		t.Fatal("the default domain resolver was not selected")
	}
	if resolver.queryOptions.Strategy != C.DomainStrategyIPv6Only {
		t.Fatalf("the default domain resolver strategy was not wired: %v", resolver.queryOptions.Strategy)
	}
}

func TestDestinationResolverQueueLimit(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.queueLimit != resolverDefaultQueueLimit {
		t.Fatalf("default queue limit = %d, want %d", resolver.queueLimit, resolverDefaultQueueLimit)
	}
	resolver, err = newDestinationResolver(services.context(), option.SocksInboundOptions{
		ListenOptions:       option.ListenOptions{TCPMaxConnections: ptrValue(uint16(3))},
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.queueLimit != 3 {
		t.Fatalf("queue limit = %d, want 3 from tcp_max_connections", resolver.queueLimit)
	}
}

func TestDestinationResolverBoundsConcurrentLookups(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	release := make(chan struct{})
	services.router.started = make(chan struct{}, 16)
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(2)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, lookupErr := resolver.lookup(context.Background(), &adapter.InboundContext{}, "example.com")
			if lookupErr != nil {
				t.Error(lookupErr)
			}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-services.router.started:
		case <-time.After(2 * time.Second):
			t.Fatal("configured lookups did not start")
		}
	}
	select {
	case <-services.router.started:
		t.Fatal("lookup concurrency exceeded resolver_concurrency")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	group.Wait()
	if count := services.router.lookupCount(); count != 4 {
		t.Fatalf("lookup count = %d, want 4", count)
	}
	if len(resolver.slots) != 0 {
		t.Fatalf("slots leaked: %d", len(resolver.slots))
	}
	if queued := resolver.queued.Load(); queued != 0 {
		t.Fatalf("queued counter leaked: %d", queued)
	}
}

func TestDestinationResolverQueueFull(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	release := make(chan struct{})
	services.router.started = make(chan struct{}, 16)
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ListenOptions:       option.ListenOptions{TCPMaxConnections: ptrValue(uint16(2))},
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	firstDone := make(chan error, 1)
	go func() {
		_, lookupErr := resolver.lookup(context.Background(), &adapter.InboundContext{}, "first.example")
		firstDone <- lookupErr
	}()
	select {
	case <-services.router.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first lookup did not start")
	}
	waiting := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, lookupErr := resolver.lookup(context.Background(), &adapter.InboundContext{}, "waiting.example")
			waiting <- lookupErr
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for resolver.queued.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if queued := resolver.queued.Load(); queued != 2 {
		t.Fatalf("queued lookups = %d, want 2", queued)
	}
	queued, cancelOverflow := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelOverflow()
	_, err = resolver.lookup(queued, &adapter.InboundContext{}, "overflow.example")
	if err != errResolverQueueFull {
		t.Fatalf("overflow lookup error = %v, want %v", err, errResolverQueueFull)
	}
	if count := services.router.lookupCount(); count != 1 {
		t.Fatalf("overflow lookup reached the DNS router: %d lookups", count)
	}
	close(release)
	if err = <-firstDone; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = <-waiting; err != nil {
			t.Fatal(err)
		}
	}
	if queued := resolver.queued.Load(); queued != 0 {
		t.Fatalf("queued counter leaked: %d", queued)
	}
}

func TestDestinationResolverCanceledWhileQueued(t *testing.T) {
	services := newResolverServices()
	services.transports.transports["default-dns"] = &fakeDNSTransport{tag: "default-dns"}
	release := make(chan struct{})
	services.router.started = make(chan struct{}, 16)
	services.router.lookupFunc = func(ctx context.Context, domain string, options adapter.DNSQueryOptions) ([]netip.Addr, error) {
		<-release
		return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
	}
	resolver, err := newDestinationResolver(services.context(), option.SocksInboundOptions{
		ResolverConcurrency: ptrValue(uint16(1)),
	})
	if err != nil {
		t.Fatal(err)
	}
	runningDone := make(chan error, 1)
	go func() {
		_, lookupErr := resolver.lookup(context.Background(), &adapter.InboundContext{}, "running.example")
		runningDone <- lookupErr
	}()
	select {
	case <-services.router.started:
	case <-time.After(2 * time.Second):
		t.Fatal("running lookup did not start")
	}
	waitCtx, cancel := context.WithCancel(context.Background())
	waitDone := make(chan error, 1)
	go func() {
		_, lookupErr := resolver.lookup(waitCtx, &adapter.InboundContext{}, "waiting.example")
		waitDone <- lookupErr
	}()
	deadline := time.Now().Add(2 * time.Second)
	for resolver.queued.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err = <-waitDone:
		if err != context.Canceled {
			t.Fatalf("queued lookup error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled queued lookup did not return")
	}
	if count := services.router.lookupCount(); count != 1 {
		t.Fatalf("canceled queued lookup reached the DNS router: %d lookups", count)
	}
	close(release)
	if err = <-runningDone; err != nil {
		t.Fatal(err)
	}
	if queued := resolver.queued.Load(); queued != 0 {
		t.Fatalf("queued counter leaked: %d", queued)
	}
}

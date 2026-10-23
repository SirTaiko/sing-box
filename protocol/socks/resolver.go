package socks

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

const (
	// resolverMaxConcurrency is the accepted upper bound of
	// SocksInboundOptions.resolver_concurrency.
	resolverMaxConcurrency = 300
	// resolverDefaultQueueLimit bounds waiting lookups when tcp_max_connections
	// is absent, matching the ordinary inbound admission bound of 10000.
	resolverDefaultQueueLimit = 10000
)

// errResolverQueueFull reports that the bounded waiting queue of this inbound
// is exhausted. It is an admission failure, not a no_resolve policy rejection.
var errResolverQueueFull = E.New("socks: destination resolver queue is full")

// destinationResolver bounds SOCKS destination lookups through the existing
// DNS router. It owns only admission slots; the transport, cache, strategy and
// routing rules stay with DNSRouter and the configured domain_resolver.
type destinationResolver struct {
	router       adapter.DNSRouter
	queryOptions adapter.DNSQueryOptions
	slots        chan struct{}
	queueLimit   int
	queued       atomic.Int64
}

// newDestinationResolver builds the per-inbound resolver. A nil
// resolver_concurrency keeps the previous behavior: no resolver, no slots and
// no inbound DNS traffic. The configured domain_resolver selects the DNS
// transport and its strategy/cache options; without it the existing default
// resolver selection of the dialer package applies, so the DNS router can still
// use its normal rules and the configured local/system transport.
func newDestinationResolver(ctx context.Context, options option.SocksInboundOptions) (*destinationResolver, error) {
	if options.ResolverConcurrency == nil {
		return nil, nil
	}
	concurrency := int(*options.ResolverConcurrency)
	if concurrency < 1 || concurrency > resolverMaxConcurrency {
		return nil, E.New("resolver_concurrency must be between 1 and ", resolverMaxConcurrency, ", got ", concurrency)
	}
	dnsRouter := service.FromContext[adapter.DNSRouter](ctx)
	if dnsRouter == nil {
		return nil, E.New("socks: resolver_concurrency requires an initialized DNS router")
	}
	queryOptions, err := dialer.NewDNSQueryOptions(ctx, options.DomainResolver, false)
	if err != nil {
		return nil, E.Cause(err, "socks: initialize destination resolver")
	}
	queueLimit := options.TCPMaxConnectionLimit()
	if queueLimit <= 0 {
		queueLimit = resolverDefaultQueueLimit
	}
	return &destinationResolver{
		router:       dnsRouter,
		queryOptions: queryOptions,
		slots:        make(chan struct{}, concurrency),
		queueLimit:   queueLimit,
	}, nil
}

// acquire takes one resolution slot, waiting in the bounded queue when every
// slot is busy. It returns immediately when the caller is canceled or when the
// queue is full.
func (r *destinationResolver) acquire(ctx context.Context) error {
	select {
	case r.slots <- struct{}{}:
		return nil
	default:
	}
	queued := r.queued.Add(1)
	if queued > int64(r.queueLimit) {
		r.queued.Add(-1)
		return errResolverQueueFull
	}
	select {
	case r.slots <- struct{}{}:
		r.queued.Add(-1)
		return nil
	case <-ctx.Done():
		r.queued.Add(-1)
		return ctx.Err()
	}
}

// release returns a slot. Callers release directly after the lookup, never at
// the end of the connection.
func (r *destinationResolver) release() {
	<-r.slots
}

// lookup resolves one parsed domain destination and returns the addresses in
// the order produced by the configured DNS strategy. A result that arrives
// after cancellation is discarded instead of being routed.
func (r *destinationResolver) lookup(ctx context.Context, metadata *adapter.InboundContext, domain string) ([]netip.Addr, error) {
	if err := r.acquire(ctx); err != nil {
		return nil, err
	}
	addresses, err := func() ([]netip.Addr, error) {
		defer r.release()
		return r.router.Lookup(adapter.WithContext(ctx, metadata), domain, r.queryOptions)
	}()
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, E.New("empty result")
	}
	return addresses, nil
}

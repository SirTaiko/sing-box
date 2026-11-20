package api

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"

	mDNS "github.com/miekg/dns"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type dnsLookup struct {
	daemon.UnimplementedDNSLookupServer
	router     adapter.DNSRouter
	transports adapter.DNSTransportManager
}

func (d *dnsLookup) LookupIPv4(ctx context.Context, req *daemon.IPv4LookupRequest) (*daemon.IPv4LookupResponse, error) {
	if _, valid := mDNS.IsDomainName(req.Name); !valid || req.Name == "." || req.Server == "" {
		return nil, status.Error(codes.InvalidArgument, "expected a hostname and DNS transport")
	}
	transport, found := d.transports.Transport(req.Server)
	if !found {
		return nil, status.Error(codes.NotFound, "DNS transport not found")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addresses, err := d.router.Lookup(ctx, req.Name, adapter.DNSQueryOptions{Transport: transport, Strategy: C.DomainStrategyIPv4Only})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "DNS lookup failed")
	}
	response := new(daemon.IPv4LookupResponse)
	for _, ip := range addresses {
		if ip.Is4() {
			response.Addresses = append(response.Addresses, ip.String())
		}
	}
	return response, nil
}

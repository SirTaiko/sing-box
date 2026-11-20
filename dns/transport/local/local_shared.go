package local

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	E "github.com/sagernet/sing/common/exceptions"

	mDNS "github.com/miekg/dns"
)

type localServerSet struct {
	config      *systemconfig.Config
	transports  []*localNameServer
	serverScope *adapter.Scope
}

// Both transports address the same DNS server supplied by the network.
type localNameServer struct {
	primary, alternate adapter.DNSTransport
	preferAlternate    atomic.Bool
}

func (s *localNameServer) reset() {
	s.primary.Reset()
	if s.alternate != nil {
		s.alternate.Reset()
		s.preferAlternate.Store(false)
	}
}

func (s *localNameServer) exchange(ctx context.Context, query *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	if s.alternate == nil {
		s.primary.ExchangeAsync(ctx, query, callback)
		return
	}
	alternateFirst := s.preferAlternate.Load()
	first, second := s.primary, s.alternate
	if alternateFirst {
		first, second = second, first
	}
	// Keep both attempts inside the existing nameserver/request deadline.
	deadline, _ := ctx.Deadline()
	firstCtx, cancel := context.WithTimeout(ctx, time.Until(deadline)/2)
	first.ExchangeAsync(firstCtx, query, func(response *mDNS.Msg, err error) {
		cancel()
		if err == nil || ctx.Err() != nil {
			callback(response, err)
			return
		}
		second.ExchangeAsync(ctx, query, func(response *mDNS.Msg, err error) {
			if err == nil {
				s.preferAlternate.CompareAndSwap(alternateFirst, !alternateFirst)
			}
			callback(response, err)
		})
	})
}

func (t *Transport) serverSetFor(systemConfig *systemconfig.Config) (*localServerSet, error) {
	serverSet := t.serverSet.Load()
	if serverSet != nil && serverSet.config == systemConfig {
		return serverSet, nil
	}
	t.serverSetAccess.Lock()
	defer t.serverSetAccess.Unlock()
	serverSet = t.serverSet.Load()
	if serverSet != nil && serverSet.config == systemConfig {
		return serverSet, nil
	}
	serverScope := adapter.NewScope(t.ctx, t.logger)
	transports := make([]*localNameServer, 0, len(systemConfig.Servers))
	for _, serverAddr := range systemConfig.Servers {
		var serverTransport adapter.DNSTransport
		if systemConfig.UseTCP {
			serverTransport = transport.NewTCPRaw(dns.NewTransportAdapter(C.DNSTypeTCP, "", nil), t.dialer, serverAddr)
		} else {
			serverTransport = transport.NewUDPRaw(t.logger, dns.NewTransportAdapter(C.DNSTypeUDP, "", nil), t.dialer, serverAddr)
		}
		err := serverTransport.Start(adapter.StartStateStart, serverScope)
		if err != nil {
			return nil, E.Errors(E.Cause(err, "initialize transport for ", serverAddr), serverScope.Close())
		}
		server := &localNameServer{primary: serverTransport}
		if C.IsWindows && !systemConfig.UseTCP {
			server.alternate = transport.NewTCPRaw(dns.NewTransportAdapter(C.DNSTypeTCP, "", nil), t.dialer, serverAddr)
			if err = server.alternate.Start(adapter.StartStateStart, serverScope); err != nil {
				return nil, E.Errors(E.Cause(err, "initialize TCP for ", serverAddr), serverScope.Close())
			}
		}
		transports = append(transports, server)
	}
	newServerSet := &localServerSet{
		config:      systemConfig,
		transports:  transports,
		serverScope: serverScope,
	}
	oldServerSet := t.serverSet.Swap(newServerSet)
	if oldServerSet != nil {
		oldServerSet.serverScope.Close()
	}
	return newServerSet, nil
}

func (t *Transport) exchangeAsync(ctx context.Context, message *mDNS.Msg, systemConfig *systemconfig.Config, domain string, callback func(response *mDNS.Msg, err error)) {
	serverSet, err := t.serverSetFor(systemConfig)
	if err != nil {
		callback(nil, err)
		return
	}
	names := systemConfig.NameList(domain)
	if len(names) == 0 {
		callback(nil, E.New("invalid domain: ", domain))
		return
	}
	transport.ExchangeNames(ctx, names, message.Question[0], func(fqdn string) transport.AsyncExchanger {
		return newNameExchanger(systemConfig, serverSet, message, fqdn)
	}, callback)
}

func newNameExchanger(systemConfig *systemconfig.Config, serverSet *localServerSet, message *mDNS.Msg, fqdn string) transport.AsyncExchanger {
	serverOffset := systemConfig.ServerOffset()
	serverCount := uint32(len(serverSet.transports))
	attemptExchangers := make([]transport.AsyncExchanger, 0, systemConfig.Attempts*int(serverCount))
	for i := 0; i < systemConfig.Attempts; i++ {
		for j := range serverCount {
			serverTransport := serverSet.transports[(serverOffset+j)%serverCount]
			attemptExchangers = append(attemptExchangers, func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
				attemptCtx, cancel := context.WithTimeout(ctx, systemConfig.Timeout)
				serverTransport.exchange(attemptCtx, transport.NewFanOutRequest(message, fqdn, systemConfig.TrustAD), func(response *mDNS.Msg, err error) {
					cancel()
					callback(response, err)
				})
			})
		}
	}
	return func(ctx context.Context, callback func(response *mDNS.Msg, err error)) {
		transport.ExchangeSequential(ctx, attemptExchangers, nil, func(response *mDNS.Msg, err error) {
			if err != nil {
				err = E.Cause(err, fqdn)
			}
			callback(response, err)
		})
	}
}

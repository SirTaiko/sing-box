package option

import (
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/json/badoption"
)

type SocksInboundOptions struct {
	ListenOptions
	Users          []auth.User           `json:"users,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
	// NoResolve refuses every CONNECT request whose original wire form is a
	// domain name before route rules, sniffing or DNS are consulted. Literal
	// IPv4/IPv6 destinations keep working. The SOCKS5 reply is the existing
	// ruleset-denied code 2.
	NoResolve bool `json:"no_resolve,omitempty"`
	// ResolverConcurrency bounds how many SOCKS destination lookups may run
	// at the same time through the existing DNS router. Additional lookups
	// wait in a queue bounded by tcp_max_connections (10000 when absent).
	// Absent keeps the previous behavior: the inbound performs no lookup.
	ResolverConcurrency *uint16 `json:"resolver_concurrency,omitempty"`
}

type HTTPMixedInboundOptions struct {
	ListenOptions
	Users          []auth.User           `json:"users,omitempty"`
	DomainResolver *DomainResolveOptions `json:"domain_resolver,omitempty"`
	SetSystemProxy bool                  `json:"set_system_proxy,omitempty"`
	InboundTLSOptionsContainer
}

type SOCKSOutboundOptions struct {
	DialerOptions
	ServerOptions
	Version    string             `json:"version,omitempty" enum:"4,4a,5"`
	Username   string             `json:"username,omitempty"`
	Password   string             `json:"password,omitempty"`
	Network    NetworkList        `json:"network,omitempty"`
	UDPOverTCP *UDPOverTCPOptions `json:"udp_over_tcp,omitempty"`
}

type HTTPOutboundOptions struct {
	DialerOptions
	ServerOptions
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	OutboundTLSOptionsContainer
	Path    string               `json:"path,omitempty"`
	Headers badoption.HTTPHeader `json:"headers,omitempty"`
}

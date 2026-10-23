package listener

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
)

// tcpBindPollInterval is the source resolution granularity (tpws polls once
// per second).
const tcpBindPollInterval = time.Second

// TCPBindInterfaceSource supplies one interface snapshot per poll. The
// production implementation enumerates the current network namespace; tests
// inject a deterministic snapshot. It is deliberately narrow: the resolver
// does not register callbacks or own a background watcher.
type TCPBindInterfaceSource interface {
	Interfaces() []control.Interface
}

// TCPBindClock abstracts the timer used by the startup waits so the exact
// grace and deadline transitions are testable without sleeping.
type TCPBindClock interface {
	Now() time.Time
	Wait(ctx context.Context, duration time.Duration) error
}

// ResolvedTCPBinding is one selected listen endpoint. Address carries the
// interface name as its zone for a link-local IPv6 address; Interface is the
// actual interface fact for interface-selected addresses and the configured
// scope for an explicit address.
type ResolvedTCPBinding struct {
	Address   netip.Addr
	Interface string
	IPVersion int
}

type networkInterfaceSource struct{}

func (networkInterfaceSource) Interfaces() []control.Interface {
	netInterfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	interfaces := make([]control.Interface, 0, len(netInterfaces))
	for _, netInterface := range netInterfaces {
		interfaces = append(interfaces, control.InterfaceFromNetAddrs(netInterface, nil))
		var addresses []netip.Prefix
		netAddresses, addressErr := netInterface.Addrs()
		if addressErr != nil {
			continue
		}
		for _, netAddress := range netAddresses {
			prefix, parseErr := netip.ParsePrefix(netAddress.String())
			if parseErr != nil {
				continue
			}
			addresses = append(addresses, prefix)
		}
		interfaces[len(interfaces)-1].Addresses = addresses
	}
	return interfaces
}

// NewTCPBindInterfaceSource returns the production snapshot source. A
// configured network-manager finder is preferred so the resolver observes the
// same interfaces as the rest of the core; nil falls back to the local
// namespace enumeration.
func NewTCPBindInterfaceSource(finder control.InterfaceFinder) TCPBindInterfaceSource {
	if finder != nil {
		return finder
	}
	return networkInterfaceSource{}
}

type realTCPBindClock struct{}

func (realTCPBindClock) Now() time.Time {
	return time.Now()
}

func (realTCPBindClock) Wait(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// DefaultTCPBindClock returns the wall-clock implementation.
func DefaultTCPBindClock() TCPBindClock {
	return realTCPBindClock{}
}

// ResolveTCPBindings resolves every configured binding to one endpoint using
// the accepted ranking and wait rules. It never binds a socket and never
// starts a listener; the bind-wait tool and the listener startup share it.
func ResolveTCPBindings(ctx context.Context, bindings []option.TCPListenBinding, source TCPBindInterfaceSource, clock TCPBindClock) ([]ResolvedTCPBinding, error) {
	if err := option.ValidateTCPListenBindings(bindings); err != nil {
		return nil, err
	}
	if source == nil {
		source = networkInterfaceSource{}
	}
	if clock == nil {
		clock = realTCPBindClock{}
	}
	resolved := make([]ResolvedTCPBinding, 0, len(bindings))
	for index := range bindings {
		binding, err := resolveTCPBinding(ctx, index, bindings[index], source, clock)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, binding)
	}
	return resolved, nil
}

func resolveTCPBinding(ctx context.Context, index int, binding option.TCPListenBinding, source TCPBindInterfaceSource, clock TCPBindClock) (ResolvedTCPBinding, error) {
	if err := ctx.Err(); err != nil {
		return ResolvedTCPBinding{}, err
	}
	linkLocal, err := binding.LinkLocal.Build()
	if err != nil {
		return ResolvedTCPBinding{}, E.Cause(err, "tcp_listen_bindings[", index, "]")
	}
	// wait_ifup precedes both the explicit-address zone resolution and the
	// independent address budget (tpws.c:1917-1941).
	if binding.WaitIfUp > 0 {
		ifupDeadline := clock.Now().Add(time.Duration(binding.WaitIfUp))
		for {
			if interfaceIsUp(source.Interfaces(), binding.Interface) {
				break
			}
			now := clock.Now()
			if !now.Before(ifupDeadline) {
				return ResolvedTCPBinding{}, E.New("tcp_listen_bindings[", index, "]: interface ", binding.Interface, " did not become up within ", time.Duration(binding.WaitIfUp))
			}
			if err = waitTCPBind(ctx, clock, now, ifupDeadline); err != nil {
				return ResolvedTCPBinding{}, E.Cause(err, "tcp_listen_bindings[", index, "]")
			}
		}
	}
	if binding.Address != nil {
		address, err := resolveExplicitListenAddress(binding, source)
		if err != nil {
			return ResolvedTCPBinding{}, E.Cause(err, "tcp_listen_bindings[", index, "]")
		}
		ipVersion := 6
		if address.Is4() {
			ipVersion = 4
		}
		return ResolvedTCPBinding{
			Address:   address,
			Interface: binding.Interface,
			IPVersion: ipVersion,
		}, nil
	}
	// The link-local grace starts after the independent ifup wait, matching
	// the source's sec counter which resets for the address loop.
	graceStart := clock.Now()
	ipDeadline := graceStart.Add(time.Duration(binding.WaitIP))
	grace := time.Duration(binding.WaitIPLinkLocal)
	for {
		now := clock.Now()
		effective := linkLocal
		if now.Sub(graceStart) < grace {
			switch linkLocal {
			case option.TCPListenLinkLocalPrefer:
				effective = option.TCPListenLinkLocalForce
			case option.TCPListenLinkLocalUnwanted:
				effective = option.TCPListenLinkLocalNo
			}
		}
		if selected, found := selectListenAddress(source.Interfaces(), binding.Interface, binding.IPVersion, effective); found {
			return ResolvedTCPBinding{
				Address:   selected.address,
				Interface: selected.interfaceName,
				IPVersion: binding.IPVersion,
			}, nil
		}
		now = clock.Now()
		if !now.Before(ipDeadline) {
			return ResolvedTCPBinding{}, E.New("tcp_listen_bindings[", index, "]: no suitable IPv", binding.IPVersion, " address found on ", binding.Interface, " within ", time.Duration(binding.WaitIP))
		}
		if err = waitTCPBind(ctx, clock, now, ipDeadline); err != nil {
			return ResolvedTCPBinding{}, E.Cause(err, "tcp_listen_bindings[", index, "]")
		}
	}
}

func waitTCPBind(ctx context.Context, clock TCPBindClock, now time.Time, deadline time.Time) error {
	wait := tcpBindPollInterval
	if remaining := deadline.Sub(now); remaining < wait {
		wait = remaining
	}
	if wait <= 0 {
		return nil
	}
	return clock.Wait(ctx, wait)
}

func interfaceIsUp(interfaces []control.Interface, name string) bool {
	for _, networkInterface := range interfaces {
		if networkInterface.Name != name {
			continue
		}
		return networkInterface.Flags&net.FlagUp != 0
	}
	return false
}

func resolveExplicitListenAddress(binding option.TCPListenBinding, source TCPBindInterfaceSource) (netip.Addr, error) {
	address := binding.Address.Build(netip.Addr{})
	if !address.Is6() || !address.IsLinkLocalUnicast() {
		return address, nil
	}
	zone := address.Zone()
	if zone == "" {
		if binding.Interface == "" {
			return netip.Addr{}, E.New("link-local address ", address, " requires a zone or interface")
		}
		zone = binding.Interface
	}
	if !zoneResolvable(source.Interfaces(), zone) {
		return netip.Addr{}, E.New("link-local address ", address, " zone ", zone, " does not resolve to an interface")
	}
	return address.WithZone(zone), nil
}

func zoneResolvable(interfaces []control.Interface, zone string) bool {
	for _, networkInterface := range interfaces {
		if networkInterface.Name == zone {
			return true
		}
		if strconv.Itoa(networkInterface.Index) == zone {
			return true
		}
	}
	return false
}

type listenAddressCandidate struct {
	address       netip.Addr
	interfaceName string
}

// selectListenAddress applies the source pass order exactly:
//
//	force:    link-local
//	prefer:   link-local, ULA, any
//	no:       ULA, non-link-local
//	unwanted: ULA, non-link-local, any
//
// Enumeration order is preserved within one rank and IPv4 interface
// selection takes the first address of that interface.
func selectListenAddress(interfaces []control.Interface, interfaceName string, ipVersion int, linkLocal option.TCPListenLinkLocal) (listenAddressCandidate, bool) {
	var candidates []listenAddressCandidate
	for _, networkInterface := range interfaces {
		if interfaceName != "" && networkInterface.Name != interfaceName {
			continue
		}
		for _, prefix := range networkInterface.Addresses {
			address := prefix.Addr()
			if ipVersion == 4 {
				if !address.Is4() {
					continue
				}
			} else {
				if !address.Is6() || address.Is4In6() {
					continue
				}
			}
			candidates = append(candidates, listenAddressCandidate{address: address, interfaceName: networkInterface.Name})
		}
	}
	if len(candidates) == 0 {
		return listenAddressCandidate{}, false
	}
	if ipVersion == 4 {
		return candidates[0], true
	}
	for _, accept := range ipv6RankPasses(linkLocal) {
		for _, candidate := range candidates {
			if accept(candidate.address) {
				return candidate.withZone(), true
			}
		}
	}
	return listenAddressCandidate{}, false
}

func (c listenAddressCandidate) withZone() listenAddressCandidate {
	if c.address.Is6() && c.address.IsLinkLocalUnicast() && c.address.Zone() == "" && c.interfaceName != "" {
		c.address = c.address.WithZone(c.interfaceName)
	}
	return c
}

func ipv6RankPasses(linkLocal option.TCPListenLinkLocal) []func(netip.Addr) bool {
	isLinkLocal := func(address netip.Addr) bool {
		return address.IsLinkLocalUnicast()
	}
	isULA := func(address netip.Addr) bool {
		return address.IsPrivate()
	}
	isNotLinkLocal := func(address netip.Addr) bool {
		return !address.IsLinkLocalUnicast()
	}
	anyAddress := func(address netip.Addr) bool {
		return true
	}
	switch linkLocal {
	case option.TCPListenLinkLocalForce:
		return []func(netip.Addr) bool{isLinkLocal}
	case option.TCPListenLinkLocalPrefer:
		return []func(netip.Addr) bool{isLinkLocal, isULA, anyAddress}
	case option.TCPListenLinkLocalNo:
		return []func(netip.Addr) bool{isULA, isNotLinkLocal}
	default:
		return []func(netip.Addr) bool{isULA, isNotLinkLocal, anyAddress}
	}
}

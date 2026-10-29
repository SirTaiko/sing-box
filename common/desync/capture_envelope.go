package desync

import (
	"fmt"

	"github.com/sagernet/sing-box/common/windivert"
)

// ownedWindowsEnvelope is the single owned-envelope builder shared by the plain
// capture path (windowsFilter) and the configured capture.windows path
// (windowsCaptureConfig.envelope). One builder means the two paths cannot drift
// on the address, port, family, protocol, direction or interface dimensions.
//
// The default no-bind case (an unspecified local address such as 0.0.0.0 or ::)
// removes only the local-address equality: the attempt's exclusive local port,
// family, protocol, direction, peer and interface facts stay mandatory. That is
// the whole point of W1 — a filter comparing a packet's source against 0.0.0.0
// never matches a real flow, while a concrete local address remains an
// equality restriction.
func ownedWindowsEnvelope(endpoint Endpoint, outbound bool) (*windivert.Filter, error) {
	switch endpoint.Transport {
	case TransportTCP, TransportUDP:
	default:
		return nil, fmt.Errorf("desync: capture envelope: unsupported transport")
	}
	if !endpoint.Source.IsValid() || endpoint.Source.Port() == 0 {
		return nil, fmt.Errorf("desync: capture requires an owned local endpoint")
	}
	if !outbound && !endpoint.Destination.IsValid() {
		return nil, fmt.Errorf("desync: inbound listener capture needs a peer")
	}
	ipv6 := endpoint.Family == FamilyIPv6
	// The bound address, when concrete, is a native fact from getsockname: it
	// must agree with the attempt's family instead of silently picking one.
	if local := endpoint.Source.Addr().Unmap(); local.IsValid() && !local.IsUnspecified() {
		if local.Is6() != ipv6 {
			return nil, fmt.Errorf("desync: capture envelope: bound local address family does not match the owned attempt")
		}
	}
	if peer := endpoint.Destination; peer.IsValid() && peer.Addr().Unmap().Is6() != ipv6 {
		return nil, fmt.Errorf("desync: capture envelope: peer address family does not match the owned attempt")
	}
	return windivert.OwnedFlowEnvelope(windivert.OwnedFlow{
		IPv6:           ipv6,
		TCP:            endpoint.Transport == TransportTCP,
		Outbound:       outbound,
		Local:          endpoint.Source,
		Peer:           endpoint.Destination,
		InterfaceIndex: endpoint.InterfaceIndex,
	})
}

// windowsFilter is the plain (unconfigured) capture path's filter builder. It is
// deliberately a thin alias of the shared owned envelope so the plain and
// configured paths cannot diverge. It lives with the shared builder rather than
// in the Windows-only backend file so the shared-builder property stays testable
// on every platform.
func windowsFilter(endpoint Endpoint, outbound bool) (*windivert.Filter, error) {
	return ownedWindowsEnvelope(endpoint, outbound)
}

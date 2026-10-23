package dialer

import (
	"net/netip"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// buildTCPOptions validates the reusable shared TCP socket object for this
// dialer. Absent options keep the exact previous behavior.
func buildTCPOptions(options option.AbstractDialerOptions) (option.TCPOptions, error) {
	if options.TCPSocketOptions == nil {
		return option.TCPOptions{}, nil
	}
	tcpOptions, err := options.TCPSocketOptions.Build()
	if err != nil {
		return option.TCPOptions{}, E.Cause(err, "outbound tcp_socket_options")
	}
	return tcpOptions, nil
}

// resolveBindZone keeps the IPv6 zone of a scoped source bind address instead
// of silently producing a scope 0 sockaddr. A link-local source without a
// zone and without a bind interface is a configuration error.
func resolveBindZone(address netip.Addr, bindInterface string) (netip.Addr, error) {
	if !address.Is6() || !address.IsLinkLocalUnicast() || address.Zone() != "" {
		return address, nil
	}
	if bindInterface != "" {
		return address.WithZone(bindInterface), nil
	}
	return netip.Addr{}, E.New("inet6_bind_address ", address, " is link-local and has no zone; configure %<interface> or bind_interface")
}

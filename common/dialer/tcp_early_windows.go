//go:build windows

package dialer

import (
	"context"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// dialAttemptPayload performs the owned deferred first-payload attempt on
// Windows through the existing ConnectEx helper, extended with the selected
// initial buffer. The helper owns socket creation, the TFO socket option, the
// single exclusive bind, the lease preparation, the ConnectEx call with the
// initial data, and adoption through the public net.FileConn path.
func dialAttemptPayload(ctx context.Context, base net.Dialer, network, address string, payload []byte, lease AttemptLease) (net.Conn, int, error) {
	if N.NetworkName(network) != N.NetworkTCP {
		return nil, 0, E.New("desync: deferred TFO supports TCP only")
	}
	return dialConnectEx(ctx, base, network, address, lease, payload)
}

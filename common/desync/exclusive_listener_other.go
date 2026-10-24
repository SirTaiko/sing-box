//go:build !windows

package desync

import "github.com/sagernet/sing/common/control"

// PacketUDPListenerControl returns nil outside Windows, so disabled and
// stream-only configurations and the enabled packet path all keep their
// existing listener controls unchanged.
//
// On the supported Linux native path an unconnected UDP socket that never set
// SO_REUSEADDR/SO_REUSEPORT already owns its local endpoint exclusively: the
// kernel refuses a second bind of the same unicast endpoint. The per-socket
// exclusive option this returns on Windows has no Linux counterpart because the
// sharing there requires both sockets to opt in, which the owned packet socket
// never does.
func PacketUDPListenerControl() control.Func { return nil }

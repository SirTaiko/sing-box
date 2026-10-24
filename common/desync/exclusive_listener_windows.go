//go:build windows

package desync

import (
	"fmt"
	"syscall"

	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/windows"
)

// soExclusiveAddrUse is Winsock's SO_EXCLUSIVEADDRUSE, which winsock2.h defines
// as (int)(~SO_REUSEADDR). x/sys/windows does not export it.
const soExclusiveAddrUse = ^windows.SO_REUSEADDR

// setExclusiveUDPBind claims the socket's eventual local endpoint exclusively.
// Winsock applies SO_EXCLUSIVEADDRUSE only before bind, so every owned packet
// UDP socket must call this on its unbound handle: the connected attempt in
// bindExclusiveUDPAddress and, for listeners, the dialer control below.
func setExclusiveUDPBind(handle windows.Handle) error {
	if err := windows.SetsockoptInt(handle, windows.SOL_SOCKET, soExclusiveAddrUse, 1); err != nil {
		return fmt.Errorf("desync: setsockopt(SO_EXCLUSIVEADDRUSE): %w", err)
	}
	return nil
}

// PacketUDPListenerControl returns the per-socket control that claims an owned
// packet-desync UDP listener endpoint exclusively before the kernel binds it.
//
// Packet capture identifies a flow by its local endpoint; it cannot distinguish
// two sockets that share one endpoint. On Windows a socket bound without
// SO_EXCLUSIVEADDRUSE can be joined by a second socket that sets SO_REUSEADDR,
// so the datagrams of that sibling would fall inside this outbound's capture
// envelope. The control runs before bind because that is the only point where
// Winsock accepts the option, and a failed option fails the bind instead of
// publishing an endpoint this outbound does not exclusively own.
//
// The returned control is installed only for enabled packet desync; disabled
// and stream-only configurations keep their ordinary listener controls.
func PacketUDPListenerControl() control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		if N.NetworkName(network) != N.NetworkUDP {
			return nil
		}
		var optionErr error
		if controlErr := conn.Control(func(fd uintptr) {
			optionErr = setExclusiveUDPBind(windows.Handle(fd))
		}); controlErr != nil {
			return controlErr
		}
		return optionErr
	}
}

//go:build !windows

package dialer

import (
	"context"
	"net"
	"syscall"

	"github.com/sagernet/sing/common/control"
)

// dialAttempt establishes the exclusive local port and capture ownership from
// the last-chance Control hook, which runs after every existing interface,
// mark and namespace control and before connect/send. For leases that own the
// bind (packet capture) the call-local dialer copy clears LocalAddr so the
// requested bind is performed exactly once, by the lease; stream-only leases
// keep the ordinary dialer bind path. On Windows TCP this path is replaced by
// the native ConnectEx helper; see attempt_windows.go.
func dialAttempt(ctx context.Context, base net.Dialer, network, address string, lease AttemptLease) (net.Conn, error) {
	perAttempt := base
	if lease.RequiresExclusiveBind() {
		perAttempt.LocalAddr = nil
	}
	perAttempt.Control = control.Append(perAttempt.Control, func(network, address string, rawConn syscall.RawConn) error {
		var prepareErr error
		if controlErr := rawConn.Control(func(fd uintptr) {
			prepareErr = lease.PrepareSocket(fd)
		}); controlErr != nil {
			return controlErr
		}
		return prepareErr
	})
	return perAttempt.DialContext(ctx, network, address)
}

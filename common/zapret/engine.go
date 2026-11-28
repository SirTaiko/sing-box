package zapret

import (
	"context"
	"syscall"
	"time"
)

type platformOptions struct {
	tag              string
	profile          *profile
	bindInterface    string
	interfaceIndex   int
	reservationPorts uint16
	startupTimeout   time.Duration
	stopTimeout      time.Duration
	logger           Logger
}

// platformEngine owns the OS-specific socket reservation and original engine
// process. Start must acquire the reservations before the child is spawned and
// report success only after the child reported post-Lua readiness.
type platformEngine interface {
	Start(ctx context.Context) error
	Control(network string, address string, conn syscall.RawConn) error
	Exited() <-chan error
	Close() error
}

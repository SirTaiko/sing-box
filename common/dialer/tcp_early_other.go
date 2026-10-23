//go:build !linux && !windows

package dialer

import (
	"context"
	"net"

	E "github.com/sagernet/sing/common/exceptions"
)

// dialAttemptPayload reports that the owned deferred TFO path has no native
// implementation on this platform. The console deliverable targets Linux and
// Windows; other platforms keep the ordinary eager TFO path and the desync
// stream/packet paths. An unavailable native capability is an actionable
// error, never a silent plaintext switch.
func dialAttemptPayload(_ context.Context, _ net.Dialer, _ string, _ string, _ []byte, _ AttemptLease) (net.Conn, int, error) {
	return nil, 0, E.New("desync: owned deferred tcp_fast_open is supported on Linux and Windows only")
}

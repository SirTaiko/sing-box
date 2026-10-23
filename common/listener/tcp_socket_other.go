//go:build !windows && !linux

package listener

import (
	E "github.com/sagernet/sing/common/exceptions"
)

// setUserTimeoutMillis is unreachable in a valid configuration:
// option.TCPSocketOptions.Build rejects a positive user_timeout outside
// Linux. The explicit error prevents a silent no-op if a future caller
// bypasses validation.
func setUserTimeoutMillis(fd uintptr, millis int) error {
	return E.New("TCP_USER_TIMEOUT is only supported on Linux")
}

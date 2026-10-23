//go:build windows

package listener

import (
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	socketOptionReceiveBuffer = windows.SO_RCVBUF
	socketOptionSendBuffer    = windows.SO_SNDBUF
)

func setSocketBuffer(fd uintptr, option int, value int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, option, value)
}

func getSocketBuffer(fd uintptr, option int) (int, error) {
	return windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, option)
}

// setUserTimeoutMillis is unreachable in a valid configuration: option
// validation rejects a positive user_timeout on Windows as source
// inapplicable. Keeping the explicit error here prevents a future caller from
// silently emulating TCP_USER_TIMEOUT with a deadline.
func setUserTimeoutMillis(fd uintptr, millis int) error {
	return E.New("TCP_USER_TIMEOUT is not supported on Windows")
}

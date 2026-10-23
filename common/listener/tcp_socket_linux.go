//go:build linux

package listener

import (
	"golang.org/x/sys/unix"
)

func setUserTimeoutMillis(fd uintptr, millis int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, millis)
}

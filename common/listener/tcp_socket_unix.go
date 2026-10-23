//go:build !windows

package listener

import (
	"golang.org/x/sys/unix"
)

const (
	socketOptionReceiveBuffer = unix.SO_RCVBUF
	socketOptionSendBuffer    = unix.SO_SNDBUF
)

func setSocketBuffer(fd uintptr, option int, value int) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, value)
}

func getSocketBuffer(fd uintptr, option int) (int, error) {
	return unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, option)
}

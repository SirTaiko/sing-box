//go:build !linux

package tlsdesync

import (
	"fmt"
	"net"
)

const Supported = false

func NewConn(conn net.Conn, options Options) (net.Conn, error) {
	return nil, fmt.Errorf("tls_desync requires Linux")
}

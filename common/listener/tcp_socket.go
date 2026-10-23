package listener

import (
	"net"
	"syscall"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
)

// The platform syscall entrypoints are package variables so the option call
// order, halving and failure paths can be exercised hermetically, without a
// live host listener or socket.
var (
	tcpSetSocketBuffer = setSocketBuffer
	tcpGetSocketBuffer = getSocketBuffer
	tcpSetUserTimeout  = setUserTimeoutMillis
)

// tcpSocketControl returns a socket Control hook that applies the validated
// TCP socket options to a not-yet-bound TCP socket. It is a no-op for UDP
// sockets, so the same dialer/listener control chain is safe for families that
// carry the control but do not use TCP.
func TCPControl(options option.TCPOptions) control.Func {
	if options.Empty() {
		return nil
	}
	return func(network, address string, conn syscall.RawConn) error {
		if N.NetworkName(network) != N.NetworkTCP {
			return nil
		}
		var applyErr error
		if controlErr := conn.Control(func(fd uintptr) {
			applyErr = applyTCPSocketOptions(fd, options)
		}); controlErr != nil {
			return controlErr
		}
		return applyErr
	}
}

// applyTCPSocketOptions sets the buffers and the user timeout in the source
// order (receive buffer, send buffer, then TCP user timeout). It runs before
// bind on a listening socket and before connect on a dialing socket.
func applyTCPSocketOptions(fd uintptr, options option.TCPOptions) error {
	if options.ReceiveBufferSize > 0 {
		err := tcpSetSocketBuffer(fd, socketOptionReceiveBuffer, options.ReceiveBufferSize)
		if err != nil {
			return E.Cause(err, "set receive buffer size")
		}
	}
	if options.SendBufferSize > 0 {
		err := tcpSetSocketBuffer(fd, socketOptionSendBuffer, options.SendBufferSize)
		if err != nil {
			return E.Cause(err, "set send buffer size")
		}
	}
	if options.UserTimeoutMillis > 0 {
		err := tcpSetUserTimeout(fd, options.UserTimeoutMillis)
		if err != nil {
			return E.Cause(err, "set TCP user timeout")
		}
	}
	return nil
}

// ensureAcceptedTCPSocketOptions verifies the socket-buffer values inherited
// from the listening socket and re-applies a value that the platform did not
// inherit, then applies the local TCP user timeout after accept (it is not a
// listen-socket inheritance control). It never changes options that are not
// configured.
func ensureAcceptedTCPSocketOptions(conn net.Conn, options option.TCPOptions) error {
	if options.Empty() {
		return nil
	}
	syscallConn, isSyscallConn := conn.(syscall.Conn)
	if !isSyscallConn {
		return E.New("accepted TCP connection does not expose a native socket")
	}
	rawConn, err := syscallConn.SyscallConn()
	if err != nil {
		return E.Cause(err, "accepted TCP connection raw control")
	}
	var applyErr error
	if controlErr := rawConn.Control(func(fd uintptr) {
		applyErr = ensureAcceptedTCPSocketOptionsFD(fd, options)
	}); controlErr != nil {
		return controlErr
	}
	return applyErr
}

func ensureAcceptedTCPSocketOptionsFD(fd uintptr, options option.TCPOptions) error {
	if options.ReceiveBufferSize > 0 {
		err := inheritOrSetSocketBuffer(fd, socketOptionReceiveBuffer, options.ReceiveBufferSize)
		if err != nil {
			return E.Cause(err, "verify inherited receive buffer size")
		}
	}
	if options.SendBufferSize > 0 {
		err := inheritOrSetSocketBuffer(fd, socketOptionSendBuffer, options.SendBufferSize)
		if err != nil {
			return E.Cause(err, "verify inherited send buffer size")
		}
	}
	if options.UserTimeoutMillis > 0 {
		err := tcpSetUserTimeout(fd, options.UserTimeoutMillis)
		if err != nil {
			return E.Cause(err, "set local TCP user timeout")
		}
	}
	return nil
}

func inheritOrSetSocketBuffer(fd uintptr, option int, requested int) error {
	effective, err := tcpGetSocketBuffer(fd, option)
	if err == nil && effective >= requested {
		return nil
	}
	return tcpSetSocketBuffer(fd, option, requested)
}

// ApplyTCPSocketOptionsFD applies validated remote TCP socket controls to one
// native TCP socket. It is used by the dialer package through its socket
// control hook; callers must not pass UDP sockets.
func ApplyTCPSocketOptionsFD(fd uintptr, options option.TCPOptions) error {
	return applyTCPSocketOptions(fd, options)
}

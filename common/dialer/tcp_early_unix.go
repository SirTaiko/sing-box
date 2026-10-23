//go:build linux

package dialer

import (
	"context"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

// firstPayloadAbortDeadline is a non-zero time in the past: it is installed only
// to interrupt an in-flight first write when the attempt context is canceled.
var firstPayloadAbortDeadline = time.Unix(0, 0)

// dialAttemptPayload performs the owned deferred first-payload attempt. Order
// on the actual socket: existing interface/mark/namespace/protect controls, the
// call-local TCP_FASTOPEN_CONNECT control, the lease's exclusive bind and
// capture registration, then connect. The first payload is written only after
// every control ran, so no SYN (with or without data) can precede capture
// ownership.
//
// This is the tfo-go v2.3.2 TCP_FASTOPEN_CONNECT algorithm without the vendored
// internal fallback: the socket option is applied by a call-local control and
// the data is written from this call. There is no second socket and no internal
// retry under one lease; an unsupported kernel is an actionable error instead of
// a silent plaintext switch.
func dialAttemptPayload(ctx context.Context, base net.Dialer, network, address string, payload []byte, lease AttemptLease) (net.Conn, int, error) {
	perAttempt := base
	if lease.RequiresExclusiveBind() {
		// The lease binds the requested source itself, inside PrepareSocket,
		// after the TFO option is set. Clearing LocalAddr prevents a second
		// bind of the same tuple on this descriptor.
		perAttempt.LocalAddr = nil
	}
	perAttempt.Control = control.Append(perAttempt.Control, func(network, address string, rawConn syscall.RawConn) error {
		var optionErr error
		if controlErr := rawConn.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
		}); controlErr != nil {
			return controlErr
		}
		if optionErr != nil {
			return E.Cause(optionErr, "desync: setsockopt(TCP_FASTOPEN_CONNECT)")
		}
		return nil
	})
	perAttempt.Control = control.Append(perAttempt.Control, func(network, address string, rawConn syscall.RawConn) error {
		var prepareErr error
		if controlErr := rawConn.Control(func(fd uintptr) {
			prepareErr = lease.PrepareSocket(fd)
		}); controlErr != nil {
			return controlErr
		}
		return prepareErr
	})
	conn, err := perAttempt.DialContext(ctx, network, address)
	if err != nil {
		return nil, 0, err
	}
	if len(payload) == 0 {
		// Explicit empty / server-first connect: no TFO data, one attempt.
		return conn, 0, nil
	}
	sent, err := writeFirstPayload(ctx, conn, payload)
	if err != nil {
		conn.Close()
		return nil, sent, err
	}
	return conn, sent, nil
}

// writeFirstPayload writes the transformed first segment on the freshly
// connected socket. With TCP_FASTOPEN_CONNECT the kernel emits it inside the
// SYN when a cookie is available and after the handshake otherwise. A canceled
// attempt interrupts the write through an immediate write deadline, matching
// tfo-go's cancellation handling; no byte is replayed by the caller.
func writeFirstPayload(ctx context.Context, conn net.Conn, payload []byte) (int, error) {
	var (
		written  int
		writeErr error
	)
	var once sync.Once
	stop := context.AfterFunc(ctx, func() {
		once.Do(func() {
			_ = conn.SetWriteDeadline(firstPayloadAbortDeadline)
		})
	})
	written, writeErr = conn.Write(payload)
	if !stop() && writeErr == nil {
		writeErr = ctx.Err()
	}
	if writeErr != nil {
		return written, writeErr
	}
	return written, nil
}

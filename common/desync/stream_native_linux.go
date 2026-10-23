//go:build linux

package desync

import (
	"encoding/binary"
	"net"
	"syscall"
	"time"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/sys/unix"
)

// Linux keeps the complete tpws native applicability: TCP_MAXSEG, TCP_CORK,
// TTL shaping, MSG_OOB and the TCP_INFO fix-seg wait (tpws_conn.c
// connect_remote/send_with_ttl/send_oob, helpers.c socket_*_notsent).

func platformStreamCaps() streamCapsInfo {
	return streamCapsInfo{
		mss:         true,
		fixSeg:      true,
		oob:         true,
		disorder:    true,
		oobDisorder: true,
		skipNoDelay: true,
	}
}

func newPlatformStreamNative() streamNative {
	return linuxStreamNative{}
}

type linuxStreamNative struct{}

func (linuxStreamNative) Prepare(fd uintptr, config streamSocketConfig) error {
	if config.skipNoDelay {
		err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 0)
		if err != nil {
			return E.Cause(err, "set TCP_NODELAY=0")
		}
	}
	if config.mss > 0 {
		err := unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, config.mss)
		if err != nil {
			return E.Cause(err, "set TCP_MAXSEG")
		}
	}
	return nil
}

func (linuxStreamNative) NewSender(conn net.Conn, _ func() time.Time) (streamSender, error) {
	// The factory resolves the socket of the already admitted attempt. It owns
	// no persistent completion event, so its admission reference covers only
	// construction; every submission takes its own operation reference.
	source, holder, release, err := acquireStreamNativeSource(conn)
	if err != nil {
		return nil, err
	}
	syscallConn, ok := source.(syscall.Conn)
	if !ok {
		release()
		return nil, E.New("desync: stream native send requires a syscall.Conn")
	}
	raw, err := syscallConn.SyscallConn()
	if err != nil {
		release()
		return nil, E.Cause(err, "obtain raw stream socket")
	}
	release()
	return &linuxSender{raw: raw, family: streamRemoteFamily(source), holder: holder}, nil
}

type linuxSender struct {
	raw    syscall.RawConn
	family int
	// holder is the admission capability of the already admitted attempt.
	// Each Send takes one operation reference before touching the socket and
	// releases it on the synchronous return; a refusal is returned instead of
	// falling back to plain I/O.
	holder nativeAdmissionHolder
}

func (s *linuxSender) Send(data []byte, options sendOptions) (int, error) {
	if s.holder == nil {
		return 0, E.New("desync: native stream send requires an admission owner")
	}
	release, err := s.holder.AcquireNativeHold()
	if err != nil {
		return 0, err
	}
	defer release()
	var (
		sent  int
		opErr error
	)
	callbackErr := s.raw.Write(func(fd uintptr) bool {
		sent, opErr = linuxSendSegment(int(fd), data, options, s.family)
		if opErr == unix.EAGAIN {
			return false
		}
		return true
	})
	if callbackErr != nil {
		return 0, callbackErr
	}
	if opErr != nil {
		return 0, opErr
	}
	return sent, nil
}

// linuxSendSegment performs one tpws send_with_ttl/send_oob call.
func linuxSendSegment(fd int, data []byte, options sendOptions, family int) (int, error) {
	ttlLevel, ttlOption, previousTTL, ttlChanged, err := prepareTTL(fd, options.ttl, family)
	if err != nil {
		return 0, err
	}
	if options.cork {
		// tpws corks around every tampered send unless --skip-nodelay.
		_ = unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_CORK, 1)
	}
	var sent int
	if options.oob {
		buffer := make([]byte, len(data)+1)
		copy(buffer, data)
		buffer[len(data)] = options.oobByte
		sent, err = unix.SendmsgN(fd, buffer, nil, nil, unix.MSG_OOB|unix.MSG_NOSIGNAL)
	} else {
		sent, err = unix.SendmsgN(fd, data, nil, nil, unix.MSG_NOSIGNAL)
	}
	if options.cork {
		_ = unix.SetsockoptInt(fd, unix.SOL_TCP, unix.TCP_CORK, 0)
	}
	if ttlChanged {
		_ = unix.SetsockoptInt(fd, ttlLevel, ttlOption, previousTTL)
	}
	return sent, err
}

func prepareTTL(fd int, ttl int, family int) (level int, option int, previous int, changed bool, err error) {
	if ttl == 0 {
		return 0, 0, 0, false, nil
	}
	tryLevel, tryOption := unix.IPPROTO_IP, unix.IP_TTL
	if family == 6 {
		tryLevel, tryOption = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	}
	previous, err = unix.GetsockoptInt(fd, tryLevel, tryOption)
	if err != nil {
		if tryLevel == unix.IPPROTO_IP {
			tryLevel, tryOption = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
		} else {
			tryLevel, tryOption = unix.IPPROTO_IP, unix.IP_TTL
		}
		previous, err = unix.GetsockoptInt(fd, tryLevel, tryOption)
		if err != nil {
			return 0, 0, 0, false, err
		}
	}
	level, option = tryLevel, tryOption
	err = unix.SetsockoptInt(fd, level, option, ttl)
	if err != nil {
		return 0, 0, 0, false, err
	}
	return level, option, previous, true, nil
}

// tcpInfoNotSentOffset is offsetof(struct tcp_info, tcpi_notsent_bytes) on
// Linux. A shorter getsockopt result means the kernel does not expose it.
const (
	tcpInfoNotSentOffset = 144
	tcpInfoEstablished   = 1
	tcpInfoBufferSize    = 256
)

func (s *linuxSender) WaitNotSent(timeout time.Duration) bool {
	notSent, ok := s.hasNotSent()
	if !ok || !notSent {
		return true
	}
	if timeout <= 0 {
		return false
	}
	tick := 10 * time.Millisecond
	waited := time.Duration(0)
	for {
		time.Sleep(tick)
		waited += tick
		notSent, ok = s.hasNotSent()
		if !ok || !notSent {
			return true
		}
		if waited >= timeout {
			return false
		}
	}
}

func (s *linuxSender) hasNotSent() (bool, bool) {
	var (
		notSent bool
		valid   bool
		opErr   error
	)
	callbackErr := s.raw.Control(func(fd uintptr) {
		notSent, valid, opErr = socketHasNotSent(int(fd))
	})
	if callbackErr != nil || opErr != nil {
		return false, false
	}
	return notSent, valid
}

func socketHasNotSent(fd int) (bool, bool, error) {
	buffer := make([]byte, tcpInfoBufferSize)
	size := uint32(len(buffer))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd),
		uintptr(unix.IPPROTO_TCP), uintptr(unix.TCP_INFO),
		uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return false, false, errno
	}
	if int(size) < tcpInfoNotSentOffset+4 || buffer[0] != tcpInfoEstablished {
		return false, false, nil
	}
	notSent := binary.NativeEndian.Uint32(buffer[tcpInfoNotSentOffset : tcpInfoNotSentOffset+4])
	return notSent != 0, true, nil
}

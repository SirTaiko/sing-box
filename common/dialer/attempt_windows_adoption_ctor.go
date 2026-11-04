//go:build windows && go1.26 && !go1.27

package dialer

import (
	"net"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	E "github.com/sagernet/sing/common/exceptions"
)

// The direct-owned adoption boundary references exactly five non-public Go
// symbols of a connected Windows socket's standard-library lifecycle. The
// accepted boundary is enumerated here and nowhere else; it is a source-qualified
// exception for the exact audited Go1.26.9 toolchain, not a permission derived
// from the blanket `-checklinkname=0` release linker flag.
//
// `*netFD` is deliberately represented only as a GC-visible unsafe.Pointer. The
// pointer argument/result representation is the one of the exact Go1.26.9
// windows/amd64 ABIInternal signatures below; the FD object itself is allocated
// by net.newFD with its real runtime type and GC layout. This package never
// dereferences it, never mirrors netFD/poll.FD/TCPConn layouts, never converts
// it through uintptr and never installs a finalizer of its own.
//
//go:linkname goNetNewFD net.newFD
func goNetNewFD(sysfd syscall.Handle, family, sotype int, network string) (unsafe.Pointer, error)

//go:linkname goNetFDInit net.(*netFD).init
func goNetFDInit(fd unsafe.Pointer) error

//go:linkname goNetFDSetAddr net.(*netFD).setAddr
func goNetFDSetAddr(fd unsafe.Pointer, local, remote net.Addr)

//go:linkname goNetFDClose net.(*netFD).Close
func goNetFDClose(fd unsafe.Pointer) error

//go:linkname goNetNewTCPConn net.newTCPConn
func goNetNewTCPConn(fd unsafe.Pointer, idle time.Duration, cfg net.KeepAliveConfig, preHook func(unsafe.Pointer), hook func(net.KeepAliveConfig)) *net.TCPConn

// defaultTCPKeepAliveIdle is net.defaultTCPKeepAliveIdle of the qualified
// toolchain (net/dial.go). net.newTCPConn applies it before the caller's own
// keepalive reassertion.
const defaultTCPKeepAliveIdle = 15 * time.Second

// newOwnedSocketConn consumes one readiness-verified carrier and returns a
// genuine *net.TCPConn in net.Conn. The caller never closes the carrier after
// this call: on success the netFD/TCPConn owns it, and on every error the
// bridge has already retired the raw descriptor or the unpublished netFD
// exactly once. Invalid sentinels 0/InvalidHandle are rejected before any
// native effect and are not closed.
func newOwnedSocketConn(carrier windows.Handle, deadline time.Time) (net.Conn, error) {
	if carrier == 0 || carrier == windows.InvalidHandle {
		return nil, E.New("desync: adoption carrier handle is invalid")
	}
	return bridgeOwnedCarrier(productionSocketAdoptionAPI(), carrier, deadline)
}

// productionSocketAdoptionAPI binds the bridge to the five qualified symbols.
// Every field has exactly one production implementation; tests substitute the
// whole API to exercise the same bridge routine without overlaying stdlib.
func productionSocketAdoptionAPI() socketAdoptionAPI {
	return socketAdoptionAPI{
		addresses: ownedCarrierAddresses,
		newFD:     goNetNewFD,
		initFD:    goNetFDInit,
		setAddr:   goNetFDSetAddr,
		tcpConn: func(fd unsafe.Pointer) net.Conn {
			conn := goNetNewTCPConn(fd, defaultTCPKeepAliveIdle, net.KeepAliveConfig{}, nil, nil)
			// The FD pointer must stay live until the last internal call that
			// may allocate: net.newTCPConn keeps it through the connection.
			runtime.KeepAlive(fd)
			return conn
		},
		closeFD: func(fd unsafe.Pointer) error {
			closeErr := goNetFDClose(fd)
			runtime.KeepAlive(fd)
			return closeErr
		},
	}
}

// ownedCarrierAddresses reads the connected context of the exact carrier that
// will be adopted. It never observes the original socket or a new duplicate.
// Only IPv4/IPv6 stream addresses are accepted, both sockaddr families must
// agree, and an IPv6 scope is preserved either by interface name or by the
// numeric zone id when no name exists.
func ownedCarrierAddresses(carrier windows.Handle) (int, *net.TCPAddr, *net.TCPAddr, error) {
	localSockaddr, err := windows.Getsockname(carrier)
	if err != nil {
		return 0, nil, nil, E.Cause(err, "desync: adopted carrier has no local address")
	}
	remoteSockaddr, err := windows.Getpeername(carrier)
	if err != nil {
		return 0, nil, nil, E.Cause(err, "desync: adopted carrier has no peer address")
	}
	local, localFamily, err := ownedCarrierTCPAddr(localSockaddr)
	if err != nil {
		return 0, nil, nil, err
	}
	remote, remoteFamily, err := ownedCarrierTCPAddr(remoteSockaddr)
	if err != nil {
		return 0, nil, nil, err
	}
	if localFamily != remoteFamily {
		return 0, nil, nil, E.New("desync: adopted carrier address families do not match")
	}
	return localFamily, local, remote, nil
}

// ownedCarrierTCPAddr converts one connected socket address to the public
// net.TCPAddr form. The family is taken from the concrete sockaddr type, so an
// unsupported or nil address is an error before net.newFD rather than a
// guessed family.
func ownedCarrierTCPAddr(sockaddr windows.Sockaddr) (*net.TCPAddr, int, error) {
	switch address := sockaddr.(type) {
	case *windows.SockaddrInet4:
		return &net.TCPAddr{
			IP:   net.IP(append([]byte(nil), address.Addr[:]...)),
			Port: address.Port,
		}, windows.AF_INET, nil
	case *windows.SockaddrInet6:
		tcpAddr := &net.TCPAddr{
			IP:   net.IP(append([]byte(nil), address.Addr[:]...)),
			Port: address.Port,
		}
		if address.ZoneId != 0 {
			if iface, ifaceErr := net.InterfaceByIndex(int(address.ZoneId)); ifaceErr == nil {
				tcpAddr.Zone = iface.Name
			} else {
				// Do not lose the scope when the interface has no name.
				tcpAddr.Zone = strconv.FormatUint(uint64(address.ZoneId), 10)
			}
		}
		return tcpAddr, windows.AF_INET6, nil
	default:
		return nil, 0, E.New("desync: adopted carrier reports an unsupported socket address")
	}
}

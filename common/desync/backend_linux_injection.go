//go:build linux

package desync

import (
	"fmt"
	"net/netip"

	"golang.org/x/sys/unix"
)

// This is an internal work quantum, not a limit on an accepted Batch. Larger
// plans are sent completely, in order, with no accumulating queue or copies.
const injectionChunkSize = 64

// inject keeps the single-packet adapter compatible with existing callers.
func (c *linuxCapture) inject(packet []byte) error {
	_, err := c.injectBatch([][]byte{packet})
	return err
}

// injectBatch serializes the whole synchronous callback. Each chunk owns one
// disposable namespace helper and one nonrecursive fork-read interval covering
// raw fd birth through Close. No raw fd survives a chunk or this callback.
func (c *linuxCapture) injectBatch(packets [][]byte) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}
	first, err := ParsePacket(packets[0])
	if err != nil {
		return 0, err
	}
	if err = ensureLinuxForkSafety(); err != nil {
		return 0, err
	}
	c.rawMu.Lock()
	defer c.rawMu.Unlock()
	type result struct {
		sent int
		err  error
	}
	sent := 0
	for sent < len(packets) {
		if sent != 0 {
			first, err = ParsePacket(packets[sent])
			if err != nil {
				return sent, err
			}
		}
		chunk := packets[sent : sent+min(injectionChunkSize, len(packets)-sent)]
		done := make(chan result)
		go func() {
			var r result
			r.err = withAnchorNamespace(c.owner.nsFD, func() error {
				return withForkReadToken(func() error {
					var sendErr error
					r.sent, sendErr = c.sendInjectedChunk(chunk, first)
					return sendErr
				})
			})
			// Restore/close origin and close raw fd precede the receipt. On
			// restore error the still-locked helper exits, never the caller.
			done <- r
		}()
		r := <-done
		sent += r.sent
		if r.err != nil {
			return sent, r.err
		}
	}
	return sent, nil
}

// Raw injection syscall seams keep the operation-scoped path testable without
// CAP_NET_RAW or changes to the calling thread's actual network namespace.
var (
	openInjectionSocket       = unix.Socket
	setInjectionSockoptInt    = unix.SetsockoptInt
	setInjectionSockoptString = unix.SetsockoptString
	bindInjectionSocket       = unix.Bind
	sendInjectionPacket       = unix.Sendto
	closeInjectionSocket      = unix.Close
)

// Capture/namespace identity is fixed by the enclosing callback. Config pointer
// identity conservatively splits runs even when a reload preserves settings.
// Zero mark, empty device and bind-fix off are values, not "keep old setting".
type injectionSocketKey struct {
	config   *Config
	family   Family
	mark     int
	device   string
	priority uint32
	bind     bool
	source   netip.Addr
}

func (c *linuxCapture) injectionKey(packet *Packet) injectionSocketKey {
	config := c.lease.engine.Config()
	c.lease.mu.Lock()
	mark, device := c.lease.socketMarkValue, c.lease.socketDeviceValue
	c.lease.mu.Unlock()
	key := injectionSocketKey{
		config: config, family: packet.Family,
		mark: injectionMark(mark, config.Capture), device: device,
		priority: c.anchor.tag, bind: bindSource(config.Capture, packet.Family),
	}
	if key.bind {
		key.source = packet.Src
	}
	return key
}

func (c *linuxCapture) sendInjectedChunk(packets [][]byte, first *Packet) (int, error) {
	fd := -1
	closeSocket := func() {
		if fd >= 0 {
			// Preserve the existing close-once/no-retry error policy. Clearing
			// the slot prevents a second Close of a reused numeric descriptor.
			_ = closeInjectionSocket(fd)
			fd = -1
		}
	}
	defer closeSocket()
	var previous injectionSocketKey
	var reusable bool
	for index, raw := range packets {
		parsed := first
		if index != 0 {
			var err error
			parsed, err = ParsePacket(raw)
			if err != nil {
				return index, err
			}
		}
		key := c.injectionKey(parsed)
		if fd < 0 || key != previous {
			closeSocket()
			var err error
			fd, reusable, err = openInjectedSocket(key)
			if err != nil {
				return index, err
			}
			previous = key
		}
		var destination unix.Sockaddr
		switch parsed.Family {
		case FamilyIPv4:
			destination = &unix.SockaddrInet4{Port: int(parsed.DstPort), Addr: parsed.Dst.As4()}
		case FamilyIPv6:
			// sin6_port is an IP protocol for raw IPv6. Transport ports stay
			// in the unmodified raw packet; zero selects the socket protocol.
			destination = &unix.SockaddrInet6{Addr: parsed.Dst.As16()}
		}
		if err := sendInjectionPacket(fd, raw, 0, destination); err != nil {
			return index, err
		}
		c.lease.noteInjection()
		if !reusable {
			closeSocket()
		}
	}
	return len(packets), nil
}

// The caller owns fd even on setup error, and closes it under the same token.
// Best-effort options still allow this packet's send, but a failed application
// must not leak uncertain socket state into a later packet through reuse.
func openInjectedSocket(key injectionSocketKey) (fd int, reusable bool, err error) {
	domain := unix.AF_INET
	switch key.family {
	case FamilyIPv4:
	case FamilyIPv6:
		domain = unix.AF_INET6
	default:
		return -1, false, fmt.Errorf("desync: unsupported injection family")
	}
	fd, err = openInjectionSocket(domain, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		return -1, false, err
	}
	if key.family == FamilyIPv4 {
		if err = setInjectionSockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
			return fd, false, err
		}
	}
	reusable = true
	if key.bind {
		reusable = bindInjectionSource(fd, key.family, key.source)
	}
	if key.mark != 0 {
		if setInjectionSockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, key.mark) != nil {
			reusable = false
		}
	}
	if key.device != "" {
		if setInjectionSockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, key.device) != nil {
			reusable = false
		}
	}
	if err = setInjectionSockoptInt(fd, unix.SOL_SOCKET, unix.SO_PRIORITY, int(key.priority)); err != nil {
		return fd, false, err
	}
	return fd, reusable, nil
}

// bindInjectionSource keeps the upstream best-effort source binding policy.
// The result governs only reuse, never whether the current send is attempted.
func bindInjectionSource(fd int, family Family, source netip.Addr) bool {
	if !source.IsValid() {
		return false
	}
	var sockaddr unix.Sockaddr
	var freebindErr error
	switch family {
	case FamilyIPv4:
		if !source.Is4() {
			return false
		}
		sockaddr = &unix.SockaddrInet4{Addr: source.As4()}
		freebindErr = setInjectionSockoptInt(fd, unix.IPPROTO_IP, unix.IP_FREEBIND, 1)
	case FamilyIPv6:
		if !source.Is6() {
			return false
		}
		sockaddr = &unix.SockaddrInet6{Addr: source.As16()}
		freebindErr = setInjectionSockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_FREEBIND, 1)
	default:
		return false
	}
	bindErr := bindInjectionSocket(fd, sockaddr)
	return freebindErr == nil && bindErr == nil
}

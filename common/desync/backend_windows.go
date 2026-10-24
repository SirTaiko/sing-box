//go:build windows

package desync

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/common/windivert"
	"golang.org/x/sys/windows"
)

type windowsBackend struct{}

func NewNativeBackend() Backend { return windowsBackend{} }

func (windowsBackend) Name() string { return "windows-windivert" }

func (windowsBackend) Open(lease *Lease) (Capture, error) {
	endpoint := lease.Endpoint()
	outFilter, err := openCaptureFilter(lease, true)
	if err != nil {
		return nil, err
	}
	// The filter dump is the explicit --wf-save equivalent: it happens when
	// the capture is actually activated, only for a configured path, and its
	// failure is a real activation error (the operator asked for it).
	if config := lease.Engine().Config().Capture; config.windows != nil {
		if err = config.windows.writeFilterDump(endpoint); err != nil {
			return nil, err
		}
	}
	outbound, err := windivert.Open(outFilter, windivert.LayerNetwork, 0, windivert.FlagSniff)
	if err != nil {
		return nil, err
	}
	// The reply side is a second, explicitly inbound handle scoped to the
	// reverse of the owned tuple. Direction is carried by the handle/filter and
	// by each captured address; it is never inferred from payload shape.
	capture := &windowsCapture{lease: lease, outbound: outbound, done: make(chan struct{}),
		injected: make(map[[sha256.Size]byte]int)}
	if endpoint.Destination.IsValid() {
		inFilter, filterErr := openCaptureFilter(lease, false)
		if filterErr != nil {
			outbound.Close()
			return nil, filterErr
		}
		inbound, openErr := windivert.Open(inFilter, windivert.LayerNetwork, 0, windivert.FlagSniff)
		if openErr != nil {
			outbound.Close()
			return nil, openErr
		}
		capture.inbound = inbound
	} else if endpoint.Transport != TransportUDP {
		// A TCP listener has no peer to observe yet; an outbound-only capture
		// is the complete ownership for it.
	}
	capture.wg.Add(1)
	go capture.loop()
	if capture.inbound != nil {
		capture.wg.Add(1)
		go capture.inboundLoop()
	}
	if lease.Engine().Config().Capture.filterTTLExpiredICMP {
		icmpFilter, filterErr := icmpErrorFilter(lease)
		if filterErr != nil {
			capture.closePartial()
			return nil, filterErr
		}
		icmpHandle, openErr := windivert.Open(icmpFilter, windivert.LayerNetwork, 0, windivert.FlagSniff)
		if openErr != nil {
			capture.closePartial()
			return nil, openErr
		}
		capture.icmp = icmpHandle
		capture.wg.Add(1)
		go capture.icmpLoop()
	}
	return capture, nil
}

// icmpErrorFilter builds the owned time-exceeded filter. The address narrowing
// is used whenever the attempt's local address is concrete; otherwise the
// filter is narrowed by the owned interface index and every packet is still
// validated against the owned tuple before a drop, so it is never a host-wide
// capture. Parameter-problem messages are not matched.
func icmpErrorFilter(lease *Lease) (*windivert.Filter, error) {
	endpoint := lease.Endpoint()
	ipv6 := endpoint.Family == FamilyIPv6
	local := lease.LocalAddress()
	address := local.Addr()
	var filter *windivert.Filter
	var err error
	if address.IsValid() && !address.IsUnspecified() && address.Is6() == ipv6 {
		filter, err = windivert.InboundICMPTimeExceeded([]netip.Addr{address})
	} else if endpoint.InterfaceIndex != 0 {
		filter, err = windivert.InboundICMPTimeExceededFamily(ipv6)
	} else {
		return nil, fmt.Errorf("desync: capture.filter_ttl_expired_icmp needs an actual local address or owned interface: the owned attempt has neither, so no bounded ICMP capture can be installed")
	}
	if err != nil {
		return nil, err
	}
	if endpoint.InterfaceIndex != 0 {
		interfaceFilter, interfaceErr := windivert.InterfaceIndex(endpoint.InterfaceIndex, 0)
		if interfaceErr != nil {
			return nil, interfaceErr
		}
		filter, err = windivert.And(filter, interfaceFilter)
		if err != nil {
			return nil, err
		}
	}
	if count := filter.InstructionCount(); count < 0 {
		return nil, fmt.Errorf("desync: capture.filter_ttl_expired_icmp filter does not compile")
	}
	return filter, nil
}

// openCaptureFilter builds the kernel filter for one direction. When
// capture.windows is configured the filter is the composed envelope AND user
// expression AND non-LAN exclusion; otherwise the plain owned envelope is
// used, which is the pre-existing behaviour.
func openCaptureFilter(lease *Lease, outbound bool) (*windivert.Filter, error) {
	endpoint := lease.Endpoint()
	config := lease.Engine().Config().Capture
	if config.windows != nil {
		return config.windows.captureFilter(endpoint, outbound)
	}
	return windowsFilter(endpoint, outbound)
}

func windowsFilter(endpoint Endpoint, outbound bool) (*windivert.Filter, error) {
	if !endpoint.Source.IsValid() || endpoint.Source.Port() == 0 {
		return nil, fmt.Errorf("desync: capture requires an owned local endpoint")
	}
	if endpoint.Transport == TransportUDP {
		if endpoint.Destination.IsValid() {
			if outbound {
				return windivert.OutboundUDP(endpoint.Source, endpoint.Destination)
			}
			return windivert.InboundUDPFlow(endpoint.Destination, endpoint.Source)
		}
		if outbound {
			return windivert.OutboundUDPLocalPort(endpoint.Source)
		}
		return nil, fmt.Errorf("desync: inbound listener capture needs a peer")
	}
	if endpoint.Destination.IsValid() {
		if outbound {
			return windivert.OutboundTCP(endpoint.Source, endpoint.Destination)
		}
		return windivert.InboundTCPFlow(endpoint.Destination, endpoint.Source)
	}
	if outbound {
		return windivert.OutboundTCPLocalPort(endpoint.Source)
	}
	return nil, fmt.Errorf("desync: inbound listener capture needs a peer")
}

type windowsCapture struct {
	lease    *Lease
	outbound *windivert.Handle
	inbound  *windivert.Handle
	// icmp is the owned time-exceeded handle. It exists only when
	// capture.filter_ttl_expired_icmp is enabled and an actual ownership fact
	// (local address or interface index) can bound it.
	icmp *windivert.Handle
	done chan struct{}
	wg   sync.WaitGroup

	closeOnce sync.Once
	closeErr  error

	mu       sync.Mutex
	injected map[[sha256.Size]byte]int
}

func (c *windowsCapture) loop() {
	defer c.wg.Done()
	defer close(c.done)
	buffer := make([]byte, windivert.MTUMax)
	for {
		length, address, err := c.outbound.Recv(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		if c.consumeInjected(packet) {
			// A replacement produced by this engine must not be transformed or
			// counted again. Re-inject it unchanged and continue.
			_, _ = c.outbound.Send(packet, &address)
			continue
		}
		addressCopy := address
		complete := func(verdict Verdict, reason string, modified []byte) {
			// A held disposition carries its own in-place bytes; the shared
			// lease slot is only for the immediate path below.
			c.sendDisposition(c.outbound, packet, &addressCopy, verdict, modified)
		}
		verdict := c.lease.HandlePacket(packet, DirectionOutbound, func(replacement []byte) error {
			c.rememberInjected(replacement)
			sendAddress := address
			materializeChecksums(&sendAddress)
			_, err := c.outbound.Send(replacement, &sendAddress)
			return err
		}, complete)
		if verdict == VerdictHold {
			// The completer owns the terminal disposition.
			continue
		}
		var modified []byte
		if verdict == VerdictModify {
			modified = c.lease.TakeModified(DirectionOutbound)
		}
		c.sendDisposition(c.outbound, packet, &address, verdict, modified)
	}
}

// inboundLoop observes replies. A reply is only ever re-injected unchanged on
// the inbound handle: it is never passed to the packet planner and never sent
// through the outbound injection path.
func (c *windowsCapture) inboundLoop() {
	defer c.wg.Done()
	buffer := make([]byte, windivert.MTUMax)
	for {
		length, address, err := c.inbound.Recv(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		_ = c.lease.HandlePacket(packet, DirectionInbound, nil, nil)
		// In-place reply transformations (window rewrite) are delivered on the
		// same inbound handle with the original direction/IfIdx preserved.
		sendPacket := packet
		if modified := c.lease.TakeModified(DirectionInbound); modified != nil {
			sendPacket = modified
		}
		sendAddress := address
		materializeChecksums(&sendAddress)
		_, _ = c.inbound.Send(sendPacket, &sendAddress)
	}
}

func (c *windowsCapture) sendDisposition(handle *windivert.Handle, packet []byte, address *windivert.Address, verdict Verdict, modified []byte) {
	if verdict == VerdictDrop {
		return
	}
	if verdict == VerdictModify && len(modified) > 0 {
		packet = modified
	}
	sendAddress := *address
	materializeChecksums(&sendAddress)
	_, _ = handle.Send(packet, &sendAddress)
}

// materializeChecksums clears the checksum-valid metadata so the driver
// recomputes IPv4/TCP/UDP checksums from the bytes actually sent. Captured
// originals may come from a checksum-offload path where the on-wire checksum was
// not materialized, and replacements have rewritten headers. Fragmented
// originals are never parsed or rewritten (ParsePacket rejects them), so this
// never runs on a fragment.
func materializeChecksums(address *windivert.Address) {
	address.SetIPChecksum(false)
	address.SetTCPChecksum(false)
	address.SetUDPChecksum(false)
}

func (c *windowsCapture) rememberInjected(packet []byte) {
	digest := sha256.Sum256(packet)
	c.mu.Lock()
	if len(c.injected) >= 256 {
		for key := range c.injected {
			delete(c.injected, key)
			break
		}
	}
	c.injected[digest]++
	c.mu.Unlock()
}

func (c *windowsCapture) consumeInjected(packet []byte) bool {
	digest := sha256.Sum256(packet)
	c.mu.Lock()
	defer c.mu.Unlock()
	count, loaded := c.injected[digest]
	if !loaded {
		return false
	}
	if count <= 1 {
		delete(c.injected, digest)
	} else {
		c.injected[digest] = count - 1
	}
	return true
}

// icmpLoop observes the owned time-exceeded capture. A validated owned low-hop
// error is dropped (never re-injected); every other error — foreign tuple,
// malformed/truncated quote, reply-side quote, parameter-problem — is passed
// unchanged. It never reaches the packet planner.
func (c *windowsCapture) icmpLoop() {
	defer c.wg.Done()
	buffer := make([]byte, windivert.MTUMax)
	for {
		length, address, err := c.icmp.Recv(buffer)
		if err != nil {
			return
		}
		packet := append([]byte(nil), buffer[:length]...)
		if c.lease.HandleICMPTimeExceeded(packet) {
			continue
		}
		sendAddress := address
		materializeChecksums(&sendAddress)
		_, _ = c.icmp.Send(packet, &sendAddress)
	}
}

// closePartial releases the handles opened before a later activation failure.
func (c *windowsCapture) closePartial() {
	_ = c.outbound.Close()
	if c.inbound != nil {
		_ = c.inbound.Close()
	}
	if c.icmp != nil {
		_ = c.icmp.Close()
	}
}

func (c *windowsCapture) Close() error {
	c.closeOnce.Do(func() {
		err := c.outbound.Close()
		if c.inbound != nil {
			if inboundErr := c.inbound.Close(); err == nil {
				err = inboundErr
			}
		}
		if c.icmp != nil {
			if icmpErr := c.icmp.Close(); err == nil {
				err = icmpErr
			}
		}
		c.wg.Wait()
		c.closeErr = err
	})
	return c.closeErr
}

// prepareSocket establishes the owned endpoint and registers capture on the
// native Winsock handle.
//
// A TCP packet attempt reaches this hook after the native ConnectEx helper has
// already bound the exclusive local port. A UDP packet attempt reaches it from
// the dialer's last-chance Control hook, which runs before net.Dialer's own
// bind, and the dialer clears its local address for packet leases so the lease
// is the single bind owner: the exclusive port therefore has to be established
// here, exactly like the Linux hook. Without that bind the socket is still
// unbound and getsockname fails with WSAEINVAL ("An invalid argument was
// supplied."), which used to abort every Windows packet-enabled connected UDP
// dial before capture or tracking.
func prepareSocket(lease *Lease, fd uintptr) error {
	if lease.Intent().Transport == TransportUDP {
		if err := bindExclusiveUDPAddress(lease, fd); err != nil {
			return err
		}
	}
	if lease.LocalAddress().Port() == 0 {
		address, err := sockaddrForHandle(fd)
		if err != nil {
			return err
		}
		lease.SetLocalAddress(address)
	}
	// The actual interface the native attempt is bound to is queried from the
	// socket itself (IP_UNICAST_IF/IPV6_UNICAST_IF), never inferred from
	// configuration. The index is what a WinDivert ifIdx comparison uses; the
	// resolved adapter name feeds the state/ipcache interface dimension.
	if index, name := querySocketInterface(fd); index != 0 {
		lease.setSocketInterface(index, name)
	}
	return lease.StartCapture()
}

// bindExclusiveUDPAddress binds the attempt's requested local address on the
// unbound Winsock UDP socket. The port stays kernel-assigned, so the owned
// capture envelope is scoped to the actual port the kernel handed out, read
// back from the socket immediately after this bind. The requested source
// address, its IPv6 zone and the interface control that already ran are
// honored; an address the host cannot bind fails the attempt closed.
func bindExclusiveUDPAddress(lease *Lease, fd uintptr) error {
	intent := lease.Intent()
	handle := windows.Handle(fd)
	// The endpoint this attempt is about to receive must be exclusively owned
	// before the kernel assigns it: a second Winsock socket that sets
	// SO_REUSEADDR can otherwise share the same local endpoint, and tuple
	// capture cannot tell the two sockets apart. Winsock honours the option
	// only before bind, so it is applied to the still-unbound handle.
	if err := setExclusiveUDPBind(handle); err != nil {
		return err
	}
	switch intent.Family {
	case FamilyIPv4:
		bind := &windows.SockaddrInet4{}
		if intent.Source.IsValid() {
			address := intent.Source.Addr().Unmap()
			if !address.Is4() {
				return fmt.Errorf("desync: IPv6 bind address for an IPv4 destination")
			}
			bind.Addr = address.As4()
		}
		if err := windows.Bind(handle, bind); err != nil {
			return fmt.Errorf("desync: bind exclusive local port: %w", err)
		}
	case FamilyIPv6:
		bind := &windows.SockaddrInet6{}
		if intent.Source.IsValid() {
			address := intent.Source.Addr().Unmap()
			if address.Is4() {
				return fmt.Errorf("desync: IPv4 bind address for an IPv6 destination")
			}
			bind.Addr = address.As16()
			if zone := intent.Source.Addr().Zone(); zone != "" {
				iface, err := net.InterfaceByName(zone)
				if err != nil {
					return fmt.Errorf("desync: resolve zone %s: %w", zone, err)
				}
				bind.ZoneId = uint32(iface.Index)
			}
		}
		if err := windows.Bind(handle, bind); err != nil {
			return fmt.Errorf("desync: bind exclusive local port: %w", err)
		}
	default:
		return fmt.Errorf("desync: unsupported address family")
	}
	return nil
}

// Winsock unicast interface options. Both families use option 31 at their own
// level (ws2ipdef.h: IP_UNICAST_IF / IPV6_UNICAST_IF); x/sys/windows does not
// export them.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// querySocketInterface returns the interface index the socket was bound to and
// the adapter name for that index, or (0, "") when the socket is not
// interface-bound.
func querySocketInterface(fd uintptr) (uint32, string) {
	handle := windows.Handle(fd)
	for _, level := range []int{windows.IPPROTO_IP, windows.IPPROTO_IPV6} {
		option := ipUnicastIf
		if level == windows.IPPROTO_IPV6 {
			option = ipv6UnicastIf
		}
		index, err := windows.GetsockoptInt(handle, level, option)
		if err != nil || index <= 0 {
			continue
		}
		return uint32(index), adapterNameByIndex(uint32(index))
	}
	return 0, ""
}

func adapterNameByIndex(index uint32) string {
	adapters, err := queryAdapters()
	if err != nil {
		return ""
	}
	for _, adapter := range adapters {
		if adapter.Index == index {
			return adapter.Name
		}
	}
	return ""
}

func sockaddrForHandle(fd uintptr) (netip.AddrPort, error) {
	sockaddr, err := windows.Getsockname(windows.Handle(fd))
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("desync: getsockname: %w", err)
	}
	switch value := sockaddr.(type) {
	case *windows.SockaddrInet4:
		return netip.AddrPortFrom(netip.AddrFrom4(value.Addr), uint16(value.Port)), nil
	case *windows.SockaddrInet6:
		return netip.AddrPortFrom(netip.AddrFrom16(value.Addr), uint16(value.Port)), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("desync: unexpected sockaddr family")
	}
}

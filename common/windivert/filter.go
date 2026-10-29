package windivert

import (
	"encoding/binary"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// WINDIVERT_FILTER VM instruction layout (24 bytes, #pragma pack(1)):
//
//	word 0 (LE):  field:11 | test:5 | success:16
//	word 1 (LE):  failure:16 | neg:1 | reserved:15
//	words 2..5:   arg[4] (native-endian uint32 each)
//
// The driver walks this as a decision tree: evaluate the test at inst i;
// on success jump to success; on failure jump to failure. Continuations
// 0x7FFE and 0x7FFF are ACCEPT and REJECT terminals.
const (
	filterInstBytes = 24
	filterMaxInsts  = 256

	fieldZero        = 0
	fieldInbound     = 1
	fieldOutbound    = 2
	fieldIP          = 5
	fieldIPv6        = 6
	fieldICMP        = 7
	fieldTCP         = 8
	fieldUDP         = 9
	fieldICMPv6      = 10
	fieldIPSrcAddr   = 21
	fieldIPDstAddr   = 22
	fieldIPv6SrcAddr = 28
	fieldIPv6DstAddr = 29
	fieldICMPType    = 30
	fieldICMPv6Type  = 34
	fieldTCPSrcPort  = 38
	fieldTCPDstPort  = 39
	fieldUDPSrcPort  = 53
	fieldUDPDstPort  = 54

	testEQ  = 0
	testLEQ = 3
	testGEQ = 5

	resultAccept uint16 = 0x7FFE
	resultReject uint16 = 0x7FFF
)

// Filter flags passed to IOCTL_WINDIVERT_STARTUP alongside the compiled
// filter. The driver installs WFP callouts only for the directions and
// address families named here (windivert_install_callouts), so a filter
// missing its direction flag never sees a packet.
const (
	filterFlagInbound  uint64 = 0x0010
	filterFlagOutbound uint64 = 0x0020
	filterFlagIP       uint64 = 0x0040
	filterFlagIPv6     uint64 = 0x0080
)

type filterInst struct {
	field   uint16
	test    uint8
	success uint16
	failure uint16
	neg     bool
	arg     [4]uint32
}

func OutboundTCP(src, dst netip.AddrPort) (*Filter, error) {
	return outboundTransport(src, dst, true)
}

// OutboundUDP matches one owned outbound UDP flow.
func OutboundUDP(src, dst netip.AddrPort) (*Filter, error) {
	return outboundTransport(src, dst, false)
}

// OutboundTCPLocalPort matches outbound TCP from one exclusively bound local
// endpoint to any destination. It is used for owned listener leases.
func OutboundTCPLocalPort(src netip.AddrPort) (*Filter, error) {
	return outboundLocal(src, true)
}

// OutboundUDPLocalPort matches outbound UDP from one exclusively bound local
// endpoint to any destination.
func OutboundUDPLocalPort(src netip.AddrPort) (*Filter, error) {
	return outboundLocal(src, false)
}

func outboundTransport(src, dst netip.AddrPort, tcp bool) (*Filter, error) {
	return transportFlow(src, dst, tcp, true)
}

// InboundTCPFlow matches the replies of one owned TCP flow: the peer is the
// source and the owned local endpoint is the destination. Direction is part of
// the filter, not an inference, so a reply can never be treated as outbound.
func InboundTCPFlow(peer, local netip.AddrPort) (*Filter, error) {
	return transportFlow(peer, local, true, false)
}

// InboundUDPFlow matches the replies of one owned UDP flow.
func InboundUDPFlow(peer, local netip.AddrPort) (*Filter, error) {
	return transportFlow(peer, local, false, false)
}

func transportFlow(src, dst netip.AddrPort, tcp bool, outbound bool) (*Filter, error) {
	if !src.IsValid() || !dst.IsValid() {
		return nil, E.New("windivert: filter: invalid address port")
	}
	if src.Addr().Is4() != dst.Addr().Is4() {
		return nil, E.New("windivert: filter: mixed IPv4/IPv6")
	}
	f := newFilterNode(0)
	if outbound {
		f.flags = filterFlagOutbound
		f.add(fieldOutbound, testEQ, argUint32(1))
	} else {
		f.flags = filterFlagInbound
		f.add(fieldInbound, testEQ, argUint32(1))
	}
	if src.Addr().Is4() {
		f.flags |= filterFlagIP
		f.add(fieldIP, testEQ, argUint32(1))
		if tcp {
			f.add(fieldTCP, testEQ, argUint32(1))
		} else {
			f.add(fieldUDP, testEQ, argUint32(1))
		}
		f.add(fieldIPSrcAddr, testEQ, argIPv4(src.Addr()))
		f.add(fieldIPDstAddr, testEQ, argIPv4(dst.Addr()))
	} else {
		f.flags |= filterFlagIPv6
		f.add(fieldIPv6, testEQ, argUint32(1))
		if tcp {
			f.add(fieldTCP, testEQ, argUint32(1))
		} else {
			f.add(fieldUDP, testEQ, argUint32(1))
		}
		f.add(fieldIPv6SrcAddr, testEQ, argIPv6(src.Addr()))
		f.add(fieldIPv6DstAddr, testEQ, argIPv6(dst.Addr()))
	}
	if tcp {
		f.add(fieldTCPSrcPort, testEQ, argUint32(uint32(src.Port())))
		f.add(fieldTCPDstPort, testEQ, argUint32(uint32(dst.Port())))
	} else {
		f.add(fieldUDPSrcPort, testEQ, argUint32(uint32(src.Port())))
		f.add(fieldUDPDstPort, testEQ, argUint32(uint32(dst.Port())))
	}
	return f, nil
}

func outboundLocal(src netip.AddrPort, tcp bool) (*Filter, error) {
	if !src.IsValid() || src.Port() == 0 {
		return nil, E.New("windivert: filter: invalid local address port")
	}
	f := newFilterNode(filterFlagOutbound)
	f.add(fieldOutbound, testEQ, argUint32(1))
	if src.Addr().Is4() {
		f.flags |= filterFlagIP
		f.add(fieldIP, testEQ, argUint32(1))
		f.add(fieldIPSrcAddr, testEQ, argIPv4(src.Addr()))
	} else {
		f.flags |= filterFlagIPv6
		f.add(fieldIPv6, testEQ, argUint32(1))
		f.add(fieldIPv6SrcAddr, testEQ, argIPv6(src.Addr()))
	}
	if tcp {
		f.add(fieldTCP, testEQ, argUint32(1))
		f.add(fieldTCPSrcPort, testEQ, argUint32(uint32(src.Port())))
	} else {
		f.add(fieldUDP, testEQ, argUint32(1))
		f.add(fieldUDPSrcPort, testEQ, argUint32(uint32(src.Port())))
	}
	return f, nil
}

// OwnedFlow is one owned packet attempt as the capture envelope sees it.
//
// Local must carry the exclusively bound local port (a zero port cannot
// authorize capture). An unspecified local address (0.0.0.0 or ::) is the
// default no-bind case: it removes only that address equality, never the
// direction, family, protocol, local port, peer or interface facts. Peer is
// empty for a TCP listener capture that has no peer yet; an inbound envelope
// always needs the peer because the reverse tuple is the only ownership fact
// it has.
type OwnedFlow struct {
	IPv6           bool
	TCP            bool
	Outbound       bool
	Local          netip.AddrPort
	Peer           netip.AddrPort
	InterfaceIndex uint32
}

// OwnedFlowEnvelope builds the authoritative kernel envelope for one direction
// of one owned flow. It is the single builder the desync capture uses for both
// the plain and the configured capture paths; the generic exact-address
// helpers above keep their meaning for other consumers.
//
// Ownership justification (the reason an unspecified local address may drop
// its equality) is the exclusive native bind: the local port cannot be shared,
// so port + family + protocol + direction + peer identify the attempt. A
// concrete local address stays an equality restriction.
func OwnedFlowEnvelope(flow OwnedFlow) (*Filter, error) {
	if !flow.Local.IsValid() || flow.Local.Port() == 0 {
		return nil, E.New("windivert: filter: owned flow needs a bound local port")
	}
	localAddress := flow.Local.Addr().Unmap()
	concreteLocal := localAddress.IsValid() && !localAddress.IsUnspecified()
	if concreteLocal && localAddress.Is6() != flow.IPv6 {
		return nil, E.New("windivert: filter: local address family does not match the owned flow")
	}
	peer := flow.Peer
	if peer.IsValid() {
		if peer.Port() == 0 {
			return nil, E.New("windivert: filter: owned peer has no port")
		}
		if peer.Addr().Unmap().Is6() != flow.IPv6 {
			return nil, E.New("windivert: filter: peer address family does not match the owned flow")
		}
	} else if !flow.Outbound {
		return nil, E.New("windivert: filter: an inbound owned flow needs a peer")
	}
	f := newFilterNode(0)
	if flow.Outbound {
		f.flags = filterFlagOutbound
		f.add(fieldOutbound, testEQ, argUint32(1))
	} else {
		f.flags = filterFlagInbound
		f.add(fieldInbound, testEQ, argUint32(1))
	}
	if flow.IPv6 {
		f.flags |= filterFlagIPv6
		f.add(fieldIPv6, testEQ, argUint32(1))
	} else {
		f.flags |= filterFlagIP
		f.add(fieldIP, testEQ, argUint32(1))
	}
	if flow.TCP {
		f.add(fieldTCP, testEQ, argUint32(1))
	} else {
		f.add(fieldUDP, testEQ, argUint32(1))
	}
	if flow.Outbound {
		if concreteLocal {
			f.add(srcAddressField(flow.IPv6), testEQ, addressArg(flow.IPv6, localAddress))
		}
		if peer.IsValid() {
			f.add(dstAddressField(flow.IPv6), testEQ, addressArg(flow.IPv6, peer.Addr().Unmap()))
		}
		f.add(srcPortField(flow.TCP), testEQ, argUint32(uint32(flow.Local.Port())))
		if peer.IsValid() {
			f.add(dstPortField(flow.TCP), testEQ, argUint32(uint32(peer.Port())))
		}
	} else {
		f.add(srcAddressField(flow.IPv6), testEQ, addressArg(flow.IPv6, peer.Addr().Unmap()))
		if concreteLocal {
			f.add(dstAddressField(flow.IPv6), testEQ, addressArg(flow.IPv6, localAddress))
		}
		f.add(srcPortField(flow.TCP), testEQ, argUint32(uint32(peer.Port())))
		f.add(dstPortField(flow.TCP), testEQ, argUint32(uint32(flow.Local.Port())))
	}
	if flow.InterfaceIndex != 0 {
		f.add(fieldIfIdx, testEQ, argUint32(flow.InterfaceIndex))
	}
	return f, nil
}

func srcAddressField(ipv6 bool) uint16 {
	if ipv6 {
		return fieldIPv6SrcAddr
	}
	return fieldIPSrcAddr
}

func dstAddressField(ipv6 bool) uint16 {
	if ipv6 {
		return fieldIPv6DstAddr
	}
	return fieldIPDstAddr
}

func addressArg(ipv6 bool, address netip.Addr) [4]uint32 {
	if ipv6 {
		return argIPv6(address)
	}
	return argIPv4(address)
}

func srcPortField(tcp bool) uint16 {
	if tcp {
		return fieldTCPSrcPort
	}
	return fieldUDPSrcPort
}

func dstPortField(tcp bool) uint16 {
	if tcp {
		return fieldTCPDstPort
	}
	return fieldUDPDstPort
}

func inboundTo(destinations []netip.Addr) (*Filter, error) {
	if len(destinations) == 0 {
		return nil, E.New("windivert: filter: no destination address")
	}
	isV6 := destinations[0].Is6()
	for _, destination := range destinations {
		if !destination.IsValid() {
			return nil, E.New("windivert: filter: invalid address")
		}
		if destination.Is6() != isV6 {
			return nil, E.New("windivert: filter: mixed IPv4/IPv6")
		}
	}
	f := newFilterNode(filterFlagInbound)
	f.add(fieldInbound, testEQ, argUint32(1))
	if !isV6 {
		f.flags |= filterFlagIP
		f.add(fieldIP, testEQ, argUint32(1))
		for _, destination := range destinations {
			f.addAny(fieldIPDstAddr, testEQ, argIPv4(destination))
		}
	} else {
		f.flags |= filterFlagIPv6
		f.add(fieldIPv6, testEQ, argUint32(1))
		for _, destination := range destinations {
			f.addAny(fieldIPv6DstAddr, testEQ, argIPv6(destination))
		}
	}
	return f, nil
}

func InboundTCPPortRange(destinations []netip.Addr, portLow, portHigh uint16) (*Filter, error) {
	f, err := inboundTo(destinations)
	if err != nil {
		return nil, err
	}
	f.add(fieldTCP, testEQ, argUint32(1))
	f.add(fieldTCPDstPort, testGEQ, argUint32(uint32(portLow)))
	f.add(fieldTCPDstPort, testLEQ, argUint32(uint32(portHigh)))
	return f, nil
}

func InboundUDPPortRange(destinations []netip.Addr, portLow, portHigh uint16) (*Filter, error) {
	f, err := inboundTo(destinations)
	if err != nil {
		return nil, err
	}
	f.add(fieldUDP, testEQ, argUint32(1))
	f.add(fieldUDPDstPort, testGEQ, argUint32(uint32(portLow)))
	f.add(fieldUDPDstPort, testLEQ, argUint32(uint32(portHigh)))
	return f, nil
}

func InboundICMPEchoReply(destinations []netip.Addr) (*Filter, error) {
	f, err := inboundTo(destinations)
	if err != nil {
		return nil, err
	}
	if destinations[0].Is4() {
		f.add(fieldICMP, testEQ, argUint32(1))
		f.add(fieldICMPType, testEQ, argUint32(0))
	} else {
		f.add(fieldICMPv6, testEQ, argUint32(1))
		f.add(fieldICMPv6Type, testEQ, argUint32(129))
	}
	return f, nil
}

func InboundICMPError(destinations []netip.Addr) (*Filter, error) {
	f, err := inboundTo(destinations)
	if err != nil {
		return nil, err
	}
	if destinations[0].Is4() {
		f.add(fieldICMP, testEQ, argUint32(1))
		f.add(fieldICMPType, testGEQ, argUint32(3))
		f.add(fieldICMPType, testLEQ, argUint32(12))
	} else {
		f.add(fieldICMPv6, testEQ, argUint32(1))
		f.add(fieldICMPv6Type, testGEQ, argUint32(1))
		f.add(fieldICMPv6Type, testLEQ, argUint32(4))
	}
	return f, nil
}

// InboundICMPTimeExceeded matches inbound ICMP/ICMPv6 time-exceeded errors
// addressed to the given local addresses. Parameter-problem/PMTU messages are
// deliberately not matched: capture.filter_ttl_expired_icmp never suppresses
// them. The caller still validates the quoted inner tuple before any drop.
func InboundICMPTimeExceeded(destinations []netip.Addr) (*Filter, error) {
	f, err := inboundTo(destinations)
	if err != nil {
		return nil, err
	}
	addTimeExceeded(f, destinations[0].Is6())
	return f, nil
}

// InboundICMPTimeExceededFamily is the address-less variant used when the owned
// attempt's local address is still unspecified (a wildcard bind before the
// first outbound packet). The caller must AND at least the owned interface
// index, so the kernel filter is never broader than the owned device scope.
func InboundICMPTimeExceededFamily(ipv6 bool) (*Filter, error) {
	f := newFilterNode(filterFlagInbound)
	f.add(fieldInbound, testEQ, argUint32(1))
	if ipv6 {
		f.flags |= filterFlagIPv6
		f.add(fieldIPv6, testEQ, argUint32(1))
	} else {
		f.flags |= filterFlagIP
		f.add(fieldIP, testEQ, argUint32(1))
	}
	addTimeExceeded(f, ipv6)
	return f, nil
}

func addTimeExceeded(f *Filter, ipv6 bool) {
	if ipv6 {
		f.add(fieldICMPv6, testEQ, argUint32(1))
		f.add(fieldICMPv6Type, testEQ, argUint32(3))
		return
	}
	f.add(fieldICMP, testEQ, argUint32(1))
	f.add(fieldICMPType, testEQ, argUint32(11))
}

func (f *Filter) add(field uint16, test uint8, arg [4]uint32) {
	f.root = andNode(f.root, testNode(field, test, arg))
}

func (f *Filter) addAny(field uint16, test uint8, arg [4]uint32) {
	f.anyNodes = append(f.anyNodes, testNode(field, test, arg))
}

func argUint32(v uint32) [4]uint32 { return [4]uint32{v, 0, 0, 0} }

// The driver compares IP_SRCADDR/IP_DSTADDR against an IPv4-mapped-IPv6
// form: {host_order_u32, 0x0000FFFF, 0, 0} (sys/windivert.c
// windivert_get_ipv4_addr).
func argIPv4(addr netip.Addr) [4]uint32 {
	b := addr.As4()
	return [4]uint32{binary.BigEndian.Uint32(b[:]), 0x0000FFFF, 0, 0}
}

// The driver stores IPV6_SRCADDR/IPV6_DSTADDR as four host-order uint32s in
// reversed word order: val[0]=low (bytes 12..15), val[3]=high (bytes 0..3)
// (sys/windivert.c windivert_outbound_network_v6_classify).
func argIPv6(addr netip.Addr) [4]uint32 {
	b := addr.As16()
	return [4]uint32{
		binary.BigEndian.Uint32(b[12:16]),
		binary.BigEndian.Uint32(b[8:12]),
		binary.BigEndian.Uint32(b[4:8]),
		binary.BigEndian.Uint32(b[0:4]),
	}
}

func encodeInst(inst filterInst) []byte {
	out := make([]byte, filterInstBytes)
	word0 := uint32(inst.field&0x7FF) | uint32(inst.test&0x1F)<<11 |
		uint32(inst.success)<<16
	word1 := uint32(inst.failure)
	if inst.neg {
		word1 |= 1 << 16
	}
	binary.LittleEndian.PutUint32(out[0:4], word0)
	binary.LittleEndian.PutUint32(out[4:8], word1)
	binary.LittleEndian.PutUint32(out[8:12], inst.arg[0])
	binary.LittleEndian.PutUint32(out[12:16], inst.arg[1])
	binary.LittleEndian.PutUint32(out[16:20], inst.arg[2])
	binary.LittleEndian.PutUint32(out[20:24], inst.arg[3])
	return out
}

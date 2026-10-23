package desync

// Owned quoted-ICMP filtering: capture.filter_ttl_expired_icmp.
//
// Upstream zapret drops every ICMP time-exceeded whose conntrack mark carries
// the desync mark (common/nft.sh nft_mark, common/ipt.sh CONNMARK) and, in
// POSTNAT mode, even `icmp type time-exceeded ct state invalid` broadly. The
// accepted contract deliberately narrows this: only an ICMP/ICMPv6
// time-exceeded error whose quoted original datagram is this lease's own
// outbound low-hop packet may be suppressed. Everything else — a foreign tuple,
// a malformed or truncated quote, a reply-side quote, a parameter-problem/PMTU
// message, or any error seen after the lease's generation ended — passes
// unchanged.
//
// The parser is shared by the Linux NFQUEUE loop and the Windows WinDivert loop,
// so both platforms make the identical decision on identical bytes.

import (
	"encoding/binary"
	"net/netip"
)

const (
	// icmpTypeTimeExceeded is the IPv4 ICMP time-exceeded type.
	icmpTypeTimeExceeded = 11
	// icmpv6TypeTimeExceeded is the ICMPv6 time-exceeded type.
	icmpv6TypeTimeExceeded = 3
	// icmpv6NextHeader is the ICMPv6 protocol number.
	icmpv6NextHeader = 58
	// ipv6QuoteInnerOffset is the fixed offset of the quoted inner IPv6 header:
	// 40-byte IPv6 header + 8-byte ICMPv6 header.
	ipv6QuoteInnerOffset = 48
)

// icmpQuote is the strictly parsed inner tuple of one captured ICMP error.
type icmpQuote struct {
	Family    Family
	Transport Transport
	Src       netip.Addr
	Dst       netip.Addr
	SrcPort   uint16
	DstPort   uint16
}

// parseTimeExceededQuote parses the quoted original datagram of an IPv4 ICMP
// type 11 or IPv6 ICMPv6 type 3 error. It is deliberately strict: any truncated
// outer datagram, non-matching family/type, non-first fragment, extension
// header or missing L4 ports is a rejection, which the caller treats as "not
// owned" and therefore passes the error unchanged.
func parseTimeExceededQuote(packet []byte, family Family) (icmpQuote, bool) {
	switch family {
	case FamilyIPv4:
		return parseTimeExceededQuote4(packet)
	case FamilyIPv6:
		return parseTimeExceededQuote6(packet)
	}
	return icmpQuote{}, false
}

func parseTimeExceededQuote4(packet []byte) (icmpQuote, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return icmpQuote{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl+8 {
		return icmpQuote{}, false
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl+8 || total > len(packet) {
		// A datagram shorter than its own header chain, or a capture that was
		// cut before the quoted header, is never used for a drop decision.
		return icmpQuote{}, false
	}
	if packet[ihl] != icmpTypeTimeExceeded {
		return icmpQuote{}, false
	}
	inner := packet[ihl+8 : total]
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return icmpQuote{}, false
	}
	innerIHL := int(inner[0]&0x0f) * 4
	if innerIHL < 20 || len(inner) < innerIHL+4 {
		return icmpQuote{}, false
	}
	// Only the first fragment carries the L4 ports.
	if binary.BigEndian.Uint16(inner[6:8])&0x1fff != 0 {
		return icmpQuote{}, false
	}
	transport, ok := quoteTransport(inner[9])
	if !ok {
		return icmpQuote{}, false
	}
	var source, destination [4]byte
	copy(source[:], inner[12:16])
	copy(destination[:], inner[16:20])
	ports := inner[innerIHL:]
	return icmpQuote{
		Family:    FamilyIPv4,
		Transport: transport,
		Src:       netip.AddrFrom4(source),
		Dst:       netip.AddrFrom4(destination),
		SrcPort:   binary.BigEndian.Uint16(ports[0:2]),
		DstPort:   binary.BigEndian.Uint16(ports[2:4]),
	}, true
}

func parseTimeExceededQuote6(packet []byte) (icmpQuote, bool) {
	if len(packet) < 40 || packet[0]>>4 != 6 {
		return icmpQuote{}, false
	}
	total := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
	if total > len(packet) || total < 48 {
		return icmpQuote{}, false
	}
	// An outer extension-header chain would move the ICMPv6 header; it is not
	// interpreted here, so such an error is passed rather than guessed.
	if packet[6] != icmpv6NextHeader {
		return icmpQuote{}, false
	}
	if packet[40] != icmpv6TypeTimeExceeded {
		return icmpQuote{}, false
	}
	inner := packet[ipv6QuoteInnerOffset:total]
	if len(inner) < 40 || inner[0]>>4 != 6 {
		return icmpQuote{}, false
	}
	// The quoted inner header must be TCP/UDP directly (no extension headers),
	// otherwise the ports are not at the fixed offset.
	transport, ok := quoteTransport(inner[6])
	if !ok {
		return icmpQuote{}, false
	}
	var source, destination [16]byte
	copy(source[:], inner[8:24])
	copy(destination[:], inner[24:40])
	ports := inner[40:]
	if len(ports) < 4 {
		return icmpQuote{}, false
	}
	return icmpQuote{
		Family:    FamilyIPv6,
		Transport: transport,
		Src:       netip.AddrFrom16(source),
		Dst:       netip.AddrFrom16(destination),
		SrcPort:   binary.BigEndian.Uint16(ports[0:2]),
		DstPort:   binary.BigEndian.Uint16(ports[2:4]),
	}, true
}

func quoteTransport(protocol byte) (Transport, bool) {
	switch protocol {
	case 6:
		return TransportTCP, true
	case 17:
		return TransportUDP, true
	}
	return 0, false
}

// noteInjection records one successful replacement send. Only a lease that has
// actually injected a low-hop packet can own a time-exceeded error caused by
// one; the flag is never set by ordinary flow traffic.
func (l *Lease) noteInjection() {
	if l != nil {
		l.lowHopSent.Store(true)
	}
}

// HandleICMPTimeExceeded reports whether one captured ICMP/ICMPv6 error must be
// dropped. The decision is positive only for a validated quote of this lease's
// own outbound tuple in the current generation:
//
//   - the filter is enabled, the lease is live and a replacement was injected;
//   - the quoted packet is TCP/UDP of the owned transport and its source
//     address/port is the actually bound local endpoint;
//   - when the attempt has a destination, the quoted destination is exactly
//     the owned peer;
//   - the kernel queue only delivers time-exceeded errors of this family.
//
// Foreign, malformed, truncated, reply-side and parameter-problem errors never
// reach a drop.
func (l *Lease) HandleICMPTimeExceeded(packet []byte) bool {
	if l == nil || l.engine == nil || !l.lowHopSent.Load() {
		return false
	}
	if !l.engine.Config().Capture.filterTTLExpiredICMP || l.closedFlag.Load() {
		return false
	}
	endpoint := l.Endpoint()
	quote, ok := parseTimeExceededQuote(packet, endpoint.Family)
	if !ok {
		return false
	}
	if quote.Transport != endpoint.Transport {
		return false
	}
	local := l.LocalAddress()
	if !local.IsValid() {
		local = endpoint.Source
	}
	if !local.IsValid() || local.Port() == 0 || quote.SrcPort != local.Port() {
		return false
	}
	// An unspecified local address cannot be compared, but the port is
	// exclusively bound to this lease; a concrete address must match exactly.
	if local.Addr().IsValid() && !local.Addr().IsUnspecified() && !sameQuoteAddr(quote.Src, local.Addr()) {
		return false
	}
	if endpoint.Destination.IsValid() {
		if quote.DstPort != endpoint.Destination.Port() {
			return false
		}
		if !sameQuoteAddr(quote.Dst, endpoint.Destination.Addr()) {
			return false
		}
	}
	return true
}

// sameQuoteAddr compares two addresses without transport zones.
func sameQuoteAddr(left netip.Addr, right netip.Addr) bool {
	if !left.IsValid() || !right.IsValid() {
		return false
	}
	left, right = left.Unmap(), right.Unmap()
	if left.Is6() {
		left = left.WithZone("")
	}
	if right.Is6() {
		right = right.WithZone("")
	}
	return left == right
}

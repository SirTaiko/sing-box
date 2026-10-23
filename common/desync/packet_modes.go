package desync

import (
	"encoding/binary"
	"fmt"
)

// parseTCPOptions records the option facts used by the upstream generators.
func parseTCPOptions(p *Packet) {
	options := p.TCPOptions
	for index := 0; index < len(options); {
		kind := options[index]
		if kind == 0 {
			return
		}
		if kind == 1 {
			index++
			continue
		}
		if index+1 >= len(options) {
			return
		}
		length := int(options[index+1])
		if length < 2 || index+length > len(options) {
			return
		}
		switch kind {
		case 2:
			if length == 4 {
				p.MSS = binary.BigEndian.Uint16(options[index+2:])
			}
		case 3:
			if length == 3 {
				p.WindowScale = int(options[index+2])
			}
		case 4:
			p.HasSACK = true
		case 8:
			if length == 10 {
				p.HasTimestamp = true
				p.TSVal = binary.BigEndian.Uint32(options[index+2:])
			}
		case 34:
			// New-style RFC 7413 TCP Fast Open option.
			p.HasFastOpen = true
		case 254:
			// Old-style RFC 6994 experimental option: only the two registered
			// magic bytes f9 89 make it TFO (upstream tcp_has_fastopen). A bare
			// option 254, a short one, or any other experiment id is not TFO
			// and must not suppress syndata or change the stream handling.
			if length >= 4 && options[index+2] == 0xf9 && options[index+3] == 0x89 {
				p.HasFastOpen = true
			}
		}
		index += length
	}
}

// BuildSpec is the complete parameter set of one generated TCP segment. It is
// a direct expression of the upstream `prepare_tcp_segment` arguments plus the
// IPv6 extension-header selector of `prepare_tcp_segment6`.
type BuildSpec struct {
	Flags *uint8
	Seq   *uint32
	Ack   *uint32

	TTL    uint8
	TTLSet bool

	IPID    uint16
	IPIDSet bool

	Window      *uint16
	WindowScale *int

	TSIncrement int32
	BadSeq      int32
	BadAck      int32
	Fooling     Fooling
	CorruptSum  bool

	// CopyOptions keeps the template's MSS/SACK/window-scale/timestamp
	// options (upstream passes bSack/nmss/scale_factor/timestamps).
	CopyOptions bool
	// Payload is the segment data.
	Payload []byte
	// ExtHeaders are IPv6 extension header types inserted before the
	// transport header, in order (0 = hop-by-hop, 60 = destination options,
	// 44 = fragment header).
	ExtHeaders []uint8
	// FragmentIdent is the IPv6 fragment identification when ExtHeaders
	// contains 44.
	FragmentIdent uint32
	Rand          RandSource
}

func (s BuildSpec) random() RandSource {
	if s.Rand != nil {
		return s.Rand
	}
	return DefaultRand
}

func tcpOptionLength(spec BuildSpec, packet *Packet) int {
	if !spec.CopyOptions {
		return 0
	}
	length := 0
	if packet.HasSACK {
		length += 2
	}
	if packet.MSS != 0 {
		length += 4
	}
	if spec.Fooling.MD5Signature {
		length += 18
	}
	if packet.HasTimestamp {
		length += 10
	}
	if spec.WindowScale != nil && *spec.WindowScale >= 0 || spec.WindowScale == nil && packet.WindowScale >= 0 {
		length += 3
	}
	return (length + 3) &^ 3
}

// BuildTCPEx builds one TCP segment from template with the full upstream
// modifier set, including IPv6 extension-header chains.
func BuildTCPEx(template *Packet, spec BuildSpec) ([]byte, error) {
	if template.Transport != TransportTCP {
		return nil, fmt.Errorf("desync: template is not TCP")
	}
	if len(spec.ExtHeaders) > 0 && template.Family != FamilyIPv6 {
		return nil, fmt.Errorf("desync: IPv6 extension headers on a non-IPv6 packet")
	}
	optionLength := tcpOptionLength(spec, template)
	transportLength := 20 + optionLength + len(spec.Payload)
	extLength := 0
	for _, header := range spec.ExtHeaders {
		switch header {
		case 0, 60:
			extLength += 8
		case 44:
			extLength += 8
		default:
			return nil, fmt.Errorf("desync: unsupported IPv6 extension header %d", header)
		}
	}
	headerEnd := template.IPHeaderLen
	out := make([]byte, headerEnd+extLength+transportLength)
	copy(out, template.Raw[:headerEnd])
	tcp := headerEnd + extLength
	payloadOffset := tcp + 20 + optionLength
	copy(out[payloadOffset:], spec.Payload)

	flags := template.TCPFlags
	if spec.Flags != nil {
		flags = *spec.Flags
	}
	seq := template.TCPSeq
	if spec.Seq != nil {
		seq = *spec.Seq
	}
	ack := template.TCPAck
	if spec.Ack != nil {
		ack = *spec.Ack
	}
	if spec.Fooling.BadSequence {
		seq += uint32(spec.BadSeq)
		ack += uint32(spec.BadAck)
	}
	window := template.TCPWindow
	if spec.Window != nil {
		window = *spec.Window
	}
	if spec.Fooling.DataNoACK && len(spec.Payload) > 0 && flags&(tcpFlagSYN|tcpFlagRST) == 0 {
		flags &^= tcpFlagACK
	}
	binary.BigEndian.PutUint16(out[tcp:tcp+2], template.SrcPort)
	binary.BigEndian.PutUint16(out[tcp+2:tcp+4], template.DstPort)
	binary.BigEndian.PutUint32(out[tcp+4:tcp+8], seq)
	binary.BigEndian.PutUint32(out[tcp+8:tcp+12], ack)
	out[tcp+12] = byte((20 + optionLength) / 4 << 4)
	out[tcp+13] = flags
	binary.BigEndian.PutUint16(out[tcp+14:tcp+16], window)

	cursor := tcp + 20
	if spec.CopyOptions {
		if template.HasSACK {
			out[cursor], out[cursor+1] = 4, 2
			cursor += 2
		}
		if template.MSS != 0 {
			out[cursor], out[cursor+1] = 2, 4
			binary.BigEndian.PutUint16(out[cursor+2:], template.MSS)
			cursor += 4
		}
		if spec.Fooling.MD5Signature {
			out[cursor], out[cursor+1] = 19, 18
			random := spec.random()
			for offset := 0; offset < 16; offset += 4 {
				binary.BigEndian.PutUint32(out[cursor+2+offset:], random.Uint32())
			}
			cursor += 18
		}
		if template.HasTimestamp {
			out[cursor], out[cursor+1] = 8, 10
			binary.BigEndian.PutUint32(out[cursor+2:], template.TSVal)
			binary.BigEndian.PutUint32(out[cursor+6:], 0)
			if spec.Fooling.Timestamp {
				binary.BigEndian.PutUint32(out[cursor+2:], template.TSVal+uint32(spec.TSIncrement))
			}
			cursor += 10
		}
		scale := template.WindowScale
		if spec.WindowScale != nil {
			scale = *spec.WindowScale
		}
		if scale >= 0 {
			out[cursor], out[cursor+1], out[cursor+2] = 3, 3, byte(scale)
			cursor += 3
		}
		for cursor < tcp+20+optionLength {
			out[cursor] = 1
			cursor++
		}
	}

	// IPv6 extension chain: every header's Next Header points at the following
	// header, and the fixed header points at the first one.
	if len(spec.ExtHeaders) > 0 {
		chainOffset := headerEnd
		for index, header := range spec.ExtHeaders {
			following := byte(TransportTCP)
			if index+1 < len(spec.ExtHeaders) {
				following = spec.ExtHeaders[index+1]
			}
			out[chainOffset] = following
			out[chainOffset+1] = 0
			if header == 44 {
				ident := spec.FragmentIdent
				if ident == 0 {
					ident = 1 + spec.random().Uint32()%0xffffffff
				}
				binary.BigEndian.PutUint32(out[chainOffset+4:], ident)
				binary.BigEndian.PutUint16(out[chainOffset+2:], 0)
			}
			chainOffset += 8
		}
		out[6] = spec.ExtHeaders[0]
	}

	if spec.TTLSet {
		if template.Family == FamilyIPv4 {
			out[8] = spec.TTL
		} else {
			out[7] = spec.TTL
		}
	}
	if template.Family == FamilyIPv4 {
		if spec.IPIDSet {
			binary.BigEndian.PutUint16(out[4:6], spec.IPID)
		} else {
			binary.BigEndian.PutUint16(out[4:6], template.IPID+1)
		}
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], inetChecksum(out[:template.IPHeaderLen], 0))
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-template.IPHeaderLen))
	}
	sum, err := pseudoHeaderSum(out, template, transportLength)
	if err != nil {
		return nil, err
	}
	out[tcp+16], out[tcp+17] = 0, 0
	tcpSum := inetChecksum(out[tcp:tcp+transportLength], sum)
	if spec.CorruptSum {
		tcpSum ^= uint16(1 + spec.random().Uint32()%0xffff)
	}
	binary.BigEndian.PutUint16(out[tcp+16:tcp+18], tcpSum)
	return out, nil
}

// BuildUDPEx builds one UDP datagram with the full modifier set, including an
// IPv6 extension-header chain and udplen padding.
func BuildUDPEx(template *Packet, spec BuildSpec) ([]byte, error) {
	if template.Transport != TransportUDP {
		return nil, fmt.Errorf("desync: template is not UDP")
	}
	if len(spec.ExtHeaders) > 0 && template.Family != FamilyIPv6 {
		return nil, fmt.Errorf("desync: IPv6 extension headers on a non-IPv6 packet")
	}
	extLength := 8 * len(spec.ExtHeaders)
	headerEnd := template.IPHeaderLen
	out := make([]byte, headerEnd+extLength+8+len(spec.Payload))
	copy(out, template.Raw[:headerEnd])
	udp := headerEnd + extLength
	copy(out[udp+8:], spec.Payload)
	binary.BigEndian.PutUint16(out[udp:udp+2], template.SrcPort)
	binary.BigEndian.PutUint16(out[udp+2:udp+4], template.DstPort)
	binary.BigEndian.PutUint16(out[udp+4:udp+6], uint16(8+len(spec.Payload)))
	binary.BigEndian.PutUint16(out[udp+6:udp+8], 0)
	if len(spec.ExtHeaders) > 0 {
		chainOffset := headerEnd
		for index, header := range spec.ExtHeaders {
			following := byte(TransportUDP)
			if index+1 < len(spec.ExtHeaders) {
				following = spec.ExtHeaders[index+1]
			}
			out[chainOffset] = following
			out[chainOffset+1] = 0
			if header == 44 {
				ident := spec.FragmentIdent
				if ident == 0 {
					ident = 1 + spec.random().Uint32()%0xffffffff
				}
				binary.BigEndian.PutUint32(out[chainOffset+4:], ident)
			}
			chainOffset += 8
		}
		out[6] = spec.ExtHeaders[0]
	}
	if spec.TTLSet {
		if template.Family == FamilyIPv4 {
			out[8] = spec.TTL
		} else {
			out[7] = spec.TTL
		}
	}
	if template.Family == FamilyIPv4 {
		if spec.IPIDSet {
			binary.BigEndian.PutUint16(out[4:6], spec.IPID)
		} else {
			binary.BigEndian.PutUint16(out[4:6], template.IPID+1)
		}
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], inetChecksum(out[:template.IPHeaderLen], 0))
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-template.IPHeaderLen))
	}
	sum, err := pseudoHeaderSum(out, template, 8+len(spec.Payload))
	if err != nil {
		return nil, err
	}
	udpSum := inetChecksum(out[udp:udp+8+len(spec.Payload)], sum)
	if udpSum == 0 {
		udpSum = 0xffff
	}
	if spec.CorruptSum {
		udpSum ^= uint16(1 + spec.random().Uint32()%0xffff)
	}
	binary.BigEndian.PutUint16(out[udp+6:udp+8], udpSum)
	return out, nil
}

// FragmentPair splits one IPv4 or IPv6 packet at a transport-relative, 8-byte
// aligned position into two real fragments, porting upstream `ip_frag4` /
// `ip_frag6`.
func FragmentPair(raw []byte, fragPos int, ident uint32, random RandSource) ([]byte, []byte, error) {
	if fragPos&7 != 0 {
		return nil, nil, fmt.Errorf("desync: fragment position is not 8-byte aligned")
	}
	if random == nil {
		random = DefaultRand
	}
	packet, err := ParsePacket(raw)
	if err != nil {
		return nil, nil, err
	}
	if packet.Family == FamilyIPv4 {
		return fragmentIPv4(packet, fragPos, ident)
	}
	return fragmentIPv6(packet, fragPos, ident)
}

func fragmentIPv4(packet *Packet, fragPos int, ident uint32) ([]byte, []byte, error) {
	headerLength := packet.IPHeaderLen
	payloadLength := len(packet.Raw) - headerLength
	if fragPos <= 0 || fragPos >= payloadLength {
		return nil, nil, fmt.Errorf("desync: invalid IPv4 fragment position")
	}
	if ident == 0 {
		ident = uint32(1+DefaultRand.Uint32()%0xffff) & 0xffff
	}
	first := make([]byte, headerLength+fragPos)
	copy(first, packet.Raw[:headerLength+fragPos])
	binary.BigEndian.PutUint16(first[6:8], 0x2000) // MF
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	binary.BigEndian.PutUint16(first[4:6], uint16(ident))
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], inetChecksum(first[:headerLength], 0))

	second := make([]byte, headerLength+payloadLength-fragPos)
	copy(second, packet.Raw[:headerLength])
	copy(second[headerLength:], packet.Raw[headerLength+fragPos:])
	binary.BigEndian.PutUint16(second[6:8], uint16(fragPos>>3))
	binary.BigEndian.PutUint16(second[2:4], uint16(len(second)))
	binary.BigEndian.PutUint16(second[4:6], uint16(ident))
	second[10], second[11] = 0, 0
	binary.BigEndian.PutUint16(second[10:12], inetChecksum(second[:headerLength], 0))
	return first, second, nil
}

func fragmentIPv6(packet *Packet, fragPos int, ident uint32) ([]byte, []byte, error) {
	// unfragmentable is the base header plus the extension-header chain;
	// upstream ip_frag6 inserts the fragment header after that chain and
	// rewrites the last extension header's next-header field, never the base
	// next-header when a chain is present.
	unfragmentable := packet.IPHeaderLen
	payloadLength := len(packet.Raw) - unfragmentable
	if fragPos <= 0 || fragPos >= payloadLength {
		return nil, nil, fmt.Errorf("desync: invalid IPv6 fragment position")
	}
	if ident == 0 {
		ident = 1 + DefaultRand.Uint32()%0xffffffff
	}
	lastNextHeader := 6
	if unfragmentable > 40 {
		// InsertIPv6Extension only builds 8-byte simple headers, so the last
		// header in the chain starts eight bytes before the transport.
		lastNextHeader = unfragmentable - 8
	}
	build := func(offset int, more bool, data []byte) []byte {
		out := make([]byte, unfragmentable+8+len(data))
		copy(out, packet.Raw[:unfragmentable])
		out[lastNextHeader] = 44
		copy(out[unfragmentable+8:], data)
		out[unfragmentable] = byte(packet.Transport)
		binary.BigEndian.PutUint16(out[unfragmentable+2:], uint16(offset))
		if more {
			out[unfragmentable+3] |= 0x01
		}
		binary.BigEndian.PutUint32(out[unfragmentable+4:], ident)
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
		return out
	}
	first := build(0, true, packet.Raw[unfragmentable:unfragmentable+fragPos])
	second := build(fragPos, false, packet.Raw[unfragmentable+fragPos:])
	return first, second, nil
}

// InsertIPv6Extension inserts one simple extension header before the transport
// header, porting upstream `ip6_insert_simple_hdr`.
func InsertIPv6Extension(raw []byte, headerType uint8) ([]byte, error) {
	if len(raw) < 40 || raw[0]>>4 != 6 {
		return nil, fmt.Errorf("desync: not an IPv6 packet")
	}
	out := make([]byte, 0, len(raw)+8)
	out = append(out, raw[:40]...)
	out = append(out, make([]byte, 8)...)
	out = append(out, raw[40:]...)
	out[40] = out[6]
	out[6] = headerType
	binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	return out, nil
}

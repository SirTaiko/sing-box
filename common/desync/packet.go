package desync

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

type Family uint8

const (
	FamilyIPv4 Family = 4
	FamilyIPv6 Family = 6
)

type Transport uint8

const (
	TransportTCP Transport = 6
	TransportUDP Transport = 17
)

type Direction uint8

const (
	DirectionOutbound Direction = iota
	DirectionInbound
)

func (d Direction) String() string {
	if d == DirectionInbound {
		return "inbound"
	}
	return "outbound"
}

// Verdict is the terminal native disposition for one captured packet.
type Verdict uint8

const (
	// VerdictPass delivers the original packet unchanged.
	VerdictPass Verdict = iota
	// VerdictDrop suppresses the original packet; replacements were sent.
	VerdictDrop
	// VerdictModify delivers the original with in-place header modifications.
	VerdictModify
	// VerdictHold keeps the original pending: the caller must not issue any
	// native disposition now. The packet's Completer delivers the terminal
	// verdict exactly once when the assembled message is planned or released.
	VerdictHold
)

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10
)

// Packet is a parsed, unfragmented IPv4/IPv6 TCP or UDP packet. Raw is never
// modified: every transform builds a new byte slice.
type Packet struct {
	Raw                []byte
	Family             Family
	Transport          Transport
	IPHeaderLen        int
	TransportHeaderLen int
	PayloadOffset      int
	Src, Dst           netip.Addr
	SrcPort, DstPort   uint16
	TCPSeq, TCPAck     uint32
	TCPFlags           uint8
	TCPWindow          uint16
	IPID               uint16
	TTL                uint8
	Payload            []byte
	// TCP option facts needed by the upstream generators. WindowScale is -1
	// when the packet carries no window-scale option.
	TCPOptions   []byte
	HasTimestamp bool
	TSVal        uint32
	WindowScale  int
	MSS          uint16
	HasSACK      bool
	HasFastOpen  bool
}

func (p *Packet) HasPayload() bool { return len(p.Payload) > 0 }

func (p *Packet) IsEmptyACK() bool {
	return p.Transport == TransportTCP && p.TCPFlags&tcpFlagACK != 0 &&
		p.TCPFlags&(tcpFlagSYN|tcpFlagFIN|tcpFlagRST) == 0 && len(p.Payload) == 0
}

func (p *Packet) IsSYN() bool { return p.Transport == TransportTCP && p.TCPFlags&tcpFlagSYN != 0 }

// ParsePacket validates and parses one unfragmented packet. Fragmented
// packets, truncated headers and unsupported extension chains are rejected so
// that the caller can pass them through untouched.
func ParsePacket(raw []byte) (*Packet, error) {
	if len(raw) < 1 {
		return nil, fmt.Errorf("desync: empty packet")
	}
	switch raw[0] >> 4 {
	case 4:
		return parseIPv4(raw)
	case 6:
		return parseIPv6(raw)
	default:
		return nil, fmt.Errorf("desync: unknown IP version")
	}
}

func parseIPv4(raw []byte) (*Packet, error) {
	if len(raw) < 20 {
		return nil, fmt.Errorf("desync: truncated IPv4 header")
	}
	ihl := int(raw[0]&0x0f) * 4
	if ihl < 20 || ihl > len(raw) {
		return nil, fmt.Errorf("desync: invalid IPv4 header length")
	}
	totalLength := int(binary.BigEndian.Uint16(raw[2:4]))
	if totalLength < ihl || totalLength > len(raw) {
		return nil, fmt.Errorf("desync: invalid IPv4 total length")
	}
	if binary.BigEndian.Uint16(raw[6:8])&0x3fff != 0 {
		return nil, fmt.Errorf("desync: fragmented IPv4 packet")
	}
	src, ok := netip.AddrFromSlice(raw[12:16])
	if !ok {
		return nil, fmt.Errorf("desync: invalid IPv4 source")
	}
	dst, ok := netip.AddrFromSlice(raw[16:20])
	if !ok {
		return nil, fmt.Errorf("desync: invalid IPv4 destination")
	}
	p := &Packet{
		Raw:         raw[:totalLength],
		Family:      FamilyIPv4,
		IPHeaderLen: ihl,
		Src:         src,
		Dst:         dst,
		IPID:        binary.BigEndian.Uint16(raw[4:6]),
		TTL:         raw[8],
	}
	return parseTransport(p, raw[9], totalLength)
}

var ipv6ExtensionHeaders = map[uint8]bool{0: true, 43: true, 60: true}

func parseIPv6(raw []byte) (*Packet, error) {
	if len(raw) < 40 {
		return nil, fmt.Errorf("desync: truncated IPv6 header")
	}
	payloadLength := int(binary.BigEndian.Uint16(raw[4:6]))
	totalLength := 40 + payloadLength
	if totalLength > len(raw) {
		return nil, fmt.Errorf("desync: truncated IPv6 payload")
	}
	src, ok := netip.AddrFromSlice(raw[8:24])
	if !ok {
		return nil, fmt.Errorf("desync: invalid IPv6 source")
	}
	dst, ok := netip.AddrFromSlice(raw[24:40])
	if !ok {
		return nil, fmt.Errorf("desync: invalid IPv6 destination")
	}
	nextHeader := raw[6]
	offset := 40
	for ipv6ExtensionHeaders[nextHeader] {
		if offset+2 > totalLength {
			return nil, fmt.Errorf("desync: truncated IPv6 extension header")
		}
		headerLength := (int(raw[offset+1]) + 1) * 8
		if offset+headerLength > totalLength {
			return nil, fmt.Errorf("desync: invalid IPv6 extension length")
		}
		nextHeader = raw[offset]
		offset += headerLength
	}
	if nextHeader == 44 {
		return nil, fmt.Errorf("desync: fragmented IPv6 packet")
	}
	p := &Packet{
		Raw:         raw[:totalLength],
		Family:      FamilyIPv6,
		IPHeaderLen: offset,
		Src:         src,
		Dst:         dst,
		TTL:         raw[7],
	}
	if offset < 40 {
		return nil, fmt.Errorf("desync: invalid IPv6 offset")
	}
	// Extension headers are copied verbatim; the transport header follows them.
	return parseTransport(p, nextHeader, totalLength)
}

func parseTransport(p *Packet, protocol uint8, totalLength int) (*Packet, error) {
	offset := p.IPHeaderLen
	if protocol == 6 {
		if offset+20 > totalLength {
			return nil, fmt.Errorf("desync: truncated TCP header")
		}
		dataOffset := int(p.Raw[offset+12]>>4) * 4
		if dataOffset < 20 || offset+dataOffset > totalLength {
			return nil, fmt.Errorf("desync: invalid TCP header length")
		}
		p.Transport = TransportTCP
		p.TransportHeaderLen = dataOffset
		p.PayloadOffset = offset + dataOffset
		p.SrcPort = binary.BigEndian.Uint16(p.Raw[offset : offset+2])
		p.DstPort = binary.BigEndian.Uint16(p.Raw[offset+2 : offset+4])
		p.TCPSeq = binary.BigEndian.Uint32(p.Raw[offset+4 : offset+8])
		p.TCPAck = binary.BigEndian.Uint32(p.Raw[offset+8 : offset+12])
		p.TCPFlags = p.Raw[offset+13]
		p.TCPWindow = binary.BigEndian.Uint16(p.Raw[offset+14 : offset+16])
		p.WindowScale = -1
		p.TCPOptions = p.Raw[offset+20 : offset+dataOffset]
		parseTCPOptions(p)
	} else if protocol == 17 {
		if offset+8 > totalLength {
			return nil, fmt.Errorf("desync: truncated UDP header")
		}
		p.Transport = TransportUDP
		p.TransportHeaderLen = 8
		p.PayloadOffset = offset + 8
		p.SrcPort = binary.BigEndian.Uint16(p.Raw[offset : offset+2])
		p.DstPort = binary.BigEndian.Uint16(p.Raw[offset+2 : offset+4])
		udpLength := int(binary.BigEndian.Uint16(p.Raw[offset+4 : offset+6]))
		if udpLength >= 8 && offset+udpLength <= totalLength {
			p.PayloadOffset = offset + 8
			totalLength = offset + udpLength
			p.Raw = p.Raw[:totalLength]
		}
	} else {
		return nil, fmt.Errorf("desync: unsupported transport protocol %d", protocol)
	}
	p.Payload = p.Raw[p.PayloadOffset:]
	return p, nil
}

func (p *Packet) tcpHeaderOffset() int { return p.IPHeaderLen }

// TCPMods are the header modifications applied to a generated packet.
type TCPMods struct {
	Seq         *uint32
	Ack         *uint32
	Flags       *uint8
	TTL         uint8
	IPID        uint16
	IPIDSet     bool
	TSIncrement int32
	CorruptSum  bool
	// ExtHeaders are the IPv6 extension header chain inserted before the
	// transport header, in wire order (0 hop-by-hop, 60 destination options,
	// 44 fragment). Used by the upstream fooling_orig propagation of the
	// hopbyhop/destopt/ipfrag1 first stage onto every real split segment.
	ExtHeaders []uint8
}

// BuildTCP returns a new TCP packet using template's IP and TCP headers,
// replacing the payload and applying mods.
func BuildTCP(template *Packet, payload []byte, mods TCPMods) ([]byte, error) {
	if template.Transport != TransportTCP {
		return nil, fmt.Errorf("desync: template is not TCP")
	}
	headerEnd := template.PayloadOffset
	out := make([]byte, headerEnd+len(payload))
	copy(out, template.Raw[:headerEnd])
	copy(out[headerEnd:], payload)
	tcp := template.IPHeaderLen
	if mods.Seq != nil {
		binary.BigEndian.PutUint32(out[tcp+4:tcp+8], *mods.Seq)
	}
	if mods.Ack != nil {
		binary.BigEndian.PutUint32(out[tcp+8:tcp+12], *mods.Ack)
	}
	if mods.Flags != nil {
		out[tcp+13] = *mods.Flags
	}
	if mods.TTL != 0 {
		if template.Family == FamilyIPv4 {
			out[8] = mods.TTL
		} else {
			out[7] = mods.TTL
		}
	}
	if mods.TSIncrement != 0 {
		if err := modifyTCPTimestamp(out, tcp, mods.TSIncrement); err != nil {
			return nil, err
		}
	}
	if template.Family == FamilyIPv4 {
		if mods.IPIDSet {
			binary.BigEndian.PutUint16(out[4:6], mods.IPID)
		} else {
			binary.BigEndian.PutUint16(out[4:6], template.IPID+1)
		}
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], inetChecksum(out[:template.IPHeaderLen], 0))
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-template.IPHeaderLen))
	}
	sum, err := pseudoHeaderSum(out, template, len(out)-template.IPHeaderLen)
	if err != nil {
		return nil, err
	}
	out[tcp+16], out[tcp+17] = 0, 0
	tcpSum := inetChecksum(out[tcp:], sum)
	if mods.CorruptSum {
		tcpSum ^= 0xffff
	}
	binary.BigEndian.PutUint16(out[tcp+16:tcp+18], tcpSum)
	if len(mods.ExtHeaders) > 0 {
		// Insert in reverse so the wire order matches the requested chain.
		for index := len(mods.ExtHeaders) - 1; index >= 0; index-- {
			var err error
			out, err = InsertIPv6Extension(out, mods.ExtHeaders[index])
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// BuildUDP returns a new UDP datagram using template's IP and UDP headers.
func BuildUDP(template *Packet, payload []byte, mods TCPMods) ([]byte, error) {
	if template.Transport != TransportUDP {
		return nil, fmt.Errorf("desync: template is not UDP")
	}
	headerEnd := template.PayloadOffset
	out := make([]byte, headerEnd+len(payload))
	copy(out, template.Raw[:headerEnd])
	copy(out[headerEnd:], payload)
	udp := template.IPHeaderLen
	if mods.TTL != 0 {
		if template.Family == FamilyIPv4 {
			out[8] = mods.TTL
		} else {
			out[7] = mods.TTL
		}
	}
	if template.Family == FamilyIPv4 {
		if mods.IPIDSet {
			binary.BigEndian.PutUint16(out[4:6], mods.IPID)
		} else {
			binary.BigEndian.PutUint16(out[4:6], template.IPID+1)
		}
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[10], out[11] = 0, 0
		binary.BigEndian.PutUint16(out[10:12], inetChecksum(out[:template.IPHeaderLen], 0))
	} else {
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-template.IPHeaderLen))
	}
	binary.BigEndian.PutUint16(out[udp+4:udp+6], uint16(len(out)-udp))
	binary.BigEndian.PutUint16(out[udp+6:udp+8], 0)
	sum, err := pseudoHeaderSum(out, template, len(out)-template.IPHeaderLen)
	if err != nil {
		return nil, err
	}
	udpSum := inetChecksum(out[udp:], sum)
	if udpSum == 0 {
		udpSum = 0xffff
	}
	if mods.CorruptSum {
		udpSum ^= 0xffff
	}
	binary.BigEndian.PutUint16(out[udp+6:udp+8], udpSum)
	if len(mods.ExtHeaders) > 0 {
		// Same fooling_orig chain support as BuildTCP: insert after the
		// transport checksum is final so offsets and the pseudo-header stay
		// correct. Insert in reverse for wire order.
		if template.Family != FamilyIPv6 {
			return nil, fmt.Errorf("desync: IPv6 extension headers on a non-IPv6 packet")
		}
		for index := len(mods.ExtHeaders) - 1; index >= 0; index-- {
			var err error
			out, err = InsertIPv6Extension(out, mods.ExtHeaders[index])
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func pseudoHeaderSum(packet []byte, template *Packet, transportLength int) (uint32, error) {
	switch template.Family {
	case FamilyIPv4:
		var sum uint32
		sum += uint32(template.Transport)
		sum += uint32(transportLength)
		for i := 12; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
		}
		return sum, nil
	case FamilyIPv6:
		var sum uint32
		sum += uint32(transportLength)
		sum += uint32(template.Transport)
		for i := 8; i < 40; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
		}
		return sum, nil
	default:
		return 0, fmt.Errorf("desync: unsupported family")
	}
}

func modifyTCPTimestamp(packet []byte, tcpOffset int, increment int32) error {
	headerLength := int(packet[tcpOffset+12]>>4) * 4
	if headerLength < 20 || tcpOffset+headerLength > len(packet) {
		return fmt.Errorf("desync: invalid TCP header length")
	}
	options := packet[tcpOffset+20 : tcpOffset+headerLength]
	for i := 0; i < len(options); {
		kind := options[i]
		if kind == 0 {
			return fmt.Errorf("desync: no TCP timestamp option")
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(options) {
			return fmt.Errorf("desync: truncated TCP option")
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			return fmt.Errorf("desync: invalid TCP option length")
		}
		if kind == 8 {
			if length != 10 {
				return fmt.Errorf("desync: invalid TCP timestamp option length")
			}
			value := binary.BigEndian.Uint32(options[i+2 : i+6])
			binary.BigEndian.PutUint32(options[i+2:i+6], value+uint32(increment))
			return nil
		}
		i += length
	}
	return fmt.Errorf("desync: no TCP timestamp option")
}

func inetChecksum(data []byte, sum uint32) uint16 {
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

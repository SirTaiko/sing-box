package windivert

import (
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

// FilterFacts is the packet-side input of Match: the fields the owned capture
// envelopes constrain. It is a host-side description, not a parsed packet.
type FilterFacts struct {
	Outbound bool
	Inbound  bool
	IPv4     bool
	IPv6     bool
	TCP      bool
	UDP      bool
	ICMP     bool
	SrcAddr  netip.Addr
	DstAddr  netip.Addr
	SrcPort  uint16
	DstPort  uint16
	IfIdx    uint32
	SubIfIdx uint32
}

// Match evaluates a compiled filter against FilterFacts using the driver's
// documented decision tree: evaluate the test at instruction i and follow the
// success or failure continuation until an ACCEPT or REJECT terminal. Address
// fields are compared with the same word encoding the driver's classifier
// produces (argIPv4/argIPv6), so an envelope that accidentally encodes an
// unspecified address as a concrete equality does not get a free pass.
//
// Match is a verification model for the owned-envelope tests. The production
// path is the instruction array itself; nothing on a packet path calls Match.
func (f *Filter) Match(facts FilterFacts) (bool, error) {
	encoded, _, err := f.encode()
	if err != nil {
		return false, err
	}
	if len(encoded)%filterInstBytes != 0 {
		return false, E.New("windivert: match: instruction array is not instruction-aligned")
	}
	instruction := 0
	for steps := 0; steps <= filterMaxInsts; steps++ {
		if instruction >= len(encoded)/filterInstBytes {
			return false, E.New("windivert: match: continuation out of range")
		}
		raw := encoded[instruction*filterInstBytes:]
		word0 := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
		word1 := uint32(raw[4]) | uint32(raw[5])<<8 | uint32(raw[6])<<16 | uint32(raw[7])<<24
		field := uint16(word0 & 0x7FF)
		test := uint8((word0 >> 11) & 0x1F)
		success := uint16(word0 >> 16)
		failure := uint16(word1 & 0xFFFF)
		arg := [4]uint32{
			uint32(raw[8]) | uint32(raw[9])<<8 | uint32(raw[10])<<16 | uint32(raw[11])<<24,
			uint32(raw[12]) | uint32(raw[13])<<8 | uint32(raw[14])<<16 | uint32(raw[15])<<24,
			uint32(raw[16]) | uint32(raw[17])<<8 | uint32(raw[18])<<16 | uint32(raw[19])<<24,
			uint32(raw[20]) | uint32(raw[21])<<8 | uint32(raw[22])<<16 | uint32(raw[23])<<24,
		}
		actual, comparable := facts.value(field)
		matched := false
		if comparable {
			switch test {
			case testEQ:
				matched = actual == arg
			case testNEQ:
				matched = actual != arg
			case testLT:
				matched = actual[0] < arg[0]
			case testLEQ:
				matched = actual[0] <= arg[0]
			case testGT:
				matched = actual[0] > arg[0]
			case testGEQ:
				matched = actual[0] >= arg[0]
			}
		}
		if word1&(1<<16) != 0 {
			matched = !matched
		}
		next := failure
		if matched {
			next = success
		}
		switch next {
		case resultAccept:
			return true, nil
		case resultReject:
			return false, nil
		default:
			instruction = int(next)
		}
	}
	return false, E.New("windivert: match: instruction budget exhausted")
}

// value returns the encoded filter argument for one packet field. The second
// result is false when the fact is absent for this packet (for example an IPv6
// address on an IPv4 packet), which makes every comparison fail instead of
// silently matching a zero word.
func (f FilterFacts) value(field uint16) ([4]uint32, bool) {
	boolean := func(value bool) ([4]uint32, bool) { return argUint32(uint32(boolToUint(value))), true }
	switch field {
	case fieldInbound:
		return boolean(f.Inbound)
	case fieldOutbound:
		return boolean(f.Outbound)
	case fieldIP:
		return boolean(f.IPv4)
	case fieldIPv6:
		return boolean(f.IPv6)
	case fieldTCP:
		return boolean(f.TCP)
	case fieldUDP:
		return boolean(f.UDP)
	case fieldIfIdx:
		return argUint32(f.IfIdx), true
	case fieldSubIfIdx:
		return argUint32(f.SubIfIdx), true
	case fieldICMP, fieldICMPv6:
		return boolean(f.ICMP)
	case fieldIPSrcAddr:
		if f.IPv4 && f.SrcAddr.Is4() {
			return argIPv4(f.SrcAddr), true
		}
		return argUint32(0), true
	case fieldIPDstAddr:
		if f.IPv4 && f.DstAddr.Is4() {
			return argIPv4(f.DstAddr), true
		}
		return argUint32(0), true
	case fieldIPv6SrcAddr:
		if f.IPv6 && f.SrcAddr.Is6() && !f.SrcAddr.Is4In6() {
			return argIPv6(f.SrcAddr), true
		}
		return argUint32(0), true
	case fieldIPv6DstAddr:
		if f.IPv6 && f.DstAddr.Is6() && !f.DstAddr.Is4In6() {
			return argIPv6(f.DstAddr), true
		}
		return argUint32(0), true
	case fieldTCPSrcPort:
		if f.TCP {
			return argUint32(uint32(f.SrcPort)), true
		}
		return argUint32(0), true
	case fieldTCPDstPort:
		if f.TCP {
			return argUint32(uint32(f.DstPort)), true
		}
		return argUint32(0), true
	case fieldUDPSrcPort:
		if f.UDP {
			return argUint32(uint32(f.SrcPort)), true
		}
		return argUint32(0), true
	case fieldUDPDstPort:
		if f.UDP {
			return argUint32(uint32(f.DstPort)), true
		}
		return argUint32(0), true
	}
	return [4]uint32{}, false
}

func boolToUint(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}

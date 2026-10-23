package tools

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// IP range to CIDR cover.
//
// Provider lists may carry inclusive ranges. They are converted to their exact
// minimal CIDR cover without ever expanding individual addresses, bounded by the
// caller's entry budget.

// rangeToPrefixes converts an inclusive address range to its minimal CIDR cover.
func rangeToPrefixes(start netip.Addr, end netip.Addr) []netip.Prefix {
	if start.Is4() != end.Is4() || start.Compare(end) > 0 {
		return nil
	}
	if start.Is4() {
		return rangeToPrefixes4(start, end)
	}
	return rangeToPrefixes6(start, end)
}

func rangeToPrefixes4(start netip.Addr, end netip.Addr) []netip.Prefix {
	first := ipv4ToUint32(start)
	last := ipv4ToUint32(end)
	remaining := uint64(last) - uint64(first) + 1
	var prefixes []netip.Prefix
	for {
		alignedBits := 32
		if first != 0 {
			alignedBits = bits.TrailingZeros32(first)
		}
		prefixBits := 32 - alignedBits
		for prefixBits < 32 {
			block := uint64(1) << uint(32-prefixBits)
			if block <= remaining {
				break
			}
			prefixBits++
		}
		prefixes = append(prefixes, netip.PrefixFrom(uint32ToIPv4(first), prefixBits))
		block := uint64(1) << uint(32-prefixBits)
		if remaining <= block {
			break
		}
		first += uint32(block)
		remaining -= block
		if len(prefixes) > 256 {
			return nil
		}
	}
	return prefixes
}

type ipv6Pair struct {
	high uint64
	low  uint64
}

func ipv6ToPair(address netip.Addr) ipv6Pair {
	bytes := address.As16()
	return ipv6Pair{high: binary.BigEndian.Uint64(bytes[:8]), low: binary.BigEndian.Uint64(bytes[8:])}
}

func (p ipv6Pair) address() netip.Addr {
	var bytes [16]byte
	binary.BigEndian.PutUint64(bytes[:8], p.high)
	binary.BigEndian.PutUint64(bytes[8:], p.low)
	return netip.AddrFrom16(bytes)
}

func (p ipv6Pair) compare(other ipv6Pair) int {
	switch {
	case p.high < other.high:
		return -1
	case p.high > other.high:
		return 1
	case p.low < other.low:
		return -1
	case p.low > other.low:
		return 1
	}
	return 0
}

func (p ipv6Pair) trailingZeros() int {
	if p.low != 0 {
		return bits.TrailingZeros64(p.low)
	}
	if p.high != 0 {
		return 64 + bits.TrailingZeros64(p.high)
	}
	return 128
}

// subtract returns p-other and whether p >= other.
func (p ipv6Pair) subtract(other ipv6Pair) (ipv6Pair, bool) {
	low := p.low - other.low
	borrow := uint64(0)
	if p.low < other.low {
		borrow = 1
	}
	high := p.high - other.high - borrow
	if p.high < other.high+borrow || (borrow == 1 && other.high == ^uint64(0)) {
		return ipv6Pair{}, false
	}
	return ipv6Pair{high: high, low: low}, true
}

func rangeToPrefixes6(start netip.Addr, end netip.Addr) []netip.Prefix {
	first := ipv6ToPair(start)
	last := ipv6ToPair(end)
	// remaining = last - first + 1; a zero pair means the complete 2^128 space.
	remaining, ok := last.subtract(first)
	if !ok {
		return nil
	}
	remaining = remaining.addOne()
	var prefixes []netip.Prefix
	for {
		zeroBits := first.trailingZeros()
		prefixBits := 128 - zeroBits
		for prefixBits < 128 {
			block, fits := ipv6Block(128 - prefixBits)
			if !fits {
				prefixBits++
				continue
			}
			if block.compare(remaining) <= 0 {
				break
			}
			prefixBits++
		}
		prefixes = append(prefixes, netip.PrefixFrom(first.address(), prefixBits))
		block, fits := ipv6Block(128 - prefixBits)
		if !fits {
			// The complete address space was consumed.
			break
		}
		if block.compare(remaining) >= 0 {
			break
		}
		next, overflow := first.add(block)
		if overflow || next.compare(last) > 0 {
			break
		}
		first = next
		remaining, ok = remaining.subtract(block)
		if !ok {
			break
		}
		if len(prefixes) > 1024 {
			return nil
		}
	}
	return prefixes
}

// ipv6Block returns 1<<shift as a pair. shift 128 is the complete address space
// and cannot be represented as a pair.
func ipv6Block(shift int) (ipv6Pair, bool) {
	switch {
	case shift < 0 || shift > 128:
		return ipv6Pair{}, false
	case shift == 128:
		return ipv6Pair{}, false
	case shift == 64:
		return ipv6Pair{high: 1}, true
	case shift > 64:
		return ipv6Pair{high: uint64(1) << uint(shift-64)}, true
	default:
		return ipv6Pair{low: uint64(1) << uint(shift)}, true
	}
}

func (p ipv6Pair) add(other ipv6Pair) (ipv6Pair, bool) {
	low := p.low + other.low
	carry := uint64(0)
	if low < p.low {
		carry = 1
	}
	high := p.high + other.high + carry
	if high < p.high || (carry == 1 && other.high == ^uint64(0)) {
		return ipv6Pair{}, true
	}
	return ipv6Pair{high: high, low: low}, false
}

func (p ipv6Pair) addOne() ipv6Pair {
	result, overflow := p.add(ipv6Pair{low: 1})
	if overflow {
		return ipv6Pair{}
	}
	return result
}

func ipv4ToUint32(address netip.Addr) uint32 {
	bytes := address.Unmap().As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

func uint32ToIPv4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

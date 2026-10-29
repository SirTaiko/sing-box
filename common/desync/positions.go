package desync

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Facts are the resolved L7 anchors used by symbolic split positions.
type Facts struct {
	// MessageLength is the length of the reassembled logical message.
	MessageLength int
	// MethodStart is the offset of the protocol method inside the message.
	MethodStart int
	// HostStart/HostEnd delimit the host value (HTTP Host or TLS SNI).
	HostStart int
	HostEnd   int
	// SLDStart/SLDEnd delimit the second-level domain inside the host value.
	SLDStart int
	SLDEnd   int
	// SNIExtEnd is the offset of the TLS server_name extension BODY: the
	// two-byte server name list length that follows the four-byte extension
	// header. Upstream TLSPos anchors `sniext` on exactly that pointer
	// (`ext-data`, nfq/protocol.c:462-470,549-554). Zero means no anchor.
	SNIExtEnd int
	// Host is the normalized host name, when known.
	Host string
	// HostKnown reports whether Host was derived from L7 data.
	HostKnown bool
	// Protocol is the detected L7 protocol of the message.
	Protocol Protocol
	// HopCount is the bounded upstream `hop_count_guess` of the observed
	// reply TTL. HaveHop false means autottl cannot be evaluated yet.
	HopCount uint8
	HaveHop  bool
	// OrigExtHeaders is the upstream fooling_orig extension-header chain that
	// the hopbyhop/destopt/ipfrag1 first stage must propagate to every real
	// segment of a following split/ipfrag second stage (IPv6 only).
	OrigExtHeaders []uint8
	// Rand is the injected randomness seam; nil uses DefaultRand.
	Rand RandSource

	// counters is the upstream orig-direction limiter state of the packet
	// currently being planned. Unexported: only the flow that observed the
	// packet may supply it, and generated/replayed packets never update it.
	counters flowCounters
	// origCounters is the counter snapshot used by the in-place original
	// modifiers. For a held packet it is the capture-time snapshot, exactly
	// like upstream rewriting the delayed packet before queueing it; the dup
	// stage keeps using the current counters.
	origCounters flowCounters
	// dupCutoffLatched/origModCutoffLatched are the upstream b_dup_cutoff and
	// b_orig_mod_cutoff latches. A reached cutoff stays reached even if a
	// retransmission moves an s-mode limit backwards.
	dupCutoffLatched     bool
	origModCutoffLatched bool
	wssizeCutoffLatched  bool
}

type positionKind uint8

const (
	positionAbsolute positionKind = iota
	positionFromEnd
	positionMethod
	positionHost
	positionEndHost
	positionSLD
	positionEndSLD
	positionMidSLD
	positionSNIExt
)

// Position is one parsed upstream split position. Numeric zero is invalid.
type Position struct {
	Kind   positionKind
	Offset int
	Raw    string
}

var positionMarkers = []struct {
	prefix string
	kind   positionKind
}{
	{"endhost", positionEndHost},
	{"endsld", positionEndSLD},
	{"midsld", positionMidSLD},
	{"sniext", positionSNIExt},
	{"method", positionMethod},
	{"host", positionHost},
	{"sld", positionSLD},
}

// ParsePosition parses upstream position spelling: N, -N, marker, marker+N,
// marker-N. Upstream also accepts deprecated absolute aliases; those are plain
// numbers and are handled by the numeric branch.
func ParsePosition(value string) (Position, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return Position{}, fmt.Errorf("desync: empty split position")
	}
	for _, marker := range positionMarkers {
		if !strings.HasPrefix(value, marker.prefix) {
			continue
		}
		rest := value[len(marker.prefix):]
		offset := 0
		if rest != "" {
			if rest[0] != '+' && rest[0] != '-' {
				continue
			}
			parsed, err := strconv.Atoi(rest)
			if err != nil {
				return Position{}, fmt.Errorf("desync: invalid split position %q", value)
			}
			offset = parsed
		}
		return Position{Kind: marker.kind, Offset: offset, Raw: value}, nil
	}
	negative := strings.HasPrefix(value, "-")
	digits := value
	if negative {
		digits = value[1:]
	}
	parsed, err := strconv.Atoi(digits)
	if err != nil {
		return Position{}, fmt.Errorf("desync: invalid split position %q", value)
	}
	if parsed == 0 {
		return Position{}, fmt.Errorf("desync: split position zero is invalid")
	}
	if negative {
		return Position{Kind: positionFromEnd, Offset: parsed, Raw: value}, nil
	}
	return Position{Kind: positionAbsolute, Offset: parsed, Raw: value}, nil
}

// Resolve maps a position onto an absolute offset in the reassembled message.
// Positions at or beyond the end are dropped, matching upstream's tolerance of
// out-of-range marker arithmetic.
func (p Position) Resolve(facts Facts) (int, bool) {
	var base int
	switch p.Kind {
	case positionAbsolute:
		base = p.Offset
	case positionFromEnd:
		base = facts.MessageLength - p.Offset
	case positionMethod:
		base = facts.MethodStart + p.Offset
	case positionHost:
		base = facts.HostStart + p.Offset
	case positionEndHost:
		base = facts.HostEnd + p.Offset
	case positionSLD:
		base = facts.SLDStart + p.Offset
	case positionEndSLD:
		base = facts.SLDEnd + p.Offset
	case positionMidSLD:
		base = (facts.SLDStart+facts.SLDEnd)/2 + p.Offset
	case positionSNIExt:
		// Upstream TLSPos returns no position at all when TLSFindExt did not
		// find a server_name extension (nfq/protocol.c:549-554); the packet
		// path uses zero as that "anchor absent" sentinel.
		if facts.SNIExtEnd == 0 {
			return 0, false
		}
		base = facts.SNIExtEnd + p.Offset
	default:
		return 0, false
	}
	if base <= 0 || base >= facts.MessageLength {
		return 0, false
	}
	return base, true
}

// ResolvePositions resolves, sorts and deduplicates split positions. It
// mirrors upstream ResolveMultiPos behaviour for the implemented markers.
func ResolvePositions(positions []Position, facts Facts) []int {
	resolved := make([]int, 0, len(positions))
	seen := make(map[int]struct{}, len(positions))
	for _, position := range positions {
		offset, ok := position.Resolve(facts)
		if !ok {
			continue
		}
		if _, exists := seen[offset]; exists {
			continue
		}
		seen[offset] = struct{}{}
		resolved = append(resolved, offset)
	}
	sort.Ints(resolved)
	return resolved
}

// ResolveSeqOverlap resolves a seqovl value that was declared as a position.
func ResolveSeqOverlap(position Position, facts Facts, messageLength int) int {
	if position.Kind == positionAbsolute && position.Offset > 0 {
		return position.Offset
	}
	offset, ok := position.Resolve(Facts{MessageLength: messageLength, MethodStart: facts.MethodStart,
		HostStart: facts.HostStart, HostEnd: facts.HostEnd, SLDStart: facts.SLDStart,
		SLDEnd: facts.SLDEnd, SNIExtEnd: facts.SNIExtEnd})
	if !ok {
		return 0
	}
	return offset
}

package desync

import (
	"bytes"
	"strings"
)

// streamFactSet holds the L7 anchors of one block. It embeds Facts so the
// shared Position.Resolve remains usable, and adds the two upstream anchors
// that Facts cannot express: the SNI extension data pointer (tpws PM_SNI_EXT)
// and whether the HTTP method recognizer succeeded.
//
// The anchor extraction is a port of pinned tpws protocol.c (TLSPos, HttpPos,
// TLSFindExt). The upstream MIT copyright and permission notice for this
// derived code is reproduced in UPSTREAM_LICENSE_zapret_tpws.txt.
type streamFactSet struct {
	Facts
	sniExtAnchor int
	methodOK     bool
	// hostOffset is the offset of the 'H' of the first HTTP `Host:` header, or
	// -1 when there is none. It mirrors the `host-data` pointer of HttpPos,
	// which resolves host markers from the header position even when the value
	// is empty or unterminated. HostKnown stays reserved for rule matching and
	// remains true only for a complete, non-empty value.
	hostOffset int
	// sldOK reports that FindNLD found a second-level domain in the host value.
	// A found SLD may be empty (TLS "..", "a..b"; HTTP "." / ".."), which
	// upstream HostPos still resolves to a position, so this is the parser
	// result and never SLDEnd > SLDStart.
	sldOK bool
}

// classifyStreamBlock mirrors tamper_out protocol detection on one block.
// needMore reports that the block is a prefix of HTTP or TLS and a definitive
// classification is impossible until more bytes arrive.
func classifyStreamBlock(block []byte) (protocol Protocol, needMore bool) {
	if _, ok := streamHTTPMethod(block); ok {
		return ProtocolHTTP, false
	}
	for _, method := range streamHTTPMethods {
		if len(block) < len(method) && bytes.Equal(block, []byte(method[:len(block)])) {
			return ProtocolUnknown, true
		}
	}
	if len(block) == 0 {
		return ProtocolUnknown, true
	}
	if block[0] != 0x16 {
		return ProtocolUnknown, false
	}
	if len(block) < 2 {
		return ProtocolUnknown, true
	}
	if block[1] != 0x03 {
		return ProtocolUnknown, false
	}
	if len(block) < 3 {
		return ProtocolUnknown, true
	}
	if block[2] > 0x03 {
		return ProtocolUnknown, false
	}
	if len(block) < 5 {
		return ProtocolUnknown, true
	}
	recordLength := tlsRecordDataLength(block)
	if recordLength == 0 {
		// A five-byte TLS record header with a zero record length carries no
		// handshake byte. It is a malformed record, not a TLS block; never
		// index block[5] for it.
		return ProtocolUnknown, false
	}
	if len(block) < recordLength+5 {
		return ProtocolUnknown, true
	}
	if block[5] == 0x01 {
		return ProtocolTLS, false
	}
	return ProtocolUnknown, false
}

// streamBlockFacts derives matching and position facts from a block.
func streamBlockFacts(protocol Protocol, block []byte) streamFactSet {
	set := streamFactSet{Facts: Facts{MessageLength: len(block), Protocol: protocol}, hostOffset: -1}
	switch protocol {
	case ProtocolHTTP:
		method := 0
		if len(block) >= 10 {
			for skip := 0; skip < 2 && method < len(block); skip++ {
				if block[method] == '\n' || block[method] == '\r' {
					method++
				}
			}
			letters := 0
			for letters < 7 && method+letters < len(block) &&
				block[method+letters] >= 'A' && block[method+letters] <= 'Z' {
				letters++
			}
			if letters >= 3 && method+letters < len(block) && block[method+letters] == ' ' {
				set.methodOK = true
				set.MethodStart = method
			}
		}
		hostOffset := findHostHeader(block)
		if hostOffset < 0 {
			return set
		}
		set.hostOffset = hostOffset
		start, end, ok, terminated := hostValueBounds(block, hostOffset)
		if !ok {
			return set
		}
		set.HostStart = start
		set.HostEnd = end
		if terminated {
			set.Host = normalizeHostValue(string(block[start:end]))
			set.HostKnown = set.Host != ""
		}
		if sldStart, sldEnd, found := findNLD(block[start:end], 2); found {
			set.SLDStart = start + sldStart
			set.SLDEnd = start + sldEnd
			set.sldOK = true
		}
	case ProtocolTLS:
		anchors := tlsRecordAnchorsOf(block)
		set.HostStart = anchors.HostStart
		set.HostEnd = anchors.HostEnd
		set.SLDStart = anchors.SLDStart
		set.SLDEnd = anchors.SLDEnd
		// sldOK is the FindNLD result, not SLDEnd > SLDStart: upstream reports
		// success for a zero-length SLD ("..", "a..b") and HostPos then
		// resolves a real position for it.
		set.sldOK = anchors.sldFound
		set.Host = normalizeHostValue(anchors.Host)
		set.HostKnown = set.Host != ""
		set.sniExtAnchor = anchors.SNIExtEnd
		// A ClientHello may span several TLS records. Matching uses the
		// reassembled hostname; record-scoped split anchors stay tied to the
		// first record, exactly like tpws.
		if host, _, _, _, complete := parseTLSClientHello(block); host != "" && complete {
			set.Host = normalizeHostValue(host)
			set.HostKnown = true
		}
	}
	return set
}

// normalizeHostValue strips an optional port and lowercases the host, matching
// the normalized hostname tpws feeds into its hostlist matcher.
func normalizeHostValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end > 0 {
			value = value[1:end]
		}
	} else if strings.Count(value, ":") == 1 {
		if index := strings.LastIndexByte(value, ':'); index > 0 {
			value = value[:index]
		}
	}
	return strings.ToLower(value)
}

func checkPos(size int, offset int) int {
	if offset < 0 || offset >= size {
		return 0
	}
	return offset
}

// resolveStreamPosition is ResolvePos from tpws protocol.c for the supported
// protocols. ProtocolUnknown deliberately resolves only absolute/from-end
// positions, like AnyProtoPos; symbolic markers never apply there.
func resolveStreamPosition(position Position, set streamFactSet, protocol Protocol) int {
	size := set.MessageLength
	switch protocol {
	case ProtocolHTTP:
		switch position.Kind {
		case positionMethod:
			if !set.methodOK {
				return 0
			}
			return checkPos(size, set.MethodStart+position.Offset)
		case positionHost, positionEndHost:
			// HttpPos resolves host/endhost from the Host header anchor even
			// when the value is empty or unterminated; only the
			// `host-data+7 < size` precondition applies.
			if set.hostOffset < 0 || set.hostOffset+7 >= size {
				return 0
			}
			return hostPosition(position, set)
		case positionSLD, positionEndSLD, positionMidSLD:
			// HostPos additionally requires FindNLD to succeed on the value.
			if set.hostOffset < 0 || set.hostOffset+7 >= size || !set.sldOK {
				return 0
			}
			return hostPosition(position, set)
		default:
			return anyPosition(position, size)
		}
	case ProtocolTLS:
		switch position.Kind {
		case positionHost, positionEndHost, positionSLD, positionEndSLD, positionMidSLD:
			if !set.hostAnchor() {
				return 0
			}
			return hostPosition(position, set)
		case positionSNIExt:
			if set.sniExtAnchor == 0 {
				return 0
			}
			return checkPos(size, set.sniExtAnchor+position.Offset)
		default:
			return anyPosition(position, size)
		}
	default:
		return anyPosition(position, size)
	}
}

// hostAnchor reports whether the TLS host_name anchor is valid. HostStart is
// assigned only when TLSAdvanceToHostInSNI succeeded and is never zero then,
// so it doubles as the anchor-validity sentinel (like sniExtAnchor). An empty
// host_name is a valid anchor upstream; HostKnown stays false so matching is
// unaffected.
func (set streamFactSet) hostAnchor() bool {
	return set.HostStart != 0
}

func hostPosition(position Position, set streamFactSet) int {
	size := set.MessageLength
	switch position.Kind {
	case positionHost:
		return checkPos(size, set.HostStart+position.Offset)
	case positionEndHost:
		return checkPos(size, set.HostEnd+position.Offset)
	case positionSLD:
		if !set.sldOK {
			return 0
		}
		return checkPos(size, set.SLDStart+position.Offset)
	case positionEndSLD:
		if !set.sldOK {
			return 0
		}
		return checkPos(size, set.SLDEnd+position.Offset)
	case positionMidSLD:
		if !set.sldOK {
			return 0
		}
		length := set.SLDEnd - set.SLDStart
		anchor := set.SLDStart + length/2
		if length == 1 {
			anchor = set.SLDStart + 1
		}
		return checkPos(size, anchor+position.Offset)
	default:
		return 0
	}
}

func anyPosition(position Position, size int) int {
	switch position.Kind {
	case positionAbsolute:
		return checkPos(size, position.Offset)
	case positionFromEnd:
		return checkPos(size, size-position.Offset)
	default:
		return 0
	}
}

// resolveStreamSplitPositions resolves, sorts and deduplicates a split list for
// one block, mirroring ResolveMultiPos (zero offsets are dropped).
func resolveStreamSplitPositions(positions []Position, set streamFactSet, protocol Protocol) []int {
	resolved := make([]int, 0, len(positions))
	for _, position := range positions {
		offset := resolveStreamPosition(position, set, protocol)
		if offset != 0 {
			resolved = append(resolved, offset)
		}
	}
	sortInts(resolved)
	return dedupeInts(resolved)
}

func sortInts(values []int) {
	for index := 1; index < len(values); index++ {
		for position := index; position > 0 && values[position-1] > values[position]; position-- {
			values[position-1], values[position] = values[position], values[position-1]
		}
	}
}

func dedupeInts(values []int) []int {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

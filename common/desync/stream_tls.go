package desync

import "encoding/binary"

// TLS record splitting is a port of the tamper.c TLS branch and the protocol.c
// TLS helpers of pinned tpws (zapret v72.9 c849e55e). Position resolution uses
// the first record only, exactly like tpws IsTLSClientHello(data, size, false).
// The upstream MIT copyright and permission notice for this derived code is
// reproduced in UPSTREAM_LICENSE_zapret_tpws.txt.

func tlsRecordDataLength(block []byte) int {
	return int(binary.BigEndian.Uint16(block[3:5]))
}

func isTLSClientHelloRecord(block []byte, partialOK bool) bool {
	if len(block) < 6 || block[0] != 0x16 || block[1] != 0x03 || block[2] > 0x03 || block[5] != 0x01 {
		return false
	}
	return partialOK || tlsRecordDataLength(block)+5 <= len(block)
}

// tlsRecordAnchors is the anchor set TLSPos derives from one ClientHello
// record: the server_name extension pointer (PM_SNI_EXT), the host_name
// pointer and length (PM_HOST, PM_HOST_END) and the FindNLD result
// (PM_HOST_SLD, PM_HOST_MIDSLD, PM_HOST_ENDSLD).
//
// Upstream does not require the host_name to be non-empty: an empty or
// degenerate name still anchors, and a zero-length second-level domain
// ("..", "a..b") is a *found* SLD with SLDStart == SLDEnd, not a missing one.
// Facts.HostKnown stays reserved for rule matching and remains false for an
// empty or invalid name.
type tlsRecordAnchors struct {
	Facts
	// parsed reports that the record, handshake and extension block are
	// structurally complete, so the anchor fields below are meaningful. A
	// ClientHello without a server_name extension still parses and yields
	// zero anchors, exactly like a failed TLSFindExt(type 0).
	parsed bool
	// hostAnchor reports that TLSAdvanceToHostInSNI succeeded: at least five
	// extension bytes, name type host_name (0) and a declared name length
	// that fits inside the extension body.
	hostAnchor bool
	// sldFound reports that FindNLD succeeded for the host_name.
	sldFound bool
}

// tlsRecordAnchorsOf mirrors TLSFindExtInHandshake, TLSAdvanceToHostInSNI and
// TLSHelloFindNLDInSNI for the first ClientHello record
// (protocol.c:374-513). The record is cut to its declared length like
// TLSFindExt does, and a malformed extension block clears every anchor
// instead of returning a partial set.
func tlsRecordAnchorsOf(block []byte) tlsRecordAnchors {
	anchors := tlsRecordAnchors{Facts: Facts{MessageLength: len(block), Protocol: ProtocolTLS}}
	if !isTLSClientHelloRecord(block, false) {
		return anchors
	}
	handshake := block[5 : 5+tlsRecordDataLength(block)]
	if len(handshake) < 4 {
		return anchors
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < handshakeLength+4 {
		return anchors
	}
	// 1+3 handshake header, then version and random. Upstream reads the
	// following length-prefixed fields from the record data and only requires
	// the declared handshake length to fit, so the bounds use len(handshake).
	offset := 4 + 2 + 32
	if offset >= len(handshake) {
		return anchors
	}
	offset += 1 + int(handshake[offset]) // session id
	if offset+2 > len(handshake) {
		return anchors
	}
	offset += 2 + int(binary.BigEndian.Uint16(handshake[offset:offset+2])) // cipher suites
	if offset >= len(handshake) {
		return anchors
	}
	offset += 1 + int(handshake[offset]) // compression methods
	if offset+2 > len(handshake) {
		return anchors
	}
	extensionLength := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
	offset += 2
	if offset+extensionLength > len(handshake) {
		return anchors
	}
	extensionEnd := offset + extensionLength
	anchors.parsed = true
	for offset+4 <= extensionEnd {
		extensionType := binary.BigEndian.Uint16(handshake[offset : offset+2])
		length := int(binary.BigEndian.Uint16(handshake[offset+2 : offset+4]))
		bodyStart := offset + 4
		bodyEnd := bodyStart + length
		if bodyEnd > extensionEnd {
			// Upstream breaks out of the extension loop, which drops every
			// anchor, including an extension scanned earlier. The SNI anchor
			// lives in Facts, so the whole fact set is rebuilt empty here.
			return tlsRecordAnchors{Facts: Facts{MessageLength: len(block), Protocol: ProtocolTLS}}
		}
		if extensionType == 0 {
			anchors.SNIExtEnd = 5 + bodyStart
			if bodyStart+5 <= bodyEnd && handshake[bodyStart+2] == 0 {
				nameLength := int(binary.BigEndian.Uint16(handshake[bodyStart+3 : bodyStart+5]))
				nameStart := bodyStart + 5
				if nameStart+nameLength <= bodyEnd {
					anchors.hostAnchor = true
					anchors.HostStart = 5 + nameStart
					anchors.HostEnd = 5 + nameStart + nameLength
					anchors.Host = string(handshake[nameStart : nameStart+nameLength])
					// HostKnown must not select a rule for an empty name, but
					// a non-empty degenerate name is still a known host.
					anchors.HostKnown = anchors.Host != ""
					if sldStart, sldEnd, found := findNLD(handshake[nameStart:nameStart+nameLength], 2); found {
						anchors.SLDStart = 5 + nameStart + sldStart
						anchors.SLDEnd = 5 + nameStart + sldEnd
						anchors.sldFound = true
					}
				}
			}
			return anchors
		}
		offset = bodyEnd
	}
	return anchors
}

// tlsRecordFacts is the Facts view of tlsRecordAnchorsOf used by the record
// split seam. ok reports that the record and its extension block parsed, not
// that a host_name anchor exists: a ClientHello without a server_name
// extension parses and yields zero host anchors, exactly like upstream TLSPos.
func tlsRecordFacts(block []byte) (Facts, bool) {
	anchors := tlsRecordAnchorsOf(block)
	return anchors.Facts, anchors.parsed
}

// tlsMidSLDSpecial reports whether tpws midsld treats a one-byte SLD as
// "after the dot". Position.Resolve cannot express that because it floors the
// midpoint; the stream resolver applies this correction.
func tlsMidSLDSpecial(facts Facts) bool {
	return facts.SLDEnd-facts.SLDStart == 1
}

// splitTLSRecord performs the tamper.c TLS record split. splitPositions are
// the already resolved stream split offsets of the original block; upstream
// shifts every position greater than the record boundary by the 5-byte header.
func splitTLSRecord(block []byte, spec *tlsRecordSpec, facts streamFactSet, splitPositions []int) ([]byte, []int, bool) {
	position := resolveStreamPosition(spec.position, facts, ProtocolTLS)
	if position <= 5 {
		return block, splitPositions, false
	}
	if len(block)+5 > cap(block) {
		return block, splitPositions, false
	}
	length := tlsRecordDataLength(block)
	if length < 2 {
		return block, splitPositions, false
	}
	if position-5 >= length {
		position = 6
	}
	oldLength := len(block)
	block = block[:oldLength+5]
	copy(block[position+5:], block[position:oldLength])
	copy(block[position:position+3], block[0:3])
	binary.BigEndian.PutUint16(block[position+3:position+5], uint16(length-(position-5)))
	binary.BigEndian.PutUint16(block[3:5], uint16(position-5))
	shifted := make([]int, len(splitPositions))
	copy(shifted, splitPositions)
	for index := range shifted {
		if shifted[index] > position {
			shifted[index] += 5
		}
	}
	return block, shifted, true
}

package desync

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
)

// reassembler is a bounded, retransmit-safe TCP payload reassembler. Segments
// are keyed by absolute sequence number and overlapping duplicate bytes are
// discarded, so a native retransmission is a counter event but never appends
// duplicate logical bytes.
type reassembler struct {
	limit    int
	segments map[uint32][]byte
	total    int
}

func newReassembler(limit int) *reassembler {
	return &reassembler{limit: limit, segments: make(map[uint32][]byte)}
}

func (r *reassembler) Add(sequence uint32, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if len(data) > r.limit {
		return fmt.Errorf("desync: segment exceeds reassembly limit")
	}
	start := sequence
	end := sequence + uint32(len(data))
	trimmedStart := start
	trimmed := data
	for existingStart, existing := range r.segments {
		existingEnd := existingStart + uint32(len(existing))
		if !sequenceInside(trimmedStart, existingStart, existingEnd) &&
			!sequenceInside(existingStart, trimmedStart, trimmedStart+uint32(len(trimmed))) {
			// Disjoint: also handle the case where the new segment fully
			// covers the existing one; both are kept and merged on extraction.
			continue
		}
		if sequenceBefore(trimmedStart, existingStart) && sequenceBefore(existingEnd, trimmedStart+uint32(len(trimmed))) {
			// Existing segment is inside the new one: drop it.
			delete(r.segments, existingStart)
			r.total -= len(existing)
			continue
		}
		if !sequenceBefore(trimmedStart, existingStart) {
			// New segment starts inside an existing one: trim the head.
			skip := int(trimmedStart - existingStart)
			if skip >= len(trimmed) {
				return nil
			}
			trimmedStart = existingStart + uint32(skip)
			trimmed = trimmed[skip:]
		}
		if sequenceBefore(existingEnd, trimmedStart+uint32(len(trimmed))) && sequenceBefore(trimmedStart, existingEnd) {
			// New segment extends past an existing one: trim the tail so the
			// stored ranges stay disjoint.
			overlap := int(existingEnd - trimmedStart)
			if overlap >= len(trimmed) {
				return nil
			}
			trimmed = trimmed[:overlap]
		}
	}
	_ = end
	if len(trimmed) == 0 {
		return nil
	}
	if r.total+len(trimmed) > r.limit {
		return fmt.Errorf("desync: reassembly limit exceeded")
	}
	r.segments[trimmedStart] = append([]byte(nil), trimmed...)
	r.total += len(trimmed)
	return nil
}

func sequenceBefore(a, b uint32) bool { return int32(a-b) < 0 }

func sequenceInside(value, start, end uint32) bool {
	return !sequenceBefore(value, start) && sequenceBefore(value, end)
}

// Reset drops every stored segment. It is used when a released message must
// not leak into the next one.
func (r *reassembler) Reset() {
	r.segments = make(map[uint32][]byte)
	r.total = 0
}

// Contiguous returns the contiguous byte stream starting at the lowest stored
// sequence number.
func (r *reassembler) Contiguous() (uint32, []byte) {
	if len(r.segments) == 0 {
		return 0, nil
	}
	var start uint32
	first := true
	for sequence := range r.segments {
		if first || sequenceBefore(sequence, start) {
			start = sequence
			first = false
		}
	}
	expected := start
	var out []byte
	for {
		segment, found := r.segments[expected]
		if !found {
			break
		}
		out = append(out, segment...)
		expected += uint32(len(segment))
	}
	return start, out
}

// protocolFacts inspects a TCP byte stream and returns the detected protocol,
// host name and symbolic position anchors.
func protocolFacts(message []byte) (Protocol, string, Facts) {
	facts := Facts{MessageLength: len(message)}
	if len(message) == 0 {
		return ProtocolUnknown, "", facts
	}
	if len(message) >= 1 && message[0] == 0x16 {
		host, hostStart, hostEnd, sniExtEnd, _ := parseTLSClientHello(message)
		facts.HostStart, facts.HostEnd, facts.SNIExtEnd = hostStart, hostEnd, sniExtEnd
		facts.MethodStart = 0
		facts.Protocol = ProtocolTLS
		if host != "" {
			computeSLD(&facts, host)
			facts.Host = host
			facts.HostKnown = true
		}
		return ProtocolTLS, host, facts
	}
	if method, ok := httpMethod(message); ok {
		host, hostStart, hostEnd, ok := parseHTTPHost(message, method)
		if ok {
			facts.HostStart, facts.HostEnd = hostStart, hostEnd
			facts.MethodStart = 0
			facts.Protocol = ProtocolHTTP
			computeSLD(&facts, host)
			facts.Host = host
			facts.HostKnown = true
			return ProtocolHTTP, host, facts
		}
		facts.Protocol = ProtocolHTTP
		return ProtocolHTTP, "", facts
	}
	return ProtocolUnknown, "", facts
}

func computeSLD(facts *Facts, host string) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		facts.SLDStart = facts.HostStart
		facts.SLDEnd = facts.HostEnd
		return
	}
	sld := labels[len(labels)-2]
	index := strings.LastIndex(host, "."+sld)
	if index < 0 {
		// "example.com": the SLD is the first label.
		facts.SLDStart = facts.HostStart
		facts.SLDEnd = facts.HostStart + len(sld)
		return
	}
	facts.SLDStart = facts.HostStart + index + 1
	facts.SLDEnd = facts.SLDStart + len(sld)
}

func httpMethod(message []byte) (int, bool) {
	for _, method := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "} {
		if bytes.HasPrefix(message, []byte(method)) {
			return len(method), true
		}
	}
	return 0, false
}

func parseHTTPHost(message []byte, methodEnd int) (string, int, int, bool) {
	headerEnd := bytes.Index(message, []byte("\r\n\r\n"))
	var header []byte
	if headerEnd < 0 {
		header = message[methodEnd:]
	} else {
		header = message[methodEnd:headerEnd]
	}
	offset := methodEnd
	for _, line := range bytes.Split(header, []byte("\r\n")) {
		lineStart := offset
		offset += len(line) + 2
		if len(line) < 5 {
			continue
		}
		if !bytes.EqualFold(line[:5], []byte("host:")) {
			continue
		}
		value := bytes.TrimSpace(line[5:])
		hostIndex := bytes.Index(line[5:], value)
		if hostIndex < 0 {
			continue
		}
		valueStart := lineStart + 5 + hostIndex
		host := string(value)
		if index := strings.LastIndex(host, ":"); index > 0 && !strings.Contains(host[index:], "]") {
			host = host[:index]
		}
		return host, valueStart, valueStart + len(host), true
	}
	return "", 0, 0, false
}

// messageComplete reports whether the logical message at the front of the
// contiguous stream is fully present. Only complete messages are transformed
// after a hold; an incomplete one is released unchanged at the deadline.
func messageComplete(protocol Protocol, message []byte) bool {
	switch protocol {
	case ProtocolTLS:
		_, _, _, _, complete := parseTLSClientHello(message)
		return complete
	case ProtocolHTTP:
		return bytes.Index(message, []byte("\r\n\r\n")) >= 0
	default:
		return true
	}
}

// looksLikeStructuredMessage reports whether the payload could start a TLS
// handshake record or an HTTP request. Unknown traffic is never held.
func looksLikeStructuredMessage(message []byte) bool {
	if len(message) == 0 {
		return false
	}
	if message[0] == 0x16 {
		return true
	}
	return isHTTPMethodPrefix(message)
}

func isHTTPMethodPrefix(message []byte) bool {
	for _, method := range []string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH "} {
		probe := message
		if len(probe) > len(method) {
			probe = probe[:len(method)]
		}
		if bytes.HasPrefix([]byte(method), probe) {
			return true
		}
	}
	return false
}

// tlsSegment maps a range of the concatenated handshake bytes back to its
// offset in the captured byte stream, preserving record-to-stream offsets for
// symbolic markers.
type tlsSegment struct {
	handshakeStart int
	streamStart    int
	length         int
}

func streamOffset(segments []tlsSegment, index int) int {
	for _, segment := range segments {
		if index >= segment.handshakeStart && index < segment.handshakeStart+segment.length {
			return segment.streamStart + index - segment.handshakeStart
		}
	}
	if len(segments) > 0 {
		last := segments[len(segments)-1]
		return last.streamStart + last.length
	}
	return index
}

// collectTLSHandshake concatenates the handshake bytes of consecutive TLS
// handshake records. complete is true only when the ClientHello handshake body
// is fully covered by the captured records.
func collectTLSHandshake(message []byte) ([]byte, []tlsSegment, bool) {
	var (
		handshake []byte
		segments  []tlsSegment
	)
	offset := 0
	for offset < len(message) {
		if offset+5 > len(message) || message[offset] != 0x16 {
			break
		}
		recordLength := int(binary.BigEndian.Uint16(message[offset+3 : offset+5]))
		start := offset + 5
		end := start + recordLength
		available := end
		if available > len(message) {
			available = len(message)
		}
		if available > start {
			segments = append(segments, tlsSegment{handshakeStart: len(handshake), streamStart: start, length: available - start})
			handshake = append(handshake, message[start:available]...)
		}
		if end > len(message) {
			return handshake, segments, false
		}
		offset = end
		if len(handshake) >= 4 && handshake[0] == 0x01 {
			need := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if len(handshake) >= need {
				return handshake, segments, true
			}
		}
	}
	if len(handshake) >= 4 && handshake[0] == 0x01 {
		need := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
		return handshake, segments, len(handshake) >= need
	}
	return handshake, segments, false
}

// parseTLSClientHello parses a TLS ClientHello that may span multiple TLS
// records. Offsets are returned in captured-stream coordinates and complete
// reports whether the whole handshake body is present.
func parseTLSClientHello(message []byte) (host string, hostStart int, hostEnd int, sniExtEnd int, complete bool) {
	handshake, segments, complete := collectTLSHandshake(message)
	host, helloStart, helloEnd, helloExt, helloOK := parseClientHelloBytes(handshake)
	if !helloOK {
		return "", 0, 0, 0, false
	}
	return host, streamOffset(segments, helloStart), streamOffset(segments, helloEnd),
		streamOffset(segments, helloExt), complete
}

// parseClientHelloBytes bounds-checks a concatenated ClientHello handshake and
// extracts the SNI value and the end offset of the server_name extension.
func parseClientHelloBytes(handshake []byte) (host string, hostStart int, hostEnd int, sniExtEnd int, ok bool) {
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return "", 0, 0, 0, false
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	handshakeEnd := 4 + handshakeLength
	if handshakeEnd > len(handshake) {
		handshakeEnd = len(handshake)
	}
	offset := 4
	if offset+34 > handshakeEnd {
		return "", 0, 0, 0, false
	}
	offset += 34 // legacy version + random
	if offset >= handshakeEnd {
		return "", 0, 0, 0, false
	}
	sessionIDLength := int(handshake[offset])
	offset += 1 + sessionIDLength
	if offset+2 > handshakeEnd {
		return "", 0, 0, 0, false
	}
	cipherLength := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
	offset += 2 + cipherLength
	if offset >= handshakeEnd {
		return "", 0, 0, 0, false
	}
	compressionLength := int(handshake[offset])
	offset += 1 + compressionLength
	if offset+2 > handshakeEnd {
		return "", 0, 0, 0, false
	}
	extensionLength := int(binary.BigEndian.Uint16(handshake[offset : offset+2]))
	offset += 2
	extensionEnd := offset + extensionLength
	if extensionEnd > handshakeEnd {
		extensionEnd = handshakeEnd
	}
	for offset+4 <= extensionEnd {
		extensionType := binary.BigEndian.Uint16(handshake[offset : offset+2])
		length := int(binary.BigEndian.Uint16(handshake[offset+2 : offset+4]))
		bodyStart := offset + 4
		bodyEnd := bodyStart + length
		if bodyEnd > extensionEnd {
			return "", 0, 0, 0, false
		}
		if extensionType == 0 {
			// O1: the pinned C splitter still finds the SNI extension anchor
			// when the host_name is rejected, and an empty or non-host_name
			// entry is parsed but never matchable. The shared reassembler must
			// behave the same: the hello is complete (no deferred hold), the
			// extension anchor is kept, and no host is reported.
			sniExtEnd = bodyEnd
			if bodyStart+5 > bodyEnd {
				return "", 0, 0, sniExtEnd, true
			}
			nameType := handshake[bodyStart+2]
			nameLength := int(binary.BigEndian.Uint16(handshake[bodyStart+3 : bodyStart+5]))
			nameStart := bodyStart + 5
			nameEnd := nameStart + nameLength
			if nameType != 0 || nameLength == 0 || nameEnd > bodyEnd {
				return "", 0, 0, sniExtEnd, true
			}
			return string(handshake[nameStart:nameEnd]), nameStart, nameEnd, sniExtEnd, true
		}
		offset = bodyEnd
	}
	return "", 0, 0, 0, false
}

// flowKey identifies per-peer state of a UDP listener lease.
func flowKey(destination netip.AddrPort) string {
	return destination.String()
}

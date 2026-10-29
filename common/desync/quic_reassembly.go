package desync

// Cross-datagram QUIC Initial CRYPTO reassembly.
//
// Upstream (nfq/protocol.c QUICDefragCrypto) defragments the CRYPTO frames of
// one Initial datagram. A ClientHello larger than one Initial is split by the
// client across several Initial packets (RFC 9001 allows this), so a bounded
// per-connection reassembler is required to obtain the SNI fact. The bounds
// keep the cost of hostile datagrams small and the connection identity
// (DCID+version) prevents unrelated datagrams from being concatenated.
//
// Nothing is learned before decryption and AEAD validation: a datagram that
// does not authenticate cannot contribute bytes or facts.

import (
	"bytes"
	"encoding/binary"
	"sort"
)

const (
	// maxQUICReassemblyBytes bounds the CRYPTO stream of one connection.
	// QUIC Initial datagrams are at most ~1200 bytes of CRYPTO payload, so a
	// few Initials are enough for a ClientHello; anything larger is hostile or
	// unrelated and is refused.
	maxQUICReassemblyBytes = 16 * 1024
	// maxQUICReassemblyPieces bounds the stored fragments of one connection.
	maxQUICReassemblyPieces = 256
)

type quicCryptoFragment struct {
	offset int
	data   []byte
}

// quicParseResult is the bounded outcome of parsing one decrypted Initial's
// frames. A malformed frame is a parser refusal; a frame that exceeds the
// reassembly bound is a resource refusal. Pinned treats the two differently:
// only the parser refusal is eligible for the desync_any_proto continuation,
// while reassembly-too-long goes directly to send_orig.
type quicParseResult uint8

const (
	quicParseOK quicParseResult = iota
	quicParseMalformed
	quicParseOverflow
)

// parseQUICCryptoFragments extracts every CRYPTO frame (type 6) from a
// decrypted Initial payload without requiring contiguity. Any other non
// PADDING/PING frame type ends the scan, exactly like the single-datagram
// upstream path: unsupported framing is rejected instead of guessed.
func parseQUICCryptoFragments(plaintext []byte) ([]quicCryptoFragment, quicParseResult) {
	fragments := make([]quicCryptoFragment, 0, 4)
	position := 0
	for position < len(plaintext) {
		frameType := plaintext[position]
		position++
		if frameType <= 1 {
			continue
		}
		if frameType != 6 {
			return nil, quicParseMalformed
		}
		frameOffset, size, ok := parseQUICVarint(plaintext, position)
		if !ok {
			return nil, quicParseMalformed
		}
		position += size
		frameLength, size, ok := parseQUICVarint(plaintext, position)
		if !ok {
			return nil, quicParseMalformed
		}
		position += size
		if frameOffset > maxQUICReassemblyBytes ||
			frameLength > maxQUICReassemblyBytes ||
			frameOffset+frameLength > maxQUICReassemblyBytes {
			return nil, quicParseOverflow
		}
		if position+int(frameLength) > len(plaintext) {
			return nil, quicParseMalformed
		}
		data := make([]byte, int(frameLength))
		copy(data, plaintext[position:position+int(frameLength)])
		fragments = append(fragments, quicCryptoFragment{offset: int(frameOffset), data: data})
		position += int(frameLength)
	}
	if len(fragments) == 0 {
		return nil, quicParseMalformed
	}
	return fragments, quicParseOK
}

// quicCryptoState is the upstream admission state of one captured Initial
// datagram after CRYPTO processing. A QUIC fake unit belongs only to a
// completed reassembly cycle, never to every datagram that happens to pass the
// same flow: pinned nfq/desync.c queues the Initials of an incomplete
// ClientHello, replays the queue when the cycle completes and emits the fake
// burst only for the queue head (reasm_offset == 0). The three states below are
// that distinction.
type quicCryptoState uint8

const (
	// quicCryptoRejected: decryption, CRYPTO framing, connection identity or a
	// reassembly bound refused the datagram. Upstream quic_reasm_cancel()
	// clears the session and sends the originals unchanged; only a profile
	// with desync_any_proto continues to tampering.
	quicCryptoRejected quicCryptoState = iota
	// quicCryptoPending: the datagram authenticated and its fragments were
	// accepted, but the accumulated stream does not yet carry a complete TLS
	// handshake message. Upstream delays such a datagram and replays it after
	// completion; it never owns a fake burst of its own.
	quicCryptoPending
	// quicCryptoComplete: the accumulated stream carries a complete handshake
	// message from offset zero. Upstream finishes the delayed replay cycle
	// here and belongs exactly one fake burst to the cycle.
	quicCryptoComplete
)

// quicReassembler accumulates validated CRYPTO fragments of one connection.
// It is per flow and therefore cannot mix datagrams of unrelated connections;
// the explicit DCID+version identity additionally rejects a stray datagram of
// a different connection arriving on the same flow tuple.
type quicReassembler struct {
	version   uint32
	dcid      []byte
	fragments []quicCryptoFragment
	bytes     int
}

func newQUICReassembler() *quicReassembler { return &quicReassembler{} }

// fragmentsContiguous reports whether one datagram's CRYPTO frames alone form
// a contiguous stream from offset zero.
func fragmentsContiguous(fragments []quicCryptoFragment) bool {
	ordered := append([]quicCryptoFragment(nil), fragments...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].offset < ordered[j].offset })
	if len(ordered) == 0 || ordered[0].offset != 0 {
		return false
	}
	covered := 0
	for _, fragment := range ordered {
		if fragment.offset > covered {
			return false
		}
		if end := fragment.offset + len(fragment.data); end > covered {
			covered = end
		}
	}
	return true
}

// fragmentsCoverage is the contiguous byte span starting at offset zero.
func fragmentsCoverage(fragments []quicCryptoFragment) int {
	ordered := append([]quicCryptoFragment(nil), fragments...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].offset < ordered[j].offset })
	covered := 0
	for _, fragment := range ordered {
		if fragment.offset > covered {
			break
		}
		if end := fragment.offset + len(fragment.data); end > covered {
			covered = end
		}
	}
	return covered
}

// coverage reports the contiguous byte span of the accumulated stream.
func (q *quicReassembler) coverage() int {
	return fragmentsCoverage(q.fragments)
}

// maxEnd is the highest byte offset covered by the accumulated fragments.
func (q *quicReassembler) maxEnd() int {
	end := 0
	for _, fragment := range q.fragments {
		if fragmentEnd := fragment.offset + len(fragment.data); fragmentEnd > end {
			end = fragmentEnd
		}
	}
	return end
}

// supersedes reports whether a datagram's own contiguous CRYPTO stream is
// authoritative over the assembled one: it grows beyond the assembled coverage
// or carries different bytes inside it. An exact duplicate (or a shorter exact
// prefix) does not supersede anything, so a retransmission is merged instead of
// cancelling the originals already queued for the cycle.
func (q *quicReassembler) supersedes(fragments []quicCryptoFragment) bool {
	existing, ok := q.contiguous()
	if !ok {
		return true
	}
	candidateLength := 0
	for _, fragment := range fragments {
		if end := fragment.offset + len(fragment.data); end > candidateLength {
			candidateLength = end
		}
	}
	if candidateLength > len(existing) {
		return true
	}
	candidate := make([]byte, candidateLength)
	for _, fragment := range fragments {
		copy(candidate[fragment.offset:], fragment.data)
	}
	overlap := candidateLength
	if overlap > len(existing) {
		overlap = len(existing)
	}
	return !bytes.Equal(candidate[:overlap], existing[:overlap])
}

func (q *quicReassembler) reset() {
	q.version = 0
	q.dcid = nil
	q.fragments = nil
	q.bytes = 0
}

// quicFeedResult is the internal per-datagram result of the CRYPTO owner. It
// extends the two-value feed result with the information the packet queue owner
// needs: whether accumulated state of an earlier cycle was discarded before
// this datagram (so its held originals must be cancelled first) and whether a
// refusal came from a bounded resource rather than the parser (so it is not
// eligible for the any-protocol continuation).
type quicFeedResult struct {
	state quicCryptoState
	host  string
	// sniPresent reports that the completed ClientHello carried a usable
	// server_name extension even though it yielded no hostname (an empty
	// host_name entry). Pinned TLSHelloExtractHostFromHandshake returns true
	// for that shape (bHaveHost) but false when the extension is absent, which
	// is the desync_skip_nosni gate at nfq/desync.c:2990-2998. Only meaningful
	// when state == quicCryptoComplete.
	sniPresent bool
	// replaced reports that state belonging to an earlier cycle was discarded
	// before this datagram: the connection identity (DCID/version) changed or
	// an authoritative contiguous CRYPTO stream superseded the assembled one.
	replaced bool
	// resource reports that a bounded reassembly resource refused the
	// datagram. Upstream sends such an original unchanged; it is not the
	// desync_any_proto continuation gate.
	resource bool
}

// add feeds one captured client Initial datagram and reports a hostname once
// the reassembled CRYPTO stream contains a complete, parseable ClientHello.
// Discontiguous and out-of-order fragments are kept; exact retransmissions are
// deduplicated; conflicting overlaps, malformed frames and oversized streams
// are refused without inventing a fact.
func (q *quicReassembler) add(datagram []byte) (string, bool) {
	result := q.feedCycle(datagram)
	if result.state != quicCryptoComplete {
		return "", false
	}
	return result.host, true
}

// feed adds one captured Initial datagram and reports the pinned admission
// state of its CRYPTO session together with the hostname when this datagram
// completes a ClientHello. A rejected datagram cancels the whole session
// (upstream quic_reasm_cancel -> reasm_orig_cancel), so later fragments cannot
// silently continue a stream the pinned path already discarded. A datagram
// that completes the stream is returned as complete without clearing it: the
// caller decides when the cycle ends (the flow resets after consuming the one
// fake unit the cycle owns).
func (q *quicReassembler) feed(datagram []byte) (string, quicCryptoState) {
	result := q.feedCycle(datagram)
	return result.host, result.state
}

// feedCycle is feed with the full internal result the bounded packet queue
// needs. It is the only seam that reports cycle replacement and the
// parser-versus-resource refusal category; the pinned admission enum stays
// unchanged for callers that only need the three upstream states.
func (q *quicReassembler) feedCycle(datagram []byte) quicFeedResult {
	stream, result := q.feedStream(datagram)
	if result.state != quicCryptoComplete {
		return result
	}
	result.host, result.sniPresent = quicClientHelloSNI(stream)
	return result
}

// quicClientHelloSNI extracts the server_name host_name of a completed QUIC
// ClientHello and reports whether that extension was present and structurally
// usable. It mirrors the pinned extractor used at nfq/desync.c:2992:
// TLSFindExtInHandshake(type 0) followed by TLSExtractHostFromExt, whose
// TLSAdvanceToHostInSNI accepts any five-byte-or-longer body whose name type
// is host_name and whose declared name fits. A present extension with an empty
// host_name therefore yields ("", true) and is not the SkipNoSNI case; an
// absent or unusable extension yields ("", false).
func quicClientHelloSNI(handshake []byte) (string, bool) {
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return "", false
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	handshakeEnd := 4 + handshakeLength
	if handshakeEnd > len(handshake) {
		return "", false
	}
	// TLS ClientHello layout: legacy version + random, session id, cipher
	// suites, compression methods, extensions.
	offset := 4
	if offset+34 > handshakeEnd {
		return "", false
	}
	offset += 34
	if offset >= handshakeEnd {
		return "", false
	}
	offset += 1 + int(handshake[offset])
	if offset+2 > handshakeEnd {
		return "", false
	}
	offset += 2 + int(binary.BigEndian.Uint16(handshake[offset:offset+2]))
	if offset >= handshakeEnd {
		return "", false
	}
	offset += 1 + int(handshake[offset])
	if offset+2 > handshakeEnd {
		return "", false
	}
	extensionEnd := offset + 2 + int(binary.BigEndian.Uint16(handshake[offset:offset+2]))
	if extensionEnd > handshakeEnd {
		extensionEnd = handshakeEnd
	}
	offset += 2
	for offset+4 <= extensionEnd {
		extensionType := binary.BigEndian.Uint16(handshake[offset : offset+2])
		length := int(binary.BigEndian.Uint16(handshake[offset+2 : offset+4]))
		bodyStart := offset + 4
		bodyEnd := bodyStart + length
		if bodyEnd > extensionEnd {
			return "", false
		}
		if extensionType == 0 {
			// u16 server name list length, u8 name type, u16 name length.
			if length < 5 || handshake[bodyStart+2] != 0 {
				return "", false
			}
			nameLength := int(binary.BigEndian.Uint16(handshake[bodyStart+3 : bodyStart+5]))
			if nameLength > length-5 {
				return "", false
			}
			return string(handshake[bodyStart+5 : bodyStart+5+nameLength]), true
		}
		offset = bodyEnd
	}
	return "", false
}

// feedStream is the shared decrypt and CRYPTO reassembly step. It returns the
// contiguous CRYPTO stream only when it holds a complete TLS handshake message.
func (q *quicReassembler) feedStream(datagram []byte) ([]byte, quicFeedResult) {
	result := quicFeedResult{state: quicCryptoPending}
	plaintext, dcid, version, ok := decryptQUICInitialPacket(datagram)
	if !ok {
		q.reset()
		result.state = quicCryptoRejected
		return nil, result
	}
	if len(q.dcid) != 0 && (q.version != version || !bytes.Equal(q.dcid, dcid)) {
		// A different connection on the same owned tuple: never concatenate.
		// The owner is told so the originals of the replaced cycle are
		// cancelled before this datagram becomes a new cycle.
		q.reset()
		result.replaced = true
	}
	if len(q.dcid) == 0 {
		q.dcid = append([]byte(nil), dcid...)
		q.version = version
	}
	fragments, parse := parseQUICCryptoFragments(plaintext)
	if parse != quicParseOK {
		q.reset()
		result.state = quicCryptoRejected
		result.resource = parse == quicParseOverflow
		return nil, result
	}
	if fragmentsContiguous(fragments) && q.coverage() > 0 {
		// A datagram that carries a complete CRYPTO stream at least as large as
		// everything assembled so far is authoritative for this connection
		// identity: a retransmitted Initial may replace earlier bytes instead
		// of conflicting with them. An exact duplicate (same bytes, no growth)
		// is only merged, so a captured duplicate never cancels the queued
		// originals of its own cycle.
		if q.supersedes(fragments) {
			q.fragments = nil
			q.bytes = 0
			result.replaced = true
		}
	}
	for _, fragment := range fragments {
		switch q.insert(fragment) {
		case quicInsertRefused:
			// Upstream reasm_orig_feed failure clears the session and sends the
			// delayed originals unchanged.
			q.reset()
			result.state = quicCryptoRejected
			return nil, result
		case quicInsertResource:
			q.reset()
			result.state = quicCryptoRejected
			result.resource = true
			return nil, result
		}
	}
	stream, contiguous := q.contiguous()
	if !contiguous {
		return nil, result
	}
	// Upstream requires the reassembled stream to be a TLS handshake message
	// (QUICCryptoHello) and then asks whether the declared handshake body is
	// fully present (IsTLSHandshakeFull). A stream that is not a ClientHello is
	// cancelled; a partial ClientHello stays delayed.
	if len(stream) < 4 || stream[0] != 0x01 {
		q.reset()
		result.state = quicCryptoRejected
		return nil, result
	}
	declared := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
	if declared > len(stream)-4 {
		return nil, result
	}
	// The handshake body is complete. A ClientHello without a usable SNI is
	// still a completed cycle upstream (bReqFull); it simply yields no host
	// fact of its own.
	result.state = quicCryptoComplete
	return stream, result
}

// quicInsertResult is the bounded outcome of merging one CRYPTO fragment.
type quicInsertResult uint8

const (
	quicInsertStored quicInsertResult = iota
	quicInsertCovered
	// quicInsertRefused: the fragment itself is malformed or conflicts with
	// bytes already assembled. This is a parser refusal.
	quicInsertRefused
	// quicInsertResource: the fragment would exceed the bounded reassembly
	// resources. Upstream sends the original unchanged and never routes this
	// through the any-protocol continuation gate.
	quicInsertResource
)

// insert merges one fragment. Identical retransmissions are ignored; an
// overlap must agree byte-for-byte.
func (q *quicReassembler) insert(fragment quicCryptoFragment) quicInsertResult {
	if fragment.offset < 0 || len(fragment.data) == 0 {
		return quicInsertRefused
	}
	if fragment.offset+len(fragment.data) > maxQUICReassemblyBytes {
		return quicInsertResource
	}
	if len(q.fragments) >= maxQUICReassemblyPieces {
		return quicInsertResource
	}
	if q.bytes+len(fragment.data) > maxQUICReassemblyBytes {
		return quicInsertResource
	}
	fragmentEnd := fragment.offset + len(fragment.data)
	for _, existing := range q.fragments {
		existingEnd := existing.offset + len(existing.data)
		if existingEnd <= fragment.offset || fragmentEnd <= existing.offset {
			continue
		}
		overlapStart := maxInt(existing.offset, fragment.offset)
		overlapEnd := minInt(existingEnd, fragmentEnd)
		existingBytes := existing.data[overlapStart-existing.offset : overlapEnd-existing.offset]
		fragmentBytes := fragment.data[overlapStart-fragment.offset : overlapEnd-fragment.offset]
		if !bytes.Equal(existingBytes, fragmentBytes) {
			// A conflicting overlap is a malformed or spoofed stream: refuse it
			// instead of picking one side.
			return quicInsertRefused
		}
	}
	// Trim the parts already covered to keep the bound honest.
	if q.covered(fragment.offset, fragmentEnd) {
		return quicInsertCovered
	}
	q.fragments = append(q.fragments, fragment)
	q.bytes += len(fragment.data)
	return quicInsertStored
}

func (q *quicReassembler) covered(start, end int) bool {
	covered := start
	ordered := append([]quicCryptoFragment(nil), q.fragments...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].offset < ordered[j].offset })
	for _, fragment := range ordered {
		if fragment.offset > covered {
			break
		}
		if fragmentEnd := fragment.offset + len(fragment.data); fragmentEnd > covered {
			covered = fragmentEnd
		}
	}
	return covered >= end
}

// contiguous returns the CRYPTO stream when it starts at offset zero with no
// gap. A gap means the ClientHello cannot be parsed yet, so no fact exists.
func (q *quicReassembler) contiguous() ([]byte, bool) {
	if len(q.fragments) == 0 {
		return nil, false
	}
	ordered := append([]quicCryptoFragment(nil), q.fragments...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].offset < ordered[j].offset })
	if ordered[0].offset != 0 {
		return nil, false
	}
	covered := 0
	for _, fragment := range ordered {
		if fragment.offset > covered {
			return nil, false
		}
		if fragmentEnd := fragment.offset + len(fragment.data); fragmentEnd > covered {
			covered = fragmentEnd
		}
	}
	stream := make([]byte, covered)
	for _, fragment := range ordered {
		copy(stream[fragment.offset:], fragment.data)
	}
	return stream, true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

// parseQUICCryptoFragments extracts every CRYPTO frame (type 6) from a
// decrypted Initial payload without requiring contiguity. Any other non
// PADDING/PING frame type ends the scan, exactly like the single-datagram
// upstream path: unsupported framing is rejected instead of guessed.
func parseQUICCryptoFragments(plaintext []byte) ([]quicCryptoFragment, bool) {
	fragments := make([]quicCryptoFragment, 0, 4)
	position := 0
	for position < len(plaintext) {
		frameType := plaintext[position]
		position++
		if frameType <= 1 {
			continue
		}
		if frameType != 6 {
			return nil, false
		}
		frameOffset, size, ok := parseQUICVarint(plaintext, position)
		if !ok {
			return nil, false
		}
		position += size
		frameLength, size, ok := parseQUICVarint(plaintext, position)
		if !ok {
			return nil, false
		}
		position += size
		if frameOffset > maxQUICReassemblyBytes ||
			frameLength > maxQUICReassemblyBytes ||
			frameOffset+frameLength > maxQUICReassemblyBytes ||
			position+int(frameLength) > len(plaintext) {
			return nil, false
		}
		data := make([]byte, int(frameLength))
		copy(data, plaintext[position:position+int(frameLength)])
		fragments = append(fragments, quicCryptoFragment{offset: int(frameOffset), data: data})
		position += int(frameLength)
	}
	if len(fragments) == 0 {
		return nil, false
	}
	return fragments, true
}

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

func (q *quicReassembler) reset() {
	q.version = 0
	q.dcid = nil
	q.fragments = nil
	q.bytes = 0
}

// add feeds one captured client Initial datagram and reports a hostname once
// the reassembled CRYPTO stream contains a complete, parseable ClientHello.
// Discontiguous and out-of-order fragments are kept; exact retransmissions are
// deduplicated; conflicting overlaps, malformed frames and oversized streams
// are refused without inventing a fact.
func (q *quicReassembler) add(datagram []byte) (string, bool) {
	plaintext, dcid, version, ok := decryptQUICInitialPacket(datagram)
	if !ok {
		return "", false
	}
	if len(q.dcid) != 0 && (q.version != version || !bytes.Equal(q.dcid, dcid)) {
		// A different connection on the same owned tuple: never concatenate.
		q.reset()
	}
	if len(q.dcid) == 0 {
		q.dcid = append([]byte(nil), dcid...)
		q.version = version
	}
	fragments, ok := parseQUICCryptoFragments(plaintext)
	if !ok {
		return "", false
	}
	if fragmentsContiguous(fragments) && q.coverage() > 0 {
		// A datagram that carries a complete CRYPTO stream at least as large as
		// everything assembled so far is authoritative for this connection
		// identity: a retransmitted Initial may replace earlier bytes instead
		// of conflicting with them. A smaller standalone datagram is merged so
		// out-of-order multi-datagram reassembly still completes.
		q.fragments = nil
		q.bytes = 0
	}
	for _, fragment := range fragments {
		if !q.insert(fragment) {
			return "", false
		}
	}
	stream, ok := q.contiguous()
	if !ok {
		return "", false
	}
	host, _, _, _, complete := parseTLSClientHello(stream)
	if !complete || host == "" {
		return "", false
	}
	return host, true
}

// insert merges one fragment. Identical retransmissions are ignored; an
// overlap must agree byte-for-byte.
func (q *quicReassembler) insert(fragment quicCryptoFragment) bool {
	if fragment.offset < 0 || len(fragment.data) == 0 ||
		fragment.offset+len(fragment.data) > maxQUICReassemblyBytes {
		return false
	}
	if len(q.fragments) >= maxQUICReassemblyPieces {
		return false
	}
	if q.bytes+len(fragment.data) > maxQUICReassemblyBytes {
		return false
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
			return false
		}
	}
	// Trim the parts already covered to keep the bound honest.
	if q.covered(fragment.offset, fragmentEnd) {
		return true
	}
	q.fragments = append(q.fragments, fragment)
	q.bytes += len(fragment.data)
	return true
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

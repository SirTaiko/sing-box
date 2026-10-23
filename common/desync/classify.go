package desync

import "encoding/binary"

// UDP classification is a byte-exact port of the pinned upstream dissectors
// (nfq/protocol.c, zapret v72.9 c849e55e). There are no media-port heuristics:
// a datagram is classified only by the structure upstream checks, and the
// order below matches nfq/desync.c. Anything that only looks approximately like
// a protocol stays unknown so that an explicit `unknown` rule (or a rule
// without a protocol selector) is required.

const (
	quicMaxCIDLength  = 20
	quicInitialMinPay = 96
	quicInitialMinLen = 256
)

func classifyUDPPayload(packet *Packet) Protocol {
	payload := packet.Payload
	if len(payload) == 0 {
		return ProtocolUnknown
	}
	// nfq/desync.c: QUIC Initial is tested before the whole payload dissector
	// chain because it owns the request-reassembly path.
	if IsQUICInitial(payload) {
		return ProtocolQUIC
	}
	if isWireguardHandshakeInitiation(payload) {
		return ProtocolWireGuard
	}
	if IsDhtD1(payload) {
		return ProtocolDHT
	}
	if IsDiscordIPDiscoveryRequest(payload) {
		return ProtocolDiscord
	}
	if IsSTUNMessage(payload) {
		return ProtocolSTUN
	}
	return ProtocolUnknown
}

// IsWireguardHandshakeInitiation mirrors upstream: a 148-byte message whose
// type byte is 1 (handshake initiation).
func isWireguardHandshakeInitiation(data []byte) bool {
	return len(data) == 148 && data[0] == 1
}

// IsDhtD1 mirrors upstream `IsDhtD1`: a bencoded "d1:...e" query. This is the
// complete upstream test; it is deliberately not a bencode parser and does not
// accept other DHT messages.
func IsDhtD1(data []byte) bool {
	return len(data) >= 7 && data[0] == 'd' && data[1] == '1' && data[len(data)-1] == 'e'
}

// IsDiscordIPDiscoveryRequest mirrors upstream: exactly 74 bytes,
// type 0x0001, length 0x0046 and 64 zero bytes where the address would be.
func IsDiscordIPDiscoveryRequest(data []byte) bool {
	if len(data) != 74 || data[0] != 0 || data[1] != 1 || data[2] != 0 || data[3] != 70 {
		return false
	}
	for _, value := range data[8:72] {
		if value != 0 {
			return false
		}
	}
	return true
}

// IsSTUNMessage mirrors upstream: 20-byte header, two zero leading bits, a
// length that is a multiple of four and equal to the remaining payload, and the
// STUN magic cookie.
func IsSTUNMessage(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	if data[0]&0xc0 != 0 || data[3]&0x03 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(data[4:8]) != 0x2112a442 {
		return false
	}
	return int(binary.BigEndian.Uint16(data[2:4])) == len(data)-20
}

// IsQUICInitial mirrors upstream `IsQUICInitial`: long header with the fixed
// bit and an Initial packet type for the detected version, at least the
// minimum Initial size, a present DCID, a bounded SCID, valid token and length
// varints, and a payload of at least 96 bytes. The version must be one upstream
// recognises (QUICDraftVersion), so reserved/unknown versions are not treated as
// QUIC.
func IsQUICInitial(data []byte) bool {
	if len(data) < quicInitialMinLen {
		return false
	}
	// Long header: header form bit and fixed bit.
	if data[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if quicDraftVersion(version) == 0 {
		return false
	}
	// QUIC v1 Initial packets are type 00b, v2 are 01b.
	wantType := byte(0x00)
	if isQUICV2(version) {
		wantType = 0x10
	}
	if data[0]&0x30 != wantType {
		return false
	}
	offset := 5
	// DCID must be present and bounded.
	if offset >= len(data) || data[offset] == 0 || data[offset] > quicMaxCIDLength {
		return false
	}
	offset += 1 + int(data[offset])
	// SCID may be empty but must be bounded.
	if offset >= len(data) || data[offset] > quicMaxCIDLength {
		return false
	}
	offset += 1 + int(data[offset])
	// Token length varint.
	tokenLength, size, ok := parseQUICVarint(data, offset)
	if !ok || tokenLength > uint64(len(data)) {
		return false
	}
	offset += size + int(tokenLength)
	if offset >= len(data) {
		return false
	}
	// Payload length varint.
	payloadLength, size, ok := parseQUICVarint(data, offset)
	if !ok {
		return false
	}
	offset += size + int(payloadLength)
	if offset > len(data) {
		return false
	}
	// A client hello cannot be too small; smaller is likely an ACK.
	return payloadLength >= quicInitialMinPay
}

// parseQUICVarint decodes one QUIC variable-length integer (RFC 9000 §16) and
// returns its size in bytes.
func parseQUICVarint(data []byte, offset int) (value uint64, size int, ok bool) {
	if offset >= len(data) {
		return 0, 0, false
	}
	switch data[offset] >> 6 {
	case 0:
		return uint64(data[offset] & 0x3f), 1, true
	case 1:
		if offset+2 > len(data) {
			return 0, 0, false
		}
		return uint64(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3fff), 2, true
	case 2:
		if offset+4 > len(data) {
			return 0, 0, false
		}
		return uint64(binary.BigEndian.Uint32(data[offset:offset+4]) & 0x3fffffff), 4, true
	default:
		if offset+8 > len(data) {
			return 0, 0, false
		}
		return binary.BigEndian.Uint64(data[offset:offset+8]) & 0x3fffffffffffffff, 8, true
	}
}

// quicDraftVersion mirrors upstream QUICDraftVersion: returns 0 for versions
// upstream does not recognise, otherwise a draft/version selector.
func quicDraftVersion(version uint32) uint8 {
	if version>>8 == 0xff0000 {
		return uint8(version)
	}
	switch version {
	case 0xfaceb001:
		return 22
	case 0xfaceb002, 0xfaceb00e:
		return 27
	case 0x51303530, 0x54303530, 0x54303531:
		return 27
	case 0x00000001:
		return 34
	case 0x709a50c4, 0x6b3343cf:
		return 100
	}
	// Versions of the form 0x?a?a?a?a are reserved for version negotiation.
	if version&0x0f0f0f0f == 0x0a0a0a0a {
		return 29
	}
	return 0
}

func isQUICV2(version uint32) bool {
	return version == 0x709a50c4 || version == 0x6b3343cf
}

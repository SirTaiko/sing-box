package desync

// QUIC Initial decryption and CRYPTO defragmentation.
//
// This is a Go port of the pinned upstream implementation
// (nfq/protocol.c: QUICDecryptInitial, QUICDefragCrypto,
// QUICExtractHostFromInitial, zapret v72.9 c849e55e). It is used to obtain a
// hostname fact from an owned QUIC flow, which is what a protocol/domain rule
// needs. It is deliberately bounded: one datagram, no cross-datagram CRYPTO
// reassembly and no QUIC stack.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"sort"
)

const (
	// maxQUICCryptoBytes bounds the defragmented CRYPTO stream of one Initial
	// datagram. Upstream's QUIC path uses a 1500-byte buffer; the ClientHello
	// fit into one datagram is what this function handles. Cross-datagram
	// reassembly is a separate, explicitly remaining step.
	maxQUICCryptoBytes = 4096
	// maxQUICDefragPieces is upstream MAX_DEFRAG_PIECES.
	maxQUICDefragPieces = 128
)

var (
	quicSaltDraft22 = []byte{0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
		0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a}
	quicSaltDraft23 = []byte{0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
		0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02}
	quicSaltDraft29 = []byte{0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
		0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99}
	quicSaltV1 = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
		0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	quicSaltV2 = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
		0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
	quicSaltQ50 = []byte{0x50, 0x45, 0x74, 0xef, 0xd0, 0x66, 0xfe, 0x2f, 0x9d, 0x94,
		0x5c, 0xfc, 0xdb, 0xd3, 0xa7, 0xf0, 0xd3, 0xb5, 0x6b, 0x45}
	quicSaltT50 = []byte{0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80,
		0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60, 0x48, 0x83, 0x10}
	quicSaltT51 = []byte{0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50,
		0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda, 0x6e, 0x03, 0x3d}
)

// quicInitialSalt mirrors the upstream version-to-salt selection, including the
// gQUIC variants upstream carves out and the draft bands.
func quicInitialSalt(version uint32) ([]byte, bool) {
	switch version {
	case 0x51303530:
		return quicSaltQ50, true
	case 0x54303530:
		return quicSaltT50, true
	case 0x54303531:
		return quicSaltT51, true
	}
	draft := quicDraftVersion(version)
	if draft == 0 {
		return nil, false
	}
	switch {
	case draft <= 22:
		return quicSaltDraft22, true
	case draft <= 28:
		return quicSaltDraft23, true
	case draft <= 32:
		return quicSaltDraft29, true
	case draft <= 34:
		return quicSaltV1, true
	default:
		return quicSaltV2, true
	}
}

func hkdfExtractSHA256(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpandLabel implements TLS 1.3 HKDF-Expand-Label with an empty context,
// which is what QUIC initial key derivation uses.
func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	info := make([]byte, 0, 4+len(label)+1)
	info = append(info, byte(length>>8), byte(length), byte(len(label)))
	info = append(info, label...)
	info = append(info, 0)
	var out, block []byte
	var counter byte = 1
	for len(out) < length {
		mac := hmac.New(sha256.New, secret)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
		counter++
	}
	return out[:length]
}

// quicInitialKeys derives the client Initial packet protection keys of one
// version/DCID pair.
func quicInitialKeys(dcid []byte, version uint32) (key, iv, hp []byte, ok bool) {
	salt, ok := quicInitialSalt(version)
	if !ok {
		return nil, nil, nil, false
	}
	initialSecret := hkdfExtractSHA256(salt, dcid)
	clientSecret := hkdfExpandLabel(initialSecret, "tls13 client in", sha256.Size)
	keyLabel, ivLabel, hpLabel := "tls13 quic key", "tls13 quic iv", "tls13 quic hp"
	if isQUICV2(version) {
		keyLabel, ivLabel, hpLabel = "tls13 quicv2 key", "tls13 quicv2 iv", "tls13 quicv2 hp"
	}
	return hkdfExpandLabel(clientSecret, keyLabel, 16),
		hkdfExpandLabel(clientSecret, ivLabel, 12),
		hkdfExpandLabel(clientSecret, hpLabel, 16), true
}

// decryptQUICInitial removes header protection and AEAD protection from one
// client Initial packet and returns the plaintext frames. A wrong DCID,
// corrupted ciphertext or truncated packet fails authentication and is
// rejected, never guessed.
func decryptQUICInitial(data []byte) ([]byte, bool) {
	plaintext, _, _, ok := decryptQUICInitialPacket(data)
	return plaintext, ok
}

// decryptQUICInitialPacket is decryptQUICInitial plus the connection identity
// (DCID and version) needed for bounded cross-datagram CRYPTO reassembly.
func decryptQUICInitialPacket(data []byte) (plaintext, dcid []byte, version uint32, ok bool) {
	if len(data) < 9 || data[0]&0x80 == 0 {
		return nil, nil, 0, false
	}
	version = binary.BigEndian.Uint32(data[1:5])
	if quicDraftVersion(version) == 0 {
		return nil, nil, 0, false
	}
	dcidLength := int(data[5])
	if dcidLength == 0 || dcidLength > quicMaxCIDLength || 6+dcidLength > len(data) {
		return nil, nil, 0, false
	}
	dcid = data[6 : 6+dcidLength]
	key, iv, hp, ok := quicInitialKeys(dcid, version)
	if !ok {
		return nil, nil, 0, false
	}
	offset := 1 + 4 + 1 + dcidLength
	if offset >= len(data) {
		return nil, nil, 0, false
	}
	offset += 1 + int(data[offset]) // SCID
	tokenLength, size, ok := parseQUICVarint(data, offset)
	if !ok || tokenLength > uint64(len(data)) {
		return nil, nil, 0, false
	}
	offset += size + int(tokenLength)
	if offset >= len(data) {
		return nil, nil, 0, false
	}
	payloadLength, size, ok := parseQUICVarint(data, offset)
	if !ok || payloadLength < 20 {
		return nil, nil, 0, false
	}
	offset += size
	if offset >= len(data) {
		return nil, nil, 0, false
	}
	// The sample is taken four bytes after the packet number offset, as
	// RFC 9001 §5.4.2 requires; the packet number length is only known after
	// the first mask byte.
	if offset+4+16 > len(data) {
		return nil, nil, 0, false
	}
	block, err := aes.NewCipher(hp)
	if err != nil {
		return nil, nil, 0, false
	}
	var sampleMask [16]byte
	block.Encrypt(sampleMask[:], data[offset+4:offset+20])
	firstByte := data[0] ^ (sampleMask[0] & 0x0f)
	packetNumberLength := int(firstByte&0x03) + 1
	if offset+packetNumberLength > len(data) || uint64(offset)+payloadLength > uint64(len(data)) {
		return nil, nil, 0, false
	}
	var packetNumber uint64
	for index := 0; index < packetNumberLength; index++ {
		packetNumber = packetNumber<<8 | uint64(data[offset+index]^sampleMask[1+index])
	}
	if payloadLength < uint64(packetNumberLength)+16 {
		return nil, nil, 0, false
	}
	cryptLength := int(payloadLength) - packetNumberLength - 16
	header := make([]byte, offset+packetNumberLength)
	copy(header, data[:offset+packetNumberLength])
	header[0] = firstByte
	for index := 0; index < packetNumberLength; index++ {
		header[offset+index] = byte(packetNumber >> (8 * (packetNumberLength - 1 - index)))
	}
	aeadIV := append([]byte(nil), iv...)
	var packetNumberBlock [8]byte
	binary.BigEndian.PutUint64(packetNumberBlock[:], packetNumber)
	for index := 0; index < 8; index++ {
		aeadIV[len(aeadIV)-8+index] ^= packetNumberBlock[index]
	}
	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, 0, false
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return nil, nil, 0, false
	}
	ciphertext := data[offset+packetNumberLength : offset+packetNumberLength+cryptLength]
	tag := data[offset+packetNumberLength+cryptLength : offset+packetNumberLength+cryptLength+16]
	sealed := append(append([]byte(nil), ciphertext...), tag...)
	plaintext, err = aead.Open(nil, aeadIV, sealed, header)
	if err != nil {
		return nil, nil, 0, false
	}
	return plaintext, dcid, version, true
}

// defragQUICCrypto concatenates CRYPTO frames (frame type 6) into one bounded
// buffer and reports whether the covered ranges are contiguous from offset 0.
// PADDING/PING frames are skipped as upstream does; any other frame type ends
// the scan, so a malformed or unsupported datagram is rejected rather than
// guessed at.
func defragQUICCrypto(plaintext []byte) ([]byte, bool) {
	buffer := make([]byte, maxQUICCryptoBytes)
	type frameRange struct{ offset, length int }
	ranges := make([]frameRange, 0, maxQUICDefragPieces)
	pieces := 0
	position := 0
	for position < len(plaintext) {
		frameType := plaintext[position]
		position++
		if frameType <= 1 {
			// PADDING (0x00) / PING (0x01)
			continue
		}
		if frameType != 6 {
			return nil, false
		}
		if pieces >= maxQUICDefragPieces {
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
		if frameOffset+frameLength > uint64(len(buffer)) || position+int(frameLength) > len(plaintext) {
			return nil, false
		}
		copy(buffer[frameOffset:], plaintext[position:position+int(frameLength)])
		ranges = append(ranges, frameRange{offset: int(frameOffset), length: int(frameLength)})
		position += int(frameLength)
		pieces++
	}
	if len(ranges) == 0 {
		return nil, false
	}
	// Coverage must be contiguous from offset 0; a gap means the hello cannot
	// be parsed and no fact may be reported.
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].offset < ranges[j].offset })
	covered := 0
	for _, frame := range ranges {
		if frame.offset > covered {
			return nil, false
		}
		if frame.offset+frame.length > covered {
			covered = frame.offset + frame.length
		}
	}
	return buffer[:covered], true
}

// parseQUICCryptoClientHello extracts the SNI from a reassembled QUIC CRYPTO
// stream. RFC 9001 §4.1.1 carries the TLS handshake in CRYPTO frames without
// the TLS record layer, so the stream starts with the ClientHello handshake
// message itself (HandshakeType 0x01) and not with a TLS record header 0x16.
// The declared handshake body must be fully present before a hostname is
// reported: a ClientHello split across Initial datagrams yields no fact until
// its last byte arrives, and a truncated or differently framed stream is
// refused instead of guessed.
func parseQUICCryptoClientHello(handshake []byte) (string, bool) {
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return "", false
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if handshakeLength > len(handshake)-4 {
		return "", false
	}
	host, _, _, _, ok := parseClientHelloBytes(handshake[:4+handshakeLength])
	if !ok || host == "" {
		return "", false
	}
	return host, true
}

// quicInitialServerName decrypts one Initial datagram, defragments its CRYPTO
// stream and extracts the SNI of a complete ClientHello. The result is a fact,
// not a guess: any failure in decryption, framing or hello parsing is reported
// as no hostname.
func quicInitialServerName(data []byte) (string, bool) {
	plaintext, ok := decryptQUICInitial(data)
	if !ok {
		return "", false
	}
	handshake, ok := defragQUICCrypto(plaintext)
	if !ok {
		return "", false
	}
	return parseQUICCryptoClientHello(handshake)
}

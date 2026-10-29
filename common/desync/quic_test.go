package desync

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// testQUICInitialPayload builds one authenticated client Initial whose single
// datagram carries a complete ClientHello. Tests that need the UDP fake stage
// to run must use a datagram the repaired QUIC admission accepts: the
// structural buildQUICInitial placeholder does not authenticate and is
// therefore passed through untouched, exactly like pinned quic_reasm_cancel.
func testQUICInitialPayload(t *testing.T, host string) []byte {
	t.Helper()
	return sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{rawQUICClientHello(host)}, 240),
		[]byte{1, 2, 3, 4, 5, 6, 7, 8}, 1, 1)
}

// encodeQUICVarint16 encodes a value as a two-byte QUIC varint.
func encodeQUICVarint16(value int) []byte {
	return []byte{0x40 | byte(value>>8), byte(value)}
}

// sealQUICInitial builds one protected client Initial datagram around the given
// plaintext frames. It is an independent inverse of decryptQUICInitial: the
// header protection and AEAD steps are assembled here from the RFC layout, so a
// round trip exercises the parser's offsets, sample selection and key schedule.
// Wire validation against a real client capture remains a VM check.
func sealQUICInitial(t *testing.T, frames []byte, dcid []byte, version uint32, packetNumber uint32) []byte {
	t.Helper()
	key, iv, hp, ok := quicInitialKeys(dcid, version)
	if !ok {
		t.Fatal("no keys for version")
	}
	header := []byte{0xc0, 0, 0, 0, 0, byte(len(dcid))}
	binary.BigEndian.PutUint32(header[1:5], version)
	header = append(header, dcid...)
	header = append(header, 0) // SCID length
	header = append(header, 0) // token length
	payloadLength := len(frames) + 4 + 16
	header = append(header, encodeQUICVarint16(payloadLength)...)
	packetNumberOffset := len(header)
	header = append(header, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(header[packetNumberOffset:], packetNumber)
	// Long header, fixed bit, Initial packet type, four-byte packet number.
	header[0] = 0xc3
	plaintextHeader := append([]byte(nil), header...)

	aeadIV := append([]byte(nil), iv...)
	var packetNumberBytes [8]byte
	binary.BigEndian.PutUint64(packetNumberBytes[:], uint64(packetNumber))
	for index := 0; index < 8; index++ {
		aeadIV[len(aeadIV)-8+index] ^= packetNumberBytes[index]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, aeadIV, frames, plaintextHeader)
	packet := append(append([]byte(nil), header...), sealed...)

	headerBlock, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	headerBlock.Encrypt(mask[:], packet[packetNumberOffset+4:packetNumberOffset+20])
	for index := 0; index < 4; index++ {
		packet[packetNumberOffset+index] ^= mask[1+index]
	}
	packet[0] ^= mask[0] & 0x0f
	return packet
}

// cryptoFrames builds one CRYPTO frame per chunk at the given offsets, padded
// with PADDING frames so the datagram has the size of a real Initial.
func cryptoFrames(offsets []int, chunks [][]byte, padTo int) []byte {
	var frames []byte
	for index := range offsets {
		frames = append(frames, 6)
		frames = append(frames, encodeQUICVarint16(offsets[index])...)
		frames = append(frames, encodeQUICVarint16(len(chunks[index]))...)
		frames = append(frames, chunks[index]...)
	}
	for len(frames) < padTo {
		frames = append(frames, 0)
	}
	return frames
}

// rawQUICClientHello builds the client Initial CRYPTO payload for host: the
// bare TLS ClientHello handshake message without the TLS record header that
// buildClientHello prepends. RFC 9001 §4.1.1 carries the handshake in CRYPTO
// frames without the TLS record layer, so a faithful QUIC fixture must start
// with HandshakeType 0x01, never with record type 0x16.
func rawQUICClientHello(host string) []byte {
	record := buildClientHello(host)
	if len(record) < 6 || record[0] != 0x16 {
		panic("buildClientHello no longer returns a TLS record")
	}
	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLength != len(record)-5 {
		panic("buildClientHello TLS record length mismatch")
	}
	return record[5:]
}

func TestQUICInitialDecryptsAndExtractsHost(t *testing.T) {
	hello := rawQUICClientHello("quic.example")
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	packet := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello}, 240), dcid, 1, 2)
	if !IsQUICInitial(packet) {
		t.Fatal("sealed datagram must classify as a QUIC Initial")
	}
	host, ok := quicInitialServerName(packet)
	if !ok || host != "quic.example" {
		t.Fatalf("host = %q ok = %v", host, ok)
	}
	// The decrypted frame stream is exactly the CRYPTO frame we sealed.
	plaintext, ok := decryptQUICInitial(packet)
	if !ok {
		t.Fatal("decryption failed")
	}
	if len(plaintext) < len(hello) || plaintext[0] != 6 {
		t.Fatalf("unexpected plaintext: %d bytes", len(plaintext))
	}
}

func TestQUICInitialSplitCryptoFrames(t *testing.T) {
	hello := rawQUICClientHello("split.example")
	dcid := []byte{9, 9, 9, 9, 9, 9, 9, 9}
	frames := cryptoFrames([]int{0, len(hello) / 2}, [][]byte{hello[:len(hello)/2], hello[len(hello)/2:]}, 240)
	packet := sealQUICInitial(t, frames, dcid, 1, 7)
	host, ok := quicInitialServerName(packet)
	if !ok || host != "split.example" {
		plaintext, decryptOK := decryptQUICInitial(packet)
		defrag, defragOK := defragQUICCrypto(plaintext)
		t.Fatalf("host = %q ok = %v (len=%d hello=%d decrypt=%v plaintext=%d defrag=%v defragLen=%d)",
			host, ok, len(packet), len(hello), decryptOK, len(plaintext), defragOK, len(defrag))
	}
}

func TestQUICInitialRejectsMalformed(t *testing.T) {
	hello := rawQUICClientHello("reject.example")
	dcid := []byte{4, 4, 4, 4}
	frames := cryptoFrames([]int{0}, [][]byte{hello}, 200)
	good := sealQUICInitial(t, frames, dcid, 1, 1)

	t.Run("wrong dcid", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[6] ^= 0xff
		if host, ok := quicInitialServerName(bad); ok {
			t.Fatalf("wrong DCID must not authenticate, host = %q", host)
		}
	})
	t.Run("corrupted ciphertext", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		bad[len(bad)-20] ^= 0x01
		if _, ok := quicInitialServerName(bad); ok {
			t.Fatal("corrupted ciphertext must not authenticate")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		if _, ok := quicInitialServerName(good[:len(good)/2]); ok {
			t.Fatal("truncated datagram must not authenticate")
		}
	})
	t.Run("unknown version", func(t *testing.T) {
		bad := append([]byte(nil), good...)
		binary.BigEndian.PutUint32(bad[1:5], 0xdeadbeef)
		if _, ok := quicInitialServerName(bad); ok {
			t.Fatal("unknown version must not decrypt")
		}
	})
	t.Run("crypto gap", func(t *testing.T) {
		gapped := cryptoFrames([]int{0, len(hello) + 4}, [][]byte{hello[:len(hello)-1], hello[len(hello)-1:]}, 200)
		packet := sealQUICInitial(t, gapped, dcid, 1, 3)
		if _, ok := quicInitialServerName(packet); ok {
			t.Fatal("non-contiguous CRYPTO coverage must not produce a hostname")
		}
	})
	t.Run("no crypto frame", func(t *testing.T) {
		ping := make([]byte, 200)
		ping[0] = 1
		packet := sealQUICInitial(t, ping, dcid, 1, 4)
		if _, ok := quicInitialServerName(packet); ok {
			t.Fatal("no CRYPTO frame must not produce a hostname")
		}
	})
	t.Run("incomplete hello", func(t *testing.T) {
		short := cryptoFrames([]int{0}, [][]byte{hello[:len(hello)-3]}, 200)
		packet := sealQUICInitial(t, short, dcid, 1, 5)
		if _, ok := quicInitialServerName(packet); ok {
			t.Fatal("incomplete ClientHello must not produce a hostname")
		}
	})
}

// TestQUICCapturedInitialFlightExtractsHost is the permanent regression for the
// acceptance defect: two real captured client Initial flights (Linux and
// Windows product runs, 10 authenticated 1280-byte datagrams each) carry a
// ClientHello of 1512/1511 body bytes whose CRYPTO stream is a bare TLS
// handshake, not a TLS record. The first datagram only holds the 67-byte
// prefix; the second completes the stream and must yield the SNI.
func TestQUICCapturedInitialFlightExtractsHost(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "quic-initial-"+platform+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var encoded []string
			if err = json.Unmarshal(data, &encoded); err != nil {
				t.Fatal(err)
			}
			if len(encoded) != 10 {
				t.Fatalf("captured flight has %d datagrams, want 10", len(encoded))
			}
			q := newQUICReassembler()
			firstHostIndex := -1
			host := ""
			for index, raw := range encoded {
				payload, err := hex.DecodeString(raw)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := decryptQUICInitial(payload); !ok {
					t.Fatalf("captured datagram %d does not authenticate", index)
				}
				name, ok := q.add(payload)
				if ok && firstHostIndex < 0 {
					firstHostIndex, host = index, name
				}
			}
			if firstHostIndex != 1 {
				t.Fatalf("first hostname reported on datagram %d, want the second (first carries only the partial prefix)", firstHostIndex)
			}
			if host != "www.youtube.com" {
				t.Fatalf("captured host = %q, want www.youtube.com", host)
			}
			stream, contiguous := q.contiguous()
			if !contiguous {
				t.Fatal("captured CRYPTO stream is not contiguous")
			}
			if len(stream) < 4 || stream[0] != 0x01 {
				t.Fatalf("CRYPTO stream starts with %#x, want HandshakeType 0x01 (no TLS record layer)", stream[0])
			}
			declared := int(stream[1])<<16 | int(stream[2])<<8 | int(stream[3])
			if declared != len(stream)-4 {
				t.Fatalf("captured ClientHello declares %d body bytes, stream carries %d", declared, len(stream)-4)
			}
			t.Logf("captured %s CRYPTO stream %d bytes prefix=%x declared_body=%d host=%q",
				platform, len(stream), stream[:4], declared, host)
		})
	}
}

// TestQUICCryptoClientHelloIsNotTLSRecord pins the protocol boundary: the
// CRYPTO stream of a QUIC Initial carries the bare TLS handshake message
// (RFC 9001 §4.1.1). A TLS record-framed hello inside CRYPTO is malformed and
// must not be interpreted by the TCP TLS record parser.
func TestQUICCryptoClientHelloIsNotTLSRecord(t *testing.T) {
	framed := buildClientHello("framed.example")
	if framed[0] != 0x16 {
		t.Fatal("fixture is not TLS record framed")
	}
	dcid := []byte{3, 3, 3, 3}
	packet := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{framed}, 240), dcid, 1, 1)
	if host, ok := quicInitialServerName(packet); ok {
		t.Fatalf("TLS record framing in CRYPTO must not yield a host: %q", host)
	}
	q := newQUICReassembler()
	if host, ok := q.add(packet); ok {
		t.Fatalf("TLS record framing in CRYPTO must not yield a host: %q", host)
	}
}

// TestQUICCryptoDeclaredBodyMustBeComplete proves the completeness bound: a
// hello whose SNI can already be parsed is still not a fact while the declared
// handshake body extends past the reassembled CRYPTO stream.
func TestQUICCryptoDeclaredBodyMustBeComplete(t *testing.T) {
	hello := rawQUICClientHello("complete.example")
	truncated := append([]byte(nil), hello...)
	putUint24(truncated[1:4], readUint24(truncated[1:4])+1)
	dcid := []byte{8, 8, 8, 8}
	packet := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{truncated}, 240), dcid, 1, 1)
	if host, ok := quicInitialServerName(packet); ok {
		t.Fatalf("incomplete declared handshake body must not yield a host: %q", host)
	}
	q := newQUICReassembler()
	if host, ok := q.add(packet); ok {
		t.Fatalf("incomplete declared handshake body must not yield a host: %q", host)
	}
	// The same bytes with the declared body restored are a complete hello.
	packet = sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello}, 240), dcid, 1, 2)
	if host, ok := q.add(packet); !ok || host != "complete.example" {
		t.Fatalf("complete retransmission host = %q/%v", host, ok)
	}
}

// TestQUICHostnameFeedsRuleMatching proves the decrypted hostname is the fact
// used for rule selection: a domain-gated QUIC rule matches only when the
// Initial authenticates and its CRYPTO ClientHello names that domain.
func TestQUICHostnameFeedsRuleMatching(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"port":[443],"protocol":["quic"],"domain":["quic.example"],"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"quic","hex":"0000000001"}]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	dcid := []byte{7, 7, 7, 7}
	// Different host first: the rule must not match and the flow must not be
	// latched to it.
	other := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{rawQUICClientHello("other.example")}, 240), dcid, 1, 2)
	otherPacket := buildIPv4UDP(t, other, 443)
	if verdict := lease.HandlePacket(otherPacket.Raw, DirectionOutbound, func([]byte) error {
		t.Fatal("non-matching host must not inject")
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	matching := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{rawQUICClientHello("quic.example")}, 240), dcid, 1, 1)
	packet := buildIPv4UDP(t, matching, 443)
	injected := 0
	if verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
		injected++
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("verdict = %d", verdict)
	}
	if injected != 1 {
		t.Fatalf("matching QUIC host must select the rule: injected = %d", injected)
	}
}
func TestQUICVersionSaltSelection(t *testing.T) {
	for _, testCase := range []struct {
		version uint32
		salt    []byte
	}{
		{0xff000016, quicSaltDraft22},
		{0xff00001d, quicSaltDraft29},
		{0x00000001, quicSaltV1},
		{0x6b3343cf, quicSaltV2},
		{0x51303530, quicSaltQ50},
	} {
		salt, ok := quicInitialSalt(testCase.version)
		if !ok || string(salt) != string(testCase.salt) {
			t.Fatalf("version %#x salt mismatch", testCase.version)
		}
	}
	if _, ok := quicInitialSalt(0xdeadbeef); ok {
		t.Fatal("unknown version must not have a salt")
	}
}

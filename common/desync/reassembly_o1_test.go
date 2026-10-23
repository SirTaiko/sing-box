package desync

// O1 regression: the shared reassembler must treat the SNI name_type and an
// empty/rejected host_name exactly like the pinned tpws C: the hello is parsed
// (so no deferred "incomplete" hold), the server_name extension anchor is kept,
// and a non-host_name or empty entry is never matchable.

import (
	"encoding/binary"
	"testing"
)

// buildTestClientHello builds a minimal single-record TLS ClientHello whose SNI
// body is supplied verbatim. body is the content of the server_name extension.
func buildTestClientHello(body []byte) []byte {
	extension := make([]byte, 4+len(body))
	binary.BigEndian.PutUint16(extension[0:2], 0x0000) // server_name
	binary.BigEndian.PutUint16(extension[2:4], uint16(len(body)))
	copy(extension[4:], body)

	handshake := make([]byte, 0, 128)
	handshake = append(handshake, 0x01, 0x00, 0x00, 0x00) // type + length placeholder
	handshake = append(handshake, 0x03, 0x03)             // legacy_version
	handshake = append(handshake, make([]byte, 32)...)    // random
	handshake = append(handshake, 0x00)                   // session_id length
	handshake = append(handshake, 0x00, 0x02, 0x00, 0x00) // cipher_suites
	handshake = append(handshake, 0x01, 0x00)             // compression_methods
	handshake = append(handshake, 0x00, 0x00)             // extensions length placeholder
	handshake = append(handshake, extension...)
	binary.BigEndian.PutUint16(handshake[2:4], uint16(len(handshake)-4))
	binary.BigEndian.PutUint16(handshake[len(handshake)-len(extension)-2:], uint16(len(extension)))

	record := []byte{0x16, 0x03, 0x01, 0x00, 0x00}
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	return append(record, handshake...)
}

func sniBody(nameType byte, name string) []byte {
	// server_name_list length (2) + name_type (1) + name length (2) + name.
	body := []byte{0x00, 0x00, nameType, 0x00, 0x00}
	binary.BigEndian.PutUint16(body[0:2], uint16(3+len(name)))
	binary.BigEndian.PutUint16(body[3:5], uint16(len(name)))
	return append(body, name...)
}

func TestParseClientHelloRejectsNonHostNameType(t *testing.T) {
	record := buildTestClientHello(sniBody(1, "example.com"))
	host, _, _, extEnd, ok := parseClientHelloBytes(record[5:])
	if !ok {
		t.Fatal("a parsed SNI extension with a non-host_name type must still complete")
	}
	if host != "" {
		t.Fatalf("name_type=1 host = %q, want empty (nonmatchable), the pre-O1 bug reported example.com", host)
	}
	if extEnd == 0 {
		t.Fatal("the server_name extension anchor must be kept when the name is rejected")
	}
	// The packet-side view must report the hello as complete: a rejected name
	// is a parsed hello, not an incomplete capture that is held until timeout.
	if gotHost, _, _, _, complete := parseTLSClientHello(record); gotHost != "" || !complete {
		t.Fatalf("parseTLSClientHello = (%q, complete=%v), want (\"\", true)", gotHost, complete)
	}
}

func TestParseClientHelloEmptyNameIsParsedButUnmatchable(t *testing.T) {
	record := buildTestClientHello(sniBody(0, ""))
	host, _, _, extEnd, ok := parseClientHelloBytes(record[5:])
	if !ok {
		t.Fatal("an empty server_name must not make the hello incomplete")
	}
	if host != "" {
		t.Fatalf("empty server_name host = %q, want empty", host)
	}
	if extEnd == 0 {
		t.Fatal("empty server_name must keep the extension anchor")
	}
	if gotHost, _, _, _, complete := parseTLSClientHello(record); gotHost != "" || !complete {
		t.Fatalf("parseTLSClientHello = (%q, complete=%v), want (\"\", true)", gotHost, complete)
	}
}

func TestParseClientHelloOverrunNameIsUnmatchableButParsed(t *testing.T) {
	body := sniBody(0, "example.com")
	binary.BigEndian.PutUint16(body[1:3], uint16(len("example.com")+16)) // overrun
	record := buildTestClientHello(body)
	host, _, _, extEnd, ok := parseClientHelloBytes(record[5:])
	if !ok {
		t.Fatal("a name-length overrun inside a parsed extension must not hold the hello")
	}
	if host != "" {
		t.Fatalf("overrun host = %q, want empty", host)
	}
	if extEnd == 0 {
		t.Fatal("a rejected name must keep the extension anchor")
	}
}

func TestParseClientHelloValidNameStillMatchable(t *testing.T) {
	record := buildTestClientHello(sniBody(0, "example.com"))
	host, start, end, extEnd, ok := parseClientHelloBytes(record[5:])
	if !ok || host != "example.com" || end-start != len("example.com") || extEnd == 0 {
		t.Fatalf("valid ClientHello parse = (%q, %d, %d, %d, %v)", host, start, end, extEnd, ok)
	}
}

func TestParseClientHelloTruncatedExtensionStillFails(t *testing.T) {
	record := buildTestClientHello(sniBody(0, "example.com"))
	// Claim an extension body past the handshake end: a genuinely malformed
	// extension block must still clear every anchor, like the pinned C break.
	// (An extensions-total length that merely overruns is clamped by the
	// parser, as upstream does, so the extension's own length is corrupted.)
	handshake := record[5:]
	extensionOffset := len(handshake) - (4 + len(sniBody(0, "example.com")))
	binary.BigEndian.PutUint16(handshake[extensionOffset+2:extensionOffset+4], 0xffff)
	if _, _, _, _, ok := parseClientHelloBytes(handshake); ok {
		t.Fatal("a truncated extension block must be rejected")
	}
}

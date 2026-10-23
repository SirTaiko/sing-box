package tools

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"strings"
	"testing"
)

func TestBuildDNSQueryGolden(t *testing.T) {
	t.Parallel()
	message, err := BuildDNSQuery("example.com", FamilyIPv4, 0xBEEF)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "beef01000001000000000000076578616d706c6503636f6d0000010001"
	if hex.EncodeToString(message) != expected {
		t.Fatalf("query mismatch\n got: %s\nwant: %s", hex.EncodeToString(message), expected)
	}
	if len(message) != 17+len("example.com")+1 {
		t.Fatalf("unexpected length %d", len(message))
	}
}

func TestBuildDNSQueryVariants(t *testing.T) {
	t.Parallel()
	plain, err := BuildDNSQuery("example.com", FamilyIPv4, 1)
	if err != nil {
		t.Fatal(err)
	}
	dotted, err := BuildDNSQuery("example.com.", FamilyIPv4, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, dotted) {
		t.Fatal("a single trailing dot must be stripped")
	}
	aaaa, err := BuildDNSQuery("example.com", FamilyIPv6, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(aaaa, []byte{0x00, dnsTypeAAAA, 0x00, dnsClassIN}) {
		t.Fatalf("AAAA type/class missing: %x", aaaa[len(aaaa)-4:])
	}
	root, err := BuildDNSQuery("", FamilyIPv4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 17 {
		t.Fatalf("root query length %d", len(root))
	}
	if root[12] != 0 || root[13] != 0 || root[14] != dnsTypeA || root[15] != 0 || root[16] != dnsClassIN {
		t.Fatalf("unexpected root query %x", root)
	}
	upper, err := BuildDNSQuery("EXAMPLE.com", FamilyIPv4, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(upper, []byte("EXAMPLE")) {
		t.Fatal("the encoder must not change the label case")
	}
}

func TestBuildDNSQueryErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		input  string
		family Family
	}{
		{"label too long", strings.Repeat("a", 64) + ".com", FamilyIPv4},
		{"name too long", strings.Repeat("a.", 127) + "com", FamilyIPv4},
		{"empty interior label", "example..com", FamilyIPv4},
		{"leading empty label", ".example.com", FamilyIPv4},
		{"double trailing dot", "example.com..", FamilyIPv4},
		{"both families", "example.com", FamilyIPv4 | FamilyIPv6},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := BuildDNSQuery(test.input, test.family, 1); err == nil {
				t.Fatalf("expected an error for %q", test.input)
			}
		})
	}
}

const testDNSResponse = "123481800001000200000000" +
	"076578616d706c6503636f6d0000010001" +
	"c00c000100010000003c00045db8d822" +
	"c00c001c00010000003c001026062800022000010248189325c81946"

func TestParseDNSResponseGolden(t *testing.T) {
	t.Parallel()
	message, err := hex.DecodeString(testDNSResponse)
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := ParseDNSResponse(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 2 {
		t.Fatalf("expected 2 addresses, got %v", addresses)
	}
	if addresses[0] != netip.MustParseAddr("93.184.216.34") {
		t.Fatalf("unexpected A record %v", addresses[0])
	}
	if addresses[1] != netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946") {
		t.Fatalf("unexpected AAAA record %v", addresses[1])
	}
}

func buildResponse(answers ...[]byte) []byte {
	message := []byte{
		0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, byte(len(answers)), 0x00, 0x00, 0x00, 0x00,
	}
	message = append(message, 0x07)
	message = append(message, []byte("example")...)
	message = append(message, 0x03)
	message = append(message, []byte("com")...)
	message = append(message, 0x00, 0x00, 0x01, 0x00, 0x01)
	for _, answer := range answers {
		message = append(message, answer...)
	}
	return message
}

func aRecord(address [4]byte) []byte {
	record := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04}
	return append(record, address[:]...)
}

func TestParseDNSResponseIgnoresOtherRecords(t *testing.T) {
	t.Parallel()
	cname := []byte{0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x10}
	chaos := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4}
	shortA := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03, 1, 2, 3}
	addresses, err := ParseDNSResponse(buildResponse(cname, chaos, shortA))
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 0 {
		t.Fatalf("unexpected addresses %v", addresses)
	}
}

func TestParseDNSResponseNoAnswers(t *testing.T) {
	t.Parallel()
	addresses, err := ParseDNSResponse(buildResponse())
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 0 {
		t.Fatalf("unexpected addresses %v", addresses)
	}
}

func TestParseDNSResponseMalformed(t *testing.T) {
	t.Parallel()
	valid := buildResponse(aRecord([4]byte{1, 2, 3, 4}))
	cases := []struct {
		name    string
		message []byte
	}{
		{"empty", nil},
		{"short header", valid[:11]},
		{"not a response", append(append([]byte{}, valid[:2]...), append([]byte{0x01, 0x00}, valid[4:]...)...)},
		{"truncated question name", append(append([]byte{}, valid[:12]...), 0x07, 'a', 'b')},
		{"missing question tail", append(append([]byte{}, valid[:12]...), 0x00, 0x00, 0x01)},
		{"answer name is not a pointer", buildResponse([]byte{0x03, 'a', 'b', 'c', 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4})},
		{"answer data length beyond end", valid[:len(valid)-1]},
		{"answer count larger than the message", func() []byte {
			message := append([]byte{}, valid...)
			message[7] = 0xFF
			message[6] = 0xFF
			return message
		}()},
		{"question count larger than the message", func() []byte {
			message := append([]byte{}, valid...)
			message[5] = 0xFF
			message[4] = 0xFF
			return message
		}()},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			addresses, err := ParseDNSResponse(test.message)
			if err == nil {
				t.Fatalf("expected an error, got %v", addresses)
			}
			if addresses != nil {
				t.Fatalf("a malformed blob must not emit partial addresses: %v", addresses)
			}
		})
	}
}

func TestParseDNSResponseCompressionPointerIsNotFollowed(t *testing.T) {
	t.Parallel()
	// The answer name points at its own offset; the parser must classify the
	// pointer and skip it without dereferencing, so no loop is possible.
	message := buildResponse([]byte{0xc0, 0x24, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 9, 8, 7, 6})
	addresses, err := ParseDNSResponse(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("9.8.7.6") {
		t.Fatalf("unexpected addresses %v", addresses)
	}
}

func TestReadDNSResponseBounds(t *testing.T) {
	t.Parallel()
	if _, err := ReadDNSResponse(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected an empty input error")
	}
	// mdig.c:431-443 reads into a fixed 8192 byte buffer and requires EOF, so
	// the largest accepted blob is 8191 bytes; exactly 8192 leaves the buffer
	// full without observing EOF and the C tool exits 10.
	payload := make([]byte, dnsMaxResponseSize-1)
	if _, err := ReadDNSResponse(bytes.NewReader(payload)); err != nil {
		t.Fatalf("8191 bytes must be accepted: %v", err)
	}
	exact := make([]byte, dnsMaxResponseSize)
	if _, err := ReadDNSResponse(bytes.NewReader(exact)); err == nil {
		t.Fatal("8192 bytes must be rejected like the pinned fread/feof check")
	}
	if _, err := ReadDNSResponse(bytes.NewReader(append(exact, 0))); err == nil {
		t.Fatal("expected an oversized input error")
	}
}

func TestWriteDNSQueryShortWrite(t *testing.T) {
	t.Parallel()
	if err := WriteDNSQuery(shortWriter{}, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected a short write error")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

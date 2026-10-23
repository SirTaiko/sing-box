package tools

import (
	"encoding/binary"
	"io"
	"net/netip"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// dnsMaxNameLength is the longest domain name accepted by the pinned
	// dns_mk_query_blob (it rejects l > 253).
	dnsMaxNameLength = 253
	// dnsHeaderSize is the DNS message header length.
	dnsHeaderSize = 12
	// dnsMaxResponseSize mirrors the pinned 8192 byte response buffer.
	dnsMaxResponseSize = 8192

	dnsTypeA     = 1
	dnsTypeAAAA  = 28
	dnsClassIN   = 1
	dnsFlagRD    = 0x01
	dnsFlagQR    = 0x80
	dnsMaxLabel  = 63
	dnsQNameRoot = 0x00
)

// BuildDNSQuery builds the binary query blob produced by
// dns_mk_query_blob()/dns_make_query() in mdig/mdig.c: the 12 byte header with
// RD set and QDCOUNT=1, the label encoded QNAME, and QTYPE/QCLASS.
//
// id is written verbatim so tests are deterministic; the command generates a
// random id with crypto/rand when the operator does not pin one. The pinned
// source derives the id from the real time clock instead, which is not
// reproducible and therefore not part of the stable contract.
//
// A single trailing dot is stripped. Empty interior labels are rejected as
// input validation, exactly like the pinned encoder: for an empty label
// j == i, so the unsigned `j-i-1u > 62u` check at mdig.c:351 wraps to a huge
// value and dns_mk_query_blob returns 0 ("could not make DNS query").
func BuildDNSQuery(name string, family Family, id uint16) (message []byte, err error) {
	if family != FamilyIPv4 && family != FamilyIPv6 {
		return nil, E.New("dns: --family must be 4 or 6")
	}
	if len(name) > dnsMaxNameLength+1 {
		return nil, E.New("dns: name length exceeds ", dnsMaxNameLength)
	}
	length := len(name)
	if length > 0 && name[length-1] == '.' {
		length--
	}
	if length > 0 && name[length-1] == '.' {
		return nil, E.New("dns: name has an empty trailing label")
	}
	if length > dnsMaxNameLength {
		return nil, E.New("dns: name length exceeds ", dnsMaxNameLength)
	}
	trimmed := name[:length]
	size := dnsHeaderSize + 1 + 4
	if length > 0 {
		size += length + 1
	}
	message = make([]byte, size)
	binary.BigEndian.PutUint16(message[0:2], id)
	message[2] = dnsFlagRD
	binary.BigEndian.PutUint16(message[4:6], 1)
	offset := dnsHeaderSize
	for start := 0; start < len(trimmed); {
		end := start
		for end < len(trimmed) && trimmed[end] != '.' {
			end++
		}
		labelLength := end - start
		if labelLength == 0 {
			return nil, E.New("dns: name contains an empty label")
		}
		if labelLength > dnsMaxLabel {
			return nil, E.New("dns: label length exceeds ", dnsMaxLabel)
		}
		message[offset] = byte(labelLength)
		copy(message[offset+1:], trimmed[start:end])
		offset += labelLength + 1
		start = end + 1
	}
	message[offset] = dnsQNameRoot
	offset++
	if family == FamilyIPv6 {
		binary.BigEndian.PutUint16(message[offset:offset+2], dnsTypeAAAA)
	} else {
		binary.BigEndian.PutUint16(message[offset:offset+2], dnsTypeA)
	}
	binary.BigEndian.PutUint16(message[offset+2:offset+4], dnsClassIN)
	return message, nil
}

// WriteDNSQuery writes a query blob to an operator stream and reports short
// writes instead of silently truncating the binary message.
func WriteDNSQuery(writer io.Writer, message []byte) error {
	if writer == nil {
		return E.New("dns: output stream is required")
	}
	written, err := writer.Write(message)
	if err != nil {
		return E.Cause(err, "dns: write query")
	}
	if written != len(message) {
		return io.ErrShortWrite
	}
	return nil
}

// ReadDNSResponse reads a binary DNS response blob from stdin. The pinned tool
// (mdig.c:431-443) reads into a fixed 8192 byte buffer and requires feof(), so
// its largest accepted blob is 8191 bytes and exactly 8192 is an error. The
// same bound applies here instead of silently truncating a larger blob.
func ReadDNSResponse(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, E.New("dns: input stream is required")
	}
	message, err := io.ReadAll(io.LimitReader(reader, dnsMaxResponseSize))
	if err != nil {
		return nil, E.Cause(err, "dns: read response")
	}
	if len(message) == 0 {
		return nil, E.New("dns: empty response blob")
	}
	if len(message) >= dnsMaxResponseSize {
		return nil, E.New("dns: response blob must be shorter than ", dnsMaxResponseSize, " bytes")
	}
	return message, nil
}

// ParseDNSResponse extracts the A/AAAA addresses of a DNS response blob with the
// exact rules of dns_parse_print() in mdig/mdig.c:385-430:
//
//   - the blob must be at least a header and have the QR bit set;
//   - the question section is skipped by walking the label length bytes, and
//     each question needs five more bytes for QTYPE/QCLASS;
//   - every answer name must be a compression pointer (top two bits set), and
//     it is never dereferenced, so a self referential pointer terminates
//     normally instead of looping;
//   - the record data length is RDLENGTH, and RDLENGTH+12 must fit;
//   - only TYPE 1 class IN with RDLENGTH 4 and TYPE 28 class IN with RDLENGTH 16
//     produce output.
//
// A structurally invalid blob is an error; a valid blob without A/AAAA answers
// returns no addresses and no error, like the pinned tool exiting with 0.
func ParseDNSResponse(message []byte) ([]netip.Addr, error) {
	if len(message) < dnsHeaderSize {
		return nil, E.New("dns: response is shorter than the header")
	}
	if message[2]&dnsFlagQR == 0 {
		return nil, E.New("dns: blob is not a response")
	}
	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	answerCount := int(binary.BigEndian.Uint16(message[6:8]))
	offset := dnsHeaderSize
	for index := 0; index < questionCount; index++ {
		for offset < len(message) && message[offset] != 0 {
			labelLength := int(message[offset])
			if labelLength+1 > len(message)-offset {
				return nil, E.New("dns: truncated question name")
			}
			offset += labelLength + 1
		}
		if len(message)-offset < 5 {
			return nil, E.New("dns: truncated question")
		}
		offset += 5
	}
	addresses := make([]netip.Addr, 0, answerCount)
	for index := 0; index < answerCount; index++ {
		if len(message)-offset < 12 {
			return nil, E.New("dns: truncated answer header")
		}
		if message[offset]&0xC0 != 0xC0 {
			return nil, E.New("dns: answer name is not a compression pointer")
		}
		dataLength := int(message[offset+10])<<8 | int(message[offset+11])
		if dataLength+12 > len(message)-offset {
			return nil, E.New("dns: truncated answer data")
		}
		if message[offset+2] == 0 && message[offset+4] == 0 && message[offset+5] == dnsClassIN {
			switch message[offset+3] {
			case dnsTypeA:
				if dataLength == 4 {
					var raw [4]byte
					copy(raw[:], message[offset+12:offset+16])
					addresses = append(addresses, netip.AddrFrom4(raw))
				}
			case dnsTypeAAAA:
				if dataLength == 16 {
					var raw [16]byte
					copy(raw[:], message[offset+12:offset+28])
					addresses = append(addresses, netip.AddrFrom16(raw))
				}
			}
		}
		offset += 12 + dataLength
	}
	return addresses, nil
}

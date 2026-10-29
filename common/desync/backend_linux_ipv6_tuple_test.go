//go:build linux

package desync

// Permanent regression for IPv6 capture activation (S26-IPV6-ACTIVATION). The
// submission26 production blob combined the two IPv6 addresses into one
// 32-byte nft comparison, which the kernel rejects with EOVERFLOW before the
// capture rule exists; it also used the IPv4 network-header offset 12 for IPv6.
// These cases decode the actually encoded entry rules of a capture opened over
// the hermetic anchors and pin the family-correct shape: IPv4 keeps its
// byte-identical single 8-byte comparison at offset 12, IPv6 uses two bounded
// 16-byte comparisons at offsets 8 and 24, and every comparison value respects
// the kernel's 16-byte nft_data bound. Ports and direction stay unchanged.
// Model tests: no kernel object is created.

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strconv"
	"testing"

	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

type encodedPayloadPair struct {
	base   uint32
	offset uint32
	length uint32
	data   []byte
}

// encodedPayloadPairs decodes the payload/comparison sequence of one encoded
// rule. Every payload load must be followed by its comparison, must read the
// same number of bytes, use register 1, and stay within the kernel's 16-byte
// nft_data value bound.
func encodedPayloadPairs(t *testing.T, rule *fakeNftRule) []encodedPayloadPair {
	t.Helper()
	decoded, err := decodedExpressions(rule)
	if err != nil {
		t.Fatalf("decode rule: %v", err)
	}
	var pairs []encodedPayloadPair
	for index := 0; index < len(decoded); index++ {
		if decoded[index].name != "payload" {
			continue
		}
		payload := decoded[index]
		base := binary.BigEndian.Uint32(payload.data[unix.NFTA_PAYLOAD_BASE])
		offset := binary.BigEndian.Uint32(payload.data[unix.NFTA_PAYLOAD_OFFSET])
		length := binary.BigEndian.Uint32(payload.data[unix.NFTA_PAYLOAD_LEN])
		destination := binary.BigEndian.Uint32(payload.data[unix.NFTA_PAYLOAD_DREG])
		if destination != 1 {
			t.Fatalf("payload load into register %d, want the bounded register 1", destination)
		}
		if length > 16 {
			t.Fatalf("payload at offset %d loads %d bytes, above the 16-byte register bound", offset, length)
		}
		if index+1 >= len(decoded) || decoded[index+1].name != "cmp" {
			t.Fatalf("payload at offset %d is not followed by its comparison", offset)
		}
		comparison := decoded[index+1]
		if source := binary.BigEndian.Uint32(comparison.data[unix.NFTA_CMP_SREG]); source != 1 {
			t.Fatalf("comparison reads register %d, want 1", source)
		}
		if op := binary.BigEndian.Uint32(comparison.data[unix.NFTA_CMP_OP]); op != uint32(expr.CmpOpEq) {
			t.Fatalf("comparison op=%d, want equality", op)
		}
		value := fakeCmpValue(comparison)
		if len(value) > 16 {
			t.Fatalf("comparison value %d bytes, above the kernel nft_data bound (16)", len(value))
		}
		if uint32(len(value)) != length {
			t.Fatalf("payload length %d != comparison value length %d", length, len(value))
		}
		pairs = append(pairs, encodedPayloadPair{base: base, offset: offset, length: length, data: append([]byte(nil), value...)})
		index++
	}
	return pairs
}

// captureRuleForRole returns the single encoded entry rule of one direction.
func captureRuleForRole(t *testing.T, seams *linuxCaptureSeams, capture *linuxCapture, role string) *fakeNftRule {
	t.Helper()
	_, familyByte, err := anchorFamilyNames(capture.lease.Endpoint().Family)
	if err != nil {
		t.Fatalf("family: %v", err)
	}
	rules := fakeRulesWithUserdata(seams.anchors, familyByte, anchorTableName, ":"+capture.anchor.capture+":"+role)
	if len(rules) != 1 {
		t.Fatalf("%s rules=%d, want exactly one", role, len(rules))
	}
	return rules[0]
}

// networkPairs returns only the network-header address comparisons.
func networkPairs(t *testing.T, pairs []encodedPayloadPair) []encodedPayloadPair {
	t.Helper()
	var network []encodedPayloadPair
	for _, pair := range pairs {
		if pair.base == uint32(expr.PayloadBaseNetworkHeader) {
			network = append(network, pair)
		}
	}
	return network
}

// transportPairs returns only the transport-header comparisons.
func transportPairs(t *testing.T, pairs []encodedPayloadPair) []encodedPayloadPair {
	t.Helper()
	var transport []encodedPayloadPair
	for _, pair := range pairs {
		if pair.base == uint32(expr.PayloadBaseTransportHeader) {
			transport = append(transport, pair)
		}
	}
	return transport
}

func assertAddressPairs(t *testing.T, what string, got []encodedPayloadPair, want []encodedPayloadPair) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s address comparisons=%d, want %d: %+v", what, len(got), len(want), got)
	}
	for index := range want {
		if got[index].offset != want[index].offset || got[index].length != want[index].length ||
			!bytes.Equal(got[index].data, want[index].data) {
			t.Fatalf("%s address comparison %d = offset %d len %d data %x, want offset %d len %d data %x",
				what, index, got[index].offset, got[index].length, got[index].data,
				want[index].offset, want[index].length, want[index].data)
		}
	}
}

func portBytes(port uint16) []byte {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, port)
	return data
}

// TestLinuxCaptureEncodedTupleMatchesAddressFamily opens one capture per case and
// inspects the real encoded entry-o/entry-i rules. On the submission26 blob the
// IPv6 cases fail behaviourally: one 32-byte comparison at offset 12 instead of
// two bounded 16-byte comparisons at offsets 8 and 24.
func TestLinuxCaptureEncodedTupleMatchesAddressFamily(t *testing.T) {
	cases := []struct {
		name        string
		family      Family
		source      string
		destination string
		queue       int
	}{
		{"ipv4-source-destination", FamilyIPv4, "192.0.2.1:65535", "198.51.100.7:443", 15350},
		{"ipv4-wildcard-source", FamilyIPv4, "0.0.0.0:40000", "198.51.100.7:443", 15351},
		{"ipv6-source-destination", FamilyIPv6, "[2001:db8::1]:40000", "[2001:db8::2]:65535", 15352},
		{"ipv6-wildcard-source", FamilyIPv6, "[::]:40000", "[2001:db8::2]:443", 15353},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			source := netip.MustParseAddrPort(testCase.source)
			destination := netip.MustParseAddrPort(testCase.destination)
			data := newFakeNFQueueConn("tuple", 0, nil)
			seams := installLinuxCaptureSeams(t, data)
			content := `{"enabled":true,"capture":{"linux":{"qnum":` + strconv.Itoa(testCase.queue) + `}},"rules":[{"network":["tcp"],"port":[443],"methods":[]}]}`
			config, err := Compile(enabledOption(content), "")
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			engine, err := NewEngine(config, linuxBackend{})
			if err != nil {
				t.Fatalf("engine: %v", err)
			}
			lease, err := engine.NewAttempt(Intent{
				Family:      testCase.family,
				Transport:   TransportTCP,
				Source:      source,
				Destination: destination,
			})
			if err != nil {
				t.Fatalf("attempt: %v", err)
			}
			lease.SetLocalAddress(source)
			t.Cleanup(func() {
				_ = engine.Close()
				releaseQnum(testCase.queue)
			})
			captureHandle, err := openLinuxCapture(lease)
			if err != nil {
				t.Fatalf("open capture: %v", err)
			}
			capture := captureHandle.(*linuxCapture)
			t.Cleanup(func() { _ = captureHandle.Close() })

			specifiedSource := !source.Addr().IsUnspecified()
			wantOutbound := make([]encodedPayloadPair, 0, 2)
			wantInbound := make([]encodedPayloadPair, 0, 2)
			if specifiedSource {
				switch testCase.family {
				case FamilyIPv4:
					sourceBytes, destinationBytes := source.Addr().AsSlice(), destination.Addr().AsSlice()
					out := append(append([]byte(nil), sourceBytes...), destinationBytes...)
					in := append(append([]byte(nil), destinationBytes...), sourceBytes...)
					wantOutbound = append(wantOutbound, encodedPayloadPair{base: uint32(expr.PayloadBaseNetworkHeader), offset: 12, length: 8, data: out})
					wantInbound = append(wantInbound, encodedPayloadPair{base: uint32(expr.PayloadBaseNetworkHeader), offset: 12, length: 8, data: in})
				case FamilyIPv6:
					sourceBytes, destinationBytes := source.Addr().AsSlice(), destination.Addr().AsSlice()
					wantOutbound = append(wantOutbound,
						encodedPayloadPair{base: uint32(expr.PayloadBaseNetworkHeader), offset: 8, length: 16, data: append([]byte(nil), sourceBytes...)},
						encodedPayloadPair{base: uint32(expr.PayloadBaseNetworkHeader), offset: 24, length: 16, data: append([]byte(nil), destinationBytes...)})
					wantInbound = append(wantInbound,
						encodedPayloadPair{base: uint32(expr.PayloadBaseNetworkHeader), offset: 8, length: 16, data: append([]byte(nil), destinationBytes...)},
						encodedPayloadPair{base: uint32(expr.PayloadBaseNetworkHeader), offset: 24, length: 16, data: append([]byte(nil), sourceBytes...)})
				}
			}
			wantPortsOutbound := append(portBytes(source.Port()), portBytes(destination.Port())...)
			wantPortsInbound := append(portBytes(destination.Port()), portBytes(source.Port())...)
			wantAll := map[string]struct {
				address []encodedPayloadPair
				ports   []byte
			}{
				"entry-o": {address: wantOutbound, ports: wantPortsOutbound},
				"entry-i": {address: wantInbound, ports: wantPortsInbound},
			}
			for _, role := range []string{"entry-o", "entry-i"} {
				pairs := encodedPayloadPairs(t, captureRuleForRole(t, seams, capture, role))
				assertAddressPairs(t, role, networkPairs(t, pairs), wantAll[role].address)
				transport := transportPairs(t, pairs)
				if len(transport) != 1 || transport[0].offset != 0 || transport[0].length != 4 ||
					!bytes.Equal(transport[0].data, wantAll[role].ports) {
					t.Fatalf("%s transport comparison=%+v, want offset 0 len 4 data %x", role, transport, wantAll[role].ports)
				}
			}
		})
	}
}

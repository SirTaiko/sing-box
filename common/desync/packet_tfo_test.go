package desync

import "testing"

// TestFastOpenOptionRecognition pins the upstream tcp_has_fastopen contract:
// option 34 is RFC 7413 TFO; option 254 is TFO only when its length is at least
// four and it carries the RFC 6994 magic f9 89. A bare or foreign 254 option
// must not be classified as TFO, otherwise syndata suppression would silently
// drop payload on unrelated experimental options.
func TestFastOpenOptionRecognition(t *testing.T) {
	cases := []struct {
		name    string
		options []byte
		want    bool
	}{
		{"kind 34", []byte{34, 2}, true},
		{"kind 34 with length", []byte{34, 6, 1, 2, 3, 4}, true},
		{"rfc6994 magic", []byte{254, 4, 0xf9, 0x89}, true},
		{"rfc6994 magic longer", []byte{254, 6, 0xf9, 0x89, 0, 0}, true},
		{"254 foreign experiment id", []byte{254, 4, 0xf9, 0x88}, false},
		{"254 zero magic", []byte{254, 4, 0, 0}, false},
		{"254 too short for magic", []byte{254, 3, 0xf9}, false},
		{"254 bare", []byte{254, 2}, false},
		{"254 after timestamp", []byte{8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 254, 4, 0xf9, 0x89}, true},
		{"254 foreign after mss", []byte{2, 4, 0x05, 0xb4, 254, 4, 0xf9, 0x8a}, false},
		{"no options", nil, false},
		{"malformed truncated 254", []byte{254, 8, 0xf9}, false},
	}
	for _, tc := range cases {
		packet := &Packet{Transport: TransportTCP, TCPOptions: tc.options}
		parseTCPOptions(packet)
		if packet.HasFastOpen != tc.want {
			t.Errorf("%s: HasFastOpen = %v, want %v", tc.name, packet.HasFastOpen, tc.want)
		}
	}
}

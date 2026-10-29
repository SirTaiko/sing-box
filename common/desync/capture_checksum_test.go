package desync

// W2 regression: the send-address checksum policy that decides whether the
// driver recomputes checksums or forwards the supplied bytes. This is the part of
// the disposition change that preserves deliberate badsum fakes and repaired
// offload originals; it is pure and runs on every platform.

import (
	"testing"

	"github.com/sagernet/sing-box/common/windivert"
)

func TestDispositionChecksumPolicy(t *testing.T) {
	cases := []struct {
		name   string
		apply  func(*windivert.Address)
		wantIP bool
		want   bool
	}{
		{"generated replacement keeps supplied checksums", suppliedChecksums, true, true},
		{"rewritten bytes are recomputed", recomputeChecksums, false, false},
	}
	for _, testCase := range cases {
		var address windivert.Address
		// Start from the opposite state so the policy, not the zero value, is
		// what the assertion observes.
		address.SetIPChecksum(!testCase.wantIP)
		address.SetTCPChecksum(!testCase.want)
		address.SetUDPChecksum(!testCase.want)
		testCase.apply(&address)
		if address.IPChecksum() != testCase.wantIP {
			t.Fatalf("%s: IP checksum flag = %v", testCase.name, address.IPChecksum())
		}
		if address.TCPChecksum() != testCase.want {
			t.Fatalf("%s: TCP checksum flag = %v", testCase.name, address.TCPChecksum())
		}
		if address.UDPChecksum() != testCase.want {
			t.Fatalf("%s: UDP checksum flag = %v", testCase.name, address.UDPChecksum())
		}
	}
}

package direct

// Endpoint-wrapper close regression for the held UDP ownership. The returned
// UDP transport owns the attempt's lease close (R354-UDP1); with the QUIC
// delayed-replay ownership a captured partial Initial is now held instead of
// delivered immediately, so the wrapper's Close must still discharge that held
// original exactly once through the engine's completer instead of dropping it
// with the endpoint. Memory-only: the real engine/bridge runs on the counting
// fake backend and a no-I/O packet transport.

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
)

func qa519CapturedPartialInitial(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/qa519/quic-partial-initial.json")
	if err != nil {
		t.Fatal(err)
	}
	var encoded []string
	if err = json.Unmarshal(data, &encoded); err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 1 {
		t.Fatalf("fixture datagrams = %d, want 1", len(encoded))
	}
	raw, err := hex.DecodeString(encoded[0])
	if err != nil {
		t.Fatal(err)
	}
	// IPv4 (20 bytes) + UDP (8 bytes) precede the captured QUIC Initial.
	if len(raw) <= 28 || raw[9] != 17 {
		t.Fatalf("fixture is not an IPv4/UDP datagram: %d bytes", len(raw))
	}
	return raw[28:]
}

func TestPacketUDPReturnedCloseReleasesHeldInitial(t *testing.T) {
	engine, hook, _ := newUDPLeaseEngine(t, 1, option.DirectDesyncRule{
		Network: []string{"udp"},
		Port:    []uint16{443},
		Methods: []string{"fake"},
		Fake: &option.DirectDesyncFakeOptions{
			Repeats:  2,
			Payloads: []option.DirectDesyncPayload{{Protocol: "quic", Hex: "51413531396f6e636c6f7365"}},
		},
	})
	attempt := packetUDPAttempt(t, hook, false)
	payload := qa519CapturedPartialInitial(t)
	packet := buildUDPProbePacket(netip.MustParseAddrPort("198.51.100.20:443"), payload)
	var injections atomic.Int32
	var completions atomic.Int32
	var completedVerdict atomic.Int32
	verdict := attempt.lease.HandlePacket(packet, desync.DirectionOutbound, func([]byte) error {
		injections.Add(1)
		return nil
	}, func(terminal desync.Verdict, reason string, modified []byte) {
		completions.Add(1)
		completedVerdict.Store(int32(terminal))
	})
	if verdict != desync.VerdictHold {
		t.Fatalf("partial Initial verdict = %v, want Hold (no native disposition yet)", verdict)
	}
	if injections.Load() != 0 || completions.Load() != 0 {
		t.Fatalf("held Initial leaked output: injections=%d completions=%d", injections.Load(), completions.Load())
	}
	returned := attempt.AttachPacketConn(&udpLifetimePacket{})
	if err := returned.Close(); err != nil {
		t.Fatalf("returned Close: %v", err)
	}
	if got := completions.Load(); got != 1 {
		t.Fatalf("held Initial completions after close = %d, want exactly 1", got)
	}
	if got := desync.Verdict(completedVerdict.Load()); got != desync.VerdictPass {
		t.Fatalf("held Initial completed with verdict %v, want Pass", got)
	}
	if got := injections.Load(); got != 0 {
		t.Fatalf("close of an incomplete cycle injected %d packets", got)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("close left %d charged lease(s)", engine.ActiveLeases())
	}
}

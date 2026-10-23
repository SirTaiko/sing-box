package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// stateOnlyTestBackend reproduces the capability of the production state-only
// engine for a fixture that also needs a test-owned admission limit: the engine
// classifies itself as having no packet backend (PacketEnabled false) and can
// therefore never open a capture.
type stateOnlyTestBackend struct{}

func (stateOnlyTestBackend) Name() string { return "state-only" }

func (stateOnlyTestBackend) Open(*desync.Lease) (desync.Capture, error) {
	return nil, errors.New("state-only test backend has no capture")
}

// newLimitedStateEngine builds the real Engine with the state-only capability
// and one admission slot, so a single wrongly charged attempt would deny the
// following TCP attempt.
func newLimitedStateEngine(t *testing.T) *desync.Engine {
	t.Helper()
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, stateOnlyTestBackend{})
	if err != nil {
		t.Fatalf("desync.NewEngine: %v", err)
	}
	if engine.PacketEnabled() {
		t.Fatal("fixture engine must be state-only")
	}
	return engine
}

// TestStateOnlyUDPDoesNotConsumeTCPAdmission is the RA-S2 applicability
// regression. A stream-only object owns a non-nil state engine, and an enabled
// outbound also receives ordinary UDP attempts and listeners. Neither owns
// stream, capture or native-retention work, so neither may consume the TCP
// admission pool, and closing the returned connected-UDP connection must not
// leave a charge behind.
func TestStateOnlyUDPDoesNotConsumeTCPAdmission(t *testing.T) {
	for _, listener := range []bool{false, true} {
		name := "connected-udp"
		if listener {
			name = "listener"
		}
		t.Run(name, func(t *testing.T) {
			// The actual production compile path: a stream-only object.
			compiled, stream, err := compileDirectDesync(&option.DirectDesyncOptions{
				StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
			}, "")
			if err != nil {
				t.Fatalf("compileDirectDesync: %v", err)
			}
			defer compiled.Close()
			if compiled == nil {
				t.Fatal("stream-only compile returned no state engine")
			}
			if compiled.PacketEnabled() {
				t.Fatal("stream-only compile produced a packet-enabled engine")
			}
			engine := newLimitedStateEngine(t)
			defer engine.Close()
			hook := &desyncHook{engine: engine, stream: stream, lifetime: context.Background()}
			intent := dialer.AttemptIntent{
				Network:     "udp",
				Destination: M.ParseSocksaddr("198.51.100.10:443"),
			}
			if listener {
				intent.Destination = M.Socksaddr{}
				intent.Source = netip.MustParseAddrPort("192.0.2.10:40000")
			}
			lease, err := hook.NewAttempt(context.Background(), intent)
			if err != nil {
				t.Fatalf("state-only %s attempt: %v", name, err)
			}
			if charged := engine.ActiveLeases(); charged != 0 {
				t.Fatalf("state-only %s charged %d TCP admission slot(s), want 0", name, charged)
			}
			raw, peer := net.Pipe()
			attached, err := lease.AttachConn(raw)
			if err != nil {
				_ = raw.Close()
				_ = peer.Close()
				t.Fatalf("AttachConn: %v", err)
			}
			if attached != raw {
				t.Fatalf("state-only %s AttachConn returned %T, want the original connection", name, attached)
			}
			if err = attached.Close(); err != nil {
				t.Fatalf("returned connection Close: %v", err)
			}
			_ = peer.Close()
			if charged := engine.ActiveLeases(); charged != 0 {
				t.Fatalf("closed state-only %s still consumes %d TCP admission slot(s)", name, charged)
			}
			if err = lease.Close(nil); err != nil {
				t.Fatalf("lease Close: %v", err)
			}
			tcp, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
				Network:     "tcp",
				Destination: M.ParseSocksaddr("198.51.100.10:443"),
			})
			if err != nil {
				t.Fatalf("unrelated TCP refused after one state-only %s: %v", name, err)
			}
			if charged := engine.ActiveLeases(); charged != 1 {
				t.Fatalf("following TCP attempt charged %d slot(s), want 1", charged)
			}
			if err = tcp.Close(nil); err != nil {
				t.Fatalf("TCP lease Close: %v", err)
			}
			if charged := engine.ActiveLeases(); charged != 0 {
				t.Fatalf("TCP lease not released: %d active", charged)
			}
		})
	}
}

// TestStateOnlyTCPStillOwnsAdmission is the applicability control: the same
// state-only engine with limit one still charges an actual TCP attempt, so the
// pool is not silently unused for the work it exists for.
func TestStateOnlyTCPStillOwnsAdmission(t *testing.T) {
	compiled, stream, err := compileDirectDesync(&option.DirectDesyncOptions{
		StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
	}, "")
	if err != nil {
		t.Fatalf("compileDirectDesync: %v", err)
	}
	defer compiled.Close()
	engine := newLimitedStateEngine(t)
	defer engine.Close()
	hook := &desyncHook{engine: engine, stream: stream, lifetime: context.Background()}
	first, err := hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.ParseSocksaddr("198.51.100.10:443"),
	})
	if err != nil {
		t.Fatalf("first TCP attempt: %v", err)
	}
	_, err = hook.NewAttempt(context.Background(), dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.ParseSocksaddr("198.51.100.11:443"),
	})
	if !errors.Is(err, desync.ErrAdmissionRefused) {
		t.Fatalf("second TCP attempt error = %v, want admission refusal at limit one", err)
	}
	if charged := engine.ActiveLeases(); charged != 1 {
		t.Fatalf("charged = %d, want the single admitted TCP attempt", charged)
	}
	if err = first.Close(nil); err != nil {
		t.Fatalf("TCP lease Close: %v", err)
	}
}

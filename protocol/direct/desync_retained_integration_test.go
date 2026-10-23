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

func retainedBridgeAttempt(t *testing.T, engine *desync.Engine) (*desync.Lease, dialer.AttemptIntent) {
	t.Helper()
	intent := dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.8"), 443),
	}
	lease, err := engine.NewAttempt(desync.Intent{
		Family:      desync.FamilyIPv4,
		Transport:   desync.TransportTCP,
		Destination: netip.MustParseAddrPort("203.0.113.8:443"),
	})
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	return lease, intent
}

// R02/R15: the eager bridge creates the admission-carrying connection before
// the transformation wrapper, so the native sender factory can consume the same
// already admitted attempt. The wrapper stays outside it (capture observes the
// transformed bytes), and no second lease wrapper exists.
func TestEagerAttachConnPlacesAdmissionInsideStreamWrapper(t *testing.T) {
	engine, err := desync.NewEngine(testPacketConfig(t), &countingBackend{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()
	lease, intent := retainedBridgeAttempt(t, engine)
	stream := &fakeStreamAttachment{}
	bridge := &desyncLease{lease: lease, stream: stream, intent: intent, lifetime: context.Background()}
	raw := nopConn{}
	conn, err := bridge.AttachConn(raw)
	if err != nil {
		t.Fatalf("AttachConn: %v", err)
	}
	if conn == nil {
		t.Fatalf("AttachConn returned no connection")
	}
	stream.mu.Lock()
	if len(stream.wraps) != 1 {
		stream.mu.Unlock()
		t.Fatalf("WrapConn calls = %d, want exactly 1", len(stream.wraps))
	}
	inner := stream.wraps[0].conn
	stream.mu.Unlock()
	if _, isLease := inner.(*leaseConn); !isLease {
		t.Fatalf("stream wrapper input is %T, want the admission-carrying leaseConn", inner)
	}
	source, ok := inner.(interface{ NativeStreamConn() net.Conn })
	if !ok {
		t.Fatalf("stream wrapper input does not expose the native source capability")
	}
	if source.NativeStreamConn() != net.Conn(raw) {
		t.Fatalf("native source is %v, want the owned raw connection", source.NativeStreamConn())
	}
}

// R02: a stream-only production engine owns admission but no packet capability.
// Its bridge never requests the exclusive packet bind or opens a capture, while
// a packet engine does both.
func TestStreamOnlyBridgeSkipsPacketPreparation(t *testing.T) {
	stateEngine, err := desync.NewStateEngine(&option.DirectDesyncOptions{}, nil)
	if err != nil {
		t.Fatalf("NewStateEngine: %v", err)
	}
	defer stateEngine.Close()
	stateLease, stateIntent := retainedBridgeAttempt(t, stateEngine)
	stateBridge := &desyncLease{lease: stateLease, intent: stateIntent}
	if stateLease.PacketEnabled() {
		t.Fatalf("state-only lease reports packet capability")
	}
	if stateBridge.RequiresExclusiveBind() {
		t.Fatalf("stream-only lease requested the exclusive packet bind")
	}
	if err = stateBridge.StartCapture(); err != nil {
		t.Fatalf("stream-only StartCapture: %v", err)
	}

	backend := &countingBackend{}
	packetEngine, err := desync.NewEngine(testPacketConfig(t), backend)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer packetEngine.Close()
	packetLease, packetIntent := retainedBridgeAttempt(t, packetEngine)
	packetBridge := &desyncLease{lease: packetLease, intent: packetIntent}
	if !packetBridge.RequiresExclusiveBind() {
		t.Fatalf("packet lease did not request the exclusive bind")
	}
	if err = packetBridge.StartCapture(); err != nil {
		t.Fatalf("packet StartCapture: %v", err)
	}
	if backend.opened.Load() != 1 {
		t.Fatalf("packet capture opens = %d, want 1", backend.opened.Load())
	}
	if stateBridge.lease != nil && stateBridge.lease.PacketEnabled() {
		t.Fatalf("state-only lease changed packet capability")
	}
}

// R01/R06/R11 (bridge scope): the connection capability references the same
// charged attempt. Closing the lease keeps the charge while the reference is
// owned, and the release removes it exactly once.
func TestLeaseConnNativeHoldKeepsChargeUntilRelease(t *testing.T) {
	engine, err := desync.NewEngine(testPacketConfig(t), &countingBackend{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()
	lease, _ := retainedBridgeAttempt(t, engine)
	raw := nopConn{}
	conn := &leaseConn{Conn: raw, lease: lease}
	if conn.NativeStreamConn() != net.Conn(raw) {
		t.Fatalf("NativeStreamConn did not expose the owned connection")
	}
	release, err := conn.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("ActiveLeases with retained bridge reference = %d, want 1", got)
	}
	release()
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("ActiveLeases after bridge release = %d, want 0", got)
	}
}

// R15: a bridge lease without an engine owner has no admission capability and
// refuses instead of starting an unaccounted native operation.
func TestBridgeLeaseWithoutOwnerRefusesNativeHold(t *testing.T) {
	bridge := &desyncLease{}
	if _, err := bridge.AcquireNativeHold(); err == nil || !errors.Is(err, desync.ErrAdmissionRefused) {
		t.Fatalf("AcquireNativeHold on ownerless bridge = %v, want admission refusal", err)
	}
}

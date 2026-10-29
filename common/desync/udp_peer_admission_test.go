package desync

// Contract U01-U12: aggregate UDP peer-state bound (SEC296-S1) and the
// complete-tuple semantic attachment of destination-less UDP listener peers.
//
// Every fixture is memory-only: the fake Backend returns a non-joining
// testCapture, all packets are built as private byte slices, and the semantic
// engine runs with a synthetic clock. No socket, DNS, injection, file or
// goroutine outside the test process is used.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

type udpPeerClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *udpPeerClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *udpPeerClock) Advance(span time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(span)
	c.mu.Unlock()
}

type udpPeerFixture struct {
	t       *testing.T
	engine  *Engine
	backend *testBackend
	clock   *udpPeerClock
}

// newUDPPeerEngine builds a packet-capable engine with an explicit aggregate
// allowance. The allowance is a test-owned value of the real probe
// (limits.max_leases); there is no extra runtime knob.
func newUDPPeerEngine(t *testing.T, allowance int, extra string, rules string) *udpPeerFixture {
	t.Helper()
	content := `{"enabled":true` + extra + `,"rules":` + rules + `}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile %s: %v", content, err)
	}
	config.Limits.MaxLeases = allowance
	backend := &testBackend{name: "udp-peer-memory"}
	engine, err := NewEngine(config, backend)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	clock := &udpPeerClock{now: time.Unix(1000, 0)}
	engine.SetHoldClock(clock.Now)
	t.Cleanup(func() { _ = engine.Close() })
	return &udpPeerFixture{t: t, engine: engine, backend: backend, clock: clock}
}

// udpPeerAnyRule matches every UDP datagram with no transformation method: the
// peer state must still be charged and bounded (the security observation's
// empty-method configuration).
func udpPeerAnyRule() string {
	return `[{"network":["udp"],"ip_cidr":["any"],"methods":[]}]`
}

// udpPeerFakeRule produces exactly one replacement per matching QUIC datagram,
// so a test can hold one admitted user inside injection.
func udpPeerFakeRule() string {
	return `[{"network":["udp"],"port":[443],"methods":["fake"],` +
		`"fake":{"repeats":1,"payloads":[{"protocol":"quic","hex":"0000000001"}]}}]`
}

func (f *udpPeerFixture) listener(source string) *Lease {
	f.t.Helper()
	local := netip.MustParseAddrPort(source)
	lease, err := f.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP, Source: local})
	if err != nil {
		f.t.Fatalf("listener NewAttempt: %v", err)
	}
	lease.SetLocalAddress(local)
	if err = lease.StartCapture(); err != nil {
		f.t.Fatalf("listener StartCapture: %v", err)
	}
	return lease
}

func (f *udpPeerFixture) connected(source, destination string) *Lease {
	f.t.Helper()
	local := netip.MustParseAddrPort(source)
	remote := netip.MustParseAddrPort(destination)
	lease, err := f.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: local, Destination: remote})
	if err != nil {
		f.t.Fatalf("connected NewAttempt: %v", err)
	}
	lease.SetLocalAddress(local)
	if err = lease.StartCapture(); err != nil {
		f.t.Fatalf("connected StartCapture: %v", err)
	}
	return lease
}

func udpPeerCharge(engine *Engine) int {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.udpPeers
}

func udpPeerUsers(lease *Lease) int {
	lease.engine.mu.Lock()
	defer lease.engine.mu.Unlock()
	return lease.udpUsers
}

func udpFlowCount(lease *Lease) int {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return len(lease.udpFlows)
}

func udpLeaseClosed(lease *Lease) bool {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return lease.closed
}

// udpPeerPacket builds one private IPv4/IPv6 UDP datagram with the requested
// tuple. No checksum is needed: the parser validates lengths and ports only.
func udpPeerPacket(t *testing.T, src, dst netip.AddrPort, payload []byte) *Packet {
	t.Helper()
	if !src.IsValid() || !dst.IsValid() {
		t.Fatalf("invalid tuple %v -> %v", src, dst)
	}
	var raw []byte
	if src.Addr().Is4() && dst.Addr().Is4() {
		raw = make([]byte, 20+8+len(payload))
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
		raw[8] = 64
		raw[9] = 17
		source, destination := src.Addr().As4(), dst.Addr().As4()
		copy(raw[12:16], source[:])
		copy(raw[16:20], destination[:])
		binary.BigEndian.PutUint16(raw[10:12], inetChecksum(raw[:20], 0))
		binary.BigEndian.PutUint16(raw[20:22], src.Port())
		binary.BigEndian.PutUint16(raw[22:24], dst.Port())
		binary.BigEndian.PutUint16(raw[24:26], uint16(8+len(payload)))
		copy(raw[28:], payload)
	} else if src.Addr().Is6() && dst.Addr().Is6() {
		raw = make([]byte, 40+8+len(payload))
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:6], uint16(8+len(payload)))
		raw[6] = 17
		raw[7] = 64
		source, destination := src.Addr().As16(), dst.Addr().As16()
		copy(raw[8:24], source[:])
		copy(raw[24:40], destination[:])
		binary.BigEndian.PutUint16(raw[40:42], src.Port())
		binary.BigEndian.PutUint16(raw[42:44], dst.Port())
		binary.BigEndian.PutUint16(raw[44:46], uint16(8+len(payload)))
		copy(raw[48:], payload)
	} else {
		t.Fatalf("mixed address families %v -> %v", src, dst)
	}
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("parse %v -> %v: %v", src, dst, err)
	}
	return packet
}

// udpPeerSend dispatches one outbound datagram through the real Lease callback.
// The completer fails the test if the engine ever claims a terminal disposition:
// a refused datagram stays with the caller and is never also completed.
func udpPeerSend(t *testing.T, lease *Lease, packet *Packet, inject Injector) Verdict {
	t.Helper()
	return lease.HandlePacket(packet.Raw, DirectionOutbound, inject, func(Verdict, string, []byte) {
		t.Errorf("datagram %v must not be completed by the engine", packet.DstPort)
	})
}

func udpPeerNoInject(t *testing.T) Injector {
	return func([]byte) error {
		t.Errorf("unexpected injection for a refused or untransformable datagram")
		return nil
	}
}

// U01: the effective allowance is the existing max_leases value; default and
// zero keep 4096, positive overrides it, negative stays invalid, and a
// nonpositive internal allowance authorizes no peer state at all.
func TestUDPPeerAllowanceConfiguration(t *testing.T) {
	for _, content := range []string{
		`{"enabled":true,"rules":[{"network":["udp"],"methods":[]}]}`,
		`{"enabled":true,"limits":{},"rules":[{"network":["udp"],"methods":[]}]}`,
		`{"enabled":true,"limits":{"max_leases":0},"rules":[{"network":["udp"],"methods":[]}]}`,
	} {
		config, err := Compile(enabledOption(content), "")
		if err != nil {
			t.Fatalf("compile %s: %v", content, err)
		}
		if got := config.Limits.MaxLeases; got != 4096 {
			t.Fatalf("default max_leases for %s = %d, want 4096", content, got)
		}
	}
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":7},
		"rules":[{"network":["udp"],"methods":[]}]}`), "")
	if err != nil {
		t.Fatalf("positive max_leases: %v", err)
	}
	if got := config.Limits.MaxLeases; got != 7 {
		t.Fatalf("positive max_leases = %d, want 7", got)
	}
	if _, err = Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":-1},
		"rules":[{"network":["udp"],"methods":[]}]}`), ""); err == nil {
		t.Fatal("negative max_leases must stay invalid")
	}

	// A nonpositive internal allowance is not an unlimited sentinel: it
	// authorizes no peer allocation. Ordinary admission cannot reach it (the
	// attempt uses the same B and is refused first), so the deterministic case
	// sets the internal value on a live fixture.
	fixture := newUDPPeerEngine(t, 1, "", udpPeerAnyRule())
	lease := fixture.listener("192.0.2.1:40000")
	fixture.engine.limits.MaxLeases = 0
	packet := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40000"),
		netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
	if verdict := udpPeerSend(t, lease, packet, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("zero-allowance verdict = %v, want pass", verdict)
	}
	if got := udpFlowCount(lease); got != 0 {
		t.Fatalf("zero allowance constructed %d peer states", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 0 {
		t.Fatalf("zero allowance charged %d peers", got)
	}
}

// U01/U05/U10 (security fixture): one admitted listener with an aggregate
// allowance of one retains exactly one peer state for 24 distinct destinations;
// every excess datagram passes unchanged without construction, injection or
// completion, and quiescent Close detaches the map and discharges the charge.
func TestUDPListenerPeerBoundAndRefusalDisposition(t *testing.T) {
	fixture := newUDPPeerEngine(t, 1, `,"conntrack":{"max_entries":2}`, udpPeerAnyRule())
	lease := fixture.listener("192.0.2.1:40000")
	var constructed atomic.Int64
	fixture.engine.udpPeerConstruct = func() { constructed.Add(1) }
	for port := uint16(10000); port < 10024; port++ {
		packet := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40000"),
			netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), port), []byte("x"))
		if verdict := udpPeerSend(t, lease, packet, udpPeerNoInject(t)); verdict != VerdictPass {
			t.Fatalf("peer %d verdict = %v, want pass", port, verdict)
		}
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("peer states = %d, want the aggregate allowance 1", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("aggregate peer charge = %d, want 1", got)
	}
	if got := constructed.Load(); got != 1 {
		t.Fatalf("constructed flow states = %d, want 1 (refusals allocate nothing)", got)
	}
	if got := fixture.engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases = %d, want the one admitted listener", got)
	}
	if got := fixture.engine.heldBytes.Load(); got != 0 {
		t.Fatalf("held bytes = %d, want 0", got)
	}
	if got := fixture.engine.conntrack.len(); got != 1 {
		t.Fatalf("semantic entries = %d, want 1", got)
	}
	if err := lease.Err(); err != nil {
		t.Fatalf("capacity refusal must not surface a Lease error: %v", err)
	}
	if udpLeaseClosed(lease) {
		t.Fatal("capacity refusal must not close the listener")
	}

	// An already admitted peer stays usable at capacity.
	admitted := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40000"),
		netip.MustParseAddrPort("198.51.100.7:10000"), []byte("x"))
	if verdict := udpPeerSend(t, lease, admitted, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("admitted peer verdict = %v", verdict)
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("same-peer datagram created a second state: %d", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("same-peer datagram double charged: %d", got)
	}

	if err := lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	if got := udpFlowCount(lease); got != 0 {
		t.Fatalf("quiescent Close left %d peer states reachable", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 0 {
		t.Fatalf("quiescent Close left peer charge %d", got)
	}
	if got := fixture.engine.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after Close = %d", got)
	}
	inbound := udpPeerPacket(t, netip.MustParseAddrPort("198.51.100.7:10000"),
		netip.MustParseAddrPort("192.0.2.1:40000"), []byte("x"))
	if verdict := udpPeerSend(t, lease, inbound, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("closed listener verdict = %v", verdict)
	}
	if got := udpFlowCount(lease); got != 0 {
		t.Fatalf("closed listener resurrected %d peer states", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 0 {
		t.Fatalf("closed listener recharged %d peers", got)
	}
	if got := constructed.Load(); got != 1 {
		t.Fatalf("closed listener constructed %d flow states", got)
	}
}

// U02 (negative control: allocation-before-reserve): the constructor-ordering
// seam observes that the aggregate and lease charges were already taken when
// the new peer's flowState is allocated, and that a refused peer is never
// constructed at all.
func TestUDPPeerReservationPrecedesConstruction(t *testing.T) {
	fixture := newUDPPeerEngine(t, 2, "", udpPeerAnyRule())
	lease := fixture.listener("192.0.2.1:40000")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	constructed := 0
	fixture.engine.udpPeerConstruct = func() {
		constructed++
		if got := fixture.engine.udpPeers; got != constructed {
			t.Errorf("construction %d observed aggregate charge %d: the charge must be reserved first", constructed, got)
		}
		if got := lease.udpPeerCharge; got != constructed {
			t.Errorf("construction %d observed lease charge %d: the charge must be reserved first", constructed, got)
		}
	}
	for index := 0; index < 2; index++ {
		packet := udpPeerPacket(t, source, netip.AddrPortFrom(
			netip.MustParseAddr("198.51.100.7"), uint16(1001+index)), []byte("x"))
		udpPeerSend(t, lease, packet, udpPeerNoInject(t))
	}
	if constructed != 2 {
		t.Fatalf("constructed %d flow states, want 2", constructed)
	}
	refused := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:1003"), []byte("x"))
	if verdict := udpPeerSend(t, lease, refused, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("refused verdict = %v", verdict)
	}
	if constructed != 2 {
		t.Fatalf("refused peer constructed a flow state: %d", constructed)
	}
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("aggregate charge after refusal = %d, want 2", got)
	}
}

// U02: the peer allowance is charged once per peer even under concurrent
// same-key misses, and distinct misses can never oversubscribe it.
func TestUDPPeerChargeOncePerPeer(t *testing.T) {
	fixture := newUDPPeerEngine(t, 2, "", udpPeerAnyRule())
	lease := fixture.listener("192.0.2.1:40000")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	first := netip.MustParseAddrPort("198.51.100.7:1001")

	var constructed atomic.Int64
	fixture.engine.udpPeerConstruct = func() { constructed.Add(1) }
	for index := 0; index < 24; index++ {
		udpPeerSend(t, lease, udpPeerPacket(t, source, first, []byte("x")), udpPeerNoInject(t))
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("repeated peer states = %d, want 1", got)
	}

	// Concurrent same-key misses share one charge.
	second := netip.MustParseAddrPort("198.51.100.7:1002")
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			packet := udpPeerPacket(t, source, second, []byte("x"))
			if verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
				t.Errorf("unexpected injection")
				return nil
			}, nil); verdict != VerdictPass {
				t.Errorf("same-key miss verdict = %v", verdict)
			}
		}()
	}
	wait.Wait()
	if got := udpFlowCount(lease); got != 2 {
		t.Fatalf("same-key miss states = %d, want 2", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("charge after same-key misses = %d, want 2", got)
	}

	// Distinct misses racing for the exhausted allowance insert nothing.
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			packet := udpPeerPacket(t, source,
				netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(2000+index)), []byte("x"))
			if verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
				t.Errorf("unexpected injection")
				return nil
			}, nil); verdict != VerdictPass {
				t.Errorf("distinct miss verdict = %v", verdict)
			}
		}(index)
	}
	wait.Wait()
	if got := udpFlowCount(lease); got != 2 {
		t.Fatalf("distinct misses grew the map to %d, want 2", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("distinct misses charged %d peers, want 2", got)
	}
	if got := constructed.Load(); got != 2 {
		t.Fatalf("constructed flow states = %d, want one per admitted peer", got)
	}
}

// U03: the ceiling is aggregate across listeners and connected packet UDP; a
// closed owner returns its capacity and a refused datagram is never replayed.
func TestUDPPeerAggregateAcrossListenersAndConnectedUDP(t *testing.T) {
	fixture := newUDPPeerEngine(t, 2, "", udpPeerAnyRule())
	listenerA := fixture.listener("192.0.2.1:40000")
	listenerB := fixture.listener("192.0.2.1:40001")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	peerA := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
	peerB := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:1002"), []byte("x"))
	peerC := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.8:1003"), []byte("x"))
	if verdict := udpPeerSend(t, listenerA, peerA, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("peer A verdict = %v", verdict)
	}
	if verdict := udpPeerSend(t, listenerB, peerB, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("peer B verdict = %v", verdict)
	}
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("aggregate listeners charge = %d, want 2 (no per-listener multiplication)", got)
	}
	// The third peer is refused because the aggregate, not this listener, is
	// exhausted. The refusal is a plain pass with no injection.
	if verdict := udpPeerSend(t, listenerA, peerC, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("refused peer C verdict = %v", verdict)
	}
	if got := udpFlowCount(listenerA); got != 1 {
		t.Fatalf("refused peer C inserted state: %d", got)
	}
	// Closing the owner returns exactly its own charge.
	if err := listenerA.Close(nil); err != nil {
		t.Fatalf("listenerA.Close: %v", err)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("charge after owner close = %d, want 1", got)
	}
	listenerC := fixture.listener("192.0.2.1:40002")
	if verdict := udpPeerSend(t, listenerC, peerC, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("returned-capacity peer verdict = %v", verdict)
	}
	if got := udpFlowCount(listenerC); got != 1 {
		t.Fatalf("returned-capacity peer states = %d, want 1", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("charge after capacity return = %d, want 2", got)
	}

	// Connected packet-UDP participates in the same aggregate allowance.
	connectedFixture := newUDPPeerEngine(t, 2, "", udpPeerAnyRule())
	connectedListener := connectedFixture.listener("192.0.2.11:41000")
	connected := connectedFixture.connected("192.0.2.11:41001", "198.51.100.20:5000")
	connectedSource := netip.MustParseAddrPort("192.0.2.11:41001")
	listenerPeer := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.11:41000"),
		netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
	connectedPeer := udpPeerPacket(t, connectedSource,
		netip.MustParseAddrPort("198.51.100.20:5000"), []byte("x"))
	if verdict := udpPeerSend(t, connectedListener, listenerPeer, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("listener peer verdict = %v", verdict)
	}
	if verdict := udpPeerSend(t, connected, connectedPeer, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("connected peer verdict = %v", verdict)
	}
	if got := udpPeerCharge(connectedFixture.engine); got != 2 {
		t.Fatalf("aggregate listener+connected charge = %d, want 2", got)
	}
	excess := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.11:41000"),
		netip.MustParseAddrPort("198.51.100.7:1002"), []byte("x"))
	if verdict := udpPeerSend(t, connectedListener, excess, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("excess listener peer verdict = %v", verdict)
	}
	if got := udpFlowCount(connectedListener); got != 1 {
		t.Fatalf("excess listener peer inserted state: %d", got)
	}
}

// U04: semantic expiry/eviction never releases the resource charge and never
// re-admits an already admitted peer.
func TestUDPPeerRetentionAcrossSemanticPurge(t *testing.T) {
	fixture := newUDPPeerEngine(t, 2, `,"conntrack":{"max_entries":1}`, udpPeerAnyRule())
	lease := fixture.listener("192.0.2.1:40000")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	peerA := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
	peerB := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:1002"), []byte("x"))
	peerC := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:1003"), []byte("x"))
	udpPeerSend(t, lease, peerA, udpPeerNoInject(t))
	udpPeerSend(t, lease, peerB, udpPeerNoInject(t)) // evicts A's semantic entry
	if got := fixture.engine.conntrack.len(); got != 1 {
		t.Fatalf("semantic entries = %d, want max_entries 1", got)
	}
	if got := udpFlowCount(lease); got != 2 {
		t.Fatalf("semantic eviction dropped peer states: %d", got)
	}
	fixture.clock.Advance(24 * time.Hour)
	fixture.engine.conntrack.purge()
	if got := fixture.engine.conntrack.len(); got != 0 {
		t.Fatalf("semantic entries after purge = %d", got)
	}
	if got := udpFlowCount(lease); got != 2 {
		t.Fatalf("semantic purge reclaimed peer states: %d", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("semantic purge released charge: %d", got)
	}
	// Same admitted peers remain usable and are not re-charged after the purge.
	udpPeerSend(t, lease, peerA, udpPeerNoInject(t))
	udpPeerSend(t, lease, peerB, udpPeerNoInject(t))
	if got := udpPeerCharge(fixture.engine); got != 2 {
		t.Fatalf("post-purge readmission charge = %d", got)
	}
	if verdict := udpPeerSend(t, lease, peerC, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("post-purge excess verdict = %v", verdict)
	}
	if got := udpFlowCount(lease); got != 2 {
		t.Fatalf("post-purge peer readmission added state: %d", got)
	}
}

// U06: a destination-less listener peers are attached with the complete
// captured tuple, so their semantic keys/cutoffs are independent. This is the
// negative control for reusing the incomplete attempt intent as the key.
func TestUDPPeerListenerTupleIsolation(t *testing.T) {
	fixture := newUDPPeerEngine(t, 4, `,"conntrack":{"max_entries":8}`, udpPeerAnyRule())
	lease := fixture.listener("192.0.2.1:40000")
	if lease.intent.Destination.IsValid() {
		t.Fatalf("fixture intent unexpectedly carries a destination %v", lease.intent.Destination)
	}
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	peers := []netip.AddrPort{
		netip.MustParseAddrPort("198.51.100.7:1001"),
		netip.MustParseAddrPort("198.51.100.7:1002"),
		netip.MustParseAddrPort("198.51.100.8:1001"),
	}
	for _, peer := range peers {
		packet := udpPeerPacket(t, source, peer, []byte("x"))
		if verdict := udpPeerSend(t, lease, packet, udpPeerNoInject(t)); verdict != VerdictPass {
			t.Fatalf("peer %v verdict = %v", peer, verdict)
		}
	}
	// The listener own socket may be dual-stack: a distinct IPv6 peer carries
	// its own family and complete tuple.
	ipv6Peer := udpPeerPacket(t, netip.MustParseAddrPort("[2001:db8::1]:40000"),
		netip.MustParseAddrPort("[2001:db8::2]:1003"), []byte("x"))
	if verdict := udpPeerSend(t, lease, ipv6Peer, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("IPv6 peer verdict = %v", verdict)
	}
	peers = append(peers, netip.MustParseAddrPort("[2001:db8::2]:1003"))
	if got := udpFlowCount(lease); got != len(peers) {
		t.Fatalf("listener peer states = %d, want %d", got, len(peers))
	}
	if got := udpPeerCharge(fixture.engine); got != len(peers) {
		t.Fatalf("listener peer charge = %d, want %d", got, len(peers))
	}
	if got := fixture.engine.conntrack.len(); got != len(peers) {
		t.Fatalf("semantic entries = %d, want one per complete tuple (%d)", got, len(peers))
	}
	lease.mu.Lock()
	flows := make([]*flowState, 0, len(lease.udpFlows))
	for _, flow := range lease.udpFlows {
		flows = append(flows, flow)
	}
	lease.mu.Unlock()
	if len(flows) != len(peers) {
		t.Fatalf("captured %d flows", len(flows))
	}
	keys := make(map[conntrackKey]struct{}, len(flows))
	entries := make(map[*conntrackEntry]struct{}, len(flows))
	for _, flow := range flows {
		if !flow.key.dst.IsValid() || flow.key.dstPort == 0 || flow.key.srcPort == 0 {
			t.Fatalf("incomplete semantic key %+v", flow.key)
		}
		if flow.entry == nil {
			t.Fatalf("peer %+v has no semantic entry", flow.key)
		}
		keys[flow.key] = struct{}{}
		entries[flow.entry] = struct{}{}
		if flow.entry.key != flow.key {
			t.Fatalf("entry key %+v does not match flow key %+v", flow.entry.key, flow.key)
		}
	}
	if len(keys) != len(peers) || len(entries) != len(peers) {
		t.Fatalf("semantic keys=%d entries=%d, want %d distinct", len(keys), len(entries), len(peers))
	}
	// Cutoff latches are tuple-owned: an admitted peer's latch is independent
	// from every other peer and survives capacity pressure.
	flows[0].updateCutoffLatches(func(latches *cutoffLatches) { latches.wssize = true })
	if !flows[0].cutoffLatchesSnapshot().wssize {
		t.Fatal("cutoff latch was not recorded")
	}
	for _, flow := range flows[1:] {
		if flow.cutoffLatchesSnapshot() != (cutoffLatches{}) {
			t.Fatalf("peer %+v inherited another peer's cutoffs", flow.key)
		}
	}
	for port := uint16(2000); port < 2004; port++ {
		denied := udpPeerPacket(t, source,
			netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), port), []byte("x"))
		udpPeerSend(t, lease, denied, udpPeerNoInject(t))
	}
	if !flows[0].cutoffLatchesSnapshot().wssize {
		t.Fatal("capacity pressure restarted an admitted peer's cutoff")
	}
	if got := udpFlowCount(lease); got != len(peers) {
		t.Fatalf("denied peers evicted admitted state: %d", got)
	}
}

// U07: an admitted peer keeps its own QUIC reassembler; a denied peer allocates
// no QUIC state and does not reset the admitted one.
func TestUDPPeerQUICReassemblyAdmittedOnly(t *testing.T) {
	fixture := newUDPPeerEngine(t, 1, "", udpPeerFakeRule())
	lease := fixture.listener("192.0.2.1:40000")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	admitted := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:443"), testQUICInitialPayload(t, "peer.example"))
	injected := 0
	if verdict := lease.HandlePacket(admitted.Raw, DirectionOutbound, func([]byte) error {
		injected++
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("admitted QUIC peer verdict = %v", verdict)
	}
	if injected != 1 {
		t.Fatalf("admitted QUIC peer injections = %d, want 1", injected)
	}
	lease.mu.Lock()
	var admittedFlow *flowState
	for _, flow := range lease.udpFlows {
		admittedFlow = flow
	}
	lease.mu.Unlock()
	if admittedFlow == nil || admittedFlow.quic == nil {
		t.Fatal("admitted QUIC peer owns no reassembler")
	}
	reassembler := admittedFlow.quic

	denied := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.8:443"), testQUICInitialPayload(t, "peer.example"))
	if verdict := lease.HandlePacket(denied.Raw, DirectionOutbound, func([]byte) error {
		t.Errorf("denied QUIC peer must not inject")
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("denied QUIC peer verdict = %v", verdict)
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("denied QUIC peer allocated state: %d", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("denied QUIC peer charged: %d", got)
	}
	lease.mu.Lock()
	still := admittedFlow.quic
	lease.mu.Unlock()
	if still != reassembler {
		t.Fatal("denied peer reset or replaced the admitted peer's reassembler")
	}
}

// U09 (negative control: premature release under an active callback): the
// charge and map are retained until teardown finished AND the last borrowed
// user released, in both Close/Engine.Close orderings.
func TestUDPPeerRetirementWaitsForActiveUser(t *testing.T) {
	fixture := newUDPPeerEngine(t, 1, "", udpPeerFakeRule())
	lease := fixture.listener("192.0.2.1:40000")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	packet := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:443"), testQUICInitialPayload(t, "peer.example"))
	injected := make(chan struct{})
	unblock := make(chan struct{})
	done := make(chan Verdict, 1)
	go func() {
		done <- lease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
			close(injected)
			<-unblock
			return nil
		}, nil)
	}()
	<-injected
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("charge while the user is active = %d, want 1", got)
	}

	// Another datagram at capacity is still refused while the in-flight user
	// holds the only charge.
	other := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.8:443"), testQUICInitialPayload(t, "peer.example"))
	if verdict := lease.HandlePacket(other.Raw, DirectionOutbound, func([]byte) error {
		t.Errorf("refused datagram must not inject")
		return nil
	}, nil); verdict != VerdictPass {
		t.Fatalf("refused datagram verdict = %v", verdict)
	}

	// Close is prompt with a non-joining fake capture and must not reclaim the
	// in-use charge through teardown alone.
	closed := make(chan error, 1)
	go func() { closed <- lease.Close(nil) }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Lease.Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Lease.Close blocked on an active borrowed user")
	}
	if got := fixture.engine.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after teardown = %d, want 0", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("teardown released the peer charge with an active user: %d", got)
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("teardown detached the map under an active user: %d", got)
	}

	// No premature capacity reuse: a fresh listener is admitted (the admission
	// slot is free) but its peer is refused while the user is still active.
	second := fixture.listener("192.0.2.1:40001")
	probe := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40001"),
		netip.MustParseAddrPort("198.51.100.9:8443"), []byte("x"))
	if verdict := udpPeerSend(t, second, probe, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("premature reuse verdict = %v", verdict)
	}
	if got := udpFlowCount(second); got != 0 {
		t.Fatalf("premature capacity reuse allocated %d peer states", got)
	}

	// Releasing the user retires the map and charge without another caller
	// action; only then does capacity return.
	close(unblock)
	select {
	case verdict := <-done:
		if verdict != VerdictPass {
			t.Fatalf("in-flight verdict = %v", verdict)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight callback did not finish")
	}
	if got := udpPeerCharge(fixture.engine); got != 0 {
		t.Fatalf("charge after the last user released = %d, want 0", got)
	}
	if got := udpFlowCount(lease); got != 0 {
		t.Fatalf("map after the last user released = %d, want 0", got)
	}
	if verdict := udpPeerSend(t, second, probe, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("post-retirement verdict = %v", verdict)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("post-retirement charge = %d, want 1", got)
	}
	// Repeated Close/release cannot underflow or discharge another owner.
	for index := 0; index < 3; index++ {
		if err := lease.Close(nil); err != nil {
			t.Fatalf("repeated Lease.Close: %v", err)
		}
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("repeated Close discharged another owner: %d", got)
	}

	// Engine.Close ordering: teardown done, user active, charge retained.
	engineFixture := newUDPPeerEngine(t, 1, "", udpPeerFakeRule())
	engineLease := engineFixture.listener("192.0.2.1:40000")
	engineInjected := make(chan struct{})
	engineUnblock := make(chan struct{})
	engineDone := make(chan Verdict, 1)
	go func() {
		engineDone <- engineLease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
			close(engineInjected)
			<-engineUnblock
			return nil
		}, nil)
	}()
	<-engineInjected
	if err := engineFixture.engine.Close(); err != nil {
		t.Fatalf("Engine.Close: %v", err)
	}
	if got := udpPeerCharge(engineFixture.engine); got != 1 {
		t.Fatalf("Engine.Close released an in-use peer charge: %d", got)
	}
	close(engineUnblock)
	<-engineDone
	if got := udpPeerCharge(engineFixture.engine); got != 0 {
		t.Fatalf("Engine.Close peer charge after user release = %d", got)
	}
}

// U08/U11: close-wins allocates nothing, concurrent admission/close keeps the
// accounting exact, interface snapshots are safe, reload retains charges and
// generations are local.
func TestUDPPeerCloseOrderingsReloadAndIsolation(t *testing.T) {
	t.Run("close-wins", func(t *testing.T) {
		fixture := newUDPPeerEngine(t, 2, "", udpPeerAnyRule())
		lease := fixture.listener("192.0.2.1:40000")
		if err := lease.Close(nil); err != nil {
			t.Fatalf("Lease.Close: %v", err)
		}
		packet := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40000"),
			netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
		if verdict := udpPeerSend(t, lease, packet, udpPeerNoInject(t)); verdict != VerdictPass {
			t.Fatalf("post-close verdict = %v", verdict)
		}
		if got := udpFlowCount(lease); got != 0 {
			t.Fatalf("close-wins allocated %d states", got)
		}
		if got := udpPeerUsers(lease); got != 0 {
			t.Fatalf("close-wins pinned %d users", got)
		}
	})

	t.Run("concurrent-admission-and-close", func(t *testing.T) {
		fixture := newUDPPeerEngine(t, 8, "", udpPeerAnyRule())
		lease := fixture.listener("192.0.2.1:40000")
		source := netip.MustParseAddrPort("192.0.2.1:40000")
		start := make(chan struct{})
		var wait sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			wait.Add(1)
			go func(worker int) {
				defer wait.Done()
				<-start
				for index := 0; index < 30; index++ {
					packet := udpPeerPacket(t, source,
						netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), uint16(3000+worker*30+index)),
						[]byte("x"))
					if verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, nil, nil); verdict != VerdictPass {
						t.Errorf("concurrent verdict = %v", verdict)
						return
					}
				}
			}(worker)
		}
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			for index := 0; index < 30; index++ {
				lease.setSocketDevice(fmt.Sprintf("eth-test%d", index%2))
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			for index := 0; index < 10; index++ {
				_ = lease.CaptureInterface()
				_, _, _ = lease.PreconnectHost()
			}
			_ = lease.Close(nil)
		}()
		close(start)
		wait.Wait()
		// The lease is closed; all borrowed users finished, so retirement ran.
		if got := udpPeerCharge(fixture.engine); got != 0 {
			t.Fatalf("concurrent close left peer charge %d", got)
		}
		if got := udpFlowCount(lease); got != 0 {
			t.Fatalf("concurrent close left %d peer states", got)
		}
		if got := udpPeerUsers(lease); got != 0 {
			t.Fatalf("concurrent close left %d borrowed users", got)
		}
		if got := fixture.engine.ActiveLeases(); got != 0 {
			t.Fatalf("concurrent close left %d active leases", got)
		}
	})

	t.Run("reload-retains-and-generations-are-local", func(t *testing.T) {
		fixture := newUDPPeerEngine(t, 1, "", udpPeerAnyRule())
		lease := fixture.listener("192.0.2.1:40000")
		packet := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40000"),
			netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
		udpPeerSend(t, lease, packet, udpPeerNoInject(t))
		if _, err := fixture.engine.ReloadListsContext(nil); err != nil {
			t.Fatalf("ReloadListsContext: %v", err)
		}
		if got := udpPeerCharge(fixture.engine); got != 1 {
			t.Fatalf("reload released the peer charge: %d", got)
		}
		if got := udpFlowCount(lease); got != 1 {
			t.Fatalf("reload dropped peer states: %d", got)
		}

		// A second engine owns an independent allowance and generation.
		isolation := newUDPPeerEngine(t, 1, "", udpPeerAnyRule())
		isolationLease := isolation.listener("192.0.2.2:40000")
		isolationPacket := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.2:40000"),
			netip.MustParseAddrPort("198.51.100.8:1001"), []byte("x"))
		udpPeerSend(t, isolationLease, isolationPacket, udpPeerNoInject(t))
		if got := udpPeerCharge(isolation.engine); got != 1 {
			t.Fatalf("second engine charge = %d", got)
		}
		if err := lease.Close(nil); err != nil {
			t.Fatalf("first engine close: %v", err)
		}
		if err := lease.Close(nil); err != nil {
			t.Fatalf("repeated first engine close: %v", err)
		}
		if got := udpPeerCharge(fixture.engine); got != 0 {
			t.Fatalf("old owner release left charge %d", got)
		}
		if got := udpPeerCharge(isolation.engine); got != 1 {
			t.Fatalf("old owner release discharged another generation: %d", got)
		}
	})
}

// U05: the bound stays active with semantic conntrack disabled and passive or
// rejected callbacks add no state.
func TestUDPPeerDisabledConntrackAndPassivePaths(t *testing.T) {
	fixture := newUDPPeerEngine(t, 1, `,"conntrack":{"disabled":true},"capture":{"port":[443,40000]}`,
		udpPeerAnyRule())
	if !fixture.engine.conntrack.disabled {
		t.Fatal("fixture conntrack is not disabled")
	}
	lease := fixture.listener("192.0.2.1:40000")
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	// Four distinct peers admitted by the selector, but only one aggregate
	// charge is available: the bound stays active with conntrack disabled.
	for index := 0; index < 4; index++ {
		packet := udpPeerPacket(t, source, netip.AddrPortFrom(
			netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", 7+index)), 443), []byte("x"))
		if verdict := udpPeerSend(t, lease, packet, udpPeerNoInject(t)); verdict != VerdictPass {
			t.Fatalf("disabled-conntrack verdict = %v", verdict)
		}
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("disabled conntrack bound failed: %d states", got)
	}
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("disabled conntrack charge = %d", got)
	}

	// Inbound callbacks never create outbound peer state.
	inbound := udpPeerPacket(t, netip.MustParseAddrPort("198.51.100.7:443"), source, []byte("x"))
	if verdict := lease.HandlePacket(inbound.Raw, DirectionInbound, nil, nil); verdict != VerdictPass {
		t.Fatalf("inbound verdict = %v", verdict)
	}
	// Malformed and selector-denied packets pass without state.
	if verdict := lease.HandlePacket([]byte{0x45}, DirectionOutbound, nil, nil); verdict != VerdictPass {
		t.Fatalf("malformed verdict = %v", verdict)
	}
	denied := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:9999"), []byte("x"))
	if verdict := udpPeerSend(t, lease, denied, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("selector-denied verdict = %v", verdict)
	}
	if got := udpFlowCount(lease); got != 1 {
		t.Fatalf("passive paths added peer state: %d", got)
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	closed := udpPeerPacket(t, source, netip.MustParseAddrPort("198.51.100.7:443"), []byte("x"))
	if verdict := udpPeerSend(t, lease, closed, udpPeerNoInject(t)); verdict != VerdictPass {
		t.Fatalf("closed verdict = %v", verdict)
	}
	if got := udpPeerCharge(fixture.engine); got != 0 {
		t.Fatalf("closed callback resurrected charge: %d", got)
	}
}

// U01/U12: peer state is independent from attempt admission and native holds;
// a B=1 listener still serves its first peer, and state-only UDP stays zero.
func TestUDPPeerAdmissionAndStateOnlyControls(t *testing.T) {
	fixture := newUDPPeerEngine(t, 1, "", udpPeerAnyRule())
	tcpLease, err := fixture.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.1:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatalf("TCP attempt: %v", err)
	}
	if _, err = fixture.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: netip.MustParseAddrPort("192.0.2.1:40000")}); err == nil ||
		!errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("listener attempt at the admission limit = %v, want ErrAdmissionRefused", err)
	}
	if err = tcpLease.Close(nil); err != nil {
		t.Fatalf("TCP lease close: %v", err)
	}
	listener := fixture.listener("192.0.2.1:40000")
	// The admitted listener consumes the only admission slot; its first peer is
	// still charged on the independent peer allowance (never ActiveLeases+peers).
	if got := fixture.engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases = %d, want 1", got)
	}
	packet := udpPeerPacket(t, netip.MustParseAddrPort("192.0.2.1:40000"),
		netip.MustParseAddrPort("198.51.100.7:1001"), []byte("x"))
	udpPeerSend(t, listener, packet, udpPeerNoInject(t))
	if got := udpPeerCharge(fixture.engine); got != 1 {
		t.Fatalf("peer charge with B=1 = %d, want 1", got)
	}
	if got := fixture.engine.ActiveLeases(); got != 1 {
		t.Fatalf("peer state changed admission accounting: %d", got)
	}

	// A retained native hold keeps its own admission slot and never touches the
	// peer charge.
	retained := newUDPPeerEngine(t, 2, "", udpPeerAnyRule())
	retainedLease, err := retained.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatalf("retained TCP attempt: %v", err)
	}
	release, err := retainedLease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	if err = retainedLease.Close(nil); err != nil {
		t.Fatalf("retained lease close: %v", err)
	}
	if got := retained.engine.ActiveLeases(); got != 1 {
		t.Fatalf("retained admission = %d, want the tombstone 1", got)
	}
	release()
	if got := retained.engine.ActiveLeases(); got != 0 {
		t.Fatalf("retained release = %d", got)
	}
	if got := udpPeerCharge(retained.engine); got != 0 {
		t.Fatalf("native hold discharged peer charge: %d", got)
	}

	// State-only UDP keeps RA-S2: no capture lease, no peer charge.
	stateEngine, err := NewStateEngine(&option.DirectDesyncOptions{}, nil)
	if err != nil {
		t.Fatalf("NewStateEngine: %v", err)
	}
	defer stateEngine.Close()
	if stateEngine.PacketEnabled() {
		t.Fatal("state-only engine reports packet capability")
	}
	stateLease, err := stateEngine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: netip.MustParseAddrPort("192.0.2.1:40000")})
	if err != nil {
		t.Fatalf("state-only UDP attempt: %v", err)
	}
	if got := udpPeerCharge(stateEngine); got != 0 {
		t.Fatalf("state-only UDP charged %d peers", got)
	}
	if err = stateLease.Close(nil); err != nil {
		t.Fatalf("state-only lease close: %v", err)
	}
	if got := udpPeerCharge(stateEngine); got != 0 {
		t.Fatalf("state-only close left peer charge %d", got)
	}
}

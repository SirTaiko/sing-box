package desync

import (
	"errors"
	"net/netip"
	"testing"
)

type testCapture struct {
	closed bool
}

func (c *testCapture) Close() error {
	c.closed = true
	return nil
}

type testBackend struct {
	name   string
	opened int
	fail   error
}

func (b *testBackend) Name() string { return b.name }

func (b *testBackend) Open(lease *Lease) (Capture, error) {
	if b.fail != nil {
		return nil, b.fail
	}
	b.opened++
	return &testCapture{}, nil
}

func testTCPPacket(t *testing.T, payload []byte, sequence uint32) []byte {
	t.Helper()
	packet := buildIPv4TCP(t, payload, sequence, tcpFlagACK|tcpFlagPSH)
	return append([]byte(nil), packet.Raw...)
}

func TestEngineLeaseLifecycleAndFakeInjection(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],"methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"tls","hex":"16030100"}]},"fooling":["ts"]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{name: "test"}
	engine, err := NewEngine(config, backend)
	if err != nil {
		t.Fatal(err)
	}
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.20:443")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: destination})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	if backend.opened != 1 {
		t.Fatalf("captures = %d", backend.opened)
	}
	hello := buildClientHello("blocked.example")
	packet := testTCPPacket(t, hello, 1000)
	injected := 0
	verdict := lease.HandlePacket(packet, DirectionOutbound, func(replacement []byte) error {
		injected++
		return nil
	}, nil)
	if verdict != VerdictPass {
		t.Fatalf("fake must keep the original, verdict = %d", verdict)
	}
	if injected != 2 {
		t.Fatalf("injected = %d", injected)
	}
	// Inbound packets are never transformed.
	if got := lease.HandlePacket(packet, DirectionInbound, nil, nil); got != VerdictPass {
		t.Fatal("inbound packet must pass")
	}
	// A retransmitted hello is a counter event but must not re-emit fake
	// packets for a latched cutoff: configure and verify cutoff separately.
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatal("engine close must release every lease")
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal("lease close must be idempotent")
	}
}

func TestLeaseInjectionFailureReleasesOriginal(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	packet := testTCPPacket(t, buildClientHello("blocked.example"), 1000)
	verdict := lease.HandlePacket(packet, DirectionOutbound, func([]byte) error {
		return errors.New("inject failed")
	}, nil)
	if verdict != VerdictPass {
		t.Fatalf("failed batch must release the original, verdict = %d", verdict)
	}
	if lease.Err() == nil {
		t.Fatal("injection failure must be surfaced")
	}
	// After a failure the flow must not transform further packets.
	if got := lease.HandlePacket(packet, DirectionOutbound, func([]byte) error {
		t.Fatal("flow must be latched after failure")
		return nil
	}, nil); got != VerdictPass {
		t.Fatal("latched flow must pass the original")
	}
}

func TestEngineLeaseLimit(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},"rules":[{"ip_cidr":["any"],"methods":[]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	_, err = engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Destination: netip.MustParseAddrPort("198.51.100.21:443")}); err == nil {
		t.Fatal("active lease limit must be enforced")
	}
}

func TestEngineDisabledPathAllocatesNothing(t *testing.T) {
	disabledOptions := optionDesyncDisabled(false)
	config, err := Compile(&disabledOptions, "")
	if err != nil || config != nil {
		t.Fatalf("disabled configuration must not produce a config")
	}
}

func TestBackendFailureRejectsActivation(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"ip_cidr":["any"],"methods":[]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test", fail: errors.New("no driver")})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.StartCapture(); err == nil {
		t.Fatal("capture failure must abort the attempt")
	}
	if err = lease.Close(nil); err != nil {
		t.Fatal(err)
	}
}

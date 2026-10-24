//go:build windows

package direct

// QA365-O1 production-boundary regression on native Windows.
//
// The packet-enabled UDP dial reaches the lease preparation from the
// last-chance Control hook, before net.Dialer binds, and the dialer keeps the
// lease as the single bind owner. This test dials through the real direct
// outbound and the real installed attempt bridge, with a test-owned counting
// capture backend instead of the WinDivert driver, and asserts that the native
// socket owns its actual port before the capture is scoped and returned.
//
// The requested-source and bind-refusal behavior of the same native preparation
// owner is exercised with a real unbound Winsock handle in
// common/desync/backend_windows_udp_prepare_test.go.

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
)

// bindingBackend records the endpoint the capture was opened with, so the test
// proves the capture envelope is scoped to the port the kernel actually
// assigned and opened only after the exclusive bind.
type bindingBackend struct {
	opened   int
	endpoint desync.Endpoint
}

func (b *bindingBackend) Name() string { return "windows-udp-binding" }

func (b *bindingBackend) Open(lease *desync.Lease) (desync.Capture, error) {
	b.opened++
	b.endpoint = lease.Endpoint()
	return &bindingCapture{}, nil
}

type bindingCapture struct{}

func (c *bindingCapture) Close() error { return nil }

func packetUDPOutbound(t *testing.T) *Outbound {
	t.Helper()
	return newUDPTrackingOutbound(t, option.DirectOutboundOptions{
		Desync: &option.DirectDesyncOptions{Rules: []option.DirectDesyncRule{{
			Network: []string{"udp"},
			Methods: []string{},
		}}},
	})
}

// installBindingEngine swaps the compiled packet engine for one with a
// test-owned capture backend and a lease bound of 1, exactly like the shipped
// regression does.
func installBindingEngine(t *testing.T, outbound *Outbound, backend *bindingBackend) *desync.Engine {
	t.Helper()
	original := outbound.desync
	if original == nil {
		t.Fatal("packet rule produced no engine")
	}
	installed, isDefaultDialer := common.Cast[*dialer.DefaultDialer](outbound.dialer)
	if !isDefaultDialer {
		t.Fatal("production constructor did not install a DefaultDialer")
	}
	hook, isBridge := installed.AttemptHook().(*desyncHook)
	if !isBridge {
		t.Fatal("production constructor did not install the attempt bridge")
	}
	config := original.Config()
	config.Limits.MaxLeases = 1
	engine, err := desync.NewEngine(config, backend)
	if err != nil {
		t.Fatalf("desync.NewEngine: %v", err)
	}
	hook.engine = engine
	outbound.desync = engine
	t.Cleanup(func() {
		_ = original.Close()
		_ = engine.Close()
	})
	return engine
}

func TestWindowsPacketUDPOwnsActualPortBeforeCapture(t *testing.T) {
	peer, destination := udpTrackingLabPeer(t)
	outbound := packetUDPOutbound(t)
	backend := &bindingBackend{}
	engine := installBindingEngine(t, outbound, backend)
	conn, err := outbound.DialContext(context.Background(), "udp", destination)
	if err != nil {
		t.Fatalf("QA365-O1: Windows packet-enabled connected UDP dial failed before tracking: %v", err)
	}
	local, isUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	if !isUDPAddr {
		t.Fatalf("returned transport local address is %T, not a native UDP address", conn.LocalAddr())
	}
	if local.Port == 0 {
		t.Fatal("returned transport has no owned local port")
	}
	if backend.opened != 1 {
		t.Fatalf("attempt capture opened %d times, want exactly 1", backend.opened)
	}
	if backend.endpoint.Transport != desync.TransportUDP {
		t.Fatalf("capture transport = %v", backend.endpoint.Transport)
	}
	if backend.endpoint.Source.Port() != uint16(local.Port) {
		t.Fatalf("capture source port %d is not the owned actual port %d: capture was scoped before the exclusive bind",
			backend.endpoint.Source.Port(), local.Port)
	}
	assertUDPPayloadBothWays(t, conn, peer)
	if err = conn.Close(); err != nil {
		t.Fatalf("close tracked transport: %v", err)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("returned transport close left %d charged packet leases", engine.ActiveLeases())
	}
}

func TestWindowsPacketUDPListenerOwnsActualPortBeforeCapture(t *testing.T) {
	outbound := packetUDPOutbound(t)
	backend := &bindingBackend{}
	engine := installBindingEngine(t, outbound, backend)
	conn, err := outbound.ListenPacket(context.Background(), M.ParseSocksaddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("Windows packet-enabled UDP listener: %v", err)
	}
	local, isUDPAddr := conn.LocalAddr().(*net.UDPAddr)
	if !isUDPAddr || local.Port == 0 {
		t.Fatalf("bound UDP listener local address = %v", conn.LocalAddr())
	}
	if backend.opened != 1 {
		t.Fatalf("listener capture opened %d times, want exactly 1", backend.opened)
	}
	if backend.endpoint.Source.Port() != uint16(local.Port) {
		t.Fatalf("listener capture source port %d is not the bound port %d", backend.endpoint.Source.Port(), local.Port)
	}
	if err = conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("listener deadline: %v", err)
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear listener deadline: %v", err)
	}
	if err = conn.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	if engine.ActiveLeases() != 0 {
		t.Fatalf("closed listener left %d charged packet leases", engine.ActiveLeases())
	}
}

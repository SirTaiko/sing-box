//go:build windows

package desync

// QA365-O1 native regression: a Windows packet-enabled UDP attempt reaches the
// desync preparation hook from the dialer's last-chance Control callback, i.e.
// before net.Dialer binds, because the dialer clears its own local address for
// packet leases. The lease is therefore the single bind owner and must bind the
// exclusive port itself. Before this was corrected the hook called getsockname
// on an unbound Winsock socket and every packet-enabled connected UDP dial
// failed with "desync: getsockname: An invalid argument was supplied."
//
// These tests drive prepareSocket directly with a real, unbound Winsock SOCK_DGRAM
// handle and a test-owned counting capture backend, so they exercise the native
// bind/getsockname/capture order without the WinDivert driver.

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// windowsUDPPrepareBackend records the endpoint the capture was opened with, so
// the test proves the capture envelope is scoped to the port the kernel
// actually assigned and that capture opens only after the exclusive bind.
type windowsUDPPrepareBackend struct {
	opened   int
	endpoint Endpoint
}

func (b *windowsUDPPrepareBackend) Name() string { return "test-windows-udp-prepare" }

func (b *windowsUDPPrepareBackend) Open(lease *Lease) (Capture, error) {
	b.opened++
	b.endpoint = lease.Endpoint()
	return &testCapture{}, nil
}

func windowsUDPPrepareEngine(t *testing.T) (*Engine, *windowsUDPPrepareBackend) {
	t.Helper()
	backend := &windowsUDPPrepareBackend{}
	limits := defaultLimits()
	limits.MaxLeases = 2
	engine, err := NewEngine(&Config{Limits: limits}, backend)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
	})
	return engine, backend
}

// windowsUnboundUDPSocket creates the same kind of native handle the dialer's
// Control hook receives: a fresh, unbound Winsock datagram socket.
func windowsUnboundUDPSocket(t *testing.T, family int32) windows.Handle {
	t.Helper()
	handle, err := windows.WSASocket(family, windows.SOCK_DGRAM, windows.IPPROTO_UDP, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		t.Fatalf("WSASocket: %v", err)
	}
	t.Cleanup(func() {
		_ = windows.Closesocket(handle)
	})
	return handle
}

func TestWindowsUDPPrepareBindsExclusivePortBeforeCapture(t *testing.T) {
	engine, backend := windowsUDPPrepareEngine(t)
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportUDP,
		Destination: netip.MustParseAddrPort("127.0.0.1:9"),
	})
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	if port := lease.LocalAddress().Port(); port != 0 {
		t.Fatalf("precondition: lease local port = %d, want the pre-bind state 0", port)
	}
	handle := windowsUnboundUDPSocket(t, windows.AF_INET)
	if err = lease.PrepareSocket(uintptr(handle)); err != nil {
		t.Fatalf("QA365-O1: Windows UDP preparation failed on the unbound pre-bind socket: %v", err)
	}
	local := lease.LocalAddress()
	if !local.IsValid() || local.Port() == 0 {
		t.Fatalf("exclusive bind did not publish the actual local endpoint: %v", local)
	}
	socketLocal, err := sockaddrForHandle(uintptr(handle))
	if err != nil {
		t.Fatalf("socket local endpoint after prepare: %v", err)
	}
	if socketLocal != local {
		t.Fatalf("lease local endpoint %v != socket getsockname %v", local, socketLocal)
	}
	if backend.opened != 1 {
		t.Fatalf("capture opened %d times, want exactly 1", backend.opened)
	}
	if backend.endpoint.Transport != TransportUDP {
		t.Fatalf("capture transport = %v", backend.endpoint.Transport)
	}
	if backend.endpoint.Source != local {
		t.Fatalf("capture source %v is not the owned actual endpoint %v: the capture was scoped before the exclusive port existed", backend.endpoint.Source, local)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
	if active := engine.ActiveLeases(); active != 0 {
		t.Fatalf("closed attempt left %d charged leases", active)
	}
}

func TestWindowsUDPPrepareHonorsRequestedSourceAddress(t *testing.T) {
	engine, backend := windowsUDPPrepareEngine(t)
	source := netip.MustParseAddrPort("127.0.0.1:0")
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportUDP,
		Source:      source,
		Destination: netip.MustParseAddrPort("127.0.0.1:9"),
	})
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	handle := windowsUnboundUDPSocket(t, windows.AF_INET)
	if err = lease.PrepareSocket(uintptr(handle)); err != nil {
		t.Fatalf("prepare with requested source: %v", err)
	}
	local := lease.LocalAddress()
	if local.Addr() != source.Addr() {
		t.Fatalf("requested source address %v was not honored, bound %v", source.Addr(), local.Addr())
	}
	if local.Port() == 0 {
		t.Fatal("requested source address bind did not create an owned port")
	}
	if backend.opened != 1 || backend.endpoint.Source != local {
		t.Fatalf("capture envelope %v / opens %d is not the requested-source endpoint %v", backend.endpoint.Source, backend.opened, local)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
}

func TestWindowsUDPPrepareFailsClosedOnUnbindableSource(t *testing.T) {
	engine, backend := windowsUDPPrepareEngine(t)
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportUDP,
		Source:      netip.MustParseAddrPort("192.0.2.123:0"),
		Destination: netip.MustParseAddrPort("127.0.0.1:9"),
	})
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	handle := windowsUnboundUDPSocket(t, windows.AF_INET)
	err = lease.PrepareSocket(uintptr(handle))
	if err == nil {
		t.Fatal("prepare on an unbindable source address succeeded; the attempt must fail closed")
	}
	if !strings.Contains(err.Error(), "bind exclusive local port") {
		t.Fatalf("bind failure lost its actionable reason: %v", err)
	}
	if backend.opened != 0 {
		t.Fatalf("capture opened %d times before a failed exclusive bind", backend.opened)
	}
	if closeErr := lease.Close(err); closeErr != nil {
		t.Fatalf("Lease.Close after failed prepare: %v", closeErr)
	}
	if active := engine.ActiveLeases(); active != 0 {
		t.Fatalf("failed attempt kept %d charged leases", active)
	}
}

func TestWindowsUDPPrepareIPv6Loopback(t *testing.T) {
	engine, backend := windowsUDPPrepareEngine(t)
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv6,
		Transport:   TransportUDP,
		Destination: netip.MustParseAddrPort("[::1]:9"),
	})
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	handle, socketErr := windows.WSASocket(windows.AF_INET6, windows.SOCK_DGRAM, windows.IPPROTO_UDP, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if socketErr != nil {
		t.Fatalf("WSASocket(AF_INET6): %v", socketErr)
	}
	t.Cleanup(func() {
		_ = windows.Closesocket(handle)
	})
	if err = lease.PrepareSocket(uintptr(handle)); err != nil {
		if errors.Is(err, windows.WSAEAFNOSUPPORT) {
			t.Skipf("native IPv6 datagram socket unsupported on this guest: %v", err)
		}
		t.Fatalf("native IPv6 packet-UDP preparation: %v", err)
	}
	local := lease.LocalAddress()
	if !local.Addr().Is6() || local.Addr().Is4In6() {
		t.Fatalf("IPv6 attempt bound a non-IPv6 endpoint: %v", local)
	}
	if local.Port() == 0 {
		t.Fatal("IPv6 attempt did not obtain an exclusive port")
	}
	if backend.opened != 1 || backend.endpoint.Source != local {
		t.Fatalf("IPv6 capture envelope %v / opens %d is not %v", backend.endpoint.Source, backend.opened, local)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("Lease.Close: %v", err)
	}
}

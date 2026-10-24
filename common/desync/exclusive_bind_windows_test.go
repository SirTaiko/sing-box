//go:build windows

package desync

// SEC371-S1 native exclusivity probes.
//
// The ownership premise of packet desync is an exclusively owned local UDP
// endpoint: capture identifies a flow by that endpoint and cannot tell two
// sockets sharing it apart. The regression these probes enforce is a SECOND,
// DISTINCT Winsock socket attempting to bind the endpoint an owned socket
// already holds — a second bind on the same handle proves nothing and is not
// used here.
//
// Both owner shapes are exercised with real sockets and a fake capture backend,
// so the WinDivert driver is not required:
//
//   - the connected packet-UDP attempt, prepared through the production
//     prepareSocket/bindExclusiveUDPAddress path;
//   - the bound packet-UDP listener, bound through the production
//     PacketUDPListenerControl that the dialer installs before bind (the same
//     control list is used by the ordinary ListenPacket and the serial-interface
//     listener paths).
//
// Each owner is probed by a plain contender and by a reusable contender
// (SO_REUSEADDR), on IPv4 and, where the host has an IPv6 loopback, on IPv6.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const (
	sec371ContenderTimeout = 5 * time.Second
)

// sec371ContenderBind creates an independent datagram socket and attempts to
// bind the exact endpoint an owned socket holds. The returned error is nil only
// when the contender actually obtained the endpoint, which is the failure this
// probe reports.
func sec371ContenderBind(t *testing.T, family int32, address windows.Sockaddr, reusable bool) error {
	t.Helper()
	handle, err := windows.WSASocket(family, windows.SOCK_DGRAM, windows.IPPROTO_UDP, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		t.Fatalf("contender WSASocket: %v", err)
	}
	defer windows.Closesocket(handle)
	if reusable {
		// This is the option that lets a sibling join a non-exclusive Windows
		// endpoint, i.e. the reusable contender named by the finding.
		if err = windows.SetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			t.Fatalf("contender SO_REUSEADDR: %v", err)
		}
	}
	return windows.Bind(handle, address)
}

func sec371RequireRefused(t *testing.T, label string, endpoint string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s contender bound the owned endpoint %s: the owned socket is not exclusive", label, endpoint)
	}
	// A plain contender is refused with WSAEADDRINUSE. Against a socket that
	// holds SO_EXCLUSIVEADDRUSE, Winsock refuses the SO_REUSEADDR contender with
	// WSAEACCES ("access permissions") instead: the bind is forbidden rather
	// than merely conflicting. Both outcomes prove the endpoint was not shared;
	// only nil (the contender actually bound) is exclusivity failure. The code is
	// recorded by the test log, not inferred from the option name.
	if !errors.Is(err, windows.WSAEADDRINUSE) && !errors.Is(err, windows.WSAEACCES) {
		t.Fatalf("%s contender failed with an unexpected cause (want WSAEADDRINUSE or WSAEACCES): %v", label, err)
	}
}

func sec371ProbeEndpoint(t *testing.T, family int32, address windows.Sockaddr, endpoint string) {
	t.Helper()
	plainErr := sec371ContenderBind(t, family, address, false)
	reusableErr := sec371ContenderBind(t, family, address, true)
	// The actual Winsock outcome of both contenders is recorded: exclusivity is
	// established by the observed refusal, never by the option's name.
	t.Logf("owned endpoint %s: plain contender -> %v; reusable contender -> %v", endpoint, plainErr, reusableErr)
	sec371RequireRefused(t, "plain", endpoint, plainErr)
	sec371RequireRefused(t, "reusable", endpoint, reusableErr)
}

func TestSec371WindowsConnectedUDPOwnerIsExclusive(t *testing.T) {
	cases := []struct {
		name        string
		family      Family
		socket      int32
		destination netip.AddrPort
	}{
		{"ipv4", FamilyIPv4, windows.AF_INET, netip.MustParseAddrPort("127.0.0.1:9")},
		{"ipv6", FamilyIPv6, windows.AF_INET6, netip.MustParseAddrPort("[::1]:9")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine, backend := windowsUDPPrepareEngine(t)
			lease, err := engine.NewAttempt(Intent{
				Family:      testCase.family,
				Transport:   TransportUDP,
				Destination: testCase.destination,
			})
			if err != nil {
				t.Fatalf("NewAttempt: %v", err)
			}
			handle := windowsUnboundUDPSocket(t, testCase.socket)
			if err = prepareSocket(lease, uintptr(handle)); err != nil {
				if testCase.family == FamilyIPv6 && isWindowsIPv6LoopbackUnavailable(err) {
					t.Skipf("IPv6 loopback unavailable on this host: %v", err)
				}
				t.Fatalf("prepareSocket: %v", err)
			}
			local := lease.LocalAddress()
			if !local.IsValid() || local.Port() == 0 {
				t.Fatalf("owned attempt has no actual local endpoint: %v", local)
			}
			if backend.opened != 1 {
				t.Fatalf("capture opened %d times for one owned attempt", backend.opened)
			}
			// The capture envelope must be scoped to the port the kernel
			// actually assigned after the exclusive bind.
			if backend.endpoint.Source.Port() != local.Port() {
				t.Fatalf("capture endpoint port %d differs from the bound port %d", backend.endpoint.Source.Port(), local.Port())
			}
			sec371ProbeEndpoint(t, testCase.socket, sec371Sockaddr(t, testCase.family, local), local.String())
		})
	}
}

func TestSec371WindowsPacketUDPListenerOwnerIsExclusive(t *testing.T) {
	cases := []struct {
		name    string
		network string
		address string
		family  Family
		socket  int32
	}{
		{"ipv4", "udp4", "127.0.0.1:0", FamilyIPv4, windows.AF_INET},
		{"ipv6", "udp6", "[::1]:0", FamilyIPv6, windows.AF_INET6},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// This is the exact control the direct outbound installs for an
			// enabled packet configuration; the serial-interface listener binds
			// through the same ListenConfig control list.
			listenerControl := PacketUDPListenerControl()
			if listenerControl == nil {
				t.Fatal("packet listener control is nil on windows")
			}
			listenConfig := net.ListenConfig{Control: listenerControl}
			ctx, cancel := context.WithTimeout(context.Background(), sec371ContenderTimeout)
			defer cancel()
			packetConn, err := listenConfig.ListenPacket(ctx, testCase.network, testCase.address)
			if err != nil {
				if testCase.family == FamilyIPv6 && isWindowsIPv6LoopbackUnavailable(err) {
					t.Skipf("IPv6 loopback unavailable on this host: %v", err)
				}
				t.Fatalf("packet listener bind: %v", err)
			}
			defer packetConn.Close()
			local := packetConn.LocalAddr()
			udpLocal, ok := local.(*net.UDPAddr)
			if !ok || udpLocal.Port == 0 {
				t.Fatalf("listener has no actual local endpoint: %v", local)
			}
			address := sec371Sockaddr(t, testCase.family, netip.AddrPortFrom(netip.MustParseAddr(udpLocal.IP.String()), uint16(udpLocal.Port)))
			sec371ProbeEndpoint(t, testCase.socket, address, local.String())
		})
	}
}

// sec371Sockaddr builds the exact bind address of an owned endpoint. It is used
// only by the contender, so it never participates in the production bind.
func sec371Sockaddr(t *testing.T, family Family, local netip.AddrPort) windows.Sockaddr {
	t.Helper()
	address := local.Addr().Unmap()
	switch family {
	case FamilyIPv4:
		return &windows.SockaddrInet4{Port: int(local.Port()), Addr: address.As4()}
	case FamilyIPv6:
		return &windows.SockaddrInet6{Port: int(local.Port()), Addr: address.As16()}
	default:
		t.Fatalf("unsupported family %v", family)
		return nil
	}
}

// isWindowsIPv6LoopbackUnavailable keeps a host without an IPv6 loopback from
// being reported as an exclusivity failure. It only classifies the setup
// outcome; the IPv4 probe and the IPv6 probe on a host that has the loopback are
// both mandatory.
func isWindowsIPv6LoopbackUnavailable(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL) ||
		errors.Is(err, windows.WSAEAFNOSUPPORT) ||
		errors.Is(err, windows.WSAENETUNREACH)
}

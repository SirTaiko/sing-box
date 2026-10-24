//go:build windows

package desync

// SEC371-S1 second-socket matrix.
//
// The probes in exclusive_bind_windows_test.go establish the property the owned
// packet path needs: after the owned socket binds, no second socket — plain or
// SO_REUSEADDR — can take the same endpoint. This file records the other
// direction honestly, because Windows sharing rules are ordered:
//
//   - a socket bound WITHOUT any sharing option refuses a SO_REUSEADDR
//     contender (observed on Windows Server 2022 for the product paths);
//   - a socket bound WITH SO_REUSEADDR accepts another SO_REUSEADDR socket on
//     the same endpoint — the pre-repair packet+reuse_addr exposure;
//   - a socket that applies the production exclusive option refuses to join an
//     endpoint that a SO_REUSEADDR sibling already holds.
//
// The matrix is executed natively and logged. Only the property the product now
// relies on is asserted: an owned socket that applied the exclusive option never
// joins an endpoint another socket already holds. OS defaults for the other
// pairs are recorded as observed, not assumed.

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// sec371BindMode selects the socket options a probe socket applies before bind.
type sec371BindMode string

const (
	sec371Plain     sec371BindMode = "plain"
	sec371Reusable  sec371BindMode = "reuse"
	sec371Exclusive sec371BindMode = "exclusive"
)

// sec371BindWithOptions creates one datagram socket, applies the mode's options
// and binds the requested endpoint. On success the caller owns the handle.
func sec371BindWithOptions(t *testing.T, family int32, address windows.Sockaddr, mode sec371BindMode) (windows.Handle, error) {
	t.Helper()
	handle, err := windows.WSASocket(family, windows.SOCK_DGRAM, windows.IPPROTO_UDP, nil, 0, windows.WSA_FLAG_OVERLAPPED|windows.WSA_FLAG_NO_HANDLE_INHERIT)
	if err != nil {
		t.Fatalf("WSASocket: %v", err)
	}
	if mode == sec371Reusable {
		if err = windows.SetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			windows.Closesocket(handle)
			t.Fatalf("SO_REUSEADDR: %v", err)
		}
	}
	if mode == sec371Exclusive {
		// The production option, applied through the same helper the product
		// uses, so the matrix describes the shipped mechanism.
		if err = setExclusiveUDPBind(handle); err != nil {
			windows.Closesocket(handle)
			t.Fatalf("exclusive bind option: %v", err)
		}
	}
	if err = windows.Bind(handle, address); err != nil {
		windows.Closesocket(handle)
		return 0, err
	}
	return handle, nil
}

func sec371LocalIPv4Port(t *testing.T, handle windows.Handle) int {
	t.Helper()
	name, err := windows.Getsockname(handle)
	if err != nil {
		t.Fatalf("Getsockname: %v", err)
	}
	bound, ok := name.(*windows.SockaddrInet4)
	if !ok || bound.Port == 0 {
		t.Fatalf("unexpected bound address %#v", name)
	}
	return bound.Port
}

func TestSec371WindowsSecondSocketMatrix(t *testing.T) {
	ownerAddress := func(port int) windows.Sockaddr {
		return &windows.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
	}
	cases := []struct {
		name       string
		owner      sec371BindMode
		contender  sec371BindMode
		mustRefuse bool
		reason     string
	}{
		// This is the pre-repair packet+reuse_addr configuration: both sockets
		// opt into sharing. Recorded as observed, not asserted.
		{"reuse-owner/reuse-contender", sec371Reusable, sec371Reusable, false, "pre-repair sharing pair"},
		// A shareable owner plus a plain contender: OS policy only.
		{"reuse-owner/plain-contender", sec371Reusable, sec371Plain, false, "OS policy"},
		// The security property the repaired product relies on: an owned socket
		// that applied the exclusive option refuses to join a shareable endpoint.
		{"reuse-owner/exclusive-contender", sec371Reusable, sec371Exclusive, true, "owned socket must not join another socket's endpoint"},
		// Product shape: exclusive owner, reusable contender (asserted by the
		// dedicated probes as well).
		{"exclusive-owner/reuse-contender", sec371Exclusive, sec371Reusable, true, "owned endpoint must not be joined"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			owner, err := sec371BindWithOptions(t, windows.AF_INET, ownerAddress(0), testCase.owner)
			if err != nil {
				t.Fatalf("owner bind: %v", err)
			}
			defer windows.Closesocket(owner)
			port := sec371LocalIPv4Port(t, owner)
			contender, contenderErr := sec371BindWithOptions(t, windows.AF_INET, ownerAddress(port), testCase.contender)
			if contenderErr == nil {
				_ = windows.Closesocket(contender)
			}
			t.Logf("owner=%s contender=%s endpoint=127.0.0.1:%d -> %v (%s)",
				testCase.owner, testCase.contender, port, contenderErr, testCase.reason)
			if testCase.mustRefuse {
				if contenderErr == nil {
					t.Fatalf("%s contender joined %s owner's endpoint 127.0.0.1:%d", testCase.contender, testCase.owner, port)
				}
				if !errors.Is(contenderErr, windows.WSAEADDRINUSE) && !errors.Is(contenderErr, windows.WSAEACCES) {
					t.Fatalf("join refused for an unexpected reason: %v", contenderErr)
				}
			}
		})
	}
}

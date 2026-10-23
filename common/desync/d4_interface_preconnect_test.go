//go:build linux

package desync

// D4 interface-scoped preconnect cache closure.
//
// The stream preconnect host lookup used to fall back to an outbound-wide entry
// because the dial attempt carried no interface fact. The native attempt now
// reports its actual interface (socket device first, dialer bind interface
// second) and the lookup is scoped to it, so a host learned on one device is
// never substituted for an attempt bound to another. The engine ip cache stays
// the only cache owner.

import (
	"net/netip"
	"testing"
)

func TestLeasePreconnectHostIsInterfaceScoped(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9}}]}`), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	config.IPCache.hostnameEnabled = true
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	address := netip.MustParseAddr("203.0.113.9")
	if !engine.ipcache.learnHost(address, "eth0", "example.com") {
		t.Fatal("learnHost rejected")
	}

	newLease := func(iface string) *Lease {
		t.Helper()
		lease, leaseErr := engine.NewAttempt(Intent{
			Family:      FamilyIPv4,
			Transport:   TransportTCP,
			Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
			Interface:   iface,
			Destination: netip.AddrPortFrom(address, 443),
		})
		if leaseErr != nil {
			t.Fatalf("attempt: %v", leaseErr)
		}
		t.Cleanup(func() { _ = lease.Close(nil) })
		return lease
	}

	// The attempt bound to the device the host was learned on resolves it.
	onDevice := newLease("eth0")
	if host, _, found := onDevice.PreconnectHost(); !found || host != "example.com" {
		t.Fatalf("interface-scoped lookup = %q/%v", host, found)
	}
	if onDevice.CaptureInterface() != "eth0" {
		t.Fatalf("capture interface = %q, want eth0", onDevice.CaptureInterface())
	}
	// A different device is a miss: no cross-device fallback.
	if host, _, found := newLease("eth1").PreconnectHost(); found {
		t.Fatalf("cross-device fallback returned %q", host)
	}
	// An attempt with no interface fact does not guess either.
	if host, _, found := newLease("").PreconnectHost(); found {
		t.Fatalf("unbound attempt used a device-scoped entry %q", host)
	}
	// The socket-reported device wins over the dialer-supplied interface.
	socketBound := newLease("eth0")
	socketBound.setSocketDevice("eth2")
	if host, _, found := socketBound.PreconnectHost(); found {
		t.Fatalf("socket device override still used another device entry %q", host)
	}
	if socketBound.CaptureInterface() != "eth2" {
		t.Fatalf("socket-reported interface = %q, want eth2", socketBound.CaptureInterface())
	}
	// A listener attempt has no destination to resolve.
	listener, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: netip.MustParseAddrPort("192.0.2.10:40000"), Interface: "eth0"})
	if err != nil {
		t.Fatalf("listener attempt: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close(nil) })
	if _, _, found := listener.PreconnectHost(); found {
		t.Fatal("destination-less attempt resolved a cached host")
	}
}

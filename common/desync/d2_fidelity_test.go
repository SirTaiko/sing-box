package desync

// D2 fidelity closure tests: source-valid conntrack creation, hostname_is_ip,
// interface-scoped cache and request/retransmission state on the retained
// tuple.

import (
	"net/netip"
	"testing"
	"time"
)

// primeSemanticTrack models an owned capture that attached after the SYN was
// already seen: upstream has a track for the tuple, and the captured data
// packets continue counting on it. It creates the entry without feeding any
// counter, so D1 interval expectations are unchanged.
func (f *flowState) primeSemanticTrack() {
	if f.table == nil || f.table.disabled {
		return
	}
	syn := &Packet{Family: f.key.family, Transport: TransportTCP, TCPFlags: tcpFlagSYN}
	entry := f.table.acquire(f.key, syn)
	if entry == nil {
		return
	}
	f.ctAttached = true
	f.ctLost = false
	f.entry = entry
	f.conntrackSemantics = &entry.sem
	f.countersLive = true
}

func TestConntrackCreatesOnlyOnSynForTCP(t *testing.T) {
	table := newConntrackTable(conntrackConfig{maxEntries: 16}, nil)
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.20:443")
	key := conntrackKey{family: FamilyIPv4, transport: TransportTCP,
		src: source.Addr(), dst: destination.Addr(), srcPort: source.Port(), dstPort: destination.Port()}

	// A mid-stream first packet must not create semantic state.
	midstream := &Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPFlags: tcpFlagACK | tcpFlagPSH}
	if entry := table.acquire(key, midstream); entry != nil {
		t.Fatalf("mid-stream TCP packet created a semantic entry")
	}
	fin := &Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPFlags: tcpFlagACK | tcpFlagFIN}
	if entry := table.acquire(key, fin); entry != nil {
		t.Fatalf("FIN TCP packet created a semantic entry")
	}
	// A SYN creates it.
	if entry := table.acquire(key, &Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPFlags: tcpFlagSYN}); entry == nil {
		t.Fatal("SYN did not create a semantic entry")
	}
	// An existing entry is returned for any later packet of the tuple.
	if entry := table.acquire(key, midstream); entry == nil {
		t.Fatal("existing entry was not returned for a data packet")
	}
	// SYN-ACK also creates for the reverse tuple.
	reverse := key
	reverse.src, reverse.dst = key.dst, key.src
	reverse.srcPort, reverse.dstPort = key.dstPort, key.srcPort
	if entry := table.acquire(reverse, &Packet{Family: FamilyIPv4, Transport: TransportTCP,
		TCPFlags: tcpFlagSYN | tcpFlagACK}); entry == nil {
		t.Fatal("SYN-ACK did not create a semantic entry")
	}
}

func TestFirstAttachMidstreamKeepsOwnershipButNoSemanticTrack(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9}}]}`), "")
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
	flow := lease.tcpFlow
	packet := buildIPv4TCP(t, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), 1, tcpFlagACK|tcpFlagPSH)
	flow.observe(packet, false)
	if flow.entry != nil || flow.countersLive {
		t.Fatalf("mid-stream attach created semantic state (entry=%v live=%v)", flow.entry != nil, flow.countersLive)
	}
	// Ownership and capture remain active: the flow is still registered on the
	// lease and can be closed without leaking a track.
	if lease.tcpFlow == nil {
		t.Fatal("ownership lost on mid-stream attach")
	}
	flow.mu.Lock()
	flow.observe(&Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPFlags: tcpFlagSYN}, false)
	_, semantic := flow.entry, flow.countersLive
	flow.mu.Unlock()
	if semantic == false {
		t.Fatal("SYN did not attach the semantic track")
	}
}

func TestIPCacheHostnameIsIPAndInterfaceIsolation(t *testing.T) {
	cache := newIPCache(ipCacheConfig{hostnameEnabled: true, lifetime: time.Minute, maxEntries: 8}, nil)
	address := netip.MustParseAddr("203.0.113.7")
	if !cache.learnHost(address, "eth0", "203.0.113.7") {
		t.Fatal("learnHost rejected a literal")
	}
	host, isIP, ok := cache.lookupHost(address, "eth0")
	if !ok || host != "203.0.113.7" || !isIP {
		t.Fatalf("lookup = %q is_ip=%v ok=%v", host, isIP, ok)
	}
	// Another interface is a different cache key: no cross-interface leak.
	if _, _, ok := cache.lookupHost(address, "eth1"); ok {
		t.Fatal("cache leaked across native interfaces")
	}
	if !cache.learnHost(address, "eth0", "example.com") {
		t.Fatal("learnHost rejected a name")
	}
	if host, isIP, ok := cache.lookupHost(address, "eth0"); !ok || isIP || host != "example.com" {
		t.Fatalf("name lookup = %q is_ip=%v ok=%v", host, isIP, ok)
	}
}

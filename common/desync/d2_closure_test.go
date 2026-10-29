package desync

// D2.3/D2.4/D2.5 tests: tuple-owned learning state shared by concurrent or
// reused attempts, change-detected snapshot reload, and the owned native
// interface dimension.

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func learningFlowHarness(t *testing.T) (*Engine, *flowState, *flowState, *Rule) {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],
		"learning":{"retrans_threshold":3,"fail_threshold":1}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.20:443")
	newAttempt := func() *flowState {
		lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
			Source: source, Destination: destination})
		if err != nil {
			t.Fatal(err)
		}
		lease.SetLocalAddress(source)
		if err = lease.StartCapture(); err != nil {
			t.Fatal(err)
		}
		flow := lease.tcpFlow
		flow.primeSemanticTrack()
		flow.selectRule(config, MatchFacts{Family: FamilyIPv4, Transport: TransportTCP,
			Destination: destination.Addr(), Port: destination.Port(), Host: "example.com", HostKnown: true})
		flow.setLearningHost("example.com")
		return flow
	}
	first := newAttempt()
	second := newAttempt()
	if first.entry == nil || first.entry != second.entry {
		t.Fatal("two attempts on the same owned tuple did not share one semantic entry")
	}
	return engine, first, second, config.Rules[0]
}

func TestLearningRetransStateLivesOnRetainedTuple(t *testing.T) {
	engine, first, second, _ := learningFlowHarness(t)
	first.markLearningRequestFinalized(1000, 100)
	packet := &Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPSeq: 1001, Payload: []byte("x")}
	first.countLearningRetransmission(packet, false)
	retrans := 0
	first.readLearningState(func(learn *learningSemantics) { retrans = learn.retrans })
	if retrans != 1 {
		t.Fatalf("retrans after first attempt = %d, want 1", retrans)
	}
	// A second concurrent attempt on the same tuple continues the same counter.
	second.countLearningRetransmission(packet, false)
	retrans = 0
	second.readLearningState(func(learn *learningSemantics) { retrans = learn.retrans })
	if retrans != 2 {
		t.Fatalf("retrans after second attempt = %d, want 2", retrans)
	}
	first.countLearningRetransmission(packet, false)
	stopped := false
	second.readLearningState(func(learn *learningSemantics) {
		stopped = learn.stopped
		if learn.retrans != 3 {
			t.Fatalf("retrans = %d, want 3", learn.retrans)
		}
	})
	if !stopped {
		t.Fatal("threshold did not stop the shared retransmission counter")
	}
	if !engine.learning.learned("example.com") {
		t.Fatal("threshold failure was not recorded on the engine learner")
	}
	// A fresh SYN reinitializes the whole track, learning state included.
	first.entry.mu.Lock()
	first.entry.resetLocked(first.now())
	first.entry.mu.Unlock()
	second.readLearningState(func(learn *learningSemantics) {
		if learn.retrans != 0 || learn.stopped || learn.host != "" || learn.reqRange {
			t.Fatalf("reinit did not clear tuple learning state: %+v", *learn)
		}
	})
}

func TestLearningStateLostOnTupleExpiry(t *testing.T) {
	now, advance := newFakeClock(time.Unix(1000, 0))
	table := newConntrackTable(conntrackConfig{maxEntries: 4}, now)
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	destination := netip.MustParseAddrPort("198.51.100.20:443")
	key := conntrackKey{family: FamilyIPv4, transport: TransportTCP,
		src: source.Addr(), dst: destination.Addr(), srcPort: source.Port(), dstPort: destination.Port()}
	entry := table.acquire(key, &Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPFlags: tcpFlagSYN})
	entry.sem.learn.retrans = 2
	*advance = advance.Add(table.timeouts.syn + 1)
	table.purge()
	if len(table.entries) != 0 {
		t.Fatal("expired tuple kept its entry")
	}
	fresh := table.acquire(key, &Packet{Family: FamilyIPv4, Transport: TransportTCP, TCPFlags: tcpFlagSYN})
	if fresh.sem.learn.retrans != 0 {
		t.Fatal("expired tuple leaked learning state into a new track")
	}
}

func TestLearningReloadDetectsFileChange(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auto-hostlist.txt")
	if err := os.WriteFile(path, []byte("a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := Compile(enabledOption(`{"enabled":true,"learning":{"path":`+jsonPath(t, path)+`},
		"rules":[{"network":["tcp"],"port":[443],"learning":{}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if !engine.learning.learned("a.example") {
		t.Fatal("initial snapshot not loaded")
	}
	// Unchanged file: the in-memory learned set is preserved (no replacement
	// and no duplicate re-read).
	engine.learning.mu.Lock()
	engine.learning.hosts["mem.example"] = struct{}{}
	engine.learning.mu.Unlock()
	if err = engine.ReloadLists(); err != nil {
		t.Fatal(err)
	}
	if !engine.learning.learned("mem.example") {
		t.Fatal("unchanged snapshot replaced the in-memory learned set")
	}
	// A real change is detected by size/mtime and reloaded transactionally.
	if err = os.WriteFile(path, []byte("a.example\nb.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = engine.ReloadLists(); err != nil {
		t.Fatal(err)
	}
	if !engine.learning.learned("b.example") || engine.learning.learned("mem.example") {
		t.Fatalf("changed snapshot not reloaded: %v", engine.LearnedHosts())
	}
	// A malformed change keeps the last-good set and reports the error.
	if err = os.WriteFile(path, []byte{0x1f, 0x8b, 0x08, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = engine.ReloadLists(); err == nil {
		t.Fatal("gzipped snapshot accepted")
	}
	if !engine.learning.learned("a.example") || !engine.learning.learned("b.example") {
		t.Fatal("last-good snapshot lost after a failed reload")
	}
}

func TestEngineCachedHostInterfaceScopeAndCompatibility(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],
		"orig":{"ttl":9}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	config.IPCache.hostnameEnabled = true
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	address := netip.MustParseAddr("203.0.113.9")
	if !engine.ipcache.learnHost(address, "eth0", "example.com") {
		t.Fatal("learnHost rejected")
	}
	if host, ok := engine.CachedHostOn(address, "eth0"); !ok || host != "example.com" {
		t.Fatalf("interface lookup = %q/%v", host, ok)
	}
	if _, ok := engine.CachedHostOn(address, "eth1"); ok {
		t.Fatal("interface-scoped lookup leaked across devices")
	}
	// The compatibility entrypoint is not interface-scoped and still serves
	// the exact address (never a wildcard).
	if host, ok := engine.CachedHost(address); !ok || host != "example.com" {
		t.Fatalf("compatibility lookup = %q/%v", host, ok)
	}
	if _, ok := engine.CachedHost(netip.MustParseAddr("203.0.113.10")); ok {
		t.Fatal("compatibility lookup matched a different address")
	}
}

func TestLeaseReportsOwnedInterfaceToFlowAndEndpoint(t *testing.T) {
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
	if got := lease.Endpoint().Interface; got != "" {
		t.Fatalf("unbound attempt reported interface %q", got)
	}
	// The actual device is discovered from the bound socket, not invented.
	lease.setSocketDevice("eth-test0")
	if got := lease.captureInterface(); got != "eth-test0" {
		t.Fatalf("capture interface = %q", got)
	}
	if got := lease.Endpoint().Interface; got != "eth-test0" {
		t.Fatalf("endpoint interface = %q", got)
	}
	lease.tcpFlow.mu.Lock()
	flowInterface := lease.tcpFlow.iface
	lease.tcpFlow.mu.Unlock()
	if flowInterface != "eth-test0" {
		t.Fatalf("flow interface = %q", flowInterface)
	}
}

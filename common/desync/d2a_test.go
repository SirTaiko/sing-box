package desync

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testIntent() Intent {
	return Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443")}
}

func writeGzip(path, content string) error {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write([]byte(content)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buffer.Bytes(), 0o600)
}

func newFakeClock(start time.Time) (func() time.Time, *time.Time) {
	current := start
	return func() time.Time { return current }, &current
}

func TestConntrackTimeoutsExpiryAndStickyState(t *testing.T) {
	now, advance := newFakeClock(time.Unix(1000, 0))
	table := newConntrackTable(conntrackConfig{maxEntries: 8,
		timeouts: conntrackTimeouts{syn: 5 * time.Second, established: 10 * time.Second,
			fin: 3 * time.Second, udp: 4 * time.Second}}, now)
	packet := buildIPv4TCP(t, nil, 100, tcpFlagSYN)
	entry := table.acquire(makeConntrackKey(packet, testIntent()), packet)
	if entry == nil {
		t.Fatal("SYN must create an entry")
	}
	entry.observe(packet, false, now())
	if entry.sem.state != connStateSYN || !entry.sem.seq0Set {
		t.Fatalf("SYN state = %v seq0set=%v", entry.sem.state, entry.sem.seq0Set)
	}
	*advance = now().Add(6 * time.Second)
	table.purge()
	if table.len() != 0 || !entry.isExpired() {
		t.Fatalf("idle SYN entry must expire: len=%d expired=%v", table.len(), entry.isExpired())
	}
	// ESTABLISHED uses its own timeout.
	table2 := newConntrackTable(conntrackConfig{maxEntries: 8,
		timeouts: conntrackTimeouts{syn: time.Second, established: time.Minute,
			fin: time.Second, udp: time.Second}}, now)
	syn := buildIPv4TCP(t, nil, 200, tcpFlagSYN)
	e2 := table2.acquire(makeConntrackKey(syn, testIntent()), syn)
	e2.observe(syn, false, now())
	data := buildIPv4TCP(t, []byte("data"), 201, tcpFlagACK|tcpFlagPSH)
	if e2.observe(data, false, now()) {
		t.Fatal("first data packet must establish, not reinit")
	}
	*advance = now().Add(5 * time.Second)
	if table2.len() != 1 {
		t.Fatalf("entry vanished before purge: len=%d", table2.len())
	}
	table2.purge()
	if table2.len() == 0 {
		t.Fatalf("5s idle ESTABLISHED entry must survive a 60s timeout: expired=%v", e2.isExpired())
	}
}

func TestConntrackReinitOnFreshSYNClearsCounters(t *testing.T) {
	now, _ := newFakeClock(time.Unix(2000, 0))
	table := newConntrackTable(defaultConntrackConfig(), now)
	syn := buildIPv4TCP(t, nil, 100, tcpFlagSYN)
	entry := table.acquire(makeConntrackKey(syn, testIntent()), syn)
	entry.observe(syn, false, now())
	data := buildIPv4TCP(t, []byte("x"), 101, tcpFlagACK|tcpFlagPSH)
	entry.observe(data, false, now())
	if entry.sem.counters.packets != 2 {
		t.Fatalf("packets = %d", entry.sem.counters.packets)
	}
	freshSYN := buildIPv4TCP(t, nil, 900, tcpFlagSYN)
	if !entry.observe(freshSYN, false, now()) {
		t.Fatal("a new SYN on an established tuple must reinit the track")
	}
	if entry.sem.counters.packets != 0 || entry.sem.seq0 != 900 {
		// Upstream ConntrackFeedPacket increments then ConntrackReInitTrack
		// memsets the track, so a reinit SYN leaves the new SYN's counter.
		t.Fatalf("reinit must reset counters: %+v seq0=%d", entry.sem.counters, entry.sem.seq0)
	}
}

func TestConntrackPerOutboundIsolation(t *testing.T) {
	now, _ := newFakeClock(time.Unix(3000, 0))
	first := newConntrackTable(defaultConntrackConfig(), now)
	second := newConntrackTable(defaultConntrackConfig(), now)
	syn := buildIPv4TCP(t, nil, 100, tcpFlagSYN)
	key := makeConntrackKey(syn, testIntent())
	entryFirst := first.acquire(key, syn)
	entryFirst.observe(syn, false, now())
	secondEntry := second.acquire(key, syn)
	if secondEntry == entryFirst {
		t.Fatal("different outbounds must not share conntrack state")
	}
	if secondEntry.sem.counters.packets != 0 {
		t.Fatalf("second outbound borrowed state: %+v", secondEntry.sem.counters)
	}
}

func TestIPCacheLifetimeHopAndHostIsolation(t *testing.T) {
	now, advance := newFakeClock(time.Unix(4000, 0))
	cache := newIPCache(ipCacheConfig{hostnameEnabled: true, lifetime: 30 * time.Second, maxEntries: 4}, now)
	address := netip.MustParseAddr("198.51.100.20")
	if !cache.learnHost(address, "", "quic.example") {
		t.Fatal("hostname learning must succeed when enabled")
	}
	if host, _, ok := cache.lookupHost(address, ""); !ok || host != "quic.example" {
		t.Fatalf("cache host = %q/%v", host, ok)
	}
	if _, _, ok := cache.lookupHost(netip.MustParseAddr("198.51.100.21"), ""); ok {
		t.Fatal("cache lookup must be keyed by the exact address")
	}
	hops, ok := cache.learnHop(address, 250) // 255-250 = 5 hops
	if !ok || hops != 5 {
		t.Fatalf("hop guess = %d/%v", hops, ok)
	}
	*advance = now().Add(31 * time.Second)
	if _, _, ok := cache.lookupHost(address, ""); ok {
		t.Fatal("expired hostname must not be served")
	}
	if _, ok := cache.lookupHop(address); ok {
		t.Fatal("expired hop count must not be served")
	}
	// Hostname caching is opt-in: a disabled cache never stores or serves it.
	disabled := newIPCache(ipCacheConfig{maxEntries: 4}, now)
	if disabled.learnHost(address, "", "x.example") {
		t.Fatal("disabled hostname cache must not learn")
	}
	// A different outbound has its own cache and cannot observe this entry.
	other := newIPCache(ipCacheConfig{hostnameEnabled: true, lifetime: 30 * time.Second, maxEntries: 4}, now)
	if _, _, ok := other.lookupHost(address, ""); ok {
		t.Fatal("cache state leaked between outbounds")
	}
}

func TestIPCacheExplicitZeroLifetimeNeverExpires(t *testing.T) {
	now, advance := newFakeClock(time.Unix(5000, 0))
	cache := newIPCache(ipCacheConfig{hostnameEnabled: true, noExpiry: true, lifetime: 0, maxEntries: 4}, now)
	address := netip.MustParseAddr("203.0.113.9")
	cache.learnHost(address, "", "keep.example")
	*advance = now().Add(48 * time.Hour)
	if host, _, ok := cache.lookupHost(address, ""); !ok || host != "keep.example" {
		t.Fatalf("explicit zero lifetime must not expire: %q/%v", host, ok)
	}
}

func TestQUICCrossDatagramCRYPTOReassembly(t *testing.T) {
	hello := rawQUICClientHello("spread.example")
	dcid := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	split := len(hello) / 2
	first := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:split]}, 240), dcid, 1, 1)
	second := sealQUICInitial(t, cryptoFrames([]int{split}, [][]byte{hello[split:]}, 240), dcid, 1, 2)
	q := newQUICReassembler()
	if host, ok := q.add(first); ok {
		t.Fatalf("partial CRYPTO must not report a host: %q", host)
	}
	host, ok := q.add(second)
	if !ok || host != "spread.example" {
		t.Fatalf("cross-datagram reassembly host = %q/%v", host, ok)
	}

	// Out-of-order arrival and exact retransmission are accepted.
	q2 := newQUICReassembler()
	if _, ok := q2.add(second); ok {
		t.Fatal("out-of-order partial must not report a host")
	}
	if _, ok := q2.add(second); ok {
		t.Fatal("retransmission alone must not report a host")
	}
	if host, ok := q2.add(first); !ok || host != "spread.example" {
		t.Fatalf("out-of-order completion host = %q/%v", host, ok)
	}

	// A conflicting overlap is refused rather than guessed.
	q3 := newQUICReassembler()
	helloA := rawQUICClientHello("aaaa.example")
	helloB := rawQUICClientHello("bbbb.example")
	if _, ok := q3.add(sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{helloA[:split]}, 240), dcid, 1, 1)); ok {
		t.Fatal("partial must not report")
	}
	if _, ok := q3.add(sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{helloB[:split]}, 240), dcid, 1, 2)); ok {
		t.Fatal("conflicting overlap must be refused")
	}

	// A different DCID is a different connection: no concatenation.
	q4 := newQUICReassembler()
	otherDCID := []byte{1, 1, 1, 1}
	if _, ok := q4.add(sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:split]}, 240), otherDCID, 1, 1)); ok {
		t.Fatal("different connection partial must not report")
	}
	if _, ok := q4.add(first); ok {
		t.Fatal("a datagram of another connection must not complete the first")
	}
	if host, ok := q4.add(second); !ok || host != "spread.example" {
		t.Fatalf("a new connection identity restarts reassembly: %q/%v", host, ok)
	}
}

func TestIPv6OrigExtensionPropagatesToEveryRealSplitSegment(t *testing.T) {
	for _, mode := range []struct {
		method string
		header uint8
	}{
		{"hopbyhop", 0},
		{"destopt", 60},
		{"ipfrag1", 44},
	} {
		rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["tcp"],"ip_version":[6],`+
			`"methods":["`+mode.method+`","multisplit"],"multisplit":{"split_pos":["1"]}}]}`)
		payload := []byte("abcdef")
		packet := buildIPv6TCP(t, payload, 1000, tcpFlagACK|tcpFlagPSH)
		batch, err := PlanTCP(rule, packet, payload, 0, Facts{MessageLength: len(payload), Rand: &sequenceRand{}})
		if err != nil {
			t.Fatal(err)
		}
		if batch.Original != VerdictDrop || len(batch.Packets) != 2 {
			t.Fatalf("%s: verdict=%d packets=%d", mode.method, batch.Original, len(batch.Packets))
		}
		var rebuilt []byte
		for _, generated := range batch.Packets {
			if generated[0]>>4 != 6 || generated[6] != mode.header {
				t.Fatalf("%s: real segment lacks extension header %d (next=%d)", mode.method, mode.header, generated[6])
			}
			transport := 40 + 8
			if transport+20 > len(generated) {
				t.Fatalf("%s: truncated segment", mode.method)
			}
			tcpHeaderLen := int(generated[transport+12]>>4) * 4
			if tcpHeaderLen < 20 || transport+tcpHeaderLen > len(generated) {
				t.Fatalf("%s: invalid TCP header length %d", mode.method, tcpHeaderLen)
			}
			rebuilt = append(rebuilt, generated[transport+tcpHeaderLen:]...)
		}
		if !bytes.Equal(rebuilt, payload) {
			t.Fatalf("%s: reconstructed %q", mode.method, rebuilt)
		}
	}
}

func TestListSnapshotGzipUnionEmptyPositiveAndReloadRollback(t *testing.T) {
	dir := t.TempDir()
	include := filepath.Join(dir, "domains.txt.gz")
	empty := filepath.Join(dir, "empty.txt")
	if err := writeGzip(include, "# comment\r\nquic.example\r\n\r\nCASE.example.\r\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	optionJSON := `{"enabled":true,"rules":[{"network":["tcp"],"domain_file":["domains.txt.gz"]}]}`
	config, err := Compile(enabledOption(optionJSON), dir)
	if err != nil {
		t.Fatal(err)
	}
	rule := config.Rules[0]
	if !rule.Matches(MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Protocol: ProtocolUnknown,
		Host: "www.quic.example", HostKnown: true}) {
		t.Fatal("gzip list entry must match a subdomain after normalization")
	}
	if rule.Matches(MatchFacts{Family: FamilyIPv4, Transport: TransportTCP, Protocol: ProtocolUnknown,
		Host: "other.example", HostKnown: true}) {
		t.Fatal("unlisted host must not match")
	}

	// An empty positive snapshot restricts to nothing.
	emptyConfig, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"domain_file":["empty.txt"]}]}`), dir)
	if err != nil {
		t.Fatal(err)
	}
	if emptyConfig.Rules[0].Matches(MatchFacts{Family: FamilyIPv4, Transport: TransportTCP,
		Protocol: ProtocolUnknown, Host: "anything.example", HostKnown: true}) {
		t.Fatal("empty positive list must match nothing")
	}

	// A failed transactional reload keeps the last-good snapshot and reports.
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	good := []byte("reloaded.example\n")
	if err := os.WriteFile(include[:len(include)-3]+".txt", good, 0o600); err != nil {
		t.Fatal(err)
	}
	// Point the compiled source at the plain file by rewriting the gzip source
	// to an invalid snapshot: rollback must keep the previous compiled entry.
	if err := os.WriteFile(include, []byte{0x1f, 0x8b, 0x00, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	if reloadErr := engine.ReloadLists(); reloadErr == nil {
		t.Fatal("corrupt gzip reload must report an error")
	}
	if !engine.Config().Rules[0].Matches(MatchFacts{Family: FamilyIPv4, Transport: TransportTCP,
		Protocol: ProtocolUnknown, Host: "quic.example", HostKnown: true}) {
		t.Fatal("failed reload must retain the last-good snapshot")
	}
	if err := writeGzip(include, "new.example\n"); err != nil {
		t.Fatal(err)
	}
	if reloadErr := engine.ReloadLists(); reloadErr != nil {
		t.Fatal(reloadErr)
	}
	if !engine.Config().Rules[0].Matches(MatchFacts{Family: FamilyIPv4, Transport: TransportTCP,
		Protocol: ProtocolUnknown, Host: "new.example", HostKnown: true}) {
		t.Fatal("successful reload must publish the new snapshot")
	}
}

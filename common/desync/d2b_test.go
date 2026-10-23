package desync

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeClock is a deterministic clock for the learning and conntrack windows.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func learningTestEngine(t *testing.T, learningJSON, rulesJSON string, clock *fakeClock) (*Engine, *testBackend) {
	t.Helper()
	content := `{"enabled":true,`
	if learningJSON != "" {
		content += `"learning":` + learningJSON + `,`
	}
	content += `"rules":` + rulesJSON + `}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatal(err)
	}
	backend := &testBackend{name: "test"}
	engine, err := NewEngine(config, backend)
	if err != nil {
		t.Fatal(err)
	}
	if clock != nil {
		engine.SetHoldClock(clock.Now)
	}
	t.Cleanup(func() { engine.Close() })
	return engine, backend
}

func learningRuleJSON(threshold int, extra string) string {
	return `[{"name":"learn","network":["tcp"],"any_protocol":true,"methods":["fake"],` +
		`"fake":{"repeats":1,"payloads":[{"protocol":"http","hex":"474554202f20485454502f312e310d0a"}]},` +
		`"learning":{"fail_threshold":` + itoa(threshold) + `}` + extra + `}]`
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func learningLease(t *testing.T, engine *Engine) *Lease {
	t.Helper()
	source := netip.MustParseAddrPort("192.0.2.1:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	return lease
}

// buildTestTCP builds one IPv4/TCP packet with explicit sequence, ack and
// flags. It is used instead of the fixed-ack test helper because the
// hostlist-auto reply decision observes the real ack window.
func buildTestTCP(t *testing.T, source, destination netip.Addr, sourcePort, destinationPort uint16,
	sequence, ack uint32, flags uint8, payload []byte) []byte {
	t.Helper()
	raw := make([]byte, 40+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[8] = 64
	raw[9] = 6
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(raw[12:16], sourceBytes[:])
	copy(raw[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(raw[20:22], sourcePort)
	binary.BigEndian.PutUint16(raw[22:24], destinationPort)
	binary.BigEndian.PutUint32(raw[24:28], sequence)
	binary.BigEndian.PutUint32(raw[28:32], ack)
	raw[32] = 5 << 4
	raw[33] = flags
	binary.BigEndian.PutUint16(raw[34:36], 64240)
	copy(raw[40:], payload)
	binary.BigEndian.PutUint16(raw[10:12], 0)
	binary.BigEndian.PutUint16(raw[10:12], inetChecksum(raw[:20], 0))
	binary.BigEndian.PutUint16(raw[36:38], 0)
	packet := &Packet{Family: FamilyIPv4, Transport: TransportTCP}
	transportLength := uint32(len(raw) - 20)
	sum := uint32(transportLength)
	sum += uint32(TransportTCP)
	sum += uint32(binary.BigEndian.Uint16(raw[12:14]))
	sum += uint32(binary.BigEndian.Uint16(raw[14:16]))
	sum += uint32(binary.BigEndian.Uint16(raw[16:18]))
	sum += uint32(binary.BigEndian.Uint16(raw[18:20]))
	binary.BigEndian.PutUint16(raw[36:38], inetChecksum(raw[20:], sum))
	_ = packet
	return raw
}

func sendOutbound(t *testing.T, lease *Lease, raw []byte) (Verdict, int) {
	t.Helper()
	injected := 0
	verdict := lease.HandlePacket(raw, DirectionOutbound, func([]byte) error {
		injected++
		return nil
	}, func(Verdict, string, []byte) {})
	return verdict, injected
}

func sendInbound(t *testing.T, lease *Lease, raw []byte) Verdict {
	t.Helper()
	return lease.HandlePacket(raw, DirectionInbound, func([]byte) error { return nil },
		func(Verdict, string, []byte) {})
}

func TestLearningFailureThresholdWindowAndSnapshot(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auto.txt")
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	engine, _ := learningTestEngine(t, `{"path":"`+path+`","max_hosts":8}`,
		`[{"name":"learn","network":["tcp"],"any_protocol":true,"methods":["fake"],`+
			`"fake":{"repeats":1,"payloads":[{"protocol":"unknown","hex":"00"}]},`+
			`"learning":{"fail_threshold":3,"fail_time":"30s"}}]`, clock)
	if !engine.LearningEnabled() {
		t.Fatal("learning should be enabled")
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if engine.RecordHostFailure("learn", "Blocked.Example.") {
			t.Fatalf("threshold fired early at %d", attempt)
		}
	}
	if len(engine.LearnedHosts()) != 0 {
		t.Fatal("host learned before threshold")
	}
	if !engine.RecordHostFailure("learn", "blocked.example") {
		t.Fatal("threshold did not learn the host")
	}
	if hosts := engine.LearnedHosts(); len(hosts) != 1 || hosts[0] != "blocked.example" {
		t.Fatalf("learned hosts = %v", hosts)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "blocked.example\n" {
		t.Fatalf("snapshot = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %04o, want 0600", info.Mode().Perm())
	}
	// The fail window expires: failures spread over more than 30 s never
	// accumulate to the threshold.
	if engine.RecordHostFailure("learn", "window.example") {
		t.Fatal("first windowed failure learned")
	}
	clock.Advance(31 * time.Second)
	if engine.RecordHostFailure("learn", "window.example") {
		t.Fatal("second windowed failure learned")
	}
	clock.Advance(31 * time.Second)
	if engine.RecordHostFailure("learn", "window.example") {
		t.Fatal("third windowed failure learned")
	}
	clock.Advance(time.Second)
	if engine.RecordHostFailure("learn", "window.example") {
		t.Fatal("fourth windowed failure learned")
	}
	clock.Advance(time.Second)
	if !engine.RecordHostFailure("learn", "window.example") {
		t.Fatal("two failures inside one window did not learn")
	}
	if engine.LearningLastError() != nil {
		t.Fatalf("learning error: %v", engine.LearningLastError())
	}
}

func TestLearningChangesPacketRuleEligibility(t *testing.T) {
	engine, _ := learningTestEngine(t, "", learningRuleJSON(3, ""), nil)
	lease := learningLease(t, engine)
	request := []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
	// The first data packet reveals the hostname; an unlearned host is not
	// eligible, so the original passes unchanged.
	raw := buildTestTCP(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7"),
		40000, 443, 1000, 0, tcpFlagACK|tcpFlagPSH, request)
	verdict, injected := sendOutbound(t, lease, raw)
	if verdict != VerdictPass || injected != 0 {
		t.Fatalf("unlearned host verdict=%d injected=%d, want pass/0", verdict, injected)
	}
	if len(engine.LearnedHosts()) != 0 {
		t.Fatal("host learned from a normal request")
	}
	for attempt := 0; attempt < 3; attempt++ {
		engine.RecordHostFailure("learn", "blocked.example")
	}
	lease2 := learningLease(t, engine)
	raw2 := buildTestTCP(t, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.7"),
		40001, 443, 2000, 0, tcpFlagACK|tcpFlagPSH, request)
	verdict, injected = sendOutbound(t, lease2, raw2)
	if injected == 0 {
		t.Fatalf("learned host was not eligible (verdict=%d)", verdict)
	}
	if len(engine.LearnedHosts()) != 1 {
		t.Fatalf("learned hosts = %v", engine.LearnedHosts())
	}

	// User exclusions are never learned and never become eligible.
	excluded, _ := learningTestEngine(t, "", learningRuleJSON(2,
		`,"domain_exclude":["ok.example"]`), nil)
	for attempt := 0; attempt < 5; attempt++ {
		if excluded.RecordHostFailure("learn", "ok.example") {
			t.Fatal("excluded host was learned")
		}
	}
	if len(excluded.LearnedHosts()) != 0 {
		t.Fatalf("excluded hosts = %v", excluded.LearnedHosts())
	}
}

func TestLearningReplyObservationRSTAndHTTP(t *testing.T) {
	source := netip.MustParseAddr("192.0.2.1")
	destination := netip.MustParseAddr("198.51.100.7")
	request := []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")

	engine, _ := learningTestEngine(t, "", learningRuleJSON(1, ""), nil)
	lease := learningLease(t, engine)
	syn := buildTestTCP(t, source, destination, 40000, 443, 1000, 0, tcpFlagSYN, nil)
	if verdict, _ := sendOutbound(t, lease, syn); verdict == VerdictDrop {
		t.Fatal("SYN unexpectedly dropped")
	}
	synack := buildTestTCP(t, destination, source, 443, 40000, 5000, 1001, tcpFlagSYN|tcpFlagACK, nil)
	sendInbound(t, lease, synack)
	// The ack value matches the SYN-ACK so the reverse feed keeps a coherent
	// first-sequence window.
	data := buildTestTCP(t, source, destination, 40000, 443, 1001, 5001, tcpFlagACK|tcpFlagPSH, request)
	sendOutbound(t, lease, data)
	rst := buildTestTCP(t, destination, source, 443, 40000, 5001, 1001+uint32(len(request)), tcpFlagRST|tcpFlagACK, nil)
	sendInbound(t, lease, rst)
	if hosts := engine.LearnedHosts(); len(hosts) != 1 || hosts[0] != "blocked.example" {
		t.Fatalf("RST did not learn the host: %v", hosts)
	}

	engine2, _ := learningTestEngine(t, "", learningRuleJSON(1, ""), nil)
	lease2 := learningLease(t, engine2)
	sendOutbound(t, lease2, buildTestTCP(t, source, destination, 40000, 443, 1000, 0, tcpFlagSYN, nil))
	sendInbound(t, lease2, buildTestTCP(t, destination, source, 443, 40000, 5000, 1001, tcpFlagSYN|tcpFlagACK, nil))
	sendOutbound(t, lease2, buildTestTCP(t, source, destination, 40000, 443, 1001, 5001, tcpFlagACK|tcpFlagPSH, request))
	redirect := []byte("HTTP/1.1 302 Found\r\nLocation: https://censor.example/bad\r\nContent-Length: 0\r\n\r\n")
	sendInbound(t, lease2, buildTestTCP(t, destination, source, 443, 40000, 5001, 1001+uint32(len(request)), tcpFlagACK|tcpFlagPSH, redirect))
	if hosts := engine2.LearnedHosts(); len(hosts) != 1 || hosts[0] != "blocked.example" {
		t.Fatalf("DPI redirect did not learn the host: %v", hosts)
	}

	// A normal HTTP reply proves the host works and resets the fail counter.
	engine3, _ := learningTestEngine(t, "", learningRuleJSON(2, ""), nil)
	lease3 := learningLease(t, engine3)
	sendOutbound(t, lease3, buildTestTCP(t, source, destination, 40000, 443, 1000, 0, tcpFlagSYN, nil))
	sendInbound(t, lease3, buildTestTCP(t, destination, source, 443, 40000, 5000, 1001, tcpFlagSYN|tcpFlagACK, nil))
	sendOutbound(t, lease3, buildTestTCP(t, source, destination, 40000, 443, 1001, 5001, tcpFlagACK|tcpFlagPSH, request))
	engine3.RecordHostFailure("learn", "blocked.example")
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	sendInbound(t, lease3, buildTestTCP(t, destination, source, 443, 40000, 5001, 1001+uint32(len(request)), tcpFlagACK|tcpFlagPSH, ok))
	if engine3.RecordHostFailure("learn", "blocked.example") {
		t.Fatal("fail counter was not reset by a working reply")
	}
}

func TestLearningSnapshotSafetyAndWriterClaims(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auto.txt")
	rules := learningRuleJSON(1, "")
	engine, _ := learningTestEngine(t, `{"path":"`+path+`"}`, rules, nil)
	// Duplicate in-process writer is rejected before any file work.
	config, err := Compile(enabledOption(`{"enabled":true,"learning":{"path":"`+path+`"},"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewEngine(config, &testBackend{name: "test"}); err == nil {
		t.Fatal("duplicate learning path was accepted")
	}
	engine.RecordHostFailure("learn", "one.example")
	engine.Close()
	// The claim is released on close.
	second, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatalf("claim not released: %v", err)
	}
	second.Close()

	// Symlinked snapshot paths are refused and an existing regular file is
	// never truncated by a failed construction.
	target := filepath.Join(directory, "target.txt")
	if err = os.WriteFile(target, []byte("keep.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(directory, "link.txt")
	if err = os.Symlink(target, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	symlinkConfig, err := Compile(enabledOption(`{"enabled":true,"learning":{"path":"`+linkPath+`"},"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewEngine(symlinkConfig, &testBackend{name: "test"}); err == nil {
		t.Fatal("symlink snapshot was accepted")
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "keep.example\n" {
		t.Fatalf("existing file was modified: %q %v", content, err)
	}

	// A gzipped (unsupported) snapshot is refused.
	gzipPath := filepath.Join(directory, "gzip.txt")
	if err = os.WriteFile(gzipPath, []byte{0x1f, 0x8b, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	gzipConfig, err := Compile(enabledOption(`{"enabled":true,"learning":{"path":"`+gzipPath+`"},"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewEngine(gzipConfig, &testBackend{name: "test"}); err == nil {
		t.Fatal("gzip snapshot was accepted")
	}

	// The entry bound is enforced while loading.
	largePath := filepath.Join(directory, "large.txt")
	if err = os.WriteFile(largePath, []byte("a.example\nb.example\nc.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	boundedConfig, err := Compile(enabledOption(`{"enabled":true,"learning":{"path":"`+largePath+`","max_hosts":2},"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewEngine(boundedConfig, &testBackend{name: "test"}); err == nil {
		t.Fatal("snapshot over max_hosts was accepted")
	}

	// The opt-in debug log is owner-private; construction fails on a log that
	// is not private, and no packet host is logged by default.
	debugPath := filepath.Join(directory, "debug.log")
	if err = os.WriteFile(debugPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	debugConfig, err := Compile(enabledOption(`{"enabled":true,"learning":{"path":"`+filepath.Join(directory, "debug-auto.txt")+`","debug_log":"`+debugPath+`"},"rules":`+rules+`}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewEngine(debugConfig, &testBackend{name: "test"}); err == nil {
		t.Fatal("non-private debug log was accepted")
	}
}

func TestLearningReloadKeepsLastGoodAndIsolatesOutbounds(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auto.txt")
	if err := os.WriteFile(path, []byte("initial.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine, _ := learningTestEngine(t, `{"path":"`+path+`"}`, learningRuleJSON(1, ""), nil)
	if hosts := engine.LearnedHosts(); len(hosts) != 1 || hosts[0] != "initial.example" {
		t.Fatalf("snapshot not loaded: %v", hosts)
	}
	if !engine.learning.learned("sub.initial.example") {
		t.Fatal("learned domains must match subdomains")
	}
	if err := os.WriteFile(path, []byte("external.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.ReloadLists(); err != nil {
		t.Fatal(err)
	}
	if hosts := engine.LearnedHosts(); len(hosts) != 1 || hosts[0] != "external.example" {
		t.Fatalf("reload did not publish external snapshot: %v", hosts)
	}
	// A malformed reload keeps the last-good learned set.
	if err := os.WriteFile(path, []byte("bad host!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.ReloadLists(); err == nil {
		t.Fatal("malformed snapshot reload succeeded")
	}
	if hosts := engine.LearnedHosts(); len(hosts) != 1 || hosts[0] != "external.example" {
		t.Fatalf("last-good learned set lost: %v", hosts)
	}
}

func TestLearningConcurrentObservationsReloadClose(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "auto.txt")
	engine, _ := learningTestEngine(t, `{"path":"`+path+`"}`, learningRuleJSON(2, ""), nil)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for index := 0; index < 50; index++ {
				engine.RecordHostFailure("learn", "host"+itoa(worker)+".example")
				engine.RecordHostSuccess("host" + itoa(worker) + ".example")
				_ = engine.LearnedHosts()
				_ = engine.LearningLastError()
			}
		}(worker)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		for index := 0; index < 20; index++ {
			_ = engine.ReloadLists()
		}
	}()
	workers.Wait()
	engine.Close()
	engine.Close()
}

func TestUDPSecondStageOrigExtensionPropagation(t *testing.T) {
	packet := buildIPv6UDP(t, []byte("payload"))
	// hopbyhop + udplen: every real datagram carries the hop-by-hop header,
	// keeps the original TTL (upstream ttl_orig) and has a valid checksum.
	rule := mustTestRule(t, `{"enabled":true,"rules":[{"network":["udp"],"port":[443],
		"methods":["hopbyhop","udplen"],"ttl":3,"udplen":{"increment":2}}]}`)
	batch, err := PlanUDP(rule, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 1 || batch.Original != VerdictPass {
		t.Fatalf("udplen batch = %d packets, original %v", len(batch.Packets), batch.Original)
	}
	generated, err := ParsePacket(batch.Packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if generated.Raw[6] != 0 {
		t.Fatalf("IPv6 next header = %d, want hop-by-hop 0", generated.Raw[6])
	}
	if generated.TTL != 64 {
		t.Fatalf("udplen TTL = %d, want captured TTL 64", generated.TTL)
	}
	if len(generated.Payload) != len(packet.Payload)+2 {
		t.Fatalf("udplen payload = %d, want %d", len(generated.Payload), len(packet.Payload)+2)
	}
	verifyUDPChecksum(t, batch.Packets[0])

	// destopt + ipfrag2 inserts the destination-options header before
	// fragmenting; the two fragments reconstruct the original transport bytes.
	rule = mustTestRule(t, `{"enabled":true,"rules":[{"network":["udp"],"port":[443],
		"methods":["destopt","ipfrag2"],"ipfrag_pos_udp":8}]}`)
	batch, err = PlanUDP(rule, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 2 {
		t.Fatalf("ipfrag2 batch = %d", len(batch.Packets))
	}
	firstRaw, secondRaw := batch.Packets[0], batch.Packets[1]
	if firstRaw[6] != 60 {
		t.Fatalf("ipfrag2 first fragment next header = %d, want destination options", firstRaw[6])
	}
	if firstRaw[40] != 44 { // destination-options next-header field
		t.Fatalf("destination-options chain lost: %d", firstRaw[40])
	}
	// Both fragments carry base(40)+destopt(8)+fragment(8), then the
	// transport bytes split at fragPos.
	reconstructed := append(append([]byte(nil), firstRaw[56:]...), secondRaw[56:]...)
	if !bytes.Equal(reconstructed, packet.Raw[40:]) {
		t.Fatalf("ipfrag2 reconstruction mismatch: %x vs %x", reconstructed, packet.Raw[40:])
	}

	// ipfrag1 + ipfrag2 is not nested: upstream does not insert the fragment
	// header before fragmenting, so the single fragment header is the only
	// extension and points directly at UDP.
	rule = mustTestRule(t, `{"enabled":true,"rules":[{"network":["udp"],"port":[443],
		"methods":["ipfrag1","ipfrag2"],"ipfrag_pos_udp":8}]}`)
	batch, err = PlanUDP(rule, packet)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw = batch.Packets[0]
	if firstRaw[6] != 44 || firstRaw[40] != uint8(TransportUDP) {
		t.Fatalf("ipfrag1+ipfrag2 nested a fragment header: next=%d fragnext=%d", firstRaw[6], firstRaw[40])
	}

	// Destination options + tamper: the real tampered datagram carries the
	// header; a non-DHT payload is a negative control that stays unchanged.
	rule = mustTestRule(t, `{"enabled":true,"rules":[{"network":["udp"],"port":[443],
		"methods":["destopt","tamper"]}]}`)
	batch, err = PlanUDP(rule, packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 0 || batch.Reason == "" {
		t.Fatalf("non-DHT tamper control: packets=%d reason=%q", len(batch.Packets), batch.Reason)
	}
}

func verifyUDPChecksum(t *testing.T, raw []byte) {
	t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	udpStart := packet.PayloadOffset - 8
	transportLength := len(raw) - packet.IPHeaderLen
	sum, err := pseudoHeaderSum(raw, packet, transportLength)
	if err != nil {
		t.Fatal(err)
	}
	if got := inetChecksum(raw[udpStart:], sum); got != 0 {
		t.Fatalf("UDP checksum mismatch: residual %#x", got)
	}
}

func buildIPv6UDP(t *testing.T, payload []byte) *Packet {
	t.Helper()
	raw := make([]byte, 40+8+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], uint16(8+len(payload)))
	raw[6] = 17
	raw[7] = 64
	copy(raw[8:24], mustIPv6("2001:db8::1"))
	copy(raw[24:40], mustIPv6("2001:db8::2"))
	binary.BigEndian.PutUint16(raw[40:42], 40000)
	binary.BigEndian.PutUint16(raw[42:44], 443)
	binary.BigEndian.PutUint16(raw[44:46], uint16(8+len(payload)))
	copy(raw[48:], payload)
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = refreshChecksums(raw, packet); err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestLearningRetransmissionThresholdAndExplicitZero(t *testing.T) {
	// Explicit zero is invalid for the source-bounded thresholds; an absent
	// value keeps the upstream default.
	for _, content := range []string{
		`{"enabled":true,"rules":[{"name":"learn","network":["tcp"],"any_protocol":true,"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"http","hex":"00"}]},"learning":{"fail_threshold":0}}]}`,
		`{"enabled":true,"rules":[{"name":"learn","network":["tcp"],"any_protocol":true,"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"http","hex":"00"}]},"learning":{"retrans_threshold":0}}]}`,
		`{"enabled":true,"rules":[{"name":"learn","network":["tcp"],"any_protocol":true,"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"http","hex":"00"}]},"learning":{"fail_time":"0s"}}]}`,
	} {
		config, err := Compile(enabledOption(content), "")
		if err == nil || config != nil {
			t.Fatalf("invalid learning threshold accepted: %s", content)
		}
	}

	source := netip.MustParseAddr("192.0.2.1")
	destination := netip.MustParseAddr("198.51.100.7")
	request := []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n")
	engine, _ := learningTestEngine(t, "", `[{"name":"learn","network":["tcp"],"any_protocol":true,
		"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"http","hex":"00"}]},
		"learning":{"fail_threshold":1,"retrans_threshold":2}}]`, nil)
	lease := learningLease(t, engine)
	sendOutbound(t, lease, buildTestTCP(t, source, destination, 40000, 443, 1000, 0, tcpFlagSYN, nil))
	// The complete request finalizes the tracked range; the following two
	// retransmissions are the retrans trigger, never the first transmission.
	sendOutbound(t, lease, buildTestTCP(t, source, destination, 40000, 443, 1001, 0, tcpFlagACK|tcpFlagPSH, request))
	if len(engine.LearnedHosts()) != 0 {
		t.Fatal("request itself counted as a retransmission")
	}
	sendOutbound(t, lease, buildTestTCP(t, source, destination, 40000, 443, 1001, 0, tcpFlagACK|tcpFlagPSH, request))
	if len(engine.LearnedHosts()) != 0 {
		t.Fatal("first retransmission already learned")
	}
	sendOutbound(t, lease, buildTestTCP(t, source, destination, 40000, 443, 1001, 0, tcpFlagACK|tcpFlagPSH, request))
	if hosts := engine.LearnedHosts(); len(hosts) != 1 || hosts[0] != "blocked.example" {
		t.Fatalf("retrans threshold did not learn: %v", hosts)
	}
}

func TestConntrackCutoffLatchesAreTupleOwned(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1700000000, 0)}
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["fake"],
		"fake":{"repeats":1,"payloads":[{"protocol":"unknown","hex":"00"}]},"cutoff":"n2"}]`, "")
	h.engine.SetHoldClock(clock.Now)
	// SYN creates the tuple entry (n1), the data packet reaches cutoff n2.
	h.captureFlags(nil, 1000, tcpFlagSYN)
	h.capture([]byte("data"), 1001)
	if !h.lease.tcpFlow.cutoffLatchesSnapshot().desync {
		t.Fatal("desync cutoff did not latch")
	}
	// A second native attempt reusing the retained tuple sees the shared
	// latch even though it never observed the cutoff packet itself.
	lease2, err := h.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease2.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = lease2.StartCapture(); err != nil {
		t.Fatal(err)
	}
	before := len(h.injected)
	if verdict, _ := sendOutbound(t, lease2, testTCPPacket(t, []byte("data"), 2000)); verdict != VerdictPass {
		t.Fatalf("reused tuple attempt verdict = %d, want pass", verdict)
	}
	if len(h.injected) != before {
		t.Fatal("reused tuple attempt ignored the shared cutoff latch")
	}
	// A fresh SYN on the tuple is ConntrackReInitTrack: the latches are
	// cleared with the rest of the track.
	if verdict, _ := sendOutbound(t, lease2, buildTestTCP(t, netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("198.51.100.20"), 40000, 443, 3000, 0, tcpFlagSYN, nil)); verdict == VerdictDrop {
		t.Fatal("reinit SYN dropped")
	}
	if lease2.tcpFlow.cutoffLatchesSnapshot().desync {
		t.Fatal("reinit did not clear the tuple latch")
	}
	// Expiry discards the entry and its latches; a later flow cannot restore
	// them and has no live counters.
	clock.Advance(301 * time.Second)
	h.engine.conntrack.purge()
	lease3, err := h.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease3.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = lease3.StartCapture(); err != nil {
		t.Fatal(err)
	}
	if _, _ = sendOutbound(t, lease3, testTCPPacket(t, []byte("data"), 4000)); lease3.tcpFlow.cutoffLatchesSnapshot().desync {
		t.Fatal("expired tuple latch survived")
	}
}

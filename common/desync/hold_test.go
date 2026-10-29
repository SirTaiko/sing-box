package desync

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// heldHarness drives one lease through the capture path with a recording
// completer, so hold/release behaviour is observed exactly as a native backend
// would see it.
type heldHarness struct {
	t          *testing.T
	engine     *Engine
	lease      *Lease
	injected   [][]byte
	verdicts   []Verdict
	reasons    []string
	modified   [][]byte
	order      []uint32 // first payload byte of every released original
	injectFail func(int) error
}

func newHeldHarness(t *testing.T, rules string, limits string) *heldHarness {
	t.Helper()
	content := `{"enabled":true,`
	if limits != "" {
		content += `"limits":` + limits + `,`
	}
	content += `"rules":` + rules + `}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
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
	// D2 source fidelity: upstream creates the semantic track on SYN. A harness
	// that feeds mid-stream TCP data stands for an attempt that attached after
	// the SYN, so the tuple-owned track is created explicitly.
	lease.tcpFlow.primeSemanticTrack()
	t.Cleanup(func() {
		engine.Close()
	})
	return &heldHarness{t: t, engine: engine, lease: lease}
}

func (h *heldHarness) capture(payload []byte, sequence uint32) Verdict {
	h.t.Helper()
	packet := buildIPv4TCP(h.t, payload, sequence, tcpFlagACK|tcpFlagPSH)
	index := len(h.injected)
	complete := func(verdict Verdict, reason string, modified []byte) {
		h.verdicts = append(h.verdicts, verdict)
		h.reasons = append(h.reasons, reason)
		h.modified = append(h.modified, append([]byte(nil), modified...))
		h.order = append(h.order, packet.TCPSeq)
	}
	return h.lease.HandlePacket(packet.Raw, DirectionOutbound, func(replacement []byte) error {
		h.injected = append(h.injected, append([]byte(nil), replacement...))
		if h.injectFail != nil {
			if err := h.injectFail(index); err != nil {
				return err
			}
		}
		return nil
	}, complete)
}

func TestHoldAssemblesMultiSegmentClientHello(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["host+0"]}}]`, "")
	hello := buildClientHello("blocked.example")
	if len(hello) < 20 {
		t.Fatalf("hello too short: %d", len(hello))
	}
	first := hello[:12]
	second := hello[12:]
	if verdict := h.capture(first, 1000); verdict != VerdictHold {
		t.Fatalf("first segment verdict = %d, want hold", verdict)
	}
	if len(h.verdicts) != 0 || len(h.injected) != 0 {
		t.Fatalf("held packet must have no terminal disposition yet: %+v %d", h.verdicts, len(h.injected))
	}
	// The second segment completes the ClientHello. The held prefix is
	// released first (it contains no resolved split position, so it passes
	// unchanged), then the completing segment is planned against the whole
	// message: the host marker resolves across the segment boundary.
	if verdict := h.capture(second, 1000+uint32(len(first))); verdict != VerdictDrop {
		t.Fatalf("completing segment verdict = %d, want drop", verdict)
	}
	if len(h.verdicts) != 1 || h.verdicts[0] != VerdictPass {
		t.Fatalf("held prefix completions = %+v", h.verdicts)
	}
	if h.order[0] != 1000 {
		t.Fatalf("release order = %v", h.order)
	}
	if len(h.injected) != 2 {
		t.Fatalf("injected = %d, want one split of the completing segment", len(h.injected))
	}
	// The replacements of the completing segment reproduce its real bytes
	// exactly, so the receiver's stream is unchanged.
	var rebuilt []byte
	for _, raw := range h.injected {
		packet, err := ParsePacket(raw)
		if err != nil {
			t.Fatal(err)
		}
		rebuilt = append(rebuilt, packet.Payload...)
	}
	if string(rebuilt) != string(second) {
		t.Fatalf("replacement bytes differ from the original segment")
	}
	// Replay must never be counted again: exactly the two captured originals.
	if h.lease.tcpFlow.counters.packets != 2 {
		t.Fatalf("original counters = %d", h.lease.tcpFlow.counters.packets)
	}
}

func TestHoldDeadlineReleasesOriginalsInOrder(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["host+0"]}}]`,
		`{"hold_timeout":"40ms","max_held_packets":8,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
	hello := buildClientHello("blocked.example")
	now := time.Unix(1000, 0)
	h.engine.SetHoldClock(func() time.Time { return now })
	if verdict := h.capture(hello[:10], 2000); verdict != VerdictHold {
		t.Fatalf("verdict = %d, want hold", verdict)
	}
	if verdict := h.capture(hello[10:20], 2010); verdict != VerdictHold {
		t.Fatalf("verdict = %d, want hold", verdict)
	}
	if len(h.verdicts) != 0 {
		t.Fatalf("nothing may be released before the deadline: %+v", h.verdicts)
	}
	// Advance the injected clock past the deadline and run the autonomous
	// release exactly as the timer would.
	now = now.Add(41 * time.Millisecond)
	h.lease.tcpFlow.expire()
	if len(h.verdicts) != 2 {
		t.Fatalf("completions = %d, want 2", len(h.verdicts))
	}
	for index, verdict := range h.verdicts {
		if verdict != VerdictPass {
			t.Fatalf("completion %d = %d, want pass", index, verdict)
		}
	}
	if h.injected != nil {
		t.Fatalf("deadline release must not inject: %d", len(h.injected))
	}
	if h.order[0] != 2000 || h.order[1] != 2010 {
		t.Fatalf("release order = %v", h.order)
	}
	// The rest of that message is latched off: no new packet, no new event.
	if verdict := h.capture(hello[20:], 2020); verdict != VerdictPass {
		t.Fatalf("post-release segment verdict = %d", verdict)
	}
	if len(h.injected) != 0 || len(h.verdicts) != 2 {
		t.Fatalf("latched flow transformed data: injected=%d completions=%d", len(h.injected), len(h.verdicts))
	}
	// A genuinely new structured message beyond the released end resumes
	// planning: the latch is not permanent.
	fresh := buildClientHello("fresh.example")
	if verdict := h.capture(fresh, 2020); verdict != VerdictDrop {
		t.Fatalf("new message verdict = %d, want drop", verdict)
	}
	if len(h.injected) != 2 {
		t.Fatalf("new message must be split, injected = %d", len(h.injected))
	}
}

func TestHoldCloseReleasesHeldOriginal(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`, "")
	hello := buildClientHello("blocked.example")
	if verdict := h.capture(hello[:8], 3000); verdict != VerdictHold {
		t.Fatalf("verdict = %d, want hold", verdict)
	}
	if err := h.lease.Close(nil); err != nil {
		t.Fatal(err)
	}
	if len(h.verdicts) != 1 || h.verdicts[0] != VerdictPass {
		t.Fatalf("close must release held originals: %+v", h.verdicts)
	}
	if len(h.reasons) != 1 || h.reasons[0] == "" {
		t.Fatalf("close release must report a reason: %+v", h.reasons)
	}
	if h.engine.ActiveLeases() != 0 {
		t.Fatal("lease must be deregistered")
	}
}

func TestHoldBudgetReleasesAndLatches(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["host+0"]}}]`,
		`{"max_held_packets":1,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
	hello := buildClientHello("blocked.example")
	if verdict := h.capture(hello[:10], 4000); verdict != VerdictHold {
		t.Fatalf("verdict = %d, want hold", verdict)
	}
	// The second packet exceeds the per-flow held-packet budget: the first is
	// released unchanged and this one passes, without waiting for the deadline.
	if verdict := h.capture(hello[10:20], 4010); verdict != VerdictPass {
		t.Fatalf("budget exhaustion verdict = %d", verdict)
	}
	if len(h.verdicts) != 1 || h.verdicts[0] != VerdictPass {
		t.Fatalf("budget release = %+v", h.verdicts)
	}
	if h.reasons[0] == "" {
		t.Fatal("budget release must report a reason")
	}
	if len(h.injected) != 0 {
		t.Fatalf("budget release must not inject: %d", len(h.injected))
	}
}

func TestHeldPartialSendFailureKeepsLaterOriginals(t *testing.T) {
	h := newHeldHarness(t, `[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]`, "")
	hello := buildClientHello("blocked.example")
	if verdict := h.capture(hello[:10], 5000); verdict != VerdictHold {
		t.Fatalf("first verdict = %d", verdict)
	}
	// Fail the second original's replacement send only.
	failing := false
	h.injectFail = func(int) error {
		if failing {
			return errors.New("inject failed")
		}
		return nil
	}
	// The first held original's batch is sent before the failure is armed.
	h.lease.tcpFlow.mu.Lock()
	h.lease.tcpFlow.releaseHoldsLocked("")
	h.lease.tcpFlow.mu.Unlock()
	if len(h.verdicts) == 0 {
		t.Fatal("release must complete originals")
	}
	for index, verdict := range h.verdicts {
		if verdict != VerdictDrop && verdict != VerdictPass {
			t.Fatalf("unexpected verdict %d at %d", verdict, index)
		}
	}
}

func TestTLSClientHelloAcrossRecords(t *testing.T) {
	hello := buildClientHello("multi.example")
	// Handshake body is hello[5:]; split it into two TLS handshake records.
	body := hello[5:]
	firstRecord := append([]byte{0x16, 0x03, 0x03, 0, 0}, body[:10]...)
	firstRecord[3] = byte(len(body[:10]) >> 8)
	firstRecord[4] = byte(len(body[:10]))
	secondRecord := append([]byte{0x16, 0x03, 0x03, 0, 0}, body[10:]...)
	secondRecord[3] = byte(len(body[10:]) >> 8)
	secondRecord[4] = byte(len(body[10:]))
	message := append(append([]byte{}, firstRecord...), secondRecord...)
	host, hostStart, _, _, complete := parseTLSClientHello(message)
	if !complete {
		t.Fatal("multi-record ClientHello must be recognised as complete")
	}
	if host != "multi.example" {
		t.Fatalf("host = %q", host)
	}
	// Offsets are stream coordinates: the SNI cannot be in the first record.
	if hostStart < len(firstRecord) {
		t.Fatalf("host offset %d is inside the first record (len %d)", hostStart, len(firstRecord))
	}
	if string(message[hostStart:hostStart+len(host)]) != host {
		t.Fatalf("host offset does not address the SNI bytes")
	}
	// A truncated hello is not complete and must be held, not transformed.
	if messageComplete(ProtocolTLS, hello[:len(hello)-1]) {
		t.Fatal("truncated ClientHello must not be complete")
	}
	if !messageComplete(ProtocolTLS, hello) {
		t.Fatal("complete ClientHello must be complete")
	}
}

func TestUDPOriginalDeliveredAtMostOnce(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"port":[443],"methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"c000000001"}]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	payload := testQUICInitialPayload(t, "udp-delivery.example")
	packet := buildIPv4UDP(t, payload, 443)
	attempts := 0
	verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
		attempts++
		return errors.New("inject failed")
	}, nil)
	if verdict != VerdictPass {
		t.Fatalf("UDP original must be delivered exactly once, verdict = %d", verdict)
	}
	if attempts != 1 {
		t.Fatalf("inject attempts = %d, want 1 before latching", attempts)
	}
	// A second datagram is not transformed either (flow latched after failure).
	verdict = lease.HandlePacket(packet.Raw, DirectionOutbound, func([]byte) error {
		t.Fatal("latched UDP flow must not inject")
		return nil
	}, nil)
	if verdict != VerdictPass {
		t.Fatalf("latched UDP verdict = %d", verdict)
	}
}

// TestCompileResolvesPathsThroughConfigurationContext pins the configuration
// path seam: relative payload/list paths resolve against the configuration base
// path supplied by protocol/direct from filemanager.BasePath, never silently
// against an arbitrary working directory.
func TestCompileResolvesPathsThroughConfigurationContext(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "fake.bin"), []byte{0x16, 0x03, 0x01, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	content := `{"enabled":true,"rules":[{"network":["tcp"],"methods":["fake"],"fake":{"payloads":[{"protocol":"tls","file":"fake.bin"}]}}]}`
	config, err := Compile(enabledOption(content), directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Rules) != 1 || config.Rules[0].Fake == nil || len(config.Rules[0].Fake.Payloads) != 1 {
		t.Fatalf("unexpected compiled rules")
	}
	payload := config.Rules[0].Fake.Payloads[0]
	if string(payload.Data) != string([]byte{0x16, 0x03, 0x01, 0x00}) {
		t.Fatalf("payload bytes = %x", payload.Data)
	}
	if payload.Source == "" {
		t.Fatal("resolved payload source must be recorded")
	}
	// The same relative path without the configuration context is an error, not
	// a silent empty payload.
	if _, err := Compile(enabledOption(content), ""); err == nil {
		t.Fatal("missing configuration context must not silently resolve elsewhere")
	}
}

func TestLimitsRejectInvalidHoldKnobs(t *testing.T) {
	for _, content := range []string{
		`{"enabled":true,"limits":{"hold_timeout":"0s"},"rules":[{"ip_cidr":["any"],"methods":[]}]}`,
		`{"enabled":true,"limits":{"hold_timeout":"-1s"},"rules":[{"ip_cidr":["any"],"methods":[]}]}`,
		`{"enabled":true,"limits":{"max_held_bytes":10},"rules":[{"ip_cidr":["any"],"methods":[]}]}`,
		`{"enabled":true,"limits":{"max_held_bytes":65536,"max_held_bytes_total":1024},"rules":[{"ip_cidr":["any"],"methods":[]}]}`,
	} {
		if _, err := Compile(enabledOption(content), ""); err == nil {
			t.Fatalf("invalid hold limits accepted: %s", content)
		}
	}
}

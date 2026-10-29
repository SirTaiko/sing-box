package desync

// Submission19 acceptance regressions for the coordinator-accepted contract
// direct-desync/quic-hold-replay/v1.0.
//
// The ownership the contract requires is observable from outside the flow:
// pinned nfq/desync.c queues the Initial datagrams of an incomplete QUIC
// CRYPTO cycle and replays the queue when the cycle completes, with the single
// fake burst attached to the queue head. A queued original must therefore
// return VerdictHold (no native disposition now), its captured bytes must be
// delivered exactly once through the Completer, and the fake burst must appear
// on the wire before the first original of the cycle - the submission18 caller
// delivered the pending Initial immediately and emitted the burst after it.
//
// Every fixture here is a real captured QUIC flight or a synthetic datagram
// sealed with the RFC 9001 layout from the existing parser tests. The tests use
// only the caller-facing surface (Compile, Lease.HandlePacket, Engine.Close),
// so they also run unchanged against the submission18 production blobs; the
// red/green evidence in the task artifact compares exactly that.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

const (
	qa519ProfileDir = "testdata/qa519/profiles"
	qa519AssetDir   = "testdata/qa519/assets"
	// qa519DefaultQUICSHA256 is the pinned dp_fake_defaults QUIC payload
	// (620 bytes, 0x40 then 619 zero bytes), a source-derived constant.
	qa519DefaultQUICSHA256 = "6e996949e69b2e99dba41b83660f43268527b8b4434f1ab33d61b4cfa1c89d1b"
	// qa519GamePayloadSHA256 is the supplied rule8 unknown payload
	// bin/ACTIVE_GAME_UDP.bin, which must never be replaced by the default.
	qa519GamePayloadSHA256 = "e065870cb0d13152e6132807bbf42218a9e7cd8d96f5602b61674cc540f3a56e"
)

// qa519Event is one observable step of a capture: an injected replacement, the
// terminal disposition of a captured original, or the verdict the caller
// received for the datagram it just delivered to the engine.
type qa519Event struct {
	Kind    string // "inject", "complete", "return"
	Label   string // capture label of the original (complete only)
	Payload []byte // injected UDP payload or the captured payload bytes
	Raw     []byte // injected datagram bytes
	Verdict Verdict
	Reason  string
}

type qa519Harness struct {
	t      *testing.T
	engine *Engine
	lease  *Lease

	mu       sync.Mutex
	events   []qa519Event
	labels   map[*Lease]int
	fakes    [][]byte
	injected int
	attempts int

	// injectFail returns an error for the zero-based injection call index.
	injectFail func(call int) error
	// injectEnter runs at the start of every injection; a test uses it to hold
	// the replay open while another goroutine closes the lease.
	injectEnter func()
	// onComplete runs inside the completer of every terminal disposition.
	onComplete func(label string, verdict Verdict)
}

func qa519FakeSet(config *Config) [][]byte {
	payloads := make([][]byte, 0, 8)
	for _, rule := range config.Rules {
		for _, fake := range []*FakeSpec{rule.Fake, rule.FakeKnown} {
			if fake == nil {
				continue
			}
			for _, payload := range fake.Payloads {
				payloads = append(payloads, payload.Data)
			}
		}
	}
	return payloads
}

func qa519NewHarness(t *testing.T, config *Config, source, destination string) *qa519Harness {
	t.Helper()
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	h := &qa519Harness{t: t, engine: engine, fakes: qa519FakeSet(config), labels: map[*Lease]int{}}
	h.lease = h.newLease(source, destination)
	return h
}

// newLease creates one owned native attempt of this harness. A destination-less
// listener attempt keys its peer state by the complete captured tuple.
func (h *qa519Harness) newLease(source, destination string) *Lease {
	h.t.Helper()
	src := netip.MustParseAddrPort(source)
	intent := Intent{Family: FamilyIPv4, Transport: TransportUDP, Source: src}
	if destination != "" {
		intent.Destination = netip.MustParseAddrPort(destination)
	}
	lease, err := h.engine.NewAttempt(intent)
	if err != nil {
		h.t.Fatal(err)
	}
	lease.SetLocalAddress(src)
	if err = lease.StartCapture(); err != nil {
		h.t.Fatal(err)
	}
	return lease
}

func (h *qa519Harness) record(event qa519Event) {
	h.mu.Lock()
	h.events = append(h.events, event)
	h.mu.Unlock()
}

// send delivers one captured UDP datagram through the real caller and records
// the injected replacements, the terminal dispositions and the caller verdict.
func (h *qa519Harness) send(lease *Lease, payload []byte, destinationPort uint16) Verdict {
	h.t.Helper()
	packet := buildIPv4UDP(h.t, payload, destinationPort)
	h.mu.Lock()
	label := "D" + qa519Index(h.labels[lease])
	h.labels[lease]++
	h.mu.Unlock()
	complete := func(verdict Verdict, reason string, modified []byte) {
		h.record(qa519Event{Kind: "complete", Label: label, Payload: append([]byte(nil), packet.Payload...), Verdict: verdict, Reason: reason})
		if h.onComplete != nil {
			h.onComplete(label, verdict)
		}
	}
	verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, func(raw []byte) error {
		parsed, err := ParsePacket(raw)
		if err != nil {
			return err
		}
		if h.injectEnter != nil {
			h.injectEnter()
		}
		h.mu.Lock()
		call := h.attempts
		h.attempts++
		h.mu.Unlock()
		if h.injectFail != nil {
			if err = h.injectFail(call); err != nil {
				return err
			}
		}
		h.record(qa519Event{Kind: "inject", Payload: append([]byte(nil), parsed.Payload...), Raw: append([]byte(nil), raw...)})
		h.mu.Lock()
		h.injected++
		h.mu.Unlock()
		return nil
	}, complete)
	h.record(qa519Event{Kind: "return", Label: label, Verdict: verdict})
	return verdict
}

func qa519Index(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	return qa519Index(value/10) + string(digits[value%10])
}

func qa519VerdictLetter(verdict Verdict) string {
	switch verdict {
	case VerdictDrop:
		return "D"
	case VerdictModify:
		return "M"
	case VerdictHold:
		return "H"
	}
	return "P"
}

// ops is the wire-order signature of the harness: F for a configured fake
// replacement, I for any other injected packet, O:<capture> for a terminal
// original disposition and R:<verdict> for a datagram the caller answers.
func (h *qa519Harness) ops() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.events))
	for _, event := range h.events {
		switch event.Kind {
		case "inject":
			fake := false
			for _, payload := range h.fakes {
				if bytes.Equal(payload, event.Payload) {
					fake = true
					break
				}
			}
			if fake {
				out = append(out, "F")
			} else {
				out = append(out, "I")
			}
		case "complete":
			out = append(out, "O:"+event.Label+":"+qa519VerdictLetter(event.Verdict))
		case "return":
			out = append(out, "R:"+qa519VerdictLetter(event.Verdict))
		}
	}
	return out
}

func (h *qa519Harness) resetEvents() {
	h.mu.Lock()
	h.events = nil
	h.mu.Unlock()
}

// resetPhase starts an independent assertion phase: the observation log and the
// per-lease capture labels both restart, so expectations can address D0.
func (h *qa519Harness) resetPhase() {
	h.mu.Lock()
	h.events = nil
	h.labels = map[*Lease]int{}
	h.mu.Unlock()
}

func (h *qa519Harness) injectedPayloads() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, 0, len(h.events))
	for _, event := range h.events {
		if event.Kind == "inject" {
			out = append(out, event.Payload)
		}
	}
	return out
}

func (h *qa519Harness) injectedRaws() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, 0, len(h.events))
	for _, event := range h.events {
		if event.Kind == "inject" {
			out = append(out, event.Raw)
		}
	}
	return out
}

// qa519ExpectOps compares the observed event order with the required one.
func qa519ExpectOps(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("event order\ngot:  %v\nwant: %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("event %d = %q, want %q\nfull: %v", index, got[index], want[index], got)
		}
	}
}

func qa519Repeat(value string, count int) []string {
	out := make([]string, count)
	for index := range out {
		out[index] = value
	}
	return out
}

func qa519Concat(parts ...[]string) []string {
	out := make([]string, 0, 16)
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// qa519CompileRule compiles one UDP rule body with optional limit overrides.
func qa519CompileRule(t *testing.T, ruleBody, limits string) *Config {
	t.Helper()
	content := `{"enabled":true,`
	if limits != "" {
		content += `"limits":` + limits + `,`
	}
	content += `"rules":[` + ruleBody + `]}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile %s: %v", content, err)
	}
	return config
}

// qa519CompileProfile compiles one complete supplied profile against the
// authentic list/payload assets copied from the sealed QA evidence.
func qa519CompileProfile(t *testing.T, name string) *Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(qa519ProfileDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Outbounds []struct {
			Desync option.DirectDesyncOptions `json:"desync"`
		} `json:"outbounds"`
	}
	if err = json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	if len(profile.Outbounds) == 0 {
		t.Fatalf("profile %s has no outbound", name)
	}
	config, err := Compile(&profile.Outbounds[0].Desync, qa519AssetDir)
	if err != nil {
		t.Fatalf("compile profile %s: %v", name, err)
	}
	if config == nil || len(config.Rules) == 0 {
		t.Fatalf("profile %s compiled no rules", name)
	}
	return config
}

// qa519SplitInitials seals a ClientHello split at split into two Initials of
// one connection identity.
func qa519SplitInitials(t *testing.T, host string, split int, dcid []byte, version uint32, packetNumber uint32) ([]byte, []byte) {
	t.Helper()
	hello := rawQUICClientHello(host)
	if split <= 0 || split >= len(hello) {
		t.Fatalf("split %d outside hello of %d bytes", split, len(hello))
	}
	head := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:split]}, 240), dcid, version, packetNumber)
	tail := sealQUICInitial(t, cryptoFrames([]int{split}, [][]byte{hello[split:]}, 240), dcid, version, packetNumber+1)
	return head, tail
}

func qa519CompleteInitial(t *testing.T, host string, dcid []byte, version uint32, packetNumber uint32) []byte {
	t.Helper()
	return sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{rawQUICClientHello(host)}, 240), dcid, version, packetNumber)
}

func qa519DCID(seed byte) []byte {
	return []byte{seed, seed ^ 0x11, seed ^ 0x22, seed ^ 0x33, seed ^ 0x44, seed ^ 0x55, seed ^ 0x66, seed ^ 0x77}
}

// qa519Varint4 encodes a value as a four-byte QUIC varint, which the test needs
// to build a CRYPTO frame offset beyond the bounded reassembly window (the
// two-byte encoder used by cryptoFrames cannot express it).
func qa519Varint4(value int) []byte {
	return []byte{0x80 | byte(value>>24)&0x3f, byte(value >> 16), byte(value >> 8), byte(value)}
}

// qa519OverflowCrypto builds one CRYPTO frame whose offset exceeds the bounded
// reassembly stream.
func qa519OverflowCrypto(data []byte) []byte {
	frames := []byte{6}
	frames = append(frames, qa519Varint4(20000)...)
	frames = append(frames, qa519Varint4(len(data))...)
	frames = append(frames, data...)
	for len(frames) < 240 {
		frames = append(frames, 0)
	}
	return frames
}

func qa519FakeMarker(name string) string {
	return hex.EncodeToString([]byte(name))
}

func qa519UDPRules(marker string, repeats int, extra string) string {
	return `{"network":["udp"],"port":[443],"methods":["fake"],` + extra +
		`"fake":{"repeats":` + qa519Index(repeats) + `,"payloads":[{"protocol":"quic","hex":"` + marker + `"}]}}`
}

// ---------------------------------------------------------------------------
// QH-01: the wire order of one completed cycle.

func TestP1QUICHoldReplay(t *testing.T) {
	t.Run("Order", func(t *testing.T) {
		for _, name := range []string{"03", "18"} {
			t.Run("profile"+name, func(t *testing.T) {
				config := qa519CompileProfile(t, name)
				if len(config.Rules) <= 5 || config.Rules[5].Name != "rule-5" {
					t.Fatalf("profile %s rule index 5 is not rule-5", name)
				}
				rule := config.Rules[5]
				if rule.Fake == nil || len(rule.Fake.Payloads) == 0 {
					t.Fatal("rule-5 has no compiled fake payload")
				}
				fake := rule.Fake.Payloads[0].Data
				repeats := rule.Fake.Repeats
				// Pinned selects the profile once per conntrack track, before
				// the CRYPTO reassembly, so a rule whose host predicates cannot
				// be evaluated yet is reachable only through the cached
				// hostname of the destination (the state the native caller was
				// in when it captured this flight).
				h := qa519NewHarnessCached(t, config, "192.0.2.10:40000", "198.51.100.7:443", "rule5-order.example")
				head, tail := qa519SplitInitials(t, "rule5-order.example", len(rawQUICClientHello("rule5-order.example"))/2, qa519DCID(0xa1), 1, 1)

				if verdict := h.send(h.lease, head, 443); verdict != VerdictHold {
					t.Fatalf("first Initial verdict = %v, want Hold", verdict)
				}
				qa519ExpectOps(t, h.ops(), []string{"R:H"})
				if verdict := h.send(h.lease, tail, 443); verdict != VerdictHold {
					t.Fatalf("completing Initial verdict = %v, want Hold", verdict)
				}
				want := qa519Concat(
					[]string{"R:H"},
					qa519Repeat("F", repeats),
					[]string{"O:D0:P", "O:D1:P", "R:H"},
				)
				qa519ExpectOps(t, h.ops(), want)
				for index, payload := range h.injectedPayloads() {
					if !bytes.Equal(payload, fake) {
						t.Fatalf("injected payload %d = %x, want the compiled rule-5 payload", index, payload)
					}
				}
				// The burst uses the queue head's captured envelope: same owned
				// tuple, and the head original is delivered after it.
				for index, raw := range h.injectedRaws() {
					packet, err := ParsePacket(raw)
					if err != nil {
						t.Fatal(err)
					}
					if packet.SrcPort != 40000 || packet.DstPort != 443 || !packet.Dst.IsValid() {
						t.Fatalf("injected packet %d tuple = %v->%v:%d", index, packet.Src, packet.Dst, packet.DstPort)
					}
				}
				if len(h.engine.LearnedHosts()) != 0 {
					t.Fatal("a captured cycle must not manufacture learning observations")
				}
			})
		}
	})

	// WireOrder asserts the ordering invariant directly over the observation
	// log, so a submission that delivers the pending original immediately fails
	// for the ordering defect itself (its burst follows the first original).
	t.Run("WireOrder", func(t *testing.T) {
		config := qa519CompileProfile(t, "03")
		h := qa519NewHarnessCached(t, config, "192.0.2.10:40000", "198.51.100.7:443", "rule5-order.example")
		head, tail := qa519SplitInitials(t, "rule5-order.example", len(rawQUICClientHello("rule5-order.example"))/2, qa519DCID(0xa1), 1, 1)
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		ops := h.ops()
		firstBurst := -1
		firstOriginal := -1
		for index, op := range ops {
			if op == "F" && firstBurst < 0 {
				firstBurst = index
			}
			if firstOriginal < 0 && (strings.HasPrefix(op, "O:") || op == "R:P" || op == "R:D" || op == "R:M") {
				firstOriginal = index
			}
		}
		if firstBurst < 0 {
			t.Fatalf("no configured burst was emitted for the completed cycle: %v", ops)
		}
		if firstOriginal < 0 {
			t.Fatalf("no original of the completed cycle was delivered: %v", ops)
		}
		if firstOriginal < firstBurst {
			t.Fatalf("cycle original delivered at event %d before its burst at event %d: %v", firstOriginal, firstBurst, ops)
		}
	})

	t.Run("Cycles", func(t *testing.T) {
		marker := qa519FakeMarker("QH02")
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		dcid := qa519DCID(0xb2)
		head, tail := qa519SplitInitials(t, "cycles.example", 40, dcid, 1, 1)

		// Several complete retransmission cycles: each one owns its own
		// configured burst, and no one-shot latch suppresses the later ones.
		for cycle := 0; cycle < 3; cycle++ {
			h.resetPhase()
			if verdict := h.send(h.lease, head, 443); verdict != VerdictHold {
				t.Fatalf("cycle %d head verdict = %v", cycle, verdict)
			}
			if verdict := h.send(h.lease, tail, 443); verdict != VerdictHold {
				t.Fatalf("cycle %d tail verdict = %v", cycle, verdict)
			}
			qa519ExpectOps(t, h.ops(), qa519Concat([]string{"R:H"}, qa519Repeat("F", 3), []string{"O:D0:P", "O:D1:P", "R:H"}))
		}

		// Duplicate identical datagrams of one cycle stay distinct originals.
		h.resetPhase()
		h.send(h.lease, head, 443)
		h.send(h.lease, head, 443)
		if verdict := h.send(h.lease, tail, 443); verdict != VerdictHold {
			t.Fatalf("duplicate cycle verdict = %v", verdict)
		}
		qa519ExpectOps(t, h.ops(), qa519Concat([]string{"R:H", "R:H"}, qa519Repeat("F", 3), []string{"O:D0:P", "O:D1:P", "O:D2:P", "R:H"}))

		// Out-of-order CRYPTO: the tail arrives first and is queued; the head
		// completes the cycle. Originals keep capture order.
		h.resetPhase()
		h.send(h.lease, tail, 443)
		if verdict := h.send(h.lease, head, 443); verdict != VerdictHold {
			t.Fatalf("out-of-order completion verdict = %v", verdict)
		}
		qa519ExpectOps(t, h.ops(), qa519Concat([]string{"R:H"}, qa519Repeat("F", 3), []string{"O:D0:P", "O:D1:P", "R:H"}))

		// Coalesced CRYPTO frames in one datagram: the standalone complete
		// Initial is planned immediately, with its own burst before it.
		h.resetPhase()
		coalesced := sealQUICInitial(t, cryptoFrames([]int{0, 20}, [][]byte{rawQUICClientHello("coalesced.example")[:20], rawQUICClientHello("coalesced.example")[20:]}, 240), qa519DCID(0xc3), 1, 9)
		if verdict := h.send(h.lease, coalesced, 443); verdict != VerdictPass {
			t.Fatalf("coalesced verdict = %v, want the caller disposition", verdict)
		}
		qa519ExpectOps(t, h.ops(), qa519Concat(qa519Repeat("F", 3), []string{"R:P"}))

		// A tail-only datagram is queued but never owns a burst on its own.
		h.resetPhase()
		now := time.Unix(2000, 0)
		h.engine.SetHoldClock(func() time.Time { return now })
		if verdict := h.send(h.lease, tail, 443); verdict != VerdictHold {
			t.Fatalf("tail-only verdict = %v", verdict)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H"})
		now = now.Add(251 * time.Millisecond)
		h.lease.udpFlows[qa519FlowKey(h.t, h.lease)].expire()
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P"})
	})
}

// qa519FlowKey resolves the single peer state of a harness lease.
func qa519FlowKey(t *testing.T, lease *Lease) string {
	t.Helper()
	for key := range lease.udpFlows {
		return key
	}
	t.Fatal("lease has no UDP peer state")
	return ""
}

// qa519SendNoCompleter delivers one datagram with a nil completer: without a
// completer no record may be held, and no fake may be attached to a partially
// escaped cycle.
func (h *qa519Harness) sendNoCompleter(lease *Lease, payload []byte, destinationPort uint16) Verdict {
	h.t.Helper()
	packet := buildIPv4UDP(h.t, payload, destinationPort)
	verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, func(raw []byte) error {
		parsed, err := ParsePacket(raw)
		if err != nil {
			return err
		}
		h.record(qa519Event{Kind: "inject", Payload: append([]byte(nil), parsed.Payload...), Raw: append([]byte(nil), raw...)})
		return nil
	}, nil)
	h.record(qa519Event{Kind: "return", Verdict: verdict})
	return verdict
}

// qa519NewHarnessCached builds a harness whose bounded hostname cache already
// knows the destination host, the pinned precondition for selecting a
// host-scoped profile before the ClientHello is reassembled.
func qa519NewHarnessCached(t *testing.T, config *Config, source, destination, host string) *qa519Harness {
	t.Helper()
	config.IPCache.hostnameEnabled = true
	h := qa519NewHarness(t, config, source, destination)
	address := netip.MustParseAddrPort(destination).Addr()
	if !h.engine.ipcache.learnHost(address, "", host) {
		t.Fatalf("cached host %q was not learned", host)
	}
	return h
}

func qa519Corrupt(payload []byte) []byte {
	corrupt := append([]byte(nil), payload...)
	corrupt[len(corrupt)-1] ^= 0xff
	return corrupt
}

// ---------------------------------------------------------------------------
// QH-03: refusal, replacement and interruption reset the cycle.

func TestP1QUICHoldReplayResets(t *testing.T) {
	marker := qa519FakeMarker("QH03")
	plain := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
	explicit := qa519CompileRule(t, qa519UDPRules(marker, 3, `"any_protocol":true,`), "")
	dcid := qa519DCID(0xd4)
	head, tail := qa519SplitInitials(t, "resets.example", 40, dcid, 1, 1)

	t.Run("DecryptRefusal", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		verdict := h.send(h.lease, qa519Corrupt(tail), 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
		if verdict != VerdictPass {
			t.Fatalf("refused Initial verdict = %v", verdict)
		}
	})

	t.Run("ExplicitAnyProtocolContinuation", func(t *testing.T) {
		h := qa519NewHarness(t, explicit, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		h.send(h.lease, qa519Corrupt(tail), 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "F", "F", "F", "R:P"})
	})

	t.Run("MalformedCRYPTO", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		notHello := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{{0x02, 0x00, 0x00, 0x01, 0x00}}, 240), dcid, 1, 7)
		h.send(h.lease, notHello, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
	})

	t.Run("ConflictingOverlap", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		conflict := sealQUICInitial(t, cryptoFrames([]int{10}, [][]byte{bytes.Repeat([]byte{0xaa}, 20)}, 240), dcid, 1, 8)
		h.send(h.lease, conflict, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
	})

	t.Run("IdentityReplacement", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		otherHead, _ := qa519SplitInitials(t, "replacement.example", 40, qa519DCID(0xe5), 1, 1)
		if verdict := h.send(h.lease, otherHead, 443); verdict != VerdictHold {
			t.Fatalf("new-identity Initial verdict = %v, want Hold for the new cycle", verdict)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:H"})
	})

	t.Run("AuthoritativeReplacement", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		standalone := qa519CompleteInitial(t, "authoritative.example", dcid, 1, 12)
		if verdict := h.send(h.lease, standalone, 443); verdict != VerdictPass {
			t.Fatalf("authoritative complete Initial verdict = %v, want its own disposition", verdict)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "F", "F", "F", "R:P"})
	})

	t.Run("NonInitialInterrupt", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		stun := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		h.send(h.lease, stun, 443)
		// The old cycle flushes first. STUN then owns its own pinned
		// default64 burst, not the incomplete cycle's configured QUIC fake.
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "F", "F", "F", "R:P"})
		for _, payload := range h.injectedPayloads() {
			if !bytes.Equal(payload, make([]byte, 64)) {
				t.Fatalf("interrupt fake = %x, want STUN default64", payload)
			}
		}
	})

	t.Run("UnknownInterrupt", func(t *testing.T) {
		h := qa519NewHarness(t, plain, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		h.send(h.lease, []byte(f3UnknownPayload), 443)
		// Unknown without explicit permission still flushes the old cycle
		// and passes without any fake, despite the recognized defaults.
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
	})

	t.Run("NoStaleHostname", func(t *testing.T) {
		config := qa519CompileRule(t, `{"network":["udp"],"port":[443],"domain":["a.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+marker+`"}]}}`, "")
		h := qa519NewHarnessCached(t, config, "192.0.2.10:40000", "198.51.100.7:443", "a.example")
		headA, _ := qa519SplitInitials(t, "a.example", 40, qa519DCID(0xf6), 1, 1)
		if verdict := h.send(h.lease, headA, 443); verdict != VerdictHold {
			t.Fatalf("cached-host Initial verdict = %v", verdict)
		}
		// A different connection completes with a host this rule must not keep.
		h.send(h.lease, qa519CompleteInitial(t, "b.example", qa519DCID(0x07), 1, 3), 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
		flow := h.lease.udpFlows[qa519FlowKey(t, h.lease)]
		if flow.host != "b.example" {
			t.Fatalf("validated host = %q, want the new cycle's host", flow.host)
		}
	})
}

// ---------------------------------------------------------------------------
// QH-04: every configured bound, reservation rollback and the autonomous
// deadline.

func TestP1QUICHoldReplayBounds(t *testing.T) {
	marker := qa519FakeMarker("QH04")
	dcid := qa519DCID(0x18)
	head, tail := qa519SplitInitials(t, "bounds.example", 40, dcid, 1, 1)

	t.Run("PacketBound", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""),
			`{"hold_timeout":"10s","max_held_packets":1,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("held bytes after the aborted cycle = %d, want 0", got)
		}
	})

	t.Run("ByteBound", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""),
			`{"hold_timeout":"10s","max_held_packets":8,"max_held_bytes":1500,"max_held_bytes_total":65536}`)
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		hello := rawQUICClientHello("bounds.example")
		large := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:40]}, 1600), dcid, 1, 1)
		if verdict := h.send(h.lease, large, 443); verdict != VerdictPass {
			t.Fatalf("oversized-IInitial verdict = %v, want the caller disposition", verdict)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:P"})
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("held bytes after the refused reservation = %d, want 0", got)
		}
	})

	t.Run("CompletingPacketSaturation", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""),
			`{"hold_timeout":"10s","max_held_packets":1,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("held bytes after saturation = %d, want 0", got)
		}
	})

	t.Run("EngineWideBound", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""),
			`{"hold_timeout":"10s","max_held_packets":8,"max_held_bytes":2000,"max_held_bytes_total":3000}`)
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		other := h.newLease("192.0.2.10:40000", "198.51.100.8:443")
		hello := rawQUICClientHello("engine-bound.example")
		largeHead := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:40]}, 1600), dcid, 1, 1)
		largeTail := sealQUICInitial(t, cryptoFrames([]int{40}, [][]byte{hello[40:]}, 1600), dcid, 1, 2)
		h.send(h.lease, largeHead, 443)
		if got := h.engine.heldBytes.Load(); got <= 0 {
			t.Fatalf("first held record charge = %d", got)
		}
		// The second peer's partial Initial cannot reserve from the shared
		// allowance and is passed without a hold.
		if verdict := h.send(other, largeHead, 443); verdict != VerdictPass {
			t.Fatalf("second peer verdict = %v, want Pass", verdict)
		}
		// The first peer's completing Initial also cannot fit: the whole
		// incomplete cycle is aborted and the reservation returns to zero.
		h.send(h.lease, largeTail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "R:P", "O:D0:P", "R:P"})
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("engine held bytes after both aborts = %d, want 0", got)
		}
		// The returned reservation admits the next independent cycle.
		retryHead, _ := qa519SplitInitials(t, "engine-bound.example", 40, qa519DCID(0x2a), 1, 1)
		if verdict := h.send(other, retryHead, 443); verdict != VerdictHold {
			t.Fatalf("post-rollback Initial verdict = %v, want Hold", verdict)
		}
		if got := h.engine.heldBytes.Load(); got <= 0 {
			t.Fatalf("post-rollback charge = %d", got)
		}
		if err := other.Close(nil); err != nil {
			t.Fatalf("close: %v", err)
		}
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("engine held bytes after close = %d, want 0", got)
		}
	})

	t.Run("DeadlineNotRefreshed", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""),
			`{"hold_timeout":"10s","max_held_packets":8,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		flow := h.lease.udpFlows[qa519FlowKey(t, h.lease)]
		deadline := flow.holdDeadline
		h.send(h.lease, head, 443)
		if !flow.holdDeadline.Equal(deadline) {
			t.Fatalf("deadline refreshed by a duplicate: %v -> %v", deadline, flow.holdDeadline)
		}
	})

	t.Run("AutonomousTimeout", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""),
			`{"hold_timeout":"40ms","max_held_packets":8,"max_held_bytes":65536,"max_held_bytes_total":262144}`)
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		now := time.Unix(1000, 0)
		h.engine.SetHoldClock(func() time.Time { return now })
		h.send(h.lease, head, 443)
		now = now.Add(41 * time.Millisecond)
		h.lease.udpFlows[qa519FlowKey(t, h.lease)].expire()
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P"})
		// A cancelled cycle does not disable the flow: the next independent
		// authenticated cycle completes and owns its own burst.
		h.resetEvents()
		freshHead, freshTail := qa519SplitInitials(t, "after-timeout.example", 40, qa519DCID(0x3a), 1, 1)
		h.send(h.lease, freshHead, 443)
		h.send(h.lease, freshTail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "F", "F", "F", "O:D1:P", "O:D2:P", "R:H"})
	})

	t.Run("NilCompleter", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		qa519ExpectOps(t, nil, nil)
		if verdict := h.sendNoCompleter(h.lease, head, 443); verdict != VerdictPass {
			t.Fatalf("nil-completer pending verdict = %v", verdict)
		}
		if verdict := h.sendNoCompleter(h.lease, tail, 443); verdict != VerdictPass {
			t.Fatalf("nil-completer tail verdict = %v", verdict)
		}
		if got := h.ops(); len(got) != 2 || got[0] != "R:P" || got[1] != "R:P" {
			t.Fatalf("nil-completer ops = %v, want no hold and no fake", got)
		}
		// A standalone complete Initial needs no hold, so it is still planned.
		h.resetEvents()
		standalone := qa519CompleteInitial(t, "nil-completer.example", qa519DCID(0x4b), 1, 1)
		if verdict := h.sendNoCompleter(h.lease, standalone, 443); verdict != VerdictPass {
			t.Fatalf("nil-completer standalone verdict = %v", verdict)
		}
		qa519ExpectOps(t, h.ops(), []string{"F", "F", "F", "R:P"})
	})
}

// ---------------------------------------------------------------------------
// QH-05: ordered selection, exclusions, no-SNI and the interval.

func TestP1QUICHoldReplaySelection(t *testing.T) {
	markerA := qa519FakeMarker("QH05A")
	markerB := qa519FakeMarker("QH05B")
	t.Run("AuthoritativeReselection", func(t *testing.T) {
		config := qa519CompileRule(t, `{"name":"host-rule","network":["udp"],"port":[443],"domain":["b.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerB+`"}]}},`+
			`{"name":"catch-all","network":["udp"],"port":[443],"methods":["fake"],`+
			`"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarnessCached(t, config, "192.0.2.10:40000", "198.51.100.7:443", "cached.example")
		head, tail := qa519SplitInitials(t, "b.example", 40, qa519DCID(0x5c), 1, 1)
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "F", "F", "F", "O:D0:P", "O:D1:P", "R:H"})
		want, _ := hex.DecodeString(markerB)
		for index, payload := range h.injectedPayloads() {
			if !bytes.Equal(payload, want) {
				t.Fatalf("burst packet %d used %x, want the authoritative host rule's payload", index, payload)
			}
		}
	})
	t.Run("NoMatchingRule", func(t *testing.T) {
		config := qa519CompileRule(t, `{"network":["tcp"],"port":[443],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"tls","hex":"16030100"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		head, tail := qa519SplitInitials(t, "norule.example", 40, qa519DCID(0x6d), 1, 1)
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:P", "R:P"})
	})
	t.Run("IPExclusion", func(t *testing.T) {
		config := qa519CompileRule(t, `{"network":["udp"],"port":[443],"ip_cidr_exclude":["198.51.100.0/24"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		head, _ := qa519SplitInitials(t, "excluded-ip.example", 40, qa519DCID(0x7e), 1, 1)
		h.send(h.lease, head, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:P"})
	})
	t.Run("HostExclusion", func(t *testing.T) {
		// The provisional match comes from the cached host name; the completed
		// ClientHello names an excluded host, so the final selection must flush
		// the whole cycle instead of falling back to the provisional rule.
		config := qa519CompileRule(t, `{"network":["udp"],"port":[443],"domain":["allowed.example"],"domain_exclude":["blocked.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarnessCached(t, config, "192.0.2.10:40000", "198.51.100.7:443", "allowed.example")
		head, tail := qa519SplitInitials(t, "blocked.example", 40, qa519DCID(0x8f), 1, 1)
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
	})
	t.Run("EmptyPositiveIPInclude", func(t *testing.T) {
		directory := t.TempDir()
		empty := filepath.Join(directory, "ipset-all.txt")
		if err := os.WriteFile(empty, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		config := qa519CompileRule(t, `{"network":["udp"],"port":[443],"ip_cidr_file":[`+jsonPath(t, empty)+`],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		head, tail := qa519SplitInitials(t, "empty-include.example", 40, qa519DCID(0x90), 1, 1)
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "F", "F", "F", "O:D0:P", "O:D1:P", "R:H"})
	})
	t.Run("NoSNI", func(t *testing.T) {
		hostRule := qa519CompileRule(t, `{"network":["udp"],"port":[443],"domain":["a.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarness(t, hostRule, "192.0.2.10:40000", "198.51.100.7:443")
		noSNI := qa519CompleteInitial(t, "", qa519DCID(0xa1), 1, 1)
		h.send(h.lease, noSNI, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:P"})

		catchAll := qa519CompileRule(t, qa519UDPRules(markerA, 2, ""), "")
		h2 := qa519NewHarness(t, catchAll, "192.0.2.10:40000", "198.51.100.7:443")
		h2.send(h2.lease, qa519CompleteInitial(t, "", qa519DCID(0xb2), 1, 1), 443)
		qa519ExpectOps(t, h2.ops(), []string{"F", "F", "R:P"})
	})
	t.Run("Cutoff", func(t *testing.T) {
		cutoff := qa519CompileRule(t, qa519UDPRules(markerA, 3, `"cutoff":"n2",`), "")
		h := qa519NewHarness(t, cutoff, "192.0.2.10:40000", "198.51.100.7:443")
		head, tail := qa519SplitInitials(t, "cutoff.example", 40, qa519DCID(0xc3), 1, 1)
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})

		open := qa519CompileRule(t, qa519UDPRules(markerA, 3, `"cutoff":"n4",`), "")
		h2 := qa519NewHarness(t, open, "192.0.2.10:40000", "198.51.100.7:443")
		head2, tail2 := qa519SplitInitials(t, "cutoff.example", 40, qa519DCID(0xd4), 1, 1)
		h2.send(h2.lease, head2, 443)
		h2.send(h2.lease, tail2, 443)
		qa519ExpectOps(t, h2.ops(), []string{"R:H", "F", "F", "F", "O:D0:P", "O:D1:P", "R:H"})
	})
	t.Run("ImmutableReplaySnapshot", func(t *testing.T) {
		config := qa519CompileRule(t, `{"name":"first","network":["udp"],"port":[443],"methods":["fake"],`+
			`"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}},`+
			`{"name":"second","network":["udp"],"port":[443],"methods":["fake"],`+
			`"fake":{"repeats":5,"payloads":[{"protocol":"quic","hex":"`+markerB+`"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		head, tail := qa519SplitInitials(t, "reload.example", 40, qa519DCID(0xe5), 1, 1)
		h.send(h.lease, head, 443)
		if err := h.engine.ReloadLists(); err != nil {
			t.Fatalf("reload: %v", err)
		}
		h.send(h.lease, tail, 443)
		payloads := h.injectedPayloads()
		if len(payloads) != config.Rules[0].Fake.Repeats {
			t.Fatalf("replayed burst packets = %d, want one rule snapshot of %d", len(payloads), config.Rules[0].Fake.Repeats)
		}
		wantA, _ := hex.DecodeString(markerA)
		for index, payload := range payloads {
			if !bytes.Equal(payload, wantA) {
				t.Fatalf("replayed packet %d mixed profiles: %x", index, payload)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// QH-06: injection and planning failures fail open exactly once.

func TestP1QUICHoldReplayErrors(t *testing.T) {
	marker := qa519FakeMarker("QH06")
	dcid := qa519DCID(0x16)
	head, tail := qa519SplitInitials(t, "errors.example", 40, dcid, 1, 1)

	for _, failure := range []struct {
		name string
		call int
		want int
	}{
		{"First", 0, 1},
		{"Middle", 1, 2},
		{"Last", 2, 3},
	} {
		t.Run("Inject"+failure.name, func(t *testing.T) {
			config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
			h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
			h.injectFail = func(call int) error {
				if call == failure.call {
					return errors.New("inject failed")
				}
				return nil
			}
			h.send(h.lease, head, 443)
			h.send(h.lease, tail, 443)
			qa519ExpectOps(t, h.ops(), qa519Concat([]string{"R:H"}, qa519Repeat("F", failure.want-1), []string{"O:D0:P", "O:D1:P", "R:H"}))
			if h.attempts != failure.want {
				t.Fatalf("injection attempts = %d, want %d (no retry of a failed send)", h.attempts, failure.want)
			}
			if got := len(h.injectedPayloads()); got != failure.want-1 {
				t.Fatalf("successful injections = %d, want %d", got, failure.want-1)
			}
			if h.lease.Err() == nil {
				t.Fatal("injection failure must be preserved in the lease diagnostic")
			}
		})
	}

	t.Run("PlanFailure", func(t *testing.T) {
		config := qa519CompileRule(t, `{"network":["udp"],"port":[443],"methods":["fake","ipfrag2"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+marker+`"}]},"ipfrag_pos_udp":60000}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		verdict := h.send(h.lease, tail, 443)
		if len(h.injectedPayloads()) != 0 {
			t.Fatalf("planning failure injected %d packets", len(h.injectedPayloads()))
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "O:D1:P", "R:H"})
		if verdict != VerdictHold {
			t.Fatalf("completing verdict = %v, want the owned record's Hold", verdict)
		}
		if h.lease.Err() == nil {
			t.Fatal("planning failure must be preserved in the lease diagnostic")
		}
	})

	t.Run("NextPeerContinues", func(t *testing.T) {
		config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		other := h.newLease("192.0.2.10:40000", "198.51.100.8:443")
		h.injectFail = func(call int) error { return errors.New("inject failed") }
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		if h.lease.Err() == nil {
			t.Fatal("failed peer must keep its diagnostic")
		}
		h.injectFail = nil
		h.resetEvents()
		otherHead, otherTail := qa519SplitInitials(t, "healthy.example", 40, qa519DCID(0x27), 1, 1)
		h.send(other, otherHead, 443)
		h.send(other, otherTail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "F", "F", "F", "O:D0:P", "O:D1:P", "R:H"})
	})
}

// ---------------------------------------------------------------------------
// QH-07: the existing close/incomplete/error lifecycle owns held UDP records.

func TestP1QUICHoldReplayLifecycle(t *testing.T) {
	marker := qa519FakeMarker("QH07")
	config := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
	dcid := qa519DCID(0x38)
	head, tail := qa519SplitInitials(t, "lifecycle.example", 40, dcid, 1, 1)

	t.Run("CloseReleasesHeld", func(t *testing.T) {
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		if got := h.engine.heldBytes.Load(); got <= 0 {
			t.Fatalf("held-byte charge = %d, want a live reservation", got)
		}
		if err := h.lease.Close(nil); err != nil {
			t.Fatalf("close: %v", err)
		}
		if err := h.lease.Close(nil); err != nil {
			t.Fatalf("repeated close: %v", err)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P"})
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("held bytes after close = %d, want 0", got)
		}
		// A record delivered after the fence can only pass through; it creates
		// no new hold and never overtakes the flushed original.
		if verdict := h.send(h.lease, tail, 443); verdict != VerdictPass {
			t.Fatalf("post-fence verdict = %v", verdict)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
	})

	t.Run("EngineClose", func(t *testing.T) {
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		if err := h.engine.Close(); err != nil {
			t.Fatalf("engine close: %v", err)
		}
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P"})
	})

	t.Run("CloseDuringInjection", func(t *testing.T) {
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		h.send(h.lease, head, 443)
		entered := make(chan struct{})
		release := make(chan struct{})
		var enterOnce sync.Once
		h.injectEnter = func() {
			enterOnce.Do(func() { close(entered) })
			<-release
		}
		done := make(chan Verdict, 1)
		go func() { done <- h.send(h.lease, tail, 443) }()
		<-entered
		closed := make(chan error, 1)
		go func() { closed <- h.lease.Close(nil) }()
		// Give the teardown path time to reach the held flush, which blocks on
		// the flow owner until this injection returns.
		time.Sleep(20 * time.Millisecond)
		close(release)
		<-done
		<-closed
		completions := 0
		h.mu.Lock()
		for _, event := range h.events {
			if event.Kind == "complete" {
				completions++
			}
		}
		h.mu.Unlock()
		if completions != 2 {
			t.Fatalf("terminal completions during close = %d, want one per captured record", completions)
		}
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("held bytes after the raced close = %d, want 0", got)
		}
	})

	t.Run("BudgetRetainedUntilCallbackReturns", func(t *testing.T) {
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		charges := make([]int64, 0, 2)
		h.onComplete = func(string, Verdict) {
			charges = append(charges, h.engine.heldBytes.Load())
		}
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		if len(charges) != 2 {
			t.Fatalf("observed completions = %d, want 2", len(charges))
		}
		for index, charge := range charges {
			if charge <= 0 {
				t.Fatalf("completion %d observed a released reservation (%d)", index, charge)
			}
		}
		if got := h.engine.heldBytes.Load(); got != 0 {
			t.Fatalf("held bytes after the replay = %d, want 0", got)
		}
	})
}

// ---------------------------------------------------------------------------
// QH-08: peer, destination and tuple isolation.

func TestP1QUICHoldReplayPeers(t *testing.T) {
	marker := qa519FakeMarker("QH08")
	config := qa519CompileRule(t, `{"network":["udp"],"port_range":["1024-65535"],"methods":["fake"],`+
		`"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"`+marker+`"}]}}`, "")

	t.Run("ListenerDestinations", func(t *testing.T) {
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "")
		headA, tailA := qa519SplitInitials(t, "peer-a.example", 40, qa519DCID(0x49), 1, 1)
		headB, tailB := qa519SplitInitials(t, "peer-b.example", 40, qa519DCID(0x5a), 1, 1)
		h.send(h.lease, headA, 20443)
		h.send(h.lease, headB, 30443)
		h.send(h.lease, tailA, 20443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "R:H", "F", "F", "O:D0:P", "O:D2:P", "R:H"})
		h.resetEvents()
		h.send(h.lease, tailB, 30443)
		qa519ExpectOps(t, h.ops(), []string{"F", "F", "O:D1:P", "O:D3:P", "R:H"})
		if got := len(h.lease.udpFlows); got != 2 {
			t.Fatalf("listener peer states = %d, want one per destination", got)
		}
	})

	t.Run("TupleReuse", func(t *testing.T) {
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:20443")
		head, _ := qa519SplitInitials(t, "reuse.example", 40, qa519DCID(0x6b), 1, 1)
		h.send(h.lease, head, 20443)
		if err := h.lease.Close(nil); err != nil {
			t.Fatal(err)
		}
		fresh := h.newLease("192.0.2.10:40000", "198.51.100.7:20443")
		h.resetEvents()
		h.send(fresh, qa519CompleteInitial(t, "reuse.example", qa519DCID(0x6b), 1, 1), 20443)
		qa519ExpectOps(t, h.ops(), []string{"F", "F", "R:P"})
		for _, flow := range h.lease.udpFlows {
			if len(flow.holds) != 0 {
				t.Fatalf("closed lease retained %d holds", len(flow.holds))
			}
		}
	})
}

// headOf returns the first Initial of the peer fixture used by the tuple-reuse
// case; it only needs to be a partial authenticated Initial.
func headOf(t *testing.T) []byte {
	t.Helper()
	head, _ := qa519SplitInitials(t, "reuse.example", 40, qa519DCID(0x6b), 1, 1)
	return head
}

// ---------------------------------------------------------------------------
// AP-01: the explicit any-protocol bit, the pinned default QUIC payload and the
// full supplied profiles.

func TestP1UDPAnyProtocol(t *testing.T) {
	marker := qa519FakeMarker("AP01")
	t.Run("Compiled", func(t *testing.T) {
		absent := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
		falseBit := qa519CompileRule(t, qa519UDPRules(marker, 3, `"any_protocol":false,`), "")
		trueBit := qa519CompileRule(t, qa519UDPRules(marker, 3, `"any_protocol":true,`), "")
		refused := func() []byte {
			head, _ := qa519SplitInitials(t, "anyproto.example", 40, qa519DCID(0x7c), 1, 1)
			return qa519Corrupt(head)
		}
		for _, testCase := range []struct {
			name   string
			config *Config
			fakes  int
		}{
			{"absent", absent, 0},
			{"explicit-false", falseBit, 0},
			{"explicit-true", trueBit, 3},
		} {
			h := qa519NewHarness(t, testCase.config, "192.0.2.10:40000", "198.51.100.7:443")
			h.send(h.lease, refused(), 443)
			if got := len(h.injectedPayloads()); got != testCase.fakes {
				t.Fatalf("%s: refusal continuation fake units = %d, want %d", testCase.name, got, testCase.fakes)
			}
		}

		// Every supplied corrected profile compiles unchanged, including the
		// two high-UDP any_protocol profiles. The baseline profile carries no
		// desync outbound at all and is skipped.
		entries, err := os.ReadDir(qa519ProfileDir)
		if err != nil {
			t.Fatal(err)
		}
		compiled := 0
		for _, entry := range entries {
			name := entry.Name()
			if filepath.Ext(name) != ".json" || name == "00-baseline.json" {
				continue
			}
			config := qa519CompileProfile(t, name[:len(name)-len(".json")])
			if config != nil {
				compiled++
			}
		}
		if compiled < 22 {
			t.Fatalf("supplied profiles compiled = %d, want the full corrected22 set", compiled)
		}

		config := qa519CompileProfile(t, "03")
		rule := config.Rules[8]
		if rule.Name != "rule-8" || !rule.AnyProtocol || rule.Fake == nil || rule.Fake.Repeats != 10 {
			t.Fatalf("rule-8 = %+v, want the supplied any_protocol repeats10 profile", rule)
		}
		quicPayloads := 0
		unknownPayloads := 0
		for _, payload := range rule.Fake.Payloads {
			sum := sha256.Sum256(payload.Data)
			switch payload.Protocol {
			case ProtocolQUIC:
				quicPayloads++
				if hex.EncodeToString(sum[:]) != qa519DefaultQUICSHA256 {
					t.Fatalf("implicit QUIC payload sha256 = %x, want the pinned default620", sum)
				}
				if len(payload.Data) != 620 || payload.Data[0] != 0x40 {
					t.Fatalf("implicit QUIC payload = %d bytes starting %#x", len(payload.Data), payload.Data[0])
				}
			case ProtocolUnknown:
				unknownPayloads++
				if hex.EncodeToString(sum[:]) != qa519GamePayloadSHA256 {
					t.Fatalf("unknown payload sha256 = %x, want the supplied ACTIVE_GAME_UDP.bin", sum)
				}
			}
		}
		if quicPayloads != 1 || unknownPayloads != 1 {
			t.Fatalf("rule-8 payload surfaces = quic:%d unknown:%d, want exactly one of each", quicPayloads, unknownPayloads)
		}

		// An explicit QUIC payload replaces the default instead of being
		// appended to it.
		explicit := qa519CompileRule(t, qa519UDPRules(marker, 3, ""), "")
		explicitQUIC := 0
		for _, payload := range explicit.Rules[0].Fake.Payloads {
			if payload.Protocol == ProtocolQUIC {
				explicitQUIC++
				if hex.EncodeToString(payload.Data) != marker {
					t.Fatalf("explicit QUIC payload = %x, want configured %s", payload.Data, marker)
				}
			}
		}
		if explicitQUIC != 1 {
			t.Fatalf("explicit QUIC payload count = %d, want the configured payload only", explicitQUIC)
		}

		// The unknown payload path keeps its own bytes and cutoffs.
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
		h.send(h.lease, []byte{9, 9, 9, 9}, 30000)
		payloads := h.injectedPayloads()
		if len(payloads) != 10 {
			t.Fatalf("unknown payload fake units = %d, want 10", len(payloads))
		}
		for index, payload := range payloads {
			sum := sha256.Sum256(payload)
			if hex.EncodeToString(sum[:]) != qa519GamePayloadSHA256 {
				t.Fatalf("unknown fake %d payload sha256 = %x, want ACTIVE_GAME_UDP.bin", index, sum)
			}
		}

		// No rule-name special case: the bit alone decides.
		renamed := qa519CompileRule(t, `{"name":"not-rule-8","network":["udp"],"port_range":["1024-65535"],"any_protocol":true,`+
			`"methods":["fake"],"fake":{"repeats":4,"payloads":[{"protocol":"unknown","hex":"09090909"}]}}`, "")
		h2 := qa519NewHarness(t, renamed, "192.0.2.10:40000", "198.51.100.7:30000")
		h2.send(h2.lease, qa519Corrupt(headOf(t)), 30000)
		if got := len(h2.injectedPayloads()); got != 4 {
			t.Fatalf("renamed rule continuation fake units = %d, want 4", got)
		}
	})

	t.Run("Continuation", func(t *testing.T) {
		for _, name := range []string{"03", "18"} {
			t.Run("profile"+name, func(t *testing.T) {
				config := qa519CompileProfile(t, name)
				rule := config.Rules[8]
				repeats := rule.Fake.Repeats
				// n2 blocks the second datagram of a split cycle; n4 does not.
				splitBlocked := rule.Cutoff.IsSet() && rule.Cutoff.Reached(flowCounters{packets: 2})

				h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
				h.send(h.lease, qa519CompleteInitial(t, "high-port.example", qa519DCID(0x8d), 1, 1), 30000)
				if got := len(h.injectedPayloads()); got != repeats {
					t.Fatalf("complete Initial fake units = %d, want %d", got, repeats)
				}
				qa519ExpectOps(t, h.ops(), qa519Concat(qa519Repeat("F", repeats), []string{"R:P"}))

				// A fresh flow: the cutoff counters of the previous case would
				// otherwise decide the interval for this cycle.
				h = qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
				head, tail := qa519SplitInitials(t, "high-port.example", 40, qa519DCID(0x9e), 1, 1)
				h.send(h.lease, head, 30000)
				h.send(h.lease, tail, 30000)
				if splitBlocked {
					qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
				} else {
					qa519ExpectOps(t, h.ops(), qa519Concat([]string{"R:H"}, qa519Repeat("F", repeats), []string{"O:D0:P", "O:D1:P", "R:H"}))
				}

				// A classified but refused Initial continues only through the
				// explicit bit, and remains QUIC for fake selection.
				h = qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
				head2, tail2 := qa519SplitInitials(t, "high-port.example", 40, qa519DCID(0xaf), 1, 1)
				h.send(h.lease, head2, 30000)
				h.send(h.lease, qa519Corrupt(tail2), 30000)
				continuation := qa519Concat([]string{"R:H", "O:D0:P"}, qa519Repeat("F", repeats), []string{"R:P"})
				if splitBlocked {
					// The cutoff is evaluated before tampering, so the refused
					// datagram of a blocked interval passes untouched.
					continuation = []string{"R:H", "O:D0:P", "R:P"}
				}
				qa519ExpectOps(t, h.ops(), continuation)

				// A bounded reassembly refusal is not the continuation gate.
				h = qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
				hello := rawQUICClientHello("high-port.example")
				oversized := sealQUICInitial(t, qa519OverflowCrypto(hello), qa519DCID(0xb0), 1, 1)
				h.send(h.lease, oversized, 30000)
				if got := len(h.injectedPayloads()); got != 0 {
					t.Fatalf("resource refusal fake units = %d, want 0", got)
				}
				qa519ExpectOps(t, h.ops(), []string{"R:P"})
			})
		}

		// Bit-false and rule-5 controls: the same datagram passes untouched.
		control := qa519CompileRule(t, `{"network":["udp"],"port_range":["1024-65535"],"methods":["fake"],`+
			`"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"09090909"}]}}`, "")
		h := qa519NewHarness(t, control, "192.0.2.10:40000", "198.51.100.7:30000")
		h.send(h.lease, qa519Corrupt(headOf(t)), 30000)
		qa519ExpectOps(t, h.ops(), []string{"R:P"})

		rule5 := qa519CompileProfile(t, "03")
		h5 := qa519NewHarness(t, rule5, "192.0.2.10:40000", "198.51.100.7:443")
		h5.send(h5.lease, qa519Corrupt(headOf(t)), 443)
		qa519ExpectOps(t, h5.ops(), []string{"R:P"})
	})
}

// ---------------------------------------------------------------------------
// UL-01: bounded learning on the replay seam.

func TestP1UDPLearningReplay(t *testing.T) {
	marker := qa519FakeMarker("UL01")
	learningRule := func(extra string) string {
		return `{"name":"auto","network":["udp"],"port":[443],` + extra +
			`"learning":{"fail_threshold":1,"retrans_threshold":2},"methods":["fake"],` +
			`"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"` + marker + `"}]}}`
	}

	t.Run("FirstRequestIsNotRetransmission", func(t *testing.T) {
		config := qa519CompileRule(t, learningRule(""), "")
		if !config.Learning.enabled {
			t.Fatal("learning rule must enable the engine learner")
		}
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		initial := qa519CompleteInitial(t, "learn.example", qa519DCID(0xc1), 1, 1)
		h.send(h.lease, initial, 443)
		if h.engine.HostLearned("learn.example") {
			t.Fatal("the first completed request must not be a retransmission")
		}
		h.send(h.lease, initial, 443)
		if h.engine.HostLearned("learn.example") {
			t.Fatal("one later completed request is still below the retransmission threshold")
		}
		h.send(h.lease, initial, 443)
		if !h.engine.HostLearned("learn.example") {
			t.Fatal("the second later completed request must reach the threshold")
		}
	})

	t.Run("PendingFragmentsDoNotCount", func(t *testing.T) {
		config := qa519CompileRule(t, learningRule(""), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		head, tail := qa519SplitInitials(t, "fragments.example", 40, qa519DCID(0xd2), 1, 1)
		for cycle := 0; cycle < 2; cycle++ {
			h.send(h.lease, head, 443)
			h.send(h.lease, tail, 443)
		}
		if h.engine.HostLearned("fragments.example") {
			t.Fatal("pending fragments or replayed originals must not manufacture observations")
		}
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		if !h.engine.HostLearned("fragments.example") {
			t.Fatal("the third completed request must reach the threshold")
		}
	})

	t.Run("RefusedFragmentsDoNotCount", func(t *testing.T) {
		config := qa519CompileRule(t, learningRule(""), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		initial := qa519CompleteInitial(t, "refused.example", qa519DCID(0xe3), 1, 1)
		for round := 0; round < 4; round++ {
			h.send(h.lease, qa519Corrupt(initial), 443)
		}
		if h.engine.HostLearned("refused.example") {
			t.Fatal("refused datagrams must not be learning observations")
		}
	})

	t.Run("ExcludedHostNeverLearns", func(t *testing.T) {
		config := qa519CompileRule(t, learningRule(`"domain_exclude":["excluded.example"],`), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		initial := qa519CompleteInitial(t, "excluded.example", qa519DCID(0xf4), 1, 1)
		for round := 0; round < 4; round++ {
			h.send(h.lease, initial, 443)
		}
		if h.engine.HostLearned("excluded.example") {
			t.Fatal("an excluded host must never be learned")
		}
	})

	t.Run("NoHostNeverLearns", func(t *testing.T) {
		config := qa519CompileRule(t, learningRule(""), "")
		h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
		noSNI := qa519CompleteInitial(t, "", qa519DCID(0x05), 1, 1)
		for round := 0; round < 4; round++ {
			h.send(h.lease, noSNI, 443)
		}
		if learned := h.engine.LearnedHosts(); len(learned) != 0 {
			t.Fatalf("learned hosts without a validated SNI = %v", learned)
		}
	})
}

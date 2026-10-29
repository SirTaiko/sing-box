package desync

// Submission20 acceptance regressions: cold-cache-empty QUIC hold selection and
// the true absent-SNI contract.
//
// Both defects were demonstrated by independent QA519 reproducers on the
// submission19 tree:
//
//   - a captured real QUIC split ClientHello replayed without a hostname cache
//     was reset when no provisional rule matched, so the cold tail could never
//     complete the cycle and no configured fake burst appeared;
//   - an authenticated complete ClientHello whose server_name extension is
//     absent incorrectly received the rule8 default burst even though the
//     pinned skip_no_sni default forbids it.
//
// The fixtures under testdata/qa519/fixtures are byte-identical copies of the
// authentic captured client datagrams preserved in the failed QA evidence
// (t_cbef2106/fixtures); their SHA256 values are asserted below so the test
// cannot silently drift onto rewritten bytes.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const qa520FixtureDir = "testdata/qa519/fixtures"

// qa520ColdFixture is one authentic captured flight. datagrams is the captured
// Initial count, cycles the number of completed CRYPTO cycles and trailing the
// count of datagrams after the last cycle (the captured client's refused
// Initial, which does not belong to a transformable cycle).
type qa520ColdFixture struct {
	file      string
	sha256    string
	host      string
	datagrams int
	cycles    int
	trailing  int
}

var qa520ColdFixtures = []qa520ColdFixture{
	{"quic-linux-h2-on18.json", "261e2ded5b9f80b403c5c7afd871a6d17eaa452a69ebe4436af80b80e0f98df0", "www.youtube.com", 3, 1, 1},
	{"quic-linux-h3-ref18.json", "c1a14febfe5e98131e43b2374e568d04b488769ea9eefd4c493d0b6cbbe8fdf6", "www.youtube.com", 3, 1, 1},
	{"quic-linux-c2-on18.json", "49964793e789c25513f61aa6bd64961c2055f92a17cca8c4034182c64f8f6821", "cloudflare-quic.com", 10, 5, 0},
	{"quic-linux-c3-ref18.json", "9fbcfa98efa51f8b17f29add2c2fcc4751c2f9046a19f5a49442f93c9120c831", "cloudflare-quic.com", 10, 5, 0},
	{"quic-windows-h2-on18.json", "3052eb4cf1de9169637a87475424eeeac1427d6eeb72f69b8454443522c1cdb8", "www.youtube.com", 3, 1, 1},
	{"quic-windows-h3-ref18.json", "3e67e4aac5a308fe4cb435876ca1c0e4c153f9a69699fad51e20cf280a45119e", "www.youtube.com", 3, 1, 1},
	{"quic-windows-c2-on18.json", "aac5e62db7438fce1f6ffb676a4ec557b5fd5ece1183dd3a782bcf0ffd4d1f13", "cloudflare-quic.com", 10, 5, 0},
	{"quic-windows-c3-ref18.json", "a238f8a08fdedb4f094c0a4f553c1e95c91ab3619121a524d996de47137d1fba", "cloudflare-quic.com", 10, 5, 0},
}

// qa520LoadCaptured reads one fixture and verifies its authentic bytes.
func qa520LoadCaptured(t *testing.T, fixture qa520ColdFixture) [][]byte {
	t.Helper()
	rawJSON, err := os.ReadFile(filepath.Join(qa520FixtureDir, fixture.file))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(rawJSON)
	if got := hex.EncodeToString(sum[:]); got != fixture.sha256 {
		t.Fatalf("fixture %s bytes changed: sha256 %s, want authentic %s", fixture.file, got, fixture.sha256)
	}
	var hexes []string
	if err = json.Unmarshal(rawJSON, &hexes); err != nil {
		t.Fatal(err)
	}
	if len(hexes) != fixture.datagrams {
		t.Fatalf("fixture %s carries %d datagrams, want %d", fixture.file, len(hexes), fixture.datagrams)
	}
	raw := make([][]byte, len(hexes))
	for index, value := range hexes {
		if raw[index], err = hex.DecodeString(value); err != nil {
			t.Fatalf("fixture %s datagram %d: %v", fixture.file, index, err)
		}
	}
	return raw
}

// sendRaw replays one authentic captured datagram through the same caller
// surface the native backend uses: the harness records every injected
// replacement, every terminal disposition and the verdict returned for the
// captured record itself.
func (h *qa519Harness) sendRaw(raw []byte) Verdict {
	h.t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		h.t.Fatal(err)
	}
	h.mu.Lock()
	label := "D" + qa519Index(h.labels[h.lease])
	h.labels[h.lease]++
	h.mu.Unlock()
	complete := func(verdict Verdict, reason string, modified []byte) {
		h.record(qa519Event{Kind: "complete", Label: label, Payload: append([]byte(nil), packet.Payload...), Verdict: verdict, Reason: reason})
		if h.onComplete != nil {
			h.onComplete(label, verdict)
		}
	}
	verdict := h.lease.HandlePacket(raw, DirectionOutbound, func(raw []byte) error {
		parsed, err := ParsePacket(raw)
		if err != nil {
			return err
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

// TestQA520ColdCapturedHoldReplay replays the authentic captured client flights
// with a cold hostname cache (no priming, no cached destination host) against
// the complete supplied profiles. The provisional owner of the incomplete
// cycle must hold the first Initial, the validated ClientHello must re-run the
// authoritative selection and the configured rule5 burst must be emitted
// before the first captured original, exactly once per completed cycle.
func TestQA520ColdCapturedHoldReplay(t *testing.T) {
	for _, profileName := range []string{"03", "18"} {
		for _, fixture := range qa520ColdFixtures {
			fixture := fixture
			t.Run(profileName+"/"+fixture.file, func(t *testing.T) {
				config := qa519CompileProfile(t, profileName)
				if len(config.Rules) <= 5 || config.Rules[5].Name != "rule-5" {
					t.Fatalf("profile %s rule index 5 is not rule-5", profileName)
				}
				rule5 := config.Rules[5]
				if rule5.Fake == nil || len(rule5.Fake.Payloads) == 0 || rule5.Fake.Repeats <= 0 {
					t.Fatal("rule-5 has no configured fake burst")
				}
				repeats := rule5.Fake.Repeats
				fake := rule5.Fake.Payloads[0].Data

				raw := qa520LoadCaptured(t, fixture)
				first, err := ParsePacket(raw[0])
				if err != nil {
					t.Fatal(err)
				}
				source := fmt.Sprintf("%s:%d", first.Src, first.SrcPort)
				destination := fmt.Sprintf("%s:%d", first.Dst, first.DstPort)
				// The hostname cache is part of the real caller state: the
				// acceptance case starts cold and may warm only from a
				// validated ClientHello.
				config.IPCache.hostnameEnabled = true
				h := qa519NewHarness(t, config, source, destination)

				// Cold acceptance precondition: this exact destination has no
				// cached hostname before the first captured Initial.
				if host, _, ok := h.engine.ipcache.lookupHost(first.Dst, ""); ok {
					t.Fatalf("cold cache precondition violated: cached host %q", host)
				}

				verdicts := make([]Verdict, len(raw))
				for index, datagram := range raw {
					verdicts[index] = h.sendRaw(datagram)
				}

				// The first datagram of every captured cycle is an incomplete
				// ClientHello: it must be held, never delivered immediately.
				labels := make([]string, len(raw))
				for index := range labels {
					labels[index] = "D" + qa519Index(index)
				}
				want := make([]string, 0, fixture.cycles*(repeats+3)+fixture.trailing)
				for cycle := 0; cycle < fixture.cycles; cycle++ {
					head := 2 * cycle
					tail := head + 1
					if verdicts[head] != VerdictHold {
						t.Fatalf("cycle %d head verdict = %v, want VerdictHold", cycle, verdicts[head])
					}
					if verdicts[tail] != VerdictHold {
						t.Fatalf("cycle %d completing verdict = %v, want VerdictHold", cycle, verdicts[tail])
					}
					want = append(want, "R:H")
					want = append(want, qa519Repeat("F", repeats)...)
					want = append(want, "O:"+labels[head]+":P", "O:"+labels[tail]+":P", "R:H")
				}
				for trailing := 0; trailing < fixture.trailing; trailing++ {
					index := fixture.cycles*2 + trailing
					if verdicts[index] != VerdictPass {
						t.Fatalf("trailing datagram %d verdict = %v, want VerdictPass", index, verdicts[index])
					}
					want = append(want, "R:P")
				}
				qa519ExpectOps(t, h.ops(), want)

				// Configured bytes and counts: every replacement is the
				// selected rule's configured payload, nothing else is faked.
				payloads := h.injectedPayloads()
				if len(payloads) != fixture.cycles*repeats {
					t.Fatalf("injected %d fake packets, want %d configured bursts of %d", len(payloads), fixture.cycles, repeats)
				}
				for index, payload := range payloads {
					if !bytes.Equal(payload, fake) {
						t.Fatalf("packet %d payload sha %x differs from the configured rule-5 payload sha %x",
							index, sha256.Sum256(payload), sha256.Sum256(fake))
					}
				}

				// Every held original is delivered exactly once, unchanged, in
				// capture order. A trailing refused datagram is returned Pass
				// to the caller (it never enters the completed-cycle queue).
				delivered := h.deliveredOriginals()
				if len(delivered) != fixture.cycles*2 {
					t.Fatalf("delivered %d originals, want %d", len(delivered), fixture.cycles*2)
				}
				for index, original := range delivered {
					wantPacket, err := ParsePacket(raw[index])
					if err != nil {
						t.Fatal(err)
					}
					if original.Label != labels[index] {
						t.Fatalf("original %d delivered as %s, want %s", index, original.Label, labels[index])
					}
					if original.Verdict != VerdictPass {
						t.Fatalf("original %d verdict = %v, want Pass", index, original.Verdict)
					}
					if !bytes.Equal(original.Payload, wantPacket.Payload) {
						t.Fatalf("original %d payload changed: sha %x, want %x", index,
							sha256.Sum256(original.Payload), sha256.Sum256(wantPacket.Payload))
					}
				}

				// The cache learns only from the validated ClientHello: after
				// the first completed cycle the destination host is the
				// captured SNI, never a speculative value.
				if host, _, ok := h.engine.ipcache.lookupHost(first.Dst, ""); !ok || host != fixture.host {
					t.Fatalf("learned hostname = %q ok=%v, want validated %q", host, ok, fixture.host)
				}
			})
		}
	}
}

// deliveredOriginals returns the terminal dispositions of captured records in
// event order.
func (h *qa519Harness) deliveredOriginals() []qa519Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]qa519Event, 0, len(h.events))
	for _, event := range h.events {
		if event.Kind == "complete" {
			out = append(out, event)
		}
	}
	return out
}

// qa520NoSNIHello is a structurally valid ClientHello whose server_name
// extension is removed entirely. This is the pinned "hostname in the SNI is
// absent" shape; it is not the empty host_name entry, which pinned still treats
// as a present extension.
func qa520NoSNIHello() []byte {
	hello := rawQUICClientHello("placeholder.example")
	// Skip handshake header, legacy version+random, session id, cipher suites
	// and compression methods; then replace the extension block with an empty
	// one.
	position := 4 + 2 + 32
	position += 1 + int(hello[position])
	position += 2 + int(binary.BigEndian.Uint16(hello[position:position+2]))
	position += 1 + int(hello[position])
	stripped := append(append([]byte(nil), hello[:position]...), 0, 0)
	length := len(stripped) - 4
	stripped[1] = byte(length >> 16)
	stripped[2] = byte(length >> 8)
	stripped[3] = byte(length)
	return stripped
}

// qa520SealNoSNI seals one absent-SNI ClientHello as a single complete Initial.
func qa520SealNoSNI(t *testing.T, dcid []byte, packetNumber uint32) []byte {
	t.Helper()
	return sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{qa520NoSNIHello()}, 240), dcid, 1, packetNumber)
}

// qa520SplitNoSNI seals the absent-SNI ClientHello as two Initials of one
// connection identity.
func qa520SplitNoSNI(t *testing.T, dcid []byte, split int, packetNumber uint32) ([]byte, []byte) {
	t.Helper()
	hello := qa520NoSNIHello()
	if split <= 0 || split >= len(hello) {
		t.Fatalf("split %d outside hello of %d bytes", split, len(hello))
	}
	head := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:split]}, 240), dcid, 1, packetNumber)
	tail := sealQUICInitial(t, cryptoFrames([]int{split}, [][]byte{hello[split:]}, 240), dcid, 1, packetNumber+1)
	return head, tail
}

// TestQA520TrueNoSNI proves the pinned desync_skip_nosni contract for a QUIC
// ClientHello whose server_name extension is absent. The default is true, so a
// complete authenticated Initial passes untouched; an explicit false keeps the
// rule8 continuation and its implicit pinned default payload. A stale cached
// hostname can never resurrect the missing fact.
func TestQA520TrueNoSNI(t *testing.T) {
	for _, profileName := range []string{"03", "18"} {
		profileName := profileName
		t.Run("profile"+profileName, func(t *testing.T) {
			config := qa519CompileProfile(t, profileName)
			if len(config.Rules) <= 8 || config.Rules[8].Name != "rule-8" {
				t.Fatalf("profile %s rule index 8 is not rule-8", profileName)
			}
			if !config.Rules[8].SkipNoSNI {
				t.Fatalf("profile %s rule-8 skip_no_sni default is not true", profileName)
			}
			if !config.Rules[8].DesyncAnyProtocol {
				t.Fatalf("profile %s rule-8 does not carry the explicit any-protocol bit", profileName)
			}
			destination := "198.51.100.7:30000"

			t.Run("DefaultSkips", func(t *testing.T) {
				h := qa519NewHarness(t, config, "192.0.2.10:40000", destination)
				noSNI := qa520SealNoSNI(t, qa519DCID(0x39), 1)
				packet, err := ParsePacket(buildIPv4UDP(t, noSNI, 30000).Raw)
				if err != nil {
					t.Fatal(err)
				}
				if verdict := h.send(h.lease, noSNI, 30000); verdict != VerdictPass {
					t.Fatalf("verdict = %v, want Pass", verdict)
				}
				qa519ExpectOps(t, h.ops(), []string{"R:P"})
				// Pass means the caller keeps its captured record: no
				// replacement is injected and no asynchronous disposition is
				// deferred.
				if len(h.injectedPayloads()) != 0 {
					t.Fatal("the default skip_no_sni gate injected a replacement")
				}
				if len(h.deliveredOriginals()) != 0 {
					t.Fatal("the default skip_no_sni gate deferred the original to a completer")
				}
				if _, _, ok := h.engine.ipcache.lookupHost(packet.Dst, ""); ok {
					t.Fatal("an absent SNI must not populate the hostname cache")
				}
			})

			t.Run("ExplicitFalseContinues", func(t *testing.T) {
				explicit := qa519CompileProfile(t, profileName)
				explicit.Rules[8].SkipNoSNI = false
				h := qa519NewHarness(t, explicit, "192.0.2.10:40001", destination)
				h.send(h.lease, qa520SealNoSNI(t, qa519DCID(0x3a), 1), 30000)
				payloads := h.injectedPayloads()
				if len(payloads) != 10 {
					t.Fatalf("explicit skip_no_sni=false injected %d packets, want rule-8's configured 10", len(payloads))
				}
				for index, payload := range payloads {
					sum := sha256.Sum256(payload)
					if got := hex.EncodeToString(sum[:]); got != qa519DefaultQUICSHA256 {
						t.Fatalf("packet %d sha %s is not the pinned default QUIC payload", index, got)
					}
				}
			})

			t.Run("SplitDefaultSkips", func(t *testing.T) {
				h := qa519NewHarness(t, qa519CompileProfile(t, profileName), "192.0.2.10:40002", destination)
				head, tail := qa520SplitNoSNI(t, qa519DCID(0x3b), 40, 1)
				if verdict := h.send(h.lease, head, 30000); verdict != VerdictHold {
					t.Fatalf("incomplete absent-SNI Initial verdict = %v, want VerdictHold", verdict)
				}
				h.send(h.lease, tail, 30000)
				qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
			})

			t.Run("SplitExplicitFalseContinues", func(t *testing.T) {
				// A dedicated rule isolates the skip_no_sni bit from the
				// supplied profile cutoffs (03 rule-8 is n4, 18 n2, so a
				// two-datagram split cycle is already cancelled by n2).
				marker := qa519FakeMarker("QA520SPLIT")
				explicit := qa519CompileRule(t, `{"name":"nosni-split","network":["udp"],"port_range":["1024-65535"],"any_protocol":true,"methods":["fake"],`+
					`"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"`+marker+`"}]}}`, "")
				explicit.Rules[0].SkipNoSNI = false
				if explicit.Rules[0].Fake == nil || explicit.Rules[0].Fake.Repeats != 10 {
					t.Fatal("synthetic split control lost its configured repeats")
				}
				h := qa519NewHarness(t, explicit, "192.0.2.10:40003", destination)
				head, tail := qa520SplitNoSNI(t, qa519DCID(0x3c), 40, 1)
				h.send(h.lease, head, 30000)
				h.send(h.lease, tail, 30000)
				payloads := h.injectedPayloads()
				if len(payloads) != 10 {
					t.Fatalf("explicit skip_no_sni=false split cycle injected %d packets, want the configured 10 default QUIC repeats", len(payloads))
				}
				for index, payload := range payloads {
					sum := sha256.Sum256(payload)
					if got := hex.EncodeToString(sum[:]); got != qa519DefaultQUICSHA256 {
						t.Fatalf("packet %d sha %s is not the pinned default QUIC payload", index, got)
					}
				}
			})
		})
	}

	t.Run("StaleCache", func(t *testing.T) {
		// A hostname cached for the destination before this flight must not
		// stand in for the missing server_name extension.
		marker := qa519FakeMarker("QA520")
		config := qa519CompileRule(t, `{"name":"cached","network":["udp"],"port":[443],"domain":["allowed.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+marker+`"}]}}`, "")
		h := qa519NewHarnessCached(t, config, "192.0.2.10:40004", "198.51.100.7:443", "allowed.example")
		h.send(h.lease, qa520SealNoSNI(t, qa519DCID(0x3d), 1), 443)
		qa519ExpectOps(t, h.ops(), []string{"R:P"})
		if len(h.injectedPayloads()) != 0 {
			t.Fatal("stale cached hostname approved a burst for a ClientHello without SNI")
		}

		explicit := qa519CompileRule(t, `{"name":"cached","network":["udp"],"port":[443],"domain":["allowed.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+marker+`"}]}}`, "")
		explicit.Rules[0].SkipNoSNI = false
		h2 := qa519NewHarnessCached(t, explicit, "192.0.2.10:40005", "198.51.100.7:443", "allowed.example")
		h2.send(h2.lease, qa520SealNoSNI(t, qa519DCID(0x3e), 1), 443)
		qa519ExpectOps(t, h2.ops(), []string{"F", "F", "F", "R:P"})
		want, _ := hex.DecodeString(marker)
		for index, payload := range h2.injectedPayloads() {
			if !bytes.Equal(payload, want) {
				t.Fatalf("packet %d used %x, want the governing rule's configured payload", index, payload)
			}
		}
	})
}

// TestQA520ColdProvisionalSelectionControls proves the bounded pre-host
// ownership does not speculate: the final ClientHello hostname is authoritative
// (a different rule can win, an exclusion or a missing rule flushes), and a
// datagram that is definitively ineligible on a non-host predicate is never
// held at all.
func TestQA520ColdProvisionalSelectionControls(t *testing.T) {
	markerA := qa519FakeMarker("QA520A")
	markerB := qa519FakeMarker("QA520B")
	newSplit := func(t *testing.T, host string, dcid []byte) ([]byte, []byte) {
		t.Helper()
		return qa519SplitInitials(t, host, 40, dcid, 1, 1)
	}

	t.Run("FinalReselectFromTop", func(t *testing.T) {
		// The first rule is a host-scoped profile that matches the provisional
		// predicates only; the authoritative hostname selects the second rule
		// from the top of the ordered list.
		config := qa519CompileRule(t, `{"name":"other-host","network":["udp"],"port":[443],"domain":["b.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerB+`"}]}},`+
			`{"name":"catch-all","network":["udp"],"port":[443],"methods":["fake"],`+
			`"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40010", "198.51.100.7:443")
		head, tail := newSplit(t, "a.example", qa519DCID(0x40))
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "F", "F", "O:D0:P", "O:D1:P", "R:H"})
		want, _ := hex.DecodeString(markerA)
		for index, payload := range h.injectedPayloads() {
			if !bytes.Equal(payload, want) {
				t.Fatalf("packet %d used the provisional rule's payload instead of the authoritative rule's", index)
			}
		}
	})

	t.Run("FinalExclusionFlushes", func(t *testing.T) {
		config := qa519CompileRule(t, `{"name":"excluded","network":["udp"],"port":[443],"domain_exclude":["blocked.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40011", "198.51.100.7:443")
		head, tail := newSplit(t, "blocked.example", qa519DCID(0x41))
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
		if len(h.injectedPayloads()) != 0 {
			t.Fatal("an excluded final hostname still produced the provisional rule's burst")
		}
	})

	t.Run("NoFinalRuleFlushes", func(t *testing.T) {
		config := qa519CompileRule(t, `{"name":"host-only","network":["udp"],"port":[443],"domain":["allowed.example"],"methods":["fake"],`+
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"`+markerA+`"}]}}`, "")
		h := qa519NewHarness(t, config, "192.0.2.10:40012", "198.51.100.7:443")
		head, tail := newSplit(t, "other.example", qa519DCID(0x42))
		h.send(h.lease, head, 443)
		h.send(h.lease, tail, 443)
		qa519ExpectOps(t, h.ops(), []string{"R:H", "O:D0:P", "R:P"})
		if len(h.injectedPayloads()) != 0 {
			t.Fatal("a partial cycle with no final rule fell back to the provisional rule")
		}
	})

	definitive := []struct {
		name string
		rule string
	}{
		{"PortMismatch", `{"name":"wrong-port","network":["udp"],"port":[8443],"domain":["allowed.example"],"methods":["fake"],` +
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"` + markerA + `"}]}}`},
		{"IPExclusion", `{"name":"excluded-ip","network":["udp"],"port":[443],"ip_cidr_exclude":["198.51.100.0/24"],"domain":["allowed.example"],"methods":["fake"],` +
			`"fake":{"repeats":3,"payloads":[{"protocol":"quic","hex":"` + markerA + `"}]}}`},
		{"ProtocolMismatch", `{"name":"stun-only","network":["udp"],"port":[443],"protocol":["stun"],"domain":["allowed.example"],"methods":["fake"],` +
			`"fake":{"repeats":3,"payloads":[{"protocol":"stun","hex":"` + markerA + `"}]}}`},
	}
	for _, control := range definitive {
		control := control
		t.Run(control.name, func(t *testing.T) {
			config := qa519CompileRule(t, control.rule, "")
			h := qa519NewHarness(t, config, "192.0.2.10:40013", "198.51.100.7:443")
			head, tail := newSplit(t, "allowed.example", qa519DCID(0x43))
			if verdict := h.send(h.lease, head, 443); verdict != VerdictPass {
				t.Fatalf("definitively ineligible partial Initial verdict = %v, want Pass", verdict)
			}
			if verdict := h.send(h.lease, tail, 443); verdict != VerdictPass {
				t.Fatalf("definitively ineligible completing Initial verdict = %v, want Pass", verdict)
			}
			qa519ExpectOps(t, h.ops(), []string{"R:P", "R:P"})
			if len(h.injectedPayloads()) != 0 {
				t.Fatal("a definitively ineligible datagram was held and transformed")
			}
		})
	}
}

// TestQA520PresentEmptySNIStillTransforms is the control that separates the two
// shapes: an empty host_name entry is a *present* server_name extension in the
// pinned extractor, so the default skip_no_sni gate does not apply to it.
func TestQA520PresentEmptySNIStillTransforms(t *testing.T) {
	for _, profileName := range []string{"03", "18"} {
		config := qa519CompileProfile(t, profileName)
		h := qa519NewHarness(t, config, "192.0.2.10:40006", "198.51.100.7:30000")
		h.send(h.lease, qa519CompleteInitial(t, "", qa519DCID(0x3f), 1, 1), 30000)
		payloads := h.injectedPayloads()
		if len(payloads) != 10 {
			t.Fatalf("profile %s empty host_name entry injected %d packets, want 10", profileName, len(payloads))
		}
		for index, payload := range payloads {
			sum := sha256.Sum256(payload)
			if got := hex.EncodeToString(sum[:]); got != qa519DefaultQUICSHA256 {
				t.Fatalf("packet %d sha %s is not the pinned default QUIC payload", index, got)
			}
		}
	}
}

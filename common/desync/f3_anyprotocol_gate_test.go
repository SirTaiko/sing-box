package desync

// Permanent regression for the selected-A contract §5 (finding F3).
//
// An unknown UDP payload - and an Initial whose CRYPTO reassembly the parser
// cancelled - continues to tampering only through the selected profile's
// explicit desync_any_proto permission. Matching unknown traffic is a
// different statement: a rule with no L7 selector compiles AnyProtocol=true,
// which is why the old code transformed unknown datagrams even when the source
// profile omitted the permission. The gate covers every transform
// (planUDPStages, applyOrigMod, planUDPDup), so this test observes the
// generated packets and the caller-visible requests, not an internal flag.
//
// The controls pin the rest of the decision: an explicit permission keeps the
// configured fake bytes, a recognized protocol keeps its unchanged
// eligibility, and fakeknown still excludes unknown payloads.

import "testing"

const (
	// f3UnknownPayload starts with 0x51: no upstream dissector classifies it.
	f3UnknownPayload = "QA523-UNKNOWN-NATIVE-0123456789"
	// f3GamePayload is the configured replacement bytes of the unknown-
	// protocol fixture. It is a distinct marker, not the pinned ACTIVE_GAME
	// asset: this case tests admission, not payload provenance.
	f3GameHex = "f3f3f3f3f3f3f3f3"
)

// f3Config compiles one rule on the harness port. extra carries the source
// permission field; every other predicate is the pre-F3 fixture shape.
func f3Config(t *testing.T, protocol, extra string) *Config {
	t.Helper()
	body := `{"network":["udp"],"port":[30000],"methods":["fake"],` + extra +
		`"fake":{"repeats":10,"payloads":[{"protocol":"` + protocol + `","hex":"` + f3GameHex + `"}]}}`
	return qa519CompileRule(t, body, "")
}

// f3Returns counts caller-visible request results in the current phase. A
// non-held datagram owns its terminal disposition in the native caller, so the
// harness records the request result, not an engine completion callback.
func f3Returns(h *qa519Harness) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	returns := 0
	for _, event := range h.events {
		if event.Kind == "return" {
			returns++
		}
	}
	return returns
}

// f3Send delivers one datagram and reports the caller verdict, the number of
// injected replacements and the number of caller request results.
func f3Send(t *testing.T, h *qa519Harness, payload []byte) (Verdict, int, int) {
	t.Helper()
	h.resetPhase()
	verdict := h.send(h.lease, payload, 30000)
	return verdict, len(h.injectedPayloads()), f3Returns(h)
}

// TestF3UnknownRequiresExplicitAnyProtocol is the direct F3 regression. The
// omitted and explicit-false variants are the native controls QA523 measured
// against nfqws/winws: pinned emits nothing, the pre-repair product emitted the
// configured GAME burst.
func TestF3UnknownRequiresExplicitAnyProtocol(t *testing.T) {
	cases := []struct {
		name     string
		extra    string
		explicit bool
		// wantInjected is the number of configured fake units. Pinned passes
		// the datagram unchanged without permission, so the only admissible
		// counts are 0 (no permission) and the configured burst (permission).
		wantInjected int
	}{
		{"omitted", ``, false, 0},
		{"explicit-false", `"any_protocol":false,`, false, 0},
		{"explicit-true", `"any_protocol":true,`, true, 10},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			config := f3Config(t, "unknown", testCase.extra)
			if len(config.Rules) != 1 {
				t.Fatalf("compiled rules = %d", len(config.Rules))
			}
			rule := config.Rules[0]
			// Zero ambiguity between "matches unknown traffic" and "may
			// transform it": the matcher permission is automatic for a rule
			// without an L7 selector in every variant.
			if !rule.AnyProtocol {
				t.Fatalf("fixture rule must match unknown traffic (AnyProtocol)")
			}
			if rule.DesyncAnyProtocol != testCase.explicit {
				t.Fatalf("DesyncAnyProtocol = %v, want %v", rule.DesyncAnyProtocol, testCase.explicit)
			}
			h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
			verdict, injected, completed := f3Send(t, h, []byte(f3UnknownPayload))
			if verdict != VerdictPass {
				t.Fatalf("unknown UDP verdict = %v, want Pass", verdict)
			}
			if injected != testCase.wantInjected {
				t.Fatalf("unknown UDP injected = %d, want %d", injected, testCase.wantInjected)
			}
			if completed != 1 {
				t.Fatalf("caller request results = %d, want exactly 1", completed)
			}
			for _, payload := range h.injectedPayloads() {
				if got := hexOf(payload); got != f3GameHex {
					t.Fatalf("injected payload = %s, want the configured %s", got, f3GameHex)
				}
			}
		})
	}
}

// TestF3RecognizedProtocolKeepsEligibility is the recognized-protocol control:
// the permission is not required for a classified payload, so a rule without
// any_protocol still transforms it with the payload matching its protocol.
func TestF3RecognizedProtocolKeepsEligibility(t *testing.T) {
	config := f3Config(t, "stun", ``)
	if config.Rules[0].DesyncAnyProtocol {
		t.Fatal("control fixture must not carry the explicit permission")
	}
	h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
	stun := []byte{0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	verdict, injected, completed := f3Send(t, h, stun)
	if verdict != VerdictPass {
		t.Fatalf("STUN verdict = %v, want Pass", verdict)
	}
	if injected != 10 {
		t.Fatalf("STUN injected = %d, want the configured 10", injected)
	}
	if completed != 1 {
		t.Fatalf("caller request results = %d, want exactly 1", completed)
	}
}

// TestF3CancelledInitialRequiresExplicitAnyProtocol covers the second half of
// the predicate: a parser-cancelled Initial is QUIC for fake selection but
// still needs the explicit permission before any transform.
func TestF3CancelledInitialRequiresExplicitAnyProtocol(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		name := "omitted"
		extra := ``
		if explicit {
			name = "explicit-true"
			extra = `"any_protocol":true,`
		}
		t.Run(name, func(t *testing.T) {
			config := f3Config(t, "quic", extra)
			h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
			head, tail := qa519SplitInitials(t, "f3.example", 40, qa519DCID(0x77), 1, 1)
			h.resetPhase()
			if verdict := h.send(h.lease, head, 30000); verdict != VerdictHold {
				t.Fatalf("incomplete Initial verdict = %v, want Hold", verdict)
			}
			h.resetPhase()
			verdict := h.send(h.lease, qa519Corrupt(tail), 30000)
			if verdict != VerdictPass {
				t.Fatalf("cancelled Initial verdict = %v, want Pass", verdict)
			}
			injected := len(h.injectedPayloads())
			if !explicit {
				if injected != 0 {
					t.Fatalf("cancelled Initial without permission injected = %d, want 0", injected)
				}
				return
			}
			if injected != 10 {
				t.Fatalf("cancelled Initial with permission injected = %d, want 10", injected)
			}
		})
	}
}

// TestF3FakeKnownStillExcludesUnknown pins the neighbouring rule: explicit
// desync_any_proto permission does not make a fakeknown payload apply to an
// unclassified datagram.
func TestF3FakeKnownStillExcludesUnknown(t *testing.T) {
	config := qa519CompileRule(t, `{"network":["udp"],"port":[30000],"methods":["fakeknown"],`+
		`"any_protocol":true,`+
		`"fake":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"`+f3GameHex+`"}]},`+
		`"fake_known":{"repeats":10,"payloads":[{"protocol":"unknown","hex":"`+f3GameHex+`"}]}}`, "")
	rule := config.Rules[0]
	if !rule.DesyncAnyProtocol {
		t.Fatal("fixture must carry the explicit permission")
	}
	h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
	verdict, injected, completed := f3Send(t, h, []byte(f3UnknownPayload))
	if verdict != VerdictPass {
		t.Fatalf("unknown UDP verdict = %v, want Pass", verdict)
	}
	if injected != 0 {
		t.Fatalf("fakeknown emitted %d units for an unknown payload, want 0", injected)
	}
	if completed != 1 {
		t.Fatalf("terminal original dispositions = %d, want exactly 1", completed)
	}
}

// hexOf renders bytes as lowercase hex without importing encoding/hex into
// every assertion.
func hexOf(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(data)*2)
	for _, value := range data {
		out = append(out, digits[value>>4], digits[value&0x0f])
	}
	return string(out)
}

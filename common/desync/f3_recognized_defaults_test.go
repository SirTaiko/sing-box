package desync

// F3-A2 / QA578: pinned v72.9 params.c:272-280 fills each missing recognized
// UDP fake collection with 64 zero bytes. desync.c:3198-3268 selects only that
// protocol's collection, then emits each configured item in order, with repeats.
// Unknown/GAME is not a recognized-protocol fallback. These are compile/flow
// model regressions, not native/wire acceptance.
import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func f3RecognizedDatagrams() map[string][]byte {
	wg := make([]byte, 148)
	wg[0] = 1
	dht := append([]byte("d1:ad2:id20:"), make([]byte, 20)...)
	discord := make([]byte, 74)
	discord[1], discord[3] = 1, 70
	return map[string][]byte{
		"stun":      {0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"wireguard": wg,
		"dht":       append(dht, 'e'),
		"discord":   discord,
	}
}

// Change only the source permission on full rule8, before Compile. In
// particular omitted and false are independently decoded JSON inputs.
func f3DefaultProfile(t *testing.T, profile, permission string) *Config {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(qa519ProfileDir, profile+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if err = json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	desync := source["outbounds"].([]any)[0].(map[string]any)["desync"].(map[string]any)
	rule := desync["rules"].([]any)[8].(map[string]any)
	switch permission {
	case "true":
		rule["any_protocol"] = true
	case "false":
		rule["any_protocol"] = false
	case "omitted":
		delete(rule, "any_protocol")
	default:
		t.Fatal("invalid permission")
	}
	data, err = json.Marshal(desync)
	if err != nil {
		t.Fatal(err)
	}
	config, err := Compile(enabledOption(string(data)), qa519AssetDir)
	if err != nil {
		t.Fatal(err)
	}
	if config.Rules[8].Name != "rule-8" || config.Rules[8].DesyncAnyProtocol != (permission == "true") {
		t.Fatal("wrong compiled full-profile rule8 permission")
	}
	return config
}

func TestF3RecognizedPinnedDefaultsFullProfiles(t *testing.T) {
	for _, profile := range []string{"03", "18"} {
		for _, permission := range []string{"true", "false", "omitted"} {
			for _, name := range []string{"stun", "wireguard", "dht", "discord"} {
				t.Run(profile+"/"+permission+"/"+name, func(t *testing.T) {
					config := f3DefaultProfile(t, profile, permission)
					h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:30000")
					input := f3RecognizedDatagrams()[name]
					if got := classifyUDPPayload(buildIPv4UDP(t, input, 30000)); got != protocolNames[name] {
						t.Fatalf("fixture classified %v, want %s", got, name)
					}
					// Identical captured records are not deduplicated; n4/n2
					// alone stops the burst at the fourth/second datagram.
					for n := 1; n <= 5; n++ {
						wantCount := 10
						if (profile == "03" && n >= 4) || (profile == "18" && n >= 2) {
							wantCount = 0
						}
						h.resetPhase()
						if got := h.send(h.lease, input, 30000); got != VerdictPass {
							t.Fatalf("original verdict %v", got)
						}
						payloads := h.injectedPayloads()
						if len(payloads) != wantCount {
							t.Fatalf("datagram%d recognized fake count=%d want%d DEFAULT64", n, len(payloads), wantCount)
						}
						for _, payload := range payloads {
							if !bytes.Equal(payload, make([]byte, 64)) || hashBytes(payload) != "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b" {
								t.Fatalf("recognized fake is not pinned DEFAULT64: length=%d sha256=%s", len(payload), hashBytes(payload))
							}
						}
						qa519ExpectOps(t, h.ops(), qa519Concat(qa519Repeat("F", wantCount), []string{"R:P"}))
					}
				})
			}
		}
	}
}

func TestF3RecognizedTypedOverrides(t *testing.T) {
	for _, method := range []string{"fake", "fakeknown"} {
		for _, name := range []string{"stun", "wireguard", "dht", "discord", "quic"} {
			t.Run(method+"/"+name, func(t *testing.T) {
				// Interleaved other-protocol item and duplicate same-protocol
				// items must retain configured order and multiplicity. repeats3
				// and a different port guard against a profile-specific repair.
				config := qa519CompileRule(t, `{"network":["udp"],"methods":["`+method+`"],"any_protocol":true,`+
					`"fake":{"repeats":3,"payloads":[{"protocol":"`+name+`","hex":"a1"},`+
					`{"protocol":"unknown","hex":"ee"},{"protocol":"`+name+`","hex":"a1"},`+
					`{"protocol":"`+name+`","hex":"b2"}]}}`, "")
				fake := config.Rules[0].Fake
				wantCounts := map[Protocol]int{ProtocolUnknown: 1, ProtocolQUIC: 1, ProtocolSTUN: 1, ProtocolWireGuard: 1, ProtocolDHT: 1, ProtocolDiscord: 1}
				wantCounts[protocolNames[name]] = 3
				counts := map[Protocol]int{}
				for _, p := range fake.Payloads {
					counts[p.Protocol]++
				}
				for protocol, want := range wantCounts {
					if counts[protocol] != want {
						t.Errorf("compiled %v payloads=%d want%d", protocol, counts[protocol], want)
					}
				}
				h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:31234")
				input := f3RecognizedDatagrams()[name]
				if name == "quic" {
					input = qa519CompleteInitial(t, "override.example", qa519DCID(0x73), 1, 1)
				}
				if got := h.send(h.lease, input, 31234); got != VerdictPass {
					t.Fatalf("original verdict %v", got)
				}
				want := [][]byte{{0xa1}, {0xa1}, {0xa1}, {0xa1}, {0xa1}, {0xa1}, {0xb2}, {0xb2}, {0xb2}}
				got := h.injectedPayloads()
				if len(got) != len(want) {
					t.Fatalf("custom burst=%d want%d (no extra default)", len(got), len(want))
				}
				for i := range want {
					if !bytes.Equal(got[i], want[i]) {
						t.Fatalf("custom payload%d=%x want%x", i, got[i], want[i])
					}
				}
				qa519ExpectOps(t, h.ops(), qa519Concat(qa519Repeat("F", 9), []string{"R:P"}))
				// fakeknown still excludes Unknown even with its own configured
				// payload and explicit permission.
				h.resetPhase()
				h.send(h.lease, []byte(f3UnknownPayload), 31234)
				unknownCount := 3
				if method == "fakeknown" {
					unknownCount = 0
				}
				if got := len(h.injectedPayloads()); got != unknownCount {
					t.Fatalf("Unknown count=%d want%d", got, unknownCount)
				}
				for _, p := range h.injectedPayloads() {
					if !bytes.Equal(p, []byte{0xee}) {
						t.Fatalf("Unknown fallback changed: %x", p)
					}
				}
			})
		}
	}
}

func TestF3RecognizedDefaultsRespectNetworkAndMethod(t *testing.T) {
	t.Run("tcp-only", func(t *testing.T) {
		config := qa519CompileRule(t, `{"network":["tcp"],"methods":["fake"],"fake":{"payloads":[{"protocol":"tls","hex":"010203"}]}}`, "")
		if got := config.Rules[0].Fake.Payloads; len(got) != 1 || got[0].Protocol != ProtocolTLS || !bytes.Equal(got[0].Data, []byte{1, 2, 3}) {
			t.Fatalf("TCP-only payloads changed: %+v", got)
		}
	})
	t.Run("nonfake", func(t *testing.T) {
		config := qa519CompileRule(t, `{"network":["udp"],"methods":["udplen"],"udplen":{"increment":4}}`, "")
		if config.Rules[0].Fake != nil {
			t.Fatal("nonfake stage acquired defaults")
		}
	})
}

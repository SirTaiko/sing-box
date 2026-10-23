package desync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// loadStreamExample parses one docs/examples/desync-stream document. The
// outbound envelope is decoded separately so the `desync` object itself is
// validated against the actual option type with unknown fields rejected.
func loadStreamExample(t *testing.T, name string) (*option.DirectDesyncOptions, int) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "desync-stream", name))
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Outbounds []struct {
			Type   string          `json:"type"`
			Tag    string          `json:"tag"`
			Desync json.RawMessage `json:"desync"`
		} `json:"outbounds"`
	}
	if err = json.Unmarshal(content, &document); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	desyncOutbounds := 0
	var desyncOptions *option.DirectDesyncOptions
	for _, outbound := range document.Outbounds {
		if len(outbound.Desync) == 0 {
			continue
		}
		if outbound.Type != "direct" {
			t.Fatalf("%s: desync must stay on a direct outbound, got %q", name, outbound.Type)
		}
		desyncOutbounds++
		var options option.DirectDesyncOptions
		if err = json.UnmarshalDisallowUnknownFields(outbound.Desync, &options); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		desyncOptions = &options
	}
	if desyncOutbounds != 1 || desyncOptions == nil {
		t.Fatalf("%s: desync outbounds = %d", name, desyncOutbounds)
	}
	return desyncOptions, desyncOutbounds
}

func TestDocsStreamExamplesSchema(t *testing.T) {
	streamOnly, _ := loadStreamExample(t, "stream-only.json")
	if len(streamOnly.Rules) != 0 {
		t.Fatalf("stream-only example must not contain packet rules")
	}
	if len(streamOnly.StreamRules) == 0 {
		t.Fatal("stream-only example lost its stream rules")
	}
	for _, rule := range streamOnly.StreamRules {
		methods := make(map[string]bool, len(rule.Methods))
		for _, method := range rule.Methods {
			methods[method] = true
		}
		if methods["http_tamper"] != (rule.HTTPTamper != nil) {
			t.Fatalf("%s: http_tamper object/method mismatch", rule.Name)
		}
		if methods["tls_record"] != (rule.TLSRecord != nil) {
			t.Fatalf("%s: tls_record object/method mismatch", rule.Name)
		}
		if methods["split"] != (rule.Split != nil) {
			t.Fatalf("%s: split object/method mismatch", rule.Name)
		}
	}
	streamConfig, err := CompileStream(streamOnly.StreamRules, "")
	if err != nil {
		t.Fatal(err)
	}
	if streamConfig == nil {
		t.Fatal("stream-only example did not compile to a StreamConfig")
	}
	if streamOnly.Learning == nil || streamOnly.Learning.MaxHosts != 4096 {
		t.Fatalf("stream-only example lost its common learning block: %+v", streamOnly.Learning)
	}
	var exampleLearning *ruleLearning
	for _, rule := range streamConfig.snapshotRules() {
		if rule.learning != nil {
			exampleLearning = rule.learning
		}
	}
	if exampleLearning == nil || exampleLearning.failThreshold != 3 ||
		exampleLearning.failWindow != 60*time.Second || exampleLearning.retransThreshold != 3 {
		t.Fatalf("stream rule learning was not compiled from the example: %+v", exampleLearning)
	}
	// The compiled snapshot must actually select the documented rules.
	if rule := streamConfig.selectRule(MatchFacts{Transport: TransportTCP, Port: 80, Protocol: ProtocolHTTP}); rule == nil || rule.httpTamper == nil {
		t.Fatal("stream-only example HTTP rule is not selectable")
	}
	if rule := streamConfig.selectRule(MatchFacts{Transport: TransportTCP, Port: 443, Protocol: ProtocolTLS}); rule == nil || rule.tlsRecord == nil {
		t.Fatal("stream-only example TLS rule is not selectable")
	}

	combined, _ := loadStreamExample(t, "stream-and-packet.json")
	if len(combined.Rules) == 0 || len(combined.StreamRules) == 0 {
		t.Fatalf("combined example must contain both lists: packet=%d stream=%d", len(combined.Rules), len(combined.StreamRules))
	}
	// Payload files are operator supplied and not redistributed, so only the
	// stream half is compiled here; the packet half is schema-checked above.
	combinedStream, err := CompileStream(combined.StreamRules, "")
	if err != nil {
		t.Fatal(err)
	}
	if combinedStream == nil {
		t.Fatal("combined example stream rules did not compile")
	}
	// Both lists stay separate: the stream compile must not consume packet
	// methods and the packet list must not appear in the stream snapshot.
	if rule := combinedStream.selectRule(MatchFacts{Transport: TransportTCP, Port: 80, Protocol: ProtocolHTTP, Host: "example.com", HostKnown: true}); rule == nil || rule.httpTamper == nil {
		t.Fatal("combined example HTTP stream rule is not selectable")
	}
}

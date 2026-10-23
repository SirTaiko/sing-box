package desync

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

type exampleDocument struct {
	Outbounds []struct {
		Type   string          `json:"type"`
		Tag    string          `json:"tag"`
		Desync json.RawMessage `json:"desync"`
	} `json:"outbounds"`
}

func loadExample(t *testing.T, name string) exampleDocument {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "desync", name))
	if err != nil {
		t.Fatal(err)
	}
	var document exampleDocument
	if err = json.Unmarshal(content, &document); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return document
}

func exampleDesync(t *testing.T, name string) *option.DirectDesyncOptions {
	t.Helper()
	document := loadExample(t, name)
	for _, outbound := range document.Outbounds {
		if len(outbound.Desync) == 0 {
			continue
		}
		var options option.DirectDesyncOptions
		if err := json.UnmarshalDisallowUnknownFields(outbound.Desync, &options); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return &options
	}
	t.Fatalf("%s: no desync outbound", name)
	return nil
}

func checkExampleRules(t *testing.T, name string) *option.DirectDesyncOptions {
	t.Helper()
	options := exampleDesync(t, name)
	if len(options.Rules) == 0 {
		t.Fatalf("%s: no rules", name)
	}
	for _, rule := range options.Rules {
		methods := make(map[string]bool, len(rule.Methods))
		for _, method := range rule.Methods {
			methods[method] = true
		}
		if methods["fake"] != (rule.Fake != nil) {
			t.Fatalf("%s/%s: fake object/method mismatch", name, rule.Name)
		}
		if methods["multisplit"] != (rule.MultiSplit != nil) {
			t.Fatalf("%s/%s: multisplit object/method mismatch", name, rule.Name)
		}
		if methods["multidisorder"] != (rule.MultiDisorder != nil) {
			t.Fatalf("%s/%s: multidisorder object/method mismatch", name, rule.Name)
		}
		if rule.MultiSplit != nil {
			for _, position := range rule.MultiSplit.SplitPos {
				if _, err := ParsePosition(position); err != nil {
					t.Fatalf("%s/%s: %v", name, rule.Name, err)
				}
			}
		}
		for _, value := range rule.PortRange {
			if _, err := parsePortRange(value); err != nil {
				t.Fatalf("%s/%s: %v", name, rule.Name, err)
			}
		}
		if rule.Fake != nil && len(rule.Fake.Payloads) == 0 {
			t.Fatalf("%s/%s: fake without payloads", name, rule.Name)
		}
	}
	return options
}

func TestDocsExamplesSchema(t *testing.T) {
	for _, name := range []string{"alt11.json", "alt2.json", "alt6.json", "general.json", "direct-vpn-coexistence.json", "stages.json", "d1-fidelity.json"} {
		checkExampleRules(t, name)
	}
	coexistence := loadExample(t, "direct-vpn-coexistence.json")
	if len(coexistence.Outbounds) < 3 {
		t.Fatal("coexistence example must contain desync direct, vpn and plain direct outbounds")
	}
	desyncOutbounds, vpnOutbounds, plainDirect := 0, 0, 0
	for _, outbound := range coexistence.Outbounds {
		switch {
		case len(outbound.Desync) != 0:
			desyncOutbounds++
		case outbound.Type == "socks":
			vpnOutbounds++
		case outbound.Type == "direct":
			plainDirect++
		}
	}
	if desyncOutbounds != 1 || vpnOutbounds != 1 || plainDirect != 1 {
		t.Fatalf("coexistence outbounds: desync=%d vpn=%d direct=%d", desyncOutbounds, vpnOutbounds, plainDirect)
	}
}

func TestDocsExamplesMatchReferencePresets(t *testing.T) {
	alt11 := checkExampleRules(t, "alt11.json")
	var zeroIPID, gameTCP, gameUDP bool
	for _, rule := range alt11.Rules {
		if rule.IPID == "zero" {
			zeroIPID = true
		}
		if rule.Name == "game-tcp" {
			gameTCP = rule.Cutoff == "n4" && rule.AnyProtocol
		}
		if rule.Name == "game-udp" {
			gameUDP = rule.Cutoff == "n4" && rule.AnyProtocol
		}
	}
	if !zeroIPID || !gameTCP || !gameUDP {
		t.Fatalf("ALT11 expansion incomplete: zeroIPID=%v gameTCP=%v gameUDP=%v", zeroIPID, gameTCP, gameUDP)
	}
	for _, testCase := range []struct {
		name string
		seq  int
	}{
		{"alt2.json", 652},
		{"alt6.json", 681},
		{"general.json", 568},
	} {
		options := checkExampleRules(t, testCase.name)
		matched := false
		for _, rule := range options.Rules {
			if rule.MultiSplit != nil && rule.MultiSplit.SeqOverlap != nil &&
				rule.MultiSplit.SeqOverlap.Bytes != nil && *rule.MultiSplit.SeqOverlap.Bytes == testCase.seq {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("%s: expected seqovl %d", testCase.name, testCase.seq)
		}
	}
}

package desync

// Packet + stream + revision consistency across one transactional reload.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestD5PacketStreamReloadShareOneGeneration(t *testing.T) {
	root := t.TempDir()
	buildLocalBundle(t, root, map[string]string{"hosts": "first.example\n"})
	manifestPath := filepath.Join(root, "current.json")
	packetOptions := enabledOption(`{"enabled":true,"rules":[` + bundleRuleJSON(manifestPath, []string{"hosts"}, nil, nil, nil) + `]}`)
	state := NewListBuildState()
	config, err := CompileWithState(packetOptions, "", state)
	if err != nil {
		t.Fatal(err)
	}
	streamRules := []option.DirectDesyncStreamRule{{
		DirectDesyncStreamMatch: option.DirectDesyncStreamMatch{
			ListBundle: &option.DirectDesyncListBundle{Manifest: manifestPath, Domain: []string{"hosts"}},
		},
		Methods: []string{"split"},
		Split:   &option.DirectDesyncStreamSplit{SplitPos: []string{"1"}},
	}}
	streamConfig, err := CompileStreamWithState(streamRules, "", state)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err = streamConfig.AttachEngine(engine); err != nil {
		t.Fatal(err)
	}
	if engine.BundleGenerations() == nil {
		t.Fatal("initial packet generation was not published")
	}
	buildLocalBundle(t, root, map[string]string{"hosts": "second.example\n"})
	changed, reloadErr := engine.ReloadListsContext(context.Background())
	if reloadErr != nil || !changed {
		t.Fatalf("reload: changed=%v err=%v", changed, reloadErr)
	}
	if engine.ListRevision() != 2 {
		t.Fatalf("one reload of packet+stream must increment the revision once, got %d", engine.ListRevision())
	}
	if !engine.Config().Rules[0].Domains.matches("second.example") {
		t.Fatal("packet rules were not reloaded")
	}
	streamRulesNow := engine.stream.snapshotRules()
	if len(streamRulesNow) != 1 || !streamRulesNow[0].match.Domains.matches("second.example") {
		t.Fatal("stream rules were not reloaded from the same generation")
	}
	if len(engine.BundleGenerations()) != 1 {
		t.Fatalf("unexpected bundle generations after reload: %v", engine.BundleGenerations())
	}
}

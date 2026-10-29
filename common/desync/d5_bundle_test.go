package desync

// D5 integration tests: one immutable provider bundle generation, one read of
// current.json per canonical root and per compile/reload, the shared selection
// budget, transactional reload of packet + stream + learned state, revision
// semantics and bounded legacy reads.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/desync/tools"
	"github.com/sagernet/sing-box/option"
)

// buildLocalBundle publishes one generation through the accepted explicit
// local acquisition path (no HTTP, no DNS).
func buildLocalBundle(t *testing.T, root string, datasets map[string]string) string {
	t.Helper()
	snapshots := make([]map[string]string, 0, len(datasets))
	for id, content := range datasets {
		path := filepath.Join(t.TempDir(), id+".txt")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		snapshots = append(snapshots, map[string]string{"dataset": id, "path": path})
	}
	requestJSON, err := json.Marshal(map[string]any{
		"format":      tools.ListRefreshRequestFormat,
		"provider":    "local",
		"acquisition": "local",
		"families":    []int{4},
		"snapshots":   snapshots,
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := tools.DecodeListRefreshRequest(requestJSON)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := tools.RefreshLists(context.Background(), request, root, tools.ProviderDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Committed {
		t.Fatal("local bundle was not committed")
	}
	return receipt.Generation
}

func bundleRuleJSON(manifestPath string, domain, domainExclude, ip, ipExclude []string) string {
	selector := map[string]any{"manifest": manifestPath}
	if len(domain) > 0 {
		selector["domain"] = domain
	}
	if len(domainExclude) > 0 {
		selector["domain_exclude"] = domainExclude
	}
	if len(ip) > 0 {
		selector["ip_cidr"] = ip
	}
	if len(ipExclude) > 0 {
		selector["ip_cidr_exclude"] = ipExclude
	}
	selectorJSON, _ := json.Marshal(selector)
	return `{"network":["tcp"],"methods":["multisplit"],"multisplit":{"split_pos":["1"]},"list_bundle":` + string(selectorJSON) + `}`
}

func TestD5BundleSharedStateReadsManifestOnce(t *testing.T) {
	root := t.TempDir()
	generation := buildLocalBundle(t, root, map[string]string{
		"hosts": "Example.COM.\nsub.example.org\n",
		"ip4":   "192.0.2.0/24\n",
	})
	manifestPath := filepath.Join(root, "current.json")
	options := enabledOption(`{"enabled":true,"rules":[` + bundleRuleJSON(manifestPath, []string{"hosts"}, nil, []string{"ip4"}, nil) + `]}`)
	state := NewListBuildState()
	config, err := CompileWithState(options, "", state)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Rules) != 1 {
		t.Fatalf("unexpected rule count %d", len(config.Rules))
	}
	rule := config.Rules[0]
	if !rule.Domains.matches("sub.example.org") || !rule.Domains.matches("example.com") {
		t.Fatal("bundle domain dataset was not applied")
	}
	if !rule.IPs.contains(netip.MustParseAddr("192.0.2.55")) {
		t.Fatal("bundle IP dataset was not applied")
	}
	if !rule.domainRestrict || !rule.IPs.restricts() {
		t.Fatal("nonempty bundle positives must compile into active restrictions")
	}
	if got := state.BundleGenerations(); len(got) != 1 || got[0] != generation {
		t.Fatalf("unexpected generations %v (want %s)", got, generation)
	}
	// The manifest value is pinned by the build state: moving current.json away
	// must not affect a second compiler using the same state, while a fresh
	// state fails.
	if err = os.Rename(manifestPath, manifestPath+".moved"); err != nil {
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
		t.Fatalf("stream compile must reuse the pinned manifest: %v", err)
	}
	if streamConfig == nil || len(streamConfig.rules) != 1 || !streamConfig.rules[0].match.Domains.matches("sub.example.org") {
		t.Fatal("stream match did not use the shared bundle generation")
	}
	if _, err = CompileWithState(options, "", NewListBuildState()); err == nil {
		t.Fatal("a fresh state must read current.json again and fail while it is absent")
	}
}

func TestD5BundleNegativePrecedenceAndEmptyPositive(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "current.json")
	canonical, err := filepath.Abs(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	generation := strings.Repeat("a", 32)
	state := newListBuildState()
	state.manifests[canonical] = &listBundleView{root: directory, manifest: tools.ListBundleManifest{
		Format:     tools.ListBundleFormat,
		Generation: generation,
		Datasets: []tools.ListBundleDataset{
			{ID: "hosts", Kind: tools.ListKindDomain, Entries: 1},
			{ID: "user_hosts", Kind: tools.ListKindDomain, Entries: 1},
			{ID: "exclude_hosts", Kind: tools.ListKindDomain, Entries: 2},
			{ID: "ip4", Kind: tools.ListKindIP, Family: 4, Entries: 1},
			{ID: "ip6", Kind: tools.ListKindIP, Family: 6, Entries: 1},
		},
	}}
	rule := &Rule{IPv4: true, IPv6: true}
	// A provisioned nonempty exclusion dataset relevant to a selected positive
	// must be selected too; silently dropping it would re-include excluded data.
	if _, err = state.resolveSelection(&option.DirectDesyncListBundle{Manifest: manifestPath, Domain: []string{"hosts"}}, "", rule); err == nil {
		t.Fatal("missing exclude selection must fail the compile")
	}
	if _, err = state.resolveSelection(&option.DirectDesyncListBundle{Manifest: manifestPath, Domain: []string{"hosts"}, DomainExclude: []string{"exclude_hosts"}}, "", rule); err != nil {
		t.Fatalf("selected exclusion dataset rejected: %v", err)
	}
	// Kind and family compatibility.
	if _, err = state.resolveSelection(&option.DirectDesyncListBundle{Manifest: manifestPath, Domain: []string{"ip4"}}, "", rule); err == nil {
		t.Fatal("domain selector accepted an IP dataset")
	}
	if _, err = state.resolveSelection(&option.DirectDesyncListBundle{Manifest: manifestPath, IPCIDR: []string{"ip6"}}, "", &Rule{IPv4: true}); err == nil {
		t.Fatal("IPv6 dataset accepted for an IPv4-only rule")
	}
	// Duplicate selection and empty selection.
	if _, err = state.resolveSelection(&option.DirectDesyncListBundle{Manifest: manifestPath, Domain: []string{"hosts"}, IPCIDR: []string{"hosts"}}, "", rule); err == nil {
		t.Fatal("duplicate dataset id accepted")
	}
	if _, err = state.resolveSelection(&option.DirectDesyncListBundle{Manifest: manifestPath}, "", rule); err == nil {
		t.Fatal("empty selector accepted")
	}
	// An explicitly selected but empty positive dataset is still a restriction.
	emptyRoot := t.TempDir()
	buildLocalBundle(t, emptyRoot, map[string]string{"hosts": ""})
	emptyManifest := filepath.Join(emptyRoot, "current.json")
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[`+bundleRuleJSON(emptyManifest, []string{"hosts"}, nil, nil, nil)+`]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if !config.Rules[0].domainRestrict || !config.Rules[0].Domains.empty() {
		t.Fatal("an explicitly selected empty dataset must match nothing, not everything")
	}
}

func TestD5ReloadRetainsLastGoodAndTracksRevision(t *testing.T) {
	root := t.TempDir()
	buildLocalBundle(t, root, map[string]string{"hosts": "first.example\n"})
	manifestPath := filepath.Join(root, "current.json")
	options := enabledOption(`{"enabled":true,"rules":[` + bundleRuleJSON(manifestPath, []string{"hosts"}, nil, nil, nil) + `]}`)
	config, err := Compile(options, "")
	if err != nil {
		t.Fatal(err)
	}
	config.Capture = captureConfig{qnum: 42, qnumSet: true}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if engine.ListRevision() != 1 {
		t.Fatalf("initial revision %d, want 1", engine.ListRevision())
	}
	if !engine.Config().Capture.qnumSet || engine.Config().Capture.qnum != 42 {
		t.Fatal("test capture was not compiled")
	}
	// Tamper with the referenced shard: the hash check must fail before any
	// publication, keeping the last-good snapshot and revision.
	var shardPath string
	manifest, err := readManifestForTest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, dataset := range manifest.Datasets {
		if dataset.ID == "hosts" {
			shardPath = filepath.Join(root, "generations", manifest.Generation, dataset.Files[0].Name)
		}
	}
	if shardPath == "" {
		t.Fatal("hosts shard not found")
	}
	original, err := os.ReadFile(shardPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(shardPath, append(original, []byte("tampered.example\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = engine.ReloadLists(); err == nil {
		t.Fatal("tampered generation must fail the reload")
	}
	if engine.ListRevision() != 1 {
		t.Fatalf("failed reload changed the revision to %d", engine.ListRevision())
	}
	if still := engine.Config(); still.Rules[0].Domains.matches("tampered.example") {
		t.Fatal("failed reload published tampered entries")
	}
	if !engine.Config().Capture.qnumSet || engine.Config().Capture.qnum != 42 {
		t.Fatal("failed reload changed the capture configuration")
	}
	// Restore the shard and publish a new generation; one reload publishes the
	// new selection and increments the revision exactly once.
	if err = os.WriteFile(shardPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	buildLocalBundle(t, root, map[string]string{"hosts": "second.example\n"})
	if changed, reloadErr := engine.ReloadListsContext(context.Background()); reloadErr != nil || !changed {
		t.Fatalf("changed reload: changed=%v err=%v", changed, reloadErr)
	}
	if engine.ListRevision() != 2 {
		t.Fatalf("revision after one changed publication: %d", engine.ListRevision())
	}
	if !engine.Config().Rules[0].Domains.matches("second.example") {
		t.Fatal("new selection was not published")
	}
	if changed, reloadErr := engine.ReloadListsContext(context.Background()); reloadErr != nil || changed {
		t.Fatalf("repeat reload of the same bytes must not change the revision: %v %v", changed, reloadErr)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, cancelErr := engine.ReloadListsContext(cancelled); cancelErr == nil {
		t.Fatal("cancelled reload must not succeed")
	}
}

func TestD5ReloadBusyAndClosed(t *testing.T) {
	root := t.TempDir()
	buildLocalBundle(t, root, map[string]string{"hosts": "example.com\n"})
	options := enabledOption(`{"enabled":true,"rules":[` + bundleRuleJSON(filepath.Join(root, "current.json"), []string{"hosts"}, nil, nil, nil) + `]}`)
	config, err := Compile(options, "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	engine.reloadMu.Lock()
	if _, err = engine.ReloadListsContext(context.Background()); err != ErrReloadBusy {
		t.Fatalf("concurrent reload must report busy, got %v", err)
	}
	engine.reloadMu.Unlock()
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ReloadListsContext(context.Background()); err == nil {
		t.Fatal("closed engine must reject reload")
	}
}

func TestD5LegacyListBoundBeforeAllocation(t *testing.T) {
	directory := t.TempDir()
	oversized := filepath.Join(directory, "big.txt")
	file, err := os.Create(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(maxListFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	options := enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"methods":["multisplit"],"multisplit":{"split_pos":["1"]},"domain_file":[` + fmt.Sprintf("%q", oversized) + `]}]}`)
	if _, err = Compile(options, ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized legacy list must be rejected before allocation: %v", err)
	}
}

func readManifestForTest(path string) (tools.ListBundleManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tools.ListBundleManifest{}, err
	}
	return tools.DecodeListBundleManifest(data)
}

// d5MockResolver resolves every name to one documentation address so the user
// recipe exercises its exact local DNS phase without touching DNS.
type d5MockResolver struct{}

func (d5MockResolver) Lookup(context.Context, string, tools.Family) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
}

// buildUserBundle publishes a generation with both a positive user host
// dataset and a nonempty exclusion dataset, using the local acquisition path
// with an injected resolver (no HTTP, no real DNS).
func buildUserBundle(t *testing.T, root string, userHosts string, excludeHosts string) {
	t.Helper()
	directory := t.TempDir()
	userPath := filepath.Join(directory, "user_hosts.txt")
	excludePath := filepath.Join(directory, "exclude_hosts.txt")
	if err := os.WriteFile(userPath, []byte(userHosts), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excludePath, []byte(excludeHosts), 0o600); err != nil {
		t.Fatal(err)
	}
	requestJSON, err := json.Marshal(map[string]any{
		"format":      tools.ListRefreshRequestFormat,
		"provider":    "user",
		"acquisition": "local",
		"families":    []int{4},
		"inputs": map[string]any{
			"user_hosts":    []string{userPath},
			"exclude_hosts": []string{excludePath},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := tools.DecodeListRefreshRequest(requestJSON)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := tools.RefreshLists(context.Background(), request, root, tools.ProviderDependencies{Resolver: d5MockResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Committed {
		t.Fatal("user bundle was not committed")
	}
}

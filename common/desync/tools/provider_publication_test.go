package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Publication fault controls, reader concurrency, ledger coverage and the
// remaining recipe variants of the D5 helper lane.

func TestRefreshFaultInjectionKeepsCommitPoint(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatal(err)
	}
	baseline, baselineBytes, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"write-shard", "seal-manifest", "sync-generation", "publish-temp"} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			bundleFaultHook = func(current string) error {
				if current == stage {
					return errors.New("injected failure at " + stage)
				}
				return nil
			}
			defer func() { bundleFaultHook = nil }()
			_, refreshErr := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{}))
			if refreshErr == nil {
				t.Fatalf("stage %s must fail the refresh", stage)
			}
			manifest, manifestBytes, readErr := readCurrentManifest(root)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if manifest.Generation != baseline.Generation || !bytes.Equal(manifestBytes, baselineBytes) {
				t.Fatalf("stage %s changed current.json before the commit point", stage)
			}
			entries, readErr := os.ReadDir(filepath.Join(root, listBundleGenerations))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(entries) != 1 {
				t.Fatalf("stage %s left a staged generation behind: %d", stage, len(entries))
			}
		})
	}
	t.Run("post-replace", func(t *testing.T) {
		bundleFaultHook = func(stage string) error {
			if stage == "post-replace" {
				return errors.New("injected post-commit failure")
			}
			return nil
		}
		defer func() { bundleFaultHook = nil }()
		receipt, refreshErr := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{}))
		if refreshErr != nil {
			t.Fatalf("a post-commit failure must still report the commit: %v", refreshErr)
		}
		if !receipt.Committed || receipt.Generation == baseline.Generation {
			t.Fatalf("unexpected receipt after a post-commit failure: %+v", receipt)
		}
		if len(receipt.Warnings) != 1 || receipt.Warnings[0] != "directory_sync_failed" {
			t.Fatalf("durability uncertainty must be reported: %+v", receipt.Warnings)
		}
		manifest, _, readErr := readCurrentManifest(root)
		if readErr != nil || manifest.Generation != receipt.Generation {
			t.Fatalf("published generation must be current: %v %v", manifest.Generation, readErr)
		}
	})
}

func TestRefreshReadersNeverSeeMixedGeneration(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var failures atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 4; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for !stop.Load() {
				manifest, _, err := readCurrentManifest(root)
				if err != nil {
					failures.Add(1)
					return
				}
				if err = VerifyListBundle(root, manifest); err != nil {
					failures.Add(1)
					return
				}
				if _, err = ReadListBundleDataset(root, manifest, "ip4"); err != nil {
					failures.Add(1)
					return
				}
			}
		}()
	}
	for index := 0; index < 3; index++ {
		if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
			stop.Store(true)
			wait.Wait()
			t.Fatalf("concurrent refresh: %v", err)
		}
	}
	stop.Store(true)
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("readers observed an inconsistent generation: %d", failures.Load())
	}
}

func TestRefreshLocalAndEmptyRecipes(t *testing.T) {
	empty := baseRemoteRequest(t)
	empty.Provider = ProviderEmpty
	empty.Acquisition = AcquisitionLocal
	empty.Inputs = RefreshInputs{}
	empty.Families = []int{4, 6}
	emptyRoot := t.TempDir()
	receipt, err := RefreshLists(context.Background(), empty, emptyRoot, testDependencies(&mockHTTPClient{onRequest: func(*http.Request) (*http.Response, error) {
		t.Error("empty provider must not use HTTP")
		return nil, errors.New("no")
	}}, &mockResolver{}))
	if err != nil {
		t.Fatalf("empty refresh: %v", err)
	}
	manifest, _, err := readCurrentManifest(emptyRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Sources) != 0 {
		t.Fatalf("empty generation must not declare sources: %+v", manifest.Sources)
	}
	for _, dataset := range manifest.Datasets {
		if dataset.Origin != listBundleOriginDisabled || dataset.Entries != 0 {
			t.Fatalf("empty dataset %s must be disabled and empty: %+v", dataset.ID, dataset)
		}
	}
	if !receipt.Committed {
		t.Fatal("empty refresh must commit")
	}
	// The local import extension uses typed snapshots only, without DNS.
	local := baseRemoteRequest(t)
	local.Provider = ProviderLocal
	local.Acquisition = AcquisitionLocal
	local.Families = []int{4}
	local.Snapshots = []RefreshSnapshot{
		{Dataset: "hosts", Path: filepath.Join("testdata", "provider-refresh", "user_hosts.txt")},
		{Dataset: "ip4", Path: filepath.Join("testdata", "provider-refresh", "reestr_resolved4.txt")},
	}
	localRoot := t.TempDir()
	if _, err = RefreshLists(context.Background(), local, localRoot, testDependencies(&mockHTTPClient{onRequest: func(*http.Request) (*http.Response, error) {
		t.Error("local provider must not use HTTP")
		return nil, errors.New("no")
	}}, nil)); err != nil {
		t.Fatalf("local import must work without a resolver: %v", err)
	}
	localManifest, _, err := readCurrentManifest(localRoot)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := ReadListBundleDataset(localRoot, localManifest, "hosts")
	if err != nil || len(hosts) != 120 {
		t.Fatalf("local hosts dataset: %d %v", len(hosts), err)
	}
	ip4, err := ReadListBundleDataset(localRoot, localManifest, "ip4")
	if err != nil || len(ip4) != 600 {
		t.Fatalf("local ip4 dataset: %d %v", len(ip4), err)
	}
	if hosts[0] != "user-001.example.org" {
		t.Fatalf("local domain normalization mismatch: %s", hosts[0])
	}
	// A provider recipe cannot be imported as `user`, and `user` rejects
	// provider snapshots.
	invalid := baseRemoteRequest(t)
	invalid.Provider = ProviderUser
	invalid.Acquisition = AcquisitionLocal
	invalid.Families = []int{4}
	invalid.Inputs = RefreshInputs{}
	invalid.Snapshots = []RefreshSnapshot{{Dataset: "ip4", Path: filepath.Join("testdata", "provider-refresh", "reestr_resolved4.txt")}}
	if _, err = RefreshLists(context.Background(), invalid, t.TempDir(), testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("user provider must reject provider snapshots")
	}
}

func TestRefreshGuardsPerSourceAndTotalBytes(t *testing.T) {
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	request.Limits.MaxDecodedBytes = 1024
	if _, err := RefreshLists(context.Background(), request, t.TempDir(), testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("per-source decoded limit must fail the refresh")
	}
	request = baseRemoteRequest(t)
	request.Families = []int{4, 6}
	request.Limits.MaxTotalBytes = 6000
	if _, err := RefreshLists(context.Background(), request, t.TempDir(), testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("total decoded source limit must fail the refresh")
	}
	request = baseRemoteRequest(t)
	request.Families = []int{4}
	request.Limits.MaxTotalBytes = 6000
	if _, err := RefreshLists(context.Background(), request, t.TempDir(), testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatalf("a single source below the total limit must pass: %v", err)
	}
}

func TestRefreshAntizapretRequiresGzipAndDecodedMinimum(t *testing.T) {
	var domains strings.Builder
	for index := 0; index < 4000; index++ {
		domains.WriteString("antizapret-domain-")
		domains.WriteString(itoa(index))
		domains.WriteString(".example.org\n")
	}
	decoded := []byte(domains.String())
	if len(decoded) < 102400 {
		t.Fatalf("fixture must exceed the decoded minimum: %d", len(decoded))
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(decoded); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := baseRemoteRequest(t)
	request.Provider = ProviderAntizapretDomains
	request.Families = []int{4}
	request.Inputs = RefreshInputs{}
	gzipClient := &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		header := make(http.Header)
		header.Set("Content-Encoding", "gzip")
		return newResponse(request, http.StatusOK, compressed.Bytes(), header), nil
	}}
	root := t.TempDir()
	receipt, err := RefreshLists(context.Background(), request, root, testDependencies(gzipClient, &mockResolver{}))
	if err != nil {
		t.Fatalf("antizapret gzip refresh: %v", err)
	}
	manifest, _, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Sources[0].Compression != CompressionGzip || manifest.Sources[0].DecompressedSize != int64(len(decoded)) {
		t.Fatalf("gzip provenance mismatch: %+v", manifest.Sources[0])
	}
	if !receipt.Committed {
		t.Fatal("antizapret refresh must commit")
	}
	// A plain body is rejected because the source requires gzip.
	plainClient := &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		return newResponse(request, http.StatusOK, decoded, nil), nil
	}}
	if _, err = RefreshLists(context.Background(), request, t.TempDir(), testDependencies(plainClient, &mockResolver{})); err == nil {
		t.Fatal("antizapret must require gzip")
	}
	// A gzip body below the decoded minimum is rejected.
	small := bytes.Repeat([]byte("a.example.org\n"), 100)
	var smallCompressed bytes.Buffer
	smallWriter := gzip.NewWriter(&smallCompressed)
	if _, err = smallWriter.Write(small); err != nil {
		t.Fatal(err)
	}
	if err = smallWriter.Close(); err != nil {
		t.Fatal(err)
	}
	smallClient := &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		return newResponse(request, http.StatusOK, smallCompressed.Bytes(), nil), nil
	}}
	if _, err = RefreshLists(context.Background(), request, t.TempDir(), testDependencies(smallClient, &mockResolver{})); err == nil {
		t.Fatal("antizapret decoded minimum must be enforced")
	}
}

func TestRefreshAntifilterCutLocalAndAggregation(t *testing.T) {
	body := strings.Builder{}
	for index := 0; index < 9000; index++ {
		body.WriteString("198.51.")
		body.WriteString(itoa(index / 256))
		body.WriteString(".")
		body.WriteString(itoa(index % 256))
		body.WriteString("\n")
	}
	// Private and loopback entries must be removed by cut_local; 172.16 must stay.
	body.WriteString("10.1.2.3\n127.0.0.1\n192.168.5.5\n172.16.9.9\n")
	request := baseRemoteRequest(t)
	request.Provider = ProviderAntifilterIP
	request.Families = []int{4}
	request.Inputs = RefreshInputs{}
	client := &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Accept-Encoding") != "" {
			t.Error("AntiFilter must use the plain source fetch")
		}
		return newResponse(request, http.StatusOK, []byte(body.String()), nil), nil
	}}
	root := t.TempDir()
	receipt, err := RefreshLists(context.Background(), request, root, testDependencies(client, &mockResolver{}))
	if err != nil {
		t.Fatalf("antifilter refresh: %v", err)
	}
	manifest, _, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	ip4, err := ReadListBundleDataset(root, manifest, "ip4")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range ip4 {
		if strings.HasPrefix(entry, "10.") || strings.HasPrefix(entry, "127.") || strings.HasPrefix(entry, "192.168.") {
			t.Fatalf("cut_local entry survived: %s", entry)
		}
	}
	found172 := false
	for _, entry := range ip4 {
		if strings.HasPrefix(entry, "172.16.9.9") {
			found172 = true
		}
	}
	if !found172 {
		t.Fatal("172.16/12 must not be cut")
	}
	if manifest.Resolution.Aggregation == nil || len(manifest.Resolution.Aggregation.Families) != 1 {
		t.Fatalf("antifilter aggregation must be recorded: %+v", manifest.Resolution.Aggregation)
	}
	if !receipt.Committed {
		t.Fatal("antifilter refresh must commit")
	}
}

func TestListBundleTamperingIsDetected(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatal(err)
	}
	manifest, _, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := generationPath(root, manifest.Generation)
	if err != nil {
		t.Fatal(err)
	}
	shard := filepath.Join(directory, manifest.Datasets[1].Files[0].Name)
	data, err := os.ReadFile(shard)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("shard must not be empty")
	}
	data[0] ^= 0xff
	if err = os.WriteFile(shard, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = VerifyListBundle(root, manifest); err == nil {
		t.Fatal("tampered shard must fail verification")
	}
	if _, err = ReadListBundleDataset(root, manifest, "ip4"); err == nil {
		t.Fatal("tampered shard must not be loaded")
	}
}

func TestProviderMappingLedgerCoverage(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "provider-refresh", "d5-mapping.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ledger struct {
		Format  string `json:"format"`
		Version string `json:"version"`
		Ipset   []struct {
			Path   string   `json:"path"`
			Recipe *string  `json:"recipe"`
			Owner  string   `json:"owner"`
			Tests  []string `json:"tests"`
		} `json:"ipset_files"`
		ConfigRows []struct {
			Variable string `json:"variable"`
			Source   string `json:"source"`
			Owner    string `json:"owner"`
			Mapping  string `json:"mapping"`
		} `json:"config_default_rows"`
	}
	if err = json.Unmarshal(data, &ledger); err != nil {
		t.Fatal(err)
	}
	if ledger.Format != "direct-desync.d5-mapping/v1" || ledger.Version != "direct-desync/d5-contract/v1.0" {
		t.Fatalf("unexpected ledger header: %s %s", ledger.Format, ledger.Version)
	}
	if len(ledger.Ipset) != 20 {
		t.Fatalf("expected 20 pinned ipset files, got %d", len(ledger.Ipset))
	}
	for _, file := range ledger.Ipset {
		if !strings.HasPrefix(file.Path, "ipset/") {
			t.Fatalf("ledger path escapes the pinned tree: %s", file.Path)
		}
		switch file.Owner {
		case "helper", "core", "external_deployment":
		default:
			t.Fatalf("unknown owner %q for %s", file.Owner, file.Path)
		}
		if len(file.Tests) == 0 {
			t.Fatalf("ledger entry %s has no evidence class", file.Path)
		}
		if file.Recipe == nil {
			continue
		}
		recipe, lookupErr := LookupProviderRecipe(*file.Recipe)
		if lookupErr != nil {
			t.Fatalf("ledger recipe %s is not implemented: %v", *file.Recipe, lookupErr)
		}
		script := filepath.Base(file.Path)
		if recipe.Script == script || recipe.ID == *file.Recipe {
			continue
		}
		t.Fatalf("recipe %s does not reference %s", *file.Recipe, script)
	}
	if len(ledger.ConfigRows) != 9 {
		t.Fatalf("expected 9 D5 config rows, got %d", len(ledger.ConfigRows))
	}
	rows := make(map[string]string, len(ledger.ConfigRows))
	for _, row := range ledger.ConfigRows {
		rows[row.Variable] = row.Mapping
	}
	for _, variable := range []string{
		"SET_MAXELEM", "IPSET_OPT", "IPSET_HOOK", "IP2NET_OPT4", "IP2NET_OPT6",
		"MDIG_THREADS", "GZIP_LISTS", "LISTS_RELOAD", "GETLIST",
	} {
		if _, present := rows[variable]; !present {
			t.Fatalf("config row %s is missing from the ledger", variable)
		}
	}
	// Every recipe ID in the enum, plus the local extension, must be present in
	// the ledger or implemented by the shared recipe table.
	for _, id := range ProviderRecipeIDs() {
		if _, err = LookupProviderRecipe(id); err != nil {
			t.Fatalf("recipe %s is not implemented", id)
		}
	}
	if len(providerRecipes) != 16 {
		t.Fatalf("unexpected recipe count: %d", len(providerRecipes))
	}
	// The default request limits must translate the documented config values.
	if defaults := DefaultListRefreshRequest(); defaults.Limits.MaxEntries != 522288 {
		t.Fatalf("SET_MAXELEM mapping changed: %d", defaults.Limits.MaxEntries)
	}
	if defaults := DefaultListRefreshRequest(); defaults.Resolve.Threads != 30 {
		t.Fatalf("MDIG_THREADS mapping changed: %d", defaults.Resolve.Threads)
	}
	if defaults := DefaultListRefreshRequest(); defaults.Compression != CompressionGzip {
		t.Fatalf("GZIP_LISTS mapping changed: %s", defaults.Compression)
	}
}

var _ = netip.MustParseAddr

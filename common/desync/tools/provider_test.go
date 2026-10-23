package tools

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mockClock struct {
	now time.Time
}

func (c *mockClock) Now() time.Time { return c.now }

func (c *mockClock) Sleep(ctx context.Context, _ time.Duration) error {
	return ctx.Err()
}

type mockResolver struct {
	addresses map[string]map[Family][]netip.Addr
	temporary map[string]bool
	calls     int32
}

func (r *mockResolver) Lookup(_ context.Context, name string, family Family) ([]netip.Addr, error) {
	atomic.AddInt32(&r.calls, 1)
	if r.temporary[name] {
		return nil, errors.New(ErrTemporary.Error())
	}
	if byFamily, ok := r.addresses[name]; ok {
		return byFamily[family], nil
	}
	return nil, errors.New("permanent negative")
}

type mockHTTPClient struct {
	onRequest   func(*http.Request) (*http.Response, error)
	calls       int32
	inFlight    int32
	maxInFlight int32
}

func (c *mockHTTPClient) Do(request *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.calls, 1)
	current := atomic.AddInt32(&c.inFlight, 1)
	for {
		maximum := atomic.LoadInt32(&c.maxInFlight)
		if current <= maximum || atomic.CompareAndSwapInt32(&c.maxInFlight, maximum, current) {
			break
		}
	}
	defer atomic.AddInt32(&c.inFlight, -1)
	return c.onRequest(request)
}

func mustReadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "provider-refresh", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newResponse(request *http.Request, status int, body []byte, header http.Header) *http.Response {
	if header == nil {
		header = make(http.Header)
	}
	return &http.Response{
		StatusCode:    status,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

func remoteHTTP(t *testing.T) *mockHTTPClient {
	t.Helper()
	return &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Errorf("unexpected method %s", request.Method)
		}
		if request.URL.Scheme != "https" {
			t.Errorf("unexpected scheme %s", request.URL.Scheme)
		}
		switch {
		case strings.HasSuffix(request.URL.Path, "/reestr_resolved4.txt"):
			if request.Header.Get("Accept-Encoding") != "gzip" {
				t.Errorf("missing gzip accept encoding")
			}
			return newResponse(request, http.StatusOK, mustReadFixture(t, "reestr_resolved4.txt"), nil), nil
		case strings.HasSuffix(request.URL.Path, "/reestr_resolved6.txt"):
			return newResponse(request, http.StatusOK, mustReadFixture(t, "reestr_resolved6.txt"), nil), nil
		}
		return newResponse(request, http.StatusNotFound, nil, nil), nil
	}}
}

func testDependencies(httpClient ProviderHTTPClient, resolver MDigResolver) ProviderDependencies {
	return ProviderDependencies{
		HTTP:     httpClient,
		Resolver: resolver,
		Clock:    &mockClock{now: time.Now()},
	}
}

func baseRemoteRequest(t *testing.T) ListRefreshRequest {
	t.Helper()
	request := DefaultListRefreshRequest()
	request.Inputs = RefreshInputs{}
	request.Snapshots = []RefreshSnapshot{}
	return request
}

func TestProviderRecipeTable(t *testing.T) {
	ids := ProviderRecipeIDs()
	if len(ids) != 16 {
		t.Fatalf("expected 16 recipes, got %d", len(ids))
	}
	for _, id := range ids {
		recipe, err := LookupProviderRecipe(id)
		if err != nil {
			t.Fatalf("recipe %s: %v", id, err)
		}
		if recipe.ID != id {
			t.Fatalf("recipe %s reports id %s", id, recipe.ID)
		}
		if !recipe.LocalOnly && len(recipe.Sources) == 0 {
			t.Fatalf("remote recipe %s has no source", id)
		}
		for _, source := range recipe.Sources {
			if !strings.HasPrefix(source.URL, "https://") {
				t.Fatalf("recipe %s source is not https", id)
			}
		}
	}
	antismart, _ := LookupProviderRecipe(ProviderAntifilterIPSmart)
	if antismart.Sources[0].URL != "https://antifilter.network/download/ipsmart.lst" {
		t.Fatalf("antifilter-ipsmart must use antifilter.network: %s", antismart.Sources[0].URL)
	}
	antizapret, _ := LookupProviderRecipe(ProviderAntizapretDomains)
	if !antizapret.Sources[0].RequireGzip {
		t.Fatal("antizapret must require gzip")
	}
	if antizapret.Sources[0].MaximumBytes != 251658240 {
		t.Fatalf("antizapret raw maximum mismatch: %d", antizapret.Sources[0].MaximumBytes)
	}
	reestr, _ := LookupProviderRecipe(ProviderReestrPreresolved)
	if reestr.Sources[0].MinimumBytes != 4096 || reestr.Sources[1].MinimumBytes != 2048 {
		t.Fatalf("reestr minimum sizes mismatch")
	}
	if reestr.Sources[0].Attempts != 5 || reestr.Sources[0].AttemptTimeout != 120*time.Second {
		t.Fatalf("reestr attempt budget mismatch")
	}
	antifilter, _ := LookupProviderRecipe(ProviderAntifilterIP)
	if !antifilter.AggregatesIPv4 || antifilter.Sources[0].FilteredMinimumBytes != 102400 {
		t.Fatalf("antifilter transformation mismatch")
	}
	if _, err := LookupProviderRecipe("zapret"); err == nil {
		t.Fatal("unknown recipe must be rejected")
	}
}

func TestRefreshRequestDefaultsAndStrictness(t *testing.T) {
	defaults := DefaultListRefreshRequest()
	if defaults.Limits.MaxEntries != 522288 || defaults.Limits.MaxExcludeEntries != 65536 {
		t.Fatalf("capacity defaults mismatch: %+v", defaults.Limits)
	}
	if defaults.Resolve.Threads != 30 || defaults.Resolve.EAgain != 10 || defaults.Resolve.EAgainDelayMS != 500 {
		t.Fatalf("resolver defaults mismatch: %+v", defaults.Resolve)
	}
	encoded, err := json.Marshal(defaults)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeListRefreshRequest(encoded)
	if err != nil {
		t.Fatalf("defaults must decode: %v", err)
	}
	if decoded.Limits != defaults.Limits || decoded.RawSHA256() == "" {
		t.Fatalf("decoded defaults mismatch")
	}
	badCases := map[string]string{
		"duplicate key":    `{"format":"desync.list-refresh/v1","format":"desync.list-refresh/v1"}`,
		"unknown key":      `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[4],"extra":1}`,
		"trailing":         `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[4]} {}`,
		"wrong family":     `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[5]}`,
		"duplicate fam":    `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[4,4]}`,
		"bad provider":     `{"format":"desync.list-refresh/v1","provider":"nope","acquisition":"remote","families":[4]}`,
		"bad acquisition":  `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"ftp","families":[4]}`,
		"zero entries":     `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[4],"limits":{"max_entries":0}}`,
		"remote snapshot":  `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[4],"snapshots":[{"dataset":"ip4","path":"x"}]}`,
		"empty with input": `{"format":"desync.list-refresh/v1","provider":"empty","acquisition":"local","families":[4],"inputs":{"user_hosts":["x"]}}`,
	}
	for name, document := range badCases {
		if _, err = DecodeListRefreshRequest([]byte(document)); err == nil {
			t.Fatalf("%s must be rejected", name)
		}
	}
	aggregate := `{"format":"desync.list-refresh/v1","provider":"reestr-preresolved","acquisition":"remote","families":[4],"aggregate":{"ipv4":{"prefix_length":"24-28","threshold":"1/2"}}}`
	if _, err = DecodeListRefreshRequest([]byte(aggregate)); err == nil {
		t.Fatal("non-default aggregate for a non aggregating recipe must be rejected")
	}
	oversized := make([]byte, providerRequestMaxBytes+1)
	if _, err = DecodeListRefreshRequest(oversized); err == nil {
		t.Fatal("oversized request must be rejected")
	}
}

func TestRefreshRemotePublishesVerifiedGeneration(t *testing.T) {
	root := t.TempDir()
	client := remoteHTTP(t)
	request := baseRemoteRequest(t)
	receipt, err := RefreshLists(context.Background(), request, root, testDependencies(client, &mockResolver{}))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !receipt.Committed || receipt.Generation == "" || atomic.LoadInt32(&client.calls) != 2 {
		t.Fatalf("unexpected receipt %+v calls=%d", receipt, client.calls)
	}
	if receipt.PreviousGeneration != nil {
		t.Fatal("first refresh must not report a previous generation")
	}
	manifest, manifestBytes, err := readCurrentManifest(root)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if manifest.Provider != ProviderReestrPreresolved || len(manifest.Datasets) != 12 {
		t.Fatalf("unexpected manifest %+v", manifest)
	}
	if manifest.RecipeRevision != ZapretRecipeRevision || manifest.RequestSHA256 != request.RawSHA256() {
		t.Fatal("manifest provenance mismatch")
	}
	if sha256Hex(manifestBytes) != receipt.ManifestSHA256 {
		t.Fatal("manifest hash mismatch")
	}
	for _, source := range manifest.Sources {
		if source.URL == "" || source.FinalURL == "" || source.URL != source.FinalURL {
			t.Fatalf("missing source provenance: %+v", source)
		}
	}
	if err = VerifyListBundle(root, manifest); err != nil {
		t.Fatalf("bundle verification: %v", err)
	}
	ip4, err := ReadListBundleDataset(root, manifest, "ip4")
	if err != nil || len(ip4) != 600 {
		t.Fatalf("ip4 dataset: %d entries, %v", len(ip4), err)
	}
	empty, err := ReadListBundleDataset(root, manifest, "hosts")
	if err != nil || len(empty) != 0 {
		t.Fatalf("hosts dataset must be empty: %d %v", len(empty), err)
	}
	for _, dataset := range manifest.Datasets {
		if dataset.Origin == listBundleOriginNotProvided && dataset.Entries != 0 {
			t.Fatalf("dataset %s has entries but no origin", dataset.ID)
		}
	}
	// A second refresh publishes a new generation and preserves the first.
	second, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{}))
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if second.Generation == receipt.Generation || second.PreviousGeneration == nil || *second.PreviousGeneration != receipt.Generation {
		t.Fatalf("unexpected second receipt %+v", second)
	}
	firstDirectory, _ := generationPath(root, receipt.Generation)
	if _, statErr := os.Stat(firstDirectory); statErr != nil {
		t.Fatalf("first generation must be preserved: %v", statErr)
	}
	// Rollback republishes the archived first manifest byte for byte.
	rollback, err := RollbackLists(context.Background(), root, receipt.Generation)
	if err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if rollback.ManifestSHA256 != receipt.ManifestSHA256 || rollback.PreviousGeneration == nil {
		t.Fatalf("unexpected rollback receipt %+v", rollback)
	}
	current, _, err := readCurrentManifest(root)
	if err != nil || current.Generation != receipt.Generation {
		t.Fatalf("rollback did not republish the generation: %+v %v", current, err)
	}
	if _, err = RollbackLists(context.Background(), root, strings.Repeat("0", 32)); err == nil {
		t.Fatal("rollback of an unknown generation must fail")
	}
}

func TestRefreshLocalAcquisitionNeverCallsHTTP(t *testing.T) {
	root := t.TempDir()
	failingClient := &mockHTTPClient{onRequest: func(*http.Request) (*http.Response, error) {
		t.Error("local acquisition must not perform an HTTP request")
		return nil, errors.New("transport must not be called")
	}}
	request := baseRemoteRequest(t)
	request.Acquisition = AcquisitionLocal
	request.Snapshots = []RefreshSnapshot{
		{Dataset: "ip4", Path: filepath.Join("testdata", "provider-refresh", "reestr_resolved4.txt")},
		{Dataset: "ip6", Path: filepath.Join("testdata", "provider-refresh", "reestr_resolved6.txt")},
	}
	request.Inputs = RefreshInputs{
		UserHosts:    []string{filepath.Join("testdata", "provider-refresh", "user_hosts.txt")},
		ExcludeHosts: []string{filepath.Join("testdata", "provider-refresh", "exclude_hosts.txt")},
		UserIP4:      []string{filepath.Join("testdata", "provider-refresh", "user_ip4.txt")},
		ExcludeIP4:   []string{filepath.Join("testdata", "provider-refresh", "exclude_ip4.txt")},
	}
	resolver := &mockResolver{addresses: map[string]map[Family][]netip.Addr{
		"user-001.example.org": {FamilyIPv4: {netip.MustParseAddr("5.5.5.5"), netip.MustParseAddr("10.9.9.9")}},
	}}
	receipt, err := RefreshLists(context.Background(), request, root, testDependencies(failingClient, resolver))
	if err != nil {
		t.Fatalf("local refresh: %v", err)
	}
	if !receipt.Committed || atomic.LoadInt32(&failingClient.calls) != 0 {
		t.Fatalf("local refresh must not use HTTP: calls=%d", failingClient.calls)
	}
	manifest, _, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Acquisition != AcquisitionLocal {
		t.Fatal("manifest must record local acquisition")
	}
	for _, source := range manifest.Sources {
		if source.Path == "" || source.URL != "" {
			t.Fatalf("local source must carry a path: %+v", source)
		}
	}
	userIP4, err := ReadListBundleDataset(root, manifest, "user_ip4")
	if err != nil {
		t.Fatal(err)
	}
	if len(userIP4) != 51 {
		t.Fatalf("user_ip4 must union literal and resolved entries: %d", len(userIP4))
	}
	found := false
	for _, entry := range userIP4 {
		if entry == "5.5.5.5" {
			found = true
		}
		if entry == "10.9.9.9" {
			t.Fatal("cut_local must drop 10. addresses")
		}
	}
	if !found {
		t.Fatal("resolved user host is missing")
	}
	excludeIP4, err := ReadListBundleDataset(root, manifest, "exclude_ip4")
	if err != nil || len(excludeIP4) != 2 {
		t.Fatalf("exclude_ip4: %v %v", excludeIP4, err)
	}
	if len(manifest.Resolution.Aggregation.Families) != 0 {
		t.Fatal("no aggregation is expected for an already resolved feed")
	}
}

func TestRefreshFailureRetainsLastGood(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatal(err)
	}
	before, beforeBytes, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	failing := &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		return newResponse(request, http.StatusInternalServerError, nil, nil), nil
	}}
	if _, err = RefreshLists(context.Background(), request, root, testDependencies(failing, &mockResolver{})); err == nil {
		t.Fatal("a failed source must fail the refresh")
	}
	after, afterBytes, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation || !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatal("a failed refresh must not change current.json")
	}
	if atomic.LoadInt32(&failing.calls) != 5 {
		t.Fatalf("a transient HTTP status must use the five-attempt budget: %d", failing.calls)
	}
	entries, err := os.ReadDir(filepath.Join(root, listBundleGenerations))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("a failed refresh must not leave a staged generation: %d", len(entries))
	}
}

func TestRefreshRetriesTransientStatus(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	var attempts int32
	client := &mockHTTPClient{onRequest: func(request *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&attempts, 1) < 5 {
			return newResponse(request, http.StatusTooManyRequests, nil, nil), nil
		}
		return newResponse(request, http.StatusOK, mustReadFixture(t, "reestr_resolved4.txt"), nil), nil
	}}
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(client, &mockResolver{})); err != nil {
		t.Fatalf("retryable refresh: %v", err)
	}
	if atomic.LoadInt32(&attempts) != 5 {
		t.Fatalf("expected five attempts, got %d", attempts)
	}
}

func TestRefreshBoundViolationsFail(t *testing.T) {
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	request.Limits.MaxEntries = 10
	root := t.TempDir()
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("entry bound must fail the publication")
	}
	if _, err := os.Stat(filepath.Join(root, listBundleCurrentName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("no current.json may exist after a failed publication")
	}
	small := baseRemoteRequest(t)
	small.Families = []int{4}
	small.Limits.MaxTotalBytes = 64
	if _, err := RefreshLists(context.Background(), small, t.TempDir(), testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("total byte bound must fail the publication")
	}
}

func TestRefreshCancellationLeavesState(t *testing.T) {
	root := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := baseRemoteRequest(t)
	if _, err := RefreshLists(ctx, request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("a cancelled refresh must fail")
	}
	if _, err := os.Stat(filepath.Join(root, listBundleCurrentName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a cancelled refresh must not publish")
	}
}

func TestRefreshPublicationLockSerializes(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	shared := remoteHTTP(t)
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 2)
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := RefreshLists(context.Background(), request, root, testDependencies(shared, &mockResolver{}))
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent refresh: %v", err)
		}
	}
	if atomic.LoadInt32(&shared.maxInFlight) != 1 {
		t.Fatalf("publication lock must serialize fetches, max in flight %d", shared.maxInFlight)
	}
	manifest, _, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyListBundle(root, manifest); err != nil {
		t.Fatal(err)
	}
}

func TestProviderAliasAndPublicationGuards(t *testing.T) {
	var err error
	if err := providerPublicDestination(netip.MustParseAddr("8.8.8.8")); !err {
		t.Fatal("public address must be allowed")
	}
	for _, blocked := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "224.0.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1"} {
		if providerPublicDestination(netip.MustParseAddr(blocked)) {
			t.Fatalf("%s must be rejected", blocked)
		}
	}
	recipe, _ := LookupProviderRecipe(ProviderReestrPreresolved)
	source := recipe.Sources[0]
	allowed, _ := url.Parse("https://raw.githubusercontent.com/bol-van/rulist/main/reestr_resolved4.txt")
	if err := validateFinalProviderURL(recipe, source, allowed); err != nil {
		t.Fatalf("original host must be allowed: %v", err)
	}
	privateRedirect, _ := url.Parse("https://127.0.0.1/reestr_resolved4.txt")
	if err = validateFinalProviderURL(recipe, source, privateRedirect); err == nil {
		t.Fatal("a redirect to another host must be rejected without an allowlist")
	}
	downgrade, _ := url.Parse("http://raw.githubusercontent.com/bol-van/rulist/main/reestr_resolved4.txt")
	if err = validateFinalProviderURL(recipe, source, downgrade); err == nil {
		t.Fatal("a scheme downgrade must be rejected")
	}
	portChange, _ := url.Parse("https://raw.githubusercontent.com:8443/bol-van/rulist/main/reestr_resolved4.txt")
	if err = validateFinalProviderURL(recipe, source, portChange); err == nil {
		t.Fatal("a port change must be rejected")
	}
	refilter, _ := LookupProviderRecipe(ProviderRefilterIPSum)
	refilterSource := refilter.Sources[0]
	asset, _ := url.Parse("https://release-assets.githubusercontent.com/github-production-release-asset/1")
	if err = validateFinalProviderURL(refilter, refilterSource, asset); err != nil {
		t.Fatalf("allowlisted release host must be accepted: %v", err)
	}
	// Symlinked output directory component is refused.
	parent := t.TempDir()
	realDirectory := filepath.Join(parent, "real")
	if err = os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDirectory := filepath.Join(parent, "link")
	if err = os.Symlink(realDirectory, linkDirectory); err != nil {
		t.Fatal(err)
	}
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	if _, err = RefreshLists(context.Background(), request, linkDirectory, testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("a symlinked output directory must be refused")
	}
	// Hardlinked current.json is refused.
	root := t.TempDir()
	if _, err = RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias.json")
	if err = os.Link(filepath.Join(root, listBundleCurrentName), alias); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if _, err = RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
		t.Fatal("a hardlinked current.json must be refused")
	}
	// Symlinked input is refused.
	inputLink := filepath.Join(t.TempDir(), "input.txt")
	if err = os.Symlink(filepath.Join("testdata", "provider-refresh", "user_ip4.txt"), inputLink); err == nil {
		userRequest := baseRemoteRequest(t)
		userRequest.Provider = ProviderUser
		userRequest.Acquisition = AcquisitionLocal
		userRequest.Families = []int{4}
		userRequest.Inputs = RefreshInputs{UserIP4: []string{inputLink}}
		userRequest.Aggregate = DefaultListRefreshRequest().Aggregate
		if _, err = RefreshLists(context.Background(), userRequest, t.TempDir(), testDependencies(remoteHTTP(t), &mockResolver{})); err == nil {
			t.Fatal("a symlinked input must be refused")
		}
	}
}

func TestProviderTransformsAndRanges(t *testing.T) {
	prefixes := rangeToPrefixes(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.255"))
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/24" {
		t.Fatalf("unexpected v4 cover: %v", prefixes)
	}
	prefixes = rangeToPrefixes(netip.MustParseAddr("10.0.0.0"), netip.MustParseAddr("10.0.0.1"))
	if len(prefixes) != 1 || prefixes[0].String() != "10.0.0.0/31" {
		t.Fatalf("unexpected minimal v4 cover: %v", prefixes)
	}
	prefixes = rangeToPrefixes(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"))
	if len(prefixes) != 2 {
		t.Fatalf("unaligned v4 range must keep two prefixes: %v", prefixes)
	}
	prefixes = rangeToPrefixes(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8::2"))
	if len(prefixes) != 2 || prefixes[0].String() != "2001:db8::1/128" || prefixes[1].String() != "2001:db8::2/128" {
		t.Fatalf("unexpected v6 cover: %v", prefixes)
	}
	prefixes = rangeToPrefixes(netip.MustParseAddr("2001:db8::"), netip.MustParseAddr("2001:db8::ff"))
	if len(prefixes) != 1 || prefixes[0].String() != "2001:db8::/120" {
		t.Fatalf("unexpected v6 /120 cover: %v", prefixes)
	}
	if prefixes = rangeToPrefixes(netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.0.0.1")); prefixes != nil {
		t.Fatal("reversed ranges must be rejected")
	}
	entries, ok := normalizeFeedLine("10.1.2.0-10.1.2.255", ListKindIP, 4)
	if !ok || len(entries) != 1 || entries[0] != "10.1.2.0/24" {
		t.Fatalf("range normalization failed: %v %v", entries, ok)
	}
	if providerCutLocalV4MustDrop("172.16.0.1", true) {
		t.Fatal("the exact source predicate must keep 172.16/12")
	}
	if !providerCutLocalV4MustDrop("10.1.0.0/16", true) || !providerCutLocalV4MustDrop("127.0.0.1", true) {
		t.Fatal("the exact source predicate must drop 10/8 and 127/8")
	}
	if providerCutLocalV4MustDrop("10.1.0.0/16", false) {
		t.Fatal("the predicate must be off when the recipe does not cut locally")
	}
	for _, blocked := range []string{"::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1"} {
		if !providerCutLocalV6MustDrop(netip.MustParseAddr(blocked)) {
			t.Fatalf("%s must be dropped by the v6 predicate", blocked)
		}
	}
	for _, kept := range []string{"2001:db8::1", "2a02::1", "fec0::1"} {
		if providerCutLocalV6MustDrop(netip.MustParseAddr(kept)) {
			t.Fatalf("%s must be kept by the v6 predicate", kept)
		}
	}
}

func TestDecodeGzipBounds(t *testing.T) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(bytes.Repeat([]byte("a"), 1024)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	encoded := buffer.Bytes()
	if _, err := decodeGzipOnce(encoded, 1024); err != nil {
		t.Fatalf("bounded gzip: %v", err)
	}
	if _, err := decodeGzipOnce(encoded, 16); err == nil {
		t.Fatal("decompression bomb must be rejected")
	}
	trailing := append(append([]byte{}, encoded...), 0x00)
	if _, err := decodeGzipOnce(trailing, 1024); err == nil {
		t.Fatal("trailing data after the gzip member must be rejected")
	}
	concatenated := append(append([]byte{}, encoded...), encoded...)
	if _, err := decodeGzipOnce(concatenated, 4096); err == nil {
		t.Fatal("a second concatenated gzip member must be rejected")
	}
	if _, err := decodeGzipOnce([]byte("not gzip"), 1024); err == nil {
		t.Fatal("invalid gzip must be rejected")
	}
}

func TestGzipShardDeterminism(t *testing.T) {
	first, err := gzipBytes([]byte("a\nb\n"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := gzipBytes([]byte("a\nb\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("shard compression must be deterministic")
	}
	if first[4] != 0 || first[5] != 0 || first[6] != 0 || first[7] != 0 {
		t.Fatal("gzip modification time must be zero")
	}
}

func TestManifestStrictDecode(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	if _, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{})); err != nil {
		t.Fatal(err)
	}
	_, manifestBytes, err := readCurrentManifest(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeListBundleManifest(append(manifestBytes, []byte("{}")...)); err == nil {
		t.Fatal("trailing JSON document must be rejected")
	}
	var document map[string]any
	if err = json.Unmarshal(manifestBytes, &document); err != nil {
		t.Fatal(err)
	}
	document["unknown"] = true
	unknown, _ := json.Marshal(document)
	if _, err = DecodeListBundleManifest(unknown); err == nil {
		t.Fatal("unknown manifest key must be rejected")
	}
	document = map[string]any{}
	if err = json.Unmarshal(manifestBytes, &document); err != nil {
		t.Fatal(err)
	}
	delete(document, "datasets")
	missing, _ := json.Marshal(document)
	if _, err = DecodeListBundleManifest(missing); err == nil {
		t.Fatal("manifest without datasets must be rejected")
	}
}

func TestRefreshRequestReceiptRedaction(t *testing.T) {
	root := t.TempDir()
	request := baseRemoteRequest(t)
	request.Families = []int{4}
	receipt, err := RefreshLists(context.Background(), request, root, testDependencies(remoteHTTP(t), &mockResolver{}))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, sensitive := range []string{"raw.githubusercontent.com", "reestr", "5.0."} {
		if strings.Contains(text, sensitive) {
			t.Fatalf("receipt leaked %q: %s", sensitive, text)
		}
	}
	if !strings.Contains(text, ListRefreshResultFormat) {
		t.Fatal("receipt format missing")
	}
	digest := sha256.Sum256(nil)
	_ = hex.EncodeToString(digest[:])
}

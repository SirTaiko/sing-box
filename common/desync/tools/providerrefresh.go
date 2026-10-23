package tools

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Provider refresh pipeline.
//
// The pipeline is bounded fetch/parse/resolve/normalize/aggregate/publish work
// on explicit operator input. It never imports a running core, never starts a
// service or scheduler and never executes a shell command. A partial or failed
// run leaves the previous current.json and every previous generation unchanged.

type datasetBuild struct {
	kind    ListKind
	family  int
	origin  string
	entries []string
}

type refreshRun struct {
	request     ListRefreshRequest
	recipe      ProviderRecipe
	deps        ProviderDependencies
	clock       MDigClock
	deadline    time.Time
	ctx         context.Context
	sources     []ListBundleSource
	resolution  ListBundleResolution
	datasets    map[string]*datasetBuild
	warnings    []string
	inputRaw    map[string][]string
	resolved    map[int]map[string][]netip.Addr
	sourceBytes int64
}

// RawSHA256 returns the hash of the exact request bytes that were decoded. For a
// programmatically built request it hashes the canonical JSON encoding.
func (r ListRefreshRequest) RawSHA256() string {
	if len(r.rawJSON) != 0 {
		return sha256Hex(r.rawJSON)
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return sha256Hex(encoded)
}

// RefreshLists validates the request, acquires the selected recipe, builds all
// twelve datasets and publishes one immutable generation through the single
// current.json commit point.
func RefreshLists(ctx context.Context, request ListRefreshRequest, outputDir string, deps ProviderDependencies) (ListRefreshReceipt, error) {
	var receipt ListRefreshReceipt
	if ctx == nil {
		ctx = context.Background()
	}
	if err := request.Validate(); err != nil {
		return receipt, err
	}
	recipe := providerRecipes[request.Provider]
	if strings.TrimSpace(outputDir) == "" {
		return receipt, E.New("list refresh output directory is required")
	}
	clock := deps.Clock
	if clock == nil {
		clock = systemClock{}
	}
	deadline := clock.Now().Add(time.Duration(request.Limits.TimeoutSeconds) * time.Second)
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := ensureOutputRoot(outputDir); err != nil {
		return receipt, err
	}
	release, err := acquireRefreshLock(runCtx, outputDir, clock)
	if err != nil {
		return receipt, err
	}
	defer release()
	previous := readPreviousGeneration(outputDir)
	run := &refreshRun{
		request:  request,
		recipe:   recipe,
		deps:     deps,
		clock:    clock,
		deadline: deadline,
		ctx:      runCtx,
		datasets: make(map[string]*datasetBuild, len(ListBundleDatasetIDs())),
		inputRaw: make(map[string][]string),
		resolved: make(map[int]map[string][]netip.Addr),
	}
	for _, id := range ListBundleDatasetIDs() {
		_, kind, family, _ := listBundleDatasetSpec(id)
		run.datasets[id] = &datasetBuild{kind: kind, family: family, origin: listBundleOriginNotProvided}
	}
	if err = run.execute(); err != nil {
		return receipt, err
	}
	if err = runCtx.Err(); err != nil {
		return receipt, err
	}
	manifest, payloads, err := run.manifest(previous)
	if err != nil {
		return receipt, err
	}
	generation, err := newGenerationID()
	if err != nil {
		return receipt, err
	}
	manifest.Generation = generation
	writer, err := beginBundleGeneration(outputDir, generation)
	if err != nil {
		return receipt, err
	}
	defer writer.abort()
	for _, id := range ListBundleDatasetIDs() {
		dataset, writeErr := writer.writeDataset(id, payloads[id], request.Compression)
		if writeErr != nil {
			return receipt, writeErr
		}
		for index := range manifest.Datasets {
			if manifest.Datasets[index].ID == id {
				dataset.Origin = manifest.Datasets[index].Origin
				manifest.Datasets[index] = dataset
			}
		}
	}
	if err = verifyOutputBudget(manifest, request.Limits); err != nil {
		return receipt, err
	}
	receipt, err = writer.seal(manifest)
	if err != nil {
		return receipt, err
	}
	receipt.PreviousGeneration = previous
	if previous != nil && *previous == generation {
		receipt.PreviousGeneration = nil
	}
	return receipt, nil
}

func (run *refreshRun) execute() error {
	request := run.request
	recipe := run.recipe
	if recipe.LocalOnly {
		if err := run.importSnapshots(); err != nil {
			return err
		}
		if recipe.ID != ProviderLocal {
			for _, dataset := range run.datasets {
				dataset.entries = []string{}
				dataset.origin = listBundleOriginDisabled
			}
		}
	} else {
		if err := run.acquireProvider(); err != nil {
			return err
		}
	}
	if err := run.loadInputs(); err != nil {
		return err
	}
	if err := run.resolveHosts(); err != nil {
		return err
	}
	if err := run.applyExclusions(); err != nil {
		return err
	}
	if err := run.aggregateProvider(); err != nil {
		return err
	}
	if err := run.finalizeDatasets(); err != nil {
		return err
	}
	_ = request
	return nil
}

// acquireProvider fetches or imports every active fixed source of the recipe.
func (run *refreshRun) acquireProvider() error {
	recipe := run.recipe
	snapshots := make(map[string]string, len(run.request.Snapshots))
	for _, snapshot := range run.request.Snapshots {
		snapshots[snapshot.Dataset] = snapshot.Path
	}
	for index, source := range recipe.Sources {
		familyActive := source.Family == 0 || run.request.familySelected(source.Family)
		if !familyActive {
			continue
		}
		var (
			data       []byte
			provenance ListBundleSource
			err        error
		)
		if run.request.Acquisition == AcquisitionRemote {
			fetched, fetchErr := acquireProviderSource(run.ctx, recipe, source, run.deps, run.deadline, run.clock, run.request.Limits.MaxDecodedBytes)
			if fetchErr != nil {
				return fetchErr
			}
			data = fetched.Data
			provenance = fetched.Provenance
			provenance.ID = providerSourceID(recipe, source, index)
		} else {
			snapshotPath, ok := snapshots[source.Dataset]
			if !ok {
				return E.New("missing snapshot for source ", source.Dataset)
			}
			data, provenance, err = run.readLocalSnapshot(source, snapshotPath)
			if err != nil {
				return err
			}
			provenance.ID = providerSourceID(recipe, source, index)
		}
		feed, err := run.parseFeed(data, source)
		if err != nil {
			return err
		}
		provenance.Lines = feed.lines
		provenance.Accepted = len(feed.entries)
		provenance.Invalid = feed.invalid
		provenance.Duplicates = feed.duplicates
		run.sourceBytes += provenance.DecompressedSize
		if run.sourceBytes > run.request.Limits.MaxTotalBytes {
			return E.New("total decoded source bytes exceed the configured limit")
		}
		if source.Family == 0 {
			dataset := run.datasets["hosts"]
			dataset.origin = listBundleOriginGenerated
			dataset.entries = append(dataset.entries, feed.entries...)
		} else {
			id := "ip4"
			if source.Family == 6 {
				id = "ip6"
			}
			dataset := run.datasets[id]
			dataset.origin = listBundleOriginGenerated
			dataset.entries = append(dataset.entries, feed.entries...)
		}
		run.sources = append(run.sources, provenance)
	}
	return nil
}

// readLocalSnapshot imports one typed local provider snapshot. Local records are
// strictly validated and the remote shape guards still apply.
func (run *refreshRun) readLocalSnapshot(source ProviderSource, path string) ([]byte, ListBundleSource, error) {
	var provenance ListBundleSource
	info, err := os.Lstat(path)
	if err != nil {
		return nil, provenance, E.Cause(err, "inspect snapshot")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, provenance, E.New("snapshot ", path, " is not a plain file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, provenance, E.Cause(err, "open snapshot")
	}
	defer file.Close()
	loadedByteBudget := run.request.Limits.MaxTotalBytes
	if loadedByteBudget > providerSourceMaxBytes {
		loadedByteBudget = providerSourceMaxBytes
	}
	raw, err := io.ReadAll(io.LimitReader(file, loadedByteBudget+1))
	if err != nil {
		return nil, provenance, E.Cause(err, "read snapshot")
	}
	if int64(len(raw)) > loadedByteBudget {
		return nil, provenance, E.New("snapshot exceeds the configured byte limit")
	}
	if int64(len(raw)) < source.MinimumBytes {
		return nil, provenance, E.New("snapshot is below the source minimum of ", source.MinimumBytes, " bytes")
	}
	compression := CompressionNone
	data := raw
	if gzipMagic(raw) {
		compression = CompressionGzip
		data, err = decodeGzipOnce(raw, run.request.Limits.MaxDecodedBytes)
		if err != nil {
			return nil, provenance, E.Cause(err, "decode snapshot")
		}
	} else if source.RequireGzip {
		return nil, provenance, E.New("snapshot is not the required gzip stream")
	}
	provenance = ListBundleSource{
		Path:             path,
		SHA256:           sha256Hex(raw),
		Size:             int64(len(raw)),
		Compression:      compression,
		DecompressedSize: int64(len(data)),
	}
	return data, provenance, nil
}

type feedParse struct {
	entries       []string
	lines         int
	invalid       int
	duplicates    int
	filteredBytes int64
}

// parseFeed normalizes one provider or snapshot feed. IP ranges are converted to
// their exact minimal CIDR cover and are never expanded per address.
func (run *refreshRun) parseFeed(data []byte, source ProviderSource) (feedParse, error) {
	var parsed feedParse
	kind := ListKindIP
	if source.Family == 0 {
		kind = ListKindDomain
	}
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		if int64(len(line)) > providerLineMaxBytes {
			return parsed, E.New("provider line exceeds the line limit")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		parsed.lines++
		entries, ok := normalizeFeedLine(trimmed, kind, source.Family)
		if !ok {
			parsed.invalid++
			continue
		}
		for _, entry := range entries {
			if source.Family == 4 || kind == ListKindDomain {
				if kind == ListKindIP && providerCutLocalV4MustDrop(entry, run.recipe.AggregatesIPv4) {
					continue
				}
			}
			if _, duplicate := seen[entry]; duplicate {
				parsed.duplicates++
				continue
			}
			seen[entry] = struct{}{}
			parsed.entries = append(parsed.entries, entry)
			parsed.filteredBytes += int64(len(entry)) + 1
		}
	}
	if parsed.lines > 0 && len(parsed.entries) == 0 && parsed.invalid == parsed.lines {
		return parsed, E.New("provider source contains no valid record")
	}
	if source.FilteredMinimumBytes > 0 {
		if kind == ListKindDomain {
			// The AntiZapret guard applies to the decoded body size.
			if int64(len(data)) < source.FilteredMinimumBytes {
				return parsed, E.New("provider feed is below the decoded minimum of ", source.FilteredMinimumBytes, " bytes")
			}
		} else if parsed.filteredBytes < source.FilteredMinimumBytes {
			// The AntiFilter guard applies to the filtered text.
			return parsed, E.New("provider feed is below the filtered minimum of ", source.FilteredMinimumBytes, " bytes")
		}
	}
	sortFeed(parsed.entries, kind)
	return parsed, nil
}

// providerCutLocalV4MustDrop applies the exact source cut_local predicate:
// 192.168., 127. and 10. only. It is deliberately not a full RFC1918 test.
func providerCutLocalV4MustDrop(entry string, enabled bool) bool {
	if !enabled {
		return false
	}
	addressText := entry
	if index := strings.IndexByte(addressText, '/'); index >= 0 {
		addressText = addressText[:index]
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil {
		return false
	}
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	bytes := address.As4()
	return bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 127 || bytes[0] == 10
}

// providerCutLocalV6MustDrop is the exact textual equivalent of
// ^::|^fc..:|^fd..:|^fe8.:|^fe9.:|^fea.:|^feb.: on resolver output.
func providerCutLocalV6MustDrop(address netip.Addr) bool {
	if address.Is4In6() || address.IsUnspecified() || address.IsLoopback() {
		return true
	}
	bytes := address.As16()
	if bytes[0] == 0xfc || bytes[0] == 0xfd {
		return true
	}
	return bytes[0] == 0xfe && bytes[1] >= 0x80 && bytes[1] <= 0xbf
}

func normalizeFeedLine(line string, kind ListKind, family int) ([]string, bool) {
	if kind == ListKindDomain {
		entry, ok := normalizeDomainEntry(line)
		if !ok {
			return nil, false
		}
		return []string{entry}, true
	}
	if start, end, ok := parseFeedRange(line); ok {
		prefixes := rangeToPrefixes(start, end)
		if len(prefixes) == 0 {
			return nil, false
		}
		if family == 4 && !start.Is4() || family == 6 && !start.Is6() {
			return nil, false
		}
		entries := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			entries = append(entries, prefix.Masked().String())
		}
		return entries, true
	}
	entry, ok := normalizeIPEntry(line)
	if !ok {
		return nil, false
	}
	address, err := netip.ParseAddr(strings.TrimSuffix(entry, "/"+prefixBits(entry)))
	if err == nil {
		if family == 4 && !address.Is4() || family == 6 && !address.Is6() {
			return nil, false
		}
	}
	return []string{entry}, true
}

func prefixBits(entry string) string {
	index := strings.IndexByte(entry, '/')
	if index < 0 {
		return ""
	}
	return entry[index+1:]
}

func parseFeedRange(line string) (netip.Addr, netip.Addr, bool) {
	startText, endText, found := strings.Cut(line, "-")
	if !found {
		return netip.Addr{}, netip.Addr{}, false
	}
	start, err := netip.ParseAddr(strings.TrimSpace(startText))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	end, err := netip.ParseAddr(strings.TrimSpace(endText))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	if start.Is4() != end.Is4() {
		return netip.Addr{}, netip.Addr{}, false
	}
	if start.Compare(end) > 0 {
		return netip.Addr{}, netip.Addr{}, false
	}
	return start, end, true
}

func sortFeed(entries []string, kind ListKind) {
	if kind == ListKindIP {
		sort.SliceStable(entries, func(left int, right int) bool {
			return compareIPEntries(entries[left], entries[right]) < 0
		})
		return
	}
	sort.Strings(entries)
}

func (run *refreshRun) loadInputs() error {
	inputs := run.request.Inputs
	roles := []struct {
		id     string
		kind   ListKind
		family int
		paths  []string
	}{
		{"user_hosts", ListKindDomain, 0, inputs.UserHosts},
		{"exclude_hosts", ListKindDomain, 0, inputs.ExcludeHosts},
		{"ipban_hosts", ListKindDomain, 0, inputs.IPBanHosts},
		{"user_ip4", ListKindIP, 4, inputs.UserIP4},
		{"user_ip6", ListKindIP, 6, inputs.UserIP6},
		{"exclude_ip4", ListKindIP, 4, inputs.ExcludeIP4},
		{"exclude_ip6", ListKindIP, 6, inputs.ExcludeIP6},
		{"ipban_ip4", ListKindIP, 4, inputs.IPBanIP4},
		{"ipban_ip6", ListKindIP, 6, inputs.IPBanIP6},
	}
	for _, role := range roles {
		for _, path := range role.paths {
			data, err := readStrictLocalInput(path, run.request.Limits.MaxDecodedBytes)
			if err != nil {
				return err
			}
			entries, err := parseStrictInput(data, role.kind)
			if err != nil {
				return E.Cause(err, "input ", path)
			}
			if role.kind == ListKindDomain && (role.id == "ipban_hosts") {
				for _, entry := range entries {
					if strings.HasPrefix(entry, ".") {
						return E.New("ipban host inputs must not be subdomain wildcards")
					}
				}
			}
			dataset := run.datasets[role.id]
			dataset.origin = listBundleOriginLocal
			dataset.entries = append(dataset.entries, entries...)
			run.inputRaw[role.id] = append(run.inputRaw[role.id], entries...)
		}
	}
	return nil
}

// readStrictLocalInput opens one explicit input without following a symlink.
func readStrictLocalInput(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, E.Cause(err, "inspect input")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, E.New("input ", path, " is not a plain file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, E.Cause(err, "open input")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, E.Cause(err, "stat input")
	}
	if !os.SameFile(info, opened) {
		return nil, E.New("input ", path, " changed while being opened")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, E.Cause(err, "read input")
	}
	if int64(len(raw)) > maxBytes {
		return nil, E.New("input exceeds the configured byte limit")
	}
	if gzipMagic(raw) {
		return decodeGzipOnce(raw, maxBytes)
	}
	return raw, nil
}

// parseStrictInput normalizes explicit local records and rejects every malformed
// record instead of dropping it.
func parseStrictInput(data []byte, kind ListKind) ([]string, error) {
	var entries []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(string(data), "\n") {
		if int64(len(line)) > providerLineMaxBytes {
			return nil, E.New("input line exceeds the line limit")
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		normalized, ok := normalizeListEntry(trimmed, kind)
		if !ok {
			return nil, E.New("malformed local record")
		}
		if _, duplicate := seen[normalized]; duplicate {
			continue
		}
		seen[normalized] = struct{}{}
		entries = append(entries, normalized)
	}
	return entries, nil
}

func (run *refreshRun) importSnapshots() error {
	for _, snapshot := range run.request.Snapshots {
		data, err := readStrictLocalInput(snapshot.Path, run.request.Limits.MaxDecodedBytes)
		if err != nil {
			return err
		}
		kind := ListKindDomain
		_ = kind
		id := snapshot.Dataset
		family := 0
		if id != "hosts" {
			kind = ListKindIP
			if id == "ip4" {
				family = 4
			} else {
				family = 6
			}
		}
		source := ProviderSource{Dataset: id, Family: family}
		feed, err := run.parseFeed(data, source)
		if err != nil {
			return err
		}
		dataset := run.datasets[id]
		dataset.origin = listBundleOriginLocal
		dataset.entries = append(dataset.entries, feed.entries...)
		run.sources = append(run.sources, ListBundleSource{
			ID:               "snapshot/" + id,
			Path:             snapshot.Path,
			SHA256:           sha256Hex(data),
			Size:             int64(len(data)),
			Compression:      CompressionNone,
			DecompressedSize: int64(len(data)),
			Lines:            feed.lines,
			Accepted:         len(feed.entries),
			Invalid:          feed.invalid,
			Duplicates:       feed.duplicates,
		})
	}
	return nil
}

// resolveHosts performs the explicit user phase with the existing mdig resolver
// seam and its EAGAIN retry policy. Permanent negatives are counted; exhausted
// temporary failures and resolver infrastructure errors abort the generation.
func (run *refreshRun) resolveHosts() error {
	recipe := run.recipe
	resolve := run.request.Resolve
	needsUser := recipe.UserPhase == "U" || recipe.UserPhase == "B" || recipe.UserPhase == "X"
	if !needsUser {
		return nil
	}
	type resolutionPlan struct {
		names  []string
		target string
		cut    bool
		fatal  bool
	}
	plans := make([]resolutionPlan, 0, 3)
	if recipe.UserPhase == "U" {
		plans = append(plans, resolutionPlan{names: run.inputRaw["user_hosts"], target: "user", cut: true, fatal: true})
	}
	if recipe.UserPhase == "U" || recipe.UserPhase == "B" {
		plans = append(plans, resolutionPlan{names: run.inputRaw["ipban_hosts"], target: "ipban", cut: true, fatal: true})
	}
	plans = append(plans, resolutionPlan{names: run.inputRaw["exclude_hosts"], target: "exclude", cut: false, fatal: true})
	for _, plan := range plans {
		for _, name := range plan.names {
			if strings.HasPrefix(name, ".") {
				return E.New("host resolution input must not start with a dot")
			}
			if strings.HasPrefix(name, ".") || name == "" {
				return E.New("invalid host resolution input")
			}
			addresses, err := run.resolveName(name, resolve)
			if err != nil {
				return err
			}
			for _, address := range addresses {
				if plan.cut {
					if address.Is4() && providerCutLocalV4MustDrop(address.String(), true) {
						continue
					}
					if address.Is6() && providerCutLocalV6MustDrop(address) {
						continue
					}
				}
				id := plan.target + "_ip4"
				if address.Is6() {
					id = plan.target + "_ip6"
				}
				dataset := run.datasets[id]
				dataset.origin = listBundleOriginLocal
				dataset.entries = append(dataset.entries, address.String())
				run.resolution.Addresses++
			}
		}
	}
	return nil
}

func (run *refreshRun) resolveName(name string, resolve ResolveOptions) ([]netip.Addr, error) {
	if run.deps.Resolver == nil {
		return nil, E.New("host resolution requires an explicit resolver")
	}
	if run.resolved == nil {
		run.resolved = make(map[int]map[string][]netip.Addr)
	}
	var lastError error
	for attempt := 0; attempt < resolve.EAgain; attempt++ {
		if err := run.ctx.Err(); err != nil {
			return nil, err
		}
		families := make([]Family, 0, len(run.request.Families))
		for _, family := range run.request.Families {
			if family == 4 {
				families = append(families, FamilyIPv4)
			} else {
				families = append(families, FamilyIPv6)
			}
		}
		var addresses []netip.Addr
		for _, family := range families {
			run.resolution.Domains++
			found, err := run.deps.Resolver.Lookup(run.ctx, name, family)
			if err != nil {
				if errorsIsContext(err) {
					return nil, err
				}
				if strings.Contains(err.Error(), ErrTemporary.Error()) {
					lastError = err
					break
				}
				run.resolution.Negative++
				lastError = nil
				continue
			}
			run.resolution.Success++
			if len(found) > 1024 {
				return nil, E.New("resolver returned too many addresses for one name")
			}
			addresses = append(addresses, found...)
		}
		if lastError == nil {
			return addresses, nil
		}
		run.resolution.Temporary++
		if attempt+1 < resolve.EAgain {
			run.resolution.Retries++
			if err := run.clock.Sleep(run.ctx, time.Duration(resolve.EAgainDelayMS)*time.Millisecond); err != nil {
				return nil, err
			}
		}
	}
	return nil, E.Cause(lastError, "temporary resolution failure exhausted its attempts")
}

func errorsIsContext(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// applyExclusions removes exactly excluded domains/prefixes from positive
// datasets while retaining every negative dataset for runtime suffix matching.
func (run *refreshRun) applyExclusions() error {
	excludeDomainsList := run.datasets["exclude_hosts"].entries
	excludeIPList := append(append([]string{}, run.datasets["exclude_ip4"].entries...), run.datasets["exclude_ip6"].entries...)
	for _, id := range []string{"hosts", "user_hosts"} {
		dataset := run.datasets[id]
		dataset.entries, _ = excludeDomains(dataset.entries, excludeDomainsList)
	}
	for _, id := range []string{"ip4", "ip6", "user_ip4", "user_ip6"} {
		dataset := run.datasets[id]
		budget := int64(len(dataset.entries)+1) * 129
		kept, _, err := excludeIPs(run.ctx, dataset.entries, excludeIPList, budget)
		if err != nil {
			return err
		}
		dataset.entries = kept
	}
	return nil
}

// aggregateProvider applies the exact ip2net density algorithm to the provider
// IPv4 feed of the recipes whose source script aggregates, then re-applies the
// exclusions so aggregation cannot reintroduce an excluded address.
func (run *refreshRun) aggregateProvider() error {
	if !run.recipe.AggregatesIPv4 || !run.request.familySelected(4) {
		return nil
	}
	dataset := run.datasets["ip4"]
	if len(dataset.entries) == 0 {
		return nil
	}
	before := len(dataset.entries)
	var input bytes.Buffer
	for _, entry := range dataset.entries {
		input.WriteString(entry)
		input.WriteByte('\n')
	}
	var output bytes.Buffer
	aggregate := run.request.Aggregate.IPv4
	prefixMin, prefixMax, err := parseProviderPrefixLength(aggregate.PrefixLength, 4)
	if err != nil {
		return err
	}
	mul, div, err := parseProviderRatio(fmtAny(aggregate.Threshold))
	if err != nil {
		return err
	}
	_, err = IP2Net(run.ctx, &input, &output, IP2NetOptions{
		Family:          FamilyIPv4,
		PrefixLengthMin: prefixMin,
		PrefixLengthMax: prefixMax,
		V4ThresholdMul:  mul,
		V4ThresholdDiv:  div,
		MaxEntries:      run.request.Limits.MaxEntries,
	})
	if err != nil {
		return err
	}
	entries := make([]string, 0, len(dataset.entries))
	for _, line := range strings.Split(output.String(), "\n") {
		if line != "" {
			entries = append(entries, line)
		}
	}
	excludeIPList := append(append([]string{}, run.datasets["exclude_ip4"].entries...), run.datasets["exclude_ip6"].entries...)
	entries, _, err = excludeIPs(run.ctx, entries, excludeIPList, int64(len(entries)+1)*129)
	if err != nil {
		return err
	}
	sortFeed(entries, ListKindIP)
	dataset.entries = entries
	run.resolution.Aggregation = &ListBundleAggregation{
		Families: []ListBundleAggregateFamily{{
			Family:       4,
			PrefixLength: aggregate.PrefixLength,
			Threshold:    fmtAny(aggregate.Threshold),
			Before:       before,
			After:        len(entries),
		}},
	}
	return nil
}

// finalizeDatasets enforces the per-dataset entry bounds and canonical ordering.
func (run *refreshRun) finalizeDatasets() error {
	for _, id := range ListBundleDatasetIDs() {
		dataset := run.datasets[id]
		limit := run.request.Limits.MaxEntries
		if isNegativeDataset(id) {
			limit = run.request.Limits.MaxExcludeEntries
		}
		entries := make([]string, 0, len(dataset.entries))
		seen := make(map[string]struct{}, len(dataset.entries))
		for _, entry := range dataset.entries {
			if _, duplicate := seen[entry]; duplicate {
				continue
			}
			seen[entry] = struct{}{}
			entries = append(entries, entry)
		}
		if len(entries) > limit {
			return E.New("dataset ", id, " exceeds the configured entry limit of ", limit)
		}
		sortFeed(entries, dataset.kind)
		dataset.entries = entries
		if dataset.origin == listBundleOriginNotProvided && len(entries) != 0 {
			dataset.origin = listBundleOriginLocal
		}
	}
	return nil
}

// manifest builds the manifest header and the canonical dataset payloads.
func (run *refreshRun) manifest(previous *string) (ListBundleManifest, map[string][]string, error) {
	manifest := ListBundleManifest{
		Format:         ListBundleFormat,
		CreatedAt:      run.clock.Now().UTC().Format(time.RFC3339),
		RecipeRevision: ZapretRecipeRevision,
		Provider:       run.request.Provider,
		Acquisition:    run.request.Acquisition,
		Families:       append([]int{}, run.request.Families...),
		RequestSHA256:  run.request.RawSHA256(),
		Limits: ListBundleLimits{
			MaxEntries:        run.request.Limits.MaxEntries,
			MaxExcludeEntries: run.request.Limits.MaxExcludeEntries,
			MaxDecodedBytes:   run.request.Limits.MaxDecodedBytes,
			MaxTotalBytes:     run.request.Limits.MaxTotalBytes,
			TimeoutSeconds:    run.request.Limits.TimeoutSeconds,
		},
		Sources:    append([]ListBundleSource{}, run.sources...),
		Resolution: run.resolution,
		Datasets:   make([]ListBundleDataset, 0, len(ListBundleDatasetIDs())),
	}
	_ = previous
	if manifest.RequestSHA256 == "" {
		return manifest, nil, E.New("list refresh request cannot be hashed")
	}
	if manifest.Sources == nil {
		manifest.Sources = []ListBundleSource{}
	}
	if manifest.Resolution.Aggregation == nil {
		manifest.Resolution.Aggregation = &ListBundleAggregation{Families: []ListBundleAggregateFamily{}}
	}
	payloads := make(map[string][]string, len(ListBundleDatasetIDs()))
	for _, id := range ListBundleDatasetIDs() {
		dataset := run.datasets[id]
		base, kind, family, _ := listBundleDatasetSpec(id)
		_ = base
		payloads[id] = dataset.entries
		manifest.Datasets = append(manifest.Datasets, ListBundleDataset{
			ID:      id,
			Kind:    kind,
			Family:  family,
			Origin:  dataset.origin,
			Entries: len(dataset.entries),
			SHA256:  sha256OfLines(dataset.entries),
			Size:    int64(len(joinLines(dataset.entries))),
		})
	}
	return manifest, payloads, nil
}

func sha256OfLines(entries []string) string {
	sum := sha256.Sum256(joinLines(entries))
	return hex.EncodeToString(sum[:])
}

func joinLines(entries []string) []byte {
	var buffer bytes.Buffer
	for _, entry := range entries {
		buffer.WriteString(entry)
		buffer.WriteByte('\n')
	}
	return buffer.Bytes()
}

// verifyOutputBudget enforces the total output byte bound from the actual shard
// sizes before the commit point.
func verifyOutputBudget(manifest ListBundleManifest, limits RefreshLimits) error {
	total := int64(0)
	shards := 0
	decoded := int64(0)
	for _, dataset := range manifest.Datasets {
		for _, file := range dataset.Files {
			total += file.Size
			decoded += file.DecompressedSize
			shards++
		}
	}
	if total > limits.MaxTotalBytes || decoded > limits.MaxTotalBytes {
		return E.New("list bundle exceeds the configured total output limit")
	}
	if shards > listBundleMaxShards {
		return E.New("list bundle exceeds the shard limit")
	}
	return nil
}

func newGenerationID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", E.Cause(err, "generate list bundle generation")
	}
	return hex.EncodeToString(raw[:]), nil
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [4]byte
	position := len(digits)
	for value > 0 {
		position--
		digits[position] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[position:])
}

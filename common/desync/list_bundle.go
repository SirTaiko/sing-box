package desync

// Provider list bundle selection for the packet and stream compilers.
//
// The runtime never fetches, resolves or watches provider data. It resolves the
// optional `list_bundle` selector of a rule against one immutable
// `desync.list-bundle/v1` generation published by
// `sing-box tools desync list-refresh`:
//
//   * current.json is read once per distinct canonical bundle root per
//     compile/reload and that manifest value is pinned for every rule built by
//     the same call (packet and stream share one state);
//   * every referenced dataset is verified (hash, name, shard, entry and byte
//     budget) before its entries are published;
//   * the shared per-outbound selection budget is enforced before allocation
//     and deduplicates datasets referenced by several rules;
//   * a legacy per-file list read is bounded before allocation as well and is
//     accounted in the same per-outbound budget.

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sagernet/sing-box/common/desync/tools"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// listSelectionMaxBytes is the decoded byte budget of one outbound's
	// selected lists (bundle datasets plus legacy files), independent of the
	// smaller per-file legacy bound.
	listSelectionMaxBytes int64 = 512 << 20
	// listSelectionMaxEntries is the unique-record budget of one outbound.
	listSelectionMaxEntries int64 = 4194304
	// listBundleManifestMaxRead is the reader-side manifest bound (1 MiB).
	listBundleManifestMaxRead int64 = 1 << 20
)

// bundleRuleSelection is the compiled, path-resolved selector retained on a
// Rule so a reload rebuilds exactly the same selection from a new manifest.
type bundleRuleSelection struct {
	manifest      string
	domain        []string
	domainExclude []string
	ip            []string
	ipExclude     []string
}

// listBundleView is one pinned manifest value.
type listBundleView struct {
	root     string
	manifest tools.ListBundleManifest
}

// listBuildState is shared by the packet and stream compilers of one
// initial compile or one reload. It owns the manifest cache, the dataset cache,
// the aggregate selection budget and the list digest used to detect a changed
// publication.
type listBuildState struct {
	manifests   map[string]*listBundleView
	datasets    map[string][]string
	counted     map[string]struct{}
	totalBytes  int64
	totalEntry  int64
	digest      hash.Hash
	generations []string
}

func newListBuildState() *listBuildState {
	return &listBuildState{
		manifests: make(map[string]*listBundleView),
		datasets:  make(map[string][]string),
		counted:   make(map[string]struct{}),
		digest:    sha256.New(),
	}
}

// NewListBuildState creates one shared list build state for an outbound's
// packet and stream compiles. It is the only way two compilers share one
// pinned bundle generation and one selection budget.
func NewListBuildState() *listBuildState { return newListBuildState() }

// BundleGenerations exposes the generations read through this state.
func (s *listBuildState) BundleGenerations() []string { return s.bundleGenerations() }

// bundleGenerations returns the sorted unique generations read by this state.
func (s *listBuildState) bundleGenerations() []string {
	if s == nil || len(s.generations) == 0 {
		return nil
	}
	unique := make(map[string]struct{}, len(s.generations))
	for _, generation := range s.generations {
		unique[generation] = struct{}{}
	}
	generations := make([]string, 0, len(unique))
	for generation := range unique {
		generations = append(generations, generation)
	}
	sort.Strings(generations)
	return generations
}

// digestValue returns the digest of every distinct list source read by this
// state. A reload compares it with the last published value: only a changed
// successful publication increments the outbound list revision.
func (s *listBuildState) digestValue() [32]byte {
	var value [32]byte
	if s == nil {
		return value
	}
	copy(value[:], s.digest.Sum(nil))
	return value
}

func (s *listBuildState) recordDigest(key string, contentDigest []byte) {
	if s == nil {
		return
	}
	// Length-prefixed key and digest, so two adjacent sources can never
	// produce the same byte stream.
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(key)))
	s.digest.Write(length[:])
	s.digest.Write([]byte(key))
	s.digest.Write(contentDigest)
}

// account charges one distinct source against the outbound selection budget.
// Shared references (the same bundle dataset or the same legacy file selected
// by several rules) are charged exactly once.
func (s *listBuildState) account(key string, bytes int64, entries int) error {
	if s == nil {
		return nil
	}
	if _, counted := s.counted[key]; counted {
		return nil
	}
	if bytes < 0 || entries < 0 {
		return E.New("desync: invalid list source accounting")
	}
	if s.totalBytes+bytes > listSelectionMaxBytes {
		return E.New("desync: selected lists exceed the ", listSelectionMaxBytes, " byte budget")
	}
	if s.totalEntry+int64(entries) > listSelectionMaxEntries {
		return E.New("desync: selected lists exceed the ", listSelectionMaxEntries, " entry budget")
	}
	s.counted[key] = struct{}{}
	s.totalBytes += bytes
	s.totalEntry += int64(entries)
	return nil
}

// bundle loads (once per canonical root) and verifies one manifest value.
func (s *listBuildState) bundle(manifestPath string) (*listBundleView, error) {
	canonical, err := filepath.Abs(filepath.Clean(manifestPath))
	if err != nil {
		return nil, E.Cause(err, "desync: resolve list bundle manifest")
	}
	if len(canonical) > 4096 {
		return nil, E.New("desync: list bundle manifest path is too long")
	}
	if view, loaded := s.manifests[canonical]; loaded {
		return view, nil
	}
	data, err := readBoundedFile(canonical, int(listBundleManifestMaxRead))
	if err != nil {
		return nil, E.Cause(err, "desync: read list bundle manifest")
	}
	manifest, err := tools.DecodeListBundleManifest(data)
	if err != nil {
		return nil, E.Cause(err, "desync: decode list bundle manifest")
	}
	root := filepath.Dir(canonical)
	if err = tools.VerifyListBundle(root, manifest); err != nil {
		return nil, E.Cause(err, "desync: verify list bundle ", manifest.Generation)
	}
	view := &listBundleView{root: root, manifest: manifest}
	s.manifests[canonical] = view
	s.generations = append(s.generations, manifest.Generation)
	return view, nil
}

// dataset returns one verified dataset of a pinned manifest, read at most once
// per build state and charged once against the selection budget.
func (s *listBuildState) dataset(view *listBundleView, id string) ([]string, error) {
	cacheKey := view.root + "\x00" + id
	if entries, cached := s.datasets[cacheKey]; cached {
		return entries, nil
	}
	var declared *tools.ListBundleDataset
	for index := range view.manifest.Datasets {
		if view.manifest.Datasets[index].ID == id {
			declared = &view.manifest.Datasets[index]
			break
		}
	}
	if declared == nil {
		return nil, E.New("desync: list bundle generation ", view.manifest.Generation, " has no dataset ", id)
	}
	if len(declared.Files) == 0 {
		return nil, E.New("desync: list bundle dataset ", id, " has no shards")
	}
	var shardBytes int64
	for _, file := range declared.Files {
		shardBytes += file.DecompressedSize
	}
	if declared.Size != shardBytes {
		return nil, E.New("desync: list bundle dataset ", id, " size does not match its shards")
	}
	if err := s.account("bundle\x00"+view.manifest.Generation+"\x00"+id, declared.Size, declared.Entries); err != nil {
		return nil, err
	}
	entries, err := tools.ReadListBundleDataset(view.root, view.manifest, id)
	if err != nil {
		return nil, E.Cause(err, "desync: read list bundle dataset ", id)
	}
	if len(entries) != declared.Entries {
		return nil, E.New("desync: list bundle dataset ", id, " entry count mismatch")
	}
	contentDigest := sha256.Sum256([]byte("bundle\x00" + view.manifest.Generation + "\x00" + id + "\x00" + declared.SHA256))
	s.recordDigest("bundle\x00"+id, contentDigest[:])
	s.datasets[cacheKey] = entries
	return entries, nil
}

// readLegacyList reads a configuration list file with the legacy per-file
// bound, charged against the same outbound selection budget.
func (s *listBuildState) readLegacyList(path string) ([]string, error) {
	content, err := readBoundedFile(path, maxListFileBytes)
	if err != nil {
		return nil, err
	}
	lines, err := parseListContent(path, content)
	if err != nil {
		return nil, err
	}
	if err = s.account("file\x00"+path, int64(len(content)), len(lines)); err != nil {
		return nil, err
	}
	contentDigest := sha256.Sum256(content)
	s.recordDigest("file\x00"+path, contentDigest[:])
	return lines, nil
}

// resolveSelection validates one option selector and resolves it against the
// pinned manifest value. Dataset kind, family, negative-precedence and
// uniqueness rules are enforced here, before any entry reaches a matcher set.
func (s *listBuildState) resolveSelection(selector *option.DirectDesyncListBundle, baseDir string, rule *Rule) (*bundleRuleSelection, error) {
	if selector == nil {
		return nil, nil
	}
	if strings.TrimSpace(selector.Manifest) == "" {
		return nil, E.New("desync: list_bundle.manifest is required")
	}
	seen := make(map[string]string)
	checkUnique := func(values []string, group string) error {
		for _, id := range values {
			if id == "" {
				return E.New("desync: list_bundle.", group, " contains an empty dataset id")
			}
			if previous, duplicate := seen[id]; duplicate {
				return E.New("desync: list_bundle dataset ", id, " is selected more than once (", previous, " and ", group, ")")
			}
			seen[id] = group
		}
		return nil
	}
	if err := checkUnique(selector.Domain, "domain"); err != nil {
		return nil, err
	}
	if err := checkUnique(selector.DomainExclude, "domain_exclude"); err != nil {
		return nil, err
	}
	if err := checkUnique(selector.IPCIDR, "ip_cidr"); err != nil {
		return nil, err
	}
	if err := checkUnique(selector.IPCIDRExclude, "ip_cidr_exclude"); err != nil {
		return nil, err
	}
	if len(seen) == 0 {
		return nil, E.New("desync: list_bundle selects no dataset")
	}
	selectorPath := selector.Manifest
	if !filepath.IsAbs(selectorPath) {
		selectorPath = filepath.Join(baseDir, selectorPath)
	}
	view, err := s.bundle(selectorPath)
	if err != nil {
		return nil, err
	}
	datasets := make(map[string]*tools.ListBundleDataset, len(view.manifest.Datasets))
	for index := range view.manifest.Datasets {
		datasets[view.manifest.Datasets[index].ID] = &view.manifest.Datasets[index]
	}
	checkKind := func(values []string, group string, kind tools.ListKind) error {
		for _, id := range values {
			dataset, found := datasets[id]
			if !found {
				return E.New("desync: list_bundle.", group, " references unknown dataset ", id)
			}
			if dataset.Kind != kind {
				return E.New("desync: list_bundle.", group, " dataset ", id, " has kind ", string(dataset.Kind), ", want ", string(kind))
			}
			if kind == tools.ListKindIP {
				switch dataset.Family {
				case 4:
					if !rule.IPv4 {
						return E.New("desync: list_bundle.", group, " dataset ", id, " is IPv4-only but the rule excludes IPv4")
					}
				case 6:
					if !rule.IPv6 {
						return E.New("desync: list_bundle.", group, " dataset ", id, " is IPv6-only but the rule excludes IPv6")
					}
				default:
					return E.New("desync: list_bundle.", group, " dataset ", id, " has an invalid IP family")
				}
			}
		}
		return nil
	}
	if err = checkKind(selector.Domain, "domain", tools.ListKindDomain); err != nil {
		return nil, err
	}
	if err = checkKind(selector.DomainExclude, "domain_exclude", tools.ListKindDomain); err != nil {
		return nil, err
	}
	if err = checkKind(selector.IPCIDR, "ip_cidr", tools.ListKindIP); err != nil {
		return nil, err
	}
	if err = checkKind(selector.IPCIDRExclude, "ip_cidr_exclude", tools.ListKindIP); err != nil {
		return nil, err
	}
	// Negative precedence: a supplied nonempty exclusion dataset relevant to a
	// selected positive must be selected too. Silently dropping it would
	// re-include excluded traffic.
	selected := make(map[string]struct{}, len(seen))
	for id := range seen {
		selected[id] = struct{}{}
	}
	requireNegative := func(positive []string, negative []string, negativeID string) error {
		if len(positive) == 0 {
			return nil
		}
		dataset, found := datasets[negativeID]
		if !found || dataset.Entries == 0 {
			return nil
		}
		if _, ok := selected[negativeID]; ok {
			return nil
		}
		for _, selectedID := range negative {
			if selectedID == negativeID {
				return nil
			}
		}
		return E.New("desync: list_bundle provisioned nonempty ", negativeID, "; select it in the matching exclude array")
	}
	if err = requireNegative(selector.Domain, selector.DomainExclude, "exclude_hosts"); err != nil {
		return nil, err
	}
	if len(selector.IPCIDR) > 0 {
		for _, pair := range []struct {
			family   int
			negative string
		}{{4, "exclude_ip4"}, {6, "exclude_ip6"}} {
			positiveFamily := false
			for _, id := range selector.IPCIDR {
				if dataset, found := datasets[id]; found && dataset.Family == pair.family {
					positiveFamily = true
					break
				}
			}
			if !positiveFamily {
				continue
			}
			dataset, found := datasets[pair.negative]
			if !found || dataset.Entries == 0 {
				continue
			}
			if _, ok := selected[pair.negative]; ok {
				continue
			}
			return nil, E.New("desync: list_bundle provisioned nonempty ", pair.negative, "; select it in ip_cidr_exclude")
		}
	}
	return &bundleRuleSelection{
		manifest:      selectorPath,
		domain:        append([]string(nil), selector.Domain...),
		domainExclude: append([]string(nil), selector.DomainExclude...),
		ip:            append([]string(nil), selector.IPCIDR...),
		ipExclude:     append([]string(nil), selector.IPCIDRExclude...),
	}, nil
}

// applyBundle appends the selected positive datasets to the rule's retained
// bundle-derived entries and records that an explicit positive restriction
// exists even when every selected dataset is empty.
func (r *Rule) applyBundle(state *listBuildState) error {
	if r.bundleSelection == nil {
		return nil
	}
	selection := r.bundleSelection
	view, err := state.bundle(selection.manifest)
	if err != nil {
		return err
	}
	r.domainBundle = r.domainBundle[:0]
	r.domainExcludeBundle = r.domainExcludeBundle[:0]
	r.ipBundle = r.ipBundle[:0]
	r.ipExcludeBundle = r.ipExcludeBundle[:0]
	for _, id := range selection.domain {
		entries, readErr := state.dataset(view, id)
		if readErr != nil {
			return readErr
		}
		r.domainBundle = append(r.domainBundle, entries...)
		r.bundleDomainRestrict = true
	}
	for _, id := range selection.domainExclude {
		entries, readErr := state.dataset(view, id)
		if readErr != nil {
			return readErr
		}
		r.domainExcludeBundle = append(r.domainExcludeBundle, entries...)
	}
	for _, id := range selection.ip {
		entries, readErr := state.dataset(view, id)
		if readErr != nil {
			return readErr
		}
		r.ipBundle = append(r.ipBundle, entries...)
		r.bundleIPRestrict = true
	}
	for _, id := range selection.ipExclude {
		entries, readErr := state.dataset(view, id)
		if readErr != nil {
			return readErr
		}
		r.ipExcludeBundle = append(r.ipExcludeBundle, entries...)
	}
	return nil
}

// readBoundedFile is the shared bounded reader from capture_files.go. The
// bundle and legacy list paths additionally check the on-disk size before the
// stream read where the file is regular (see readListFile/readBoundedFile).

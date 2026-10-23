package tools

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Provider recipe and refresh request model.
//
// The recipe IDs below are data acquisition recipes of the pinned bol-van/zapret
// v72.9 scripts, not desync strategies, profiles or executable names. All work is
// explicit: nothing in this file runs on configuration load, starts a service,
// schedules a timer or invokes a shell.

const (
	// ProviderReestrPreresolved is get_reestr_preresolved.sh.
	ProviderReestrPreresolved = "reestr-preresolved"
	// ProviderReestrPreresolvedSmart is get_reestr_preresolved_smart.sh.
	ProviderReestrPreresolvedSmart = "reestr-preresolved-smart"
	// ProviderReestrResolvableDomains is get_reestr_resolvable_domains.sh.
	ProviderReestrResolvableDomains = "reestr-resolvable-domains"
	// ProviderAntifilterIP is get_antifilter_ip.sh.
	ProviderAntifilterIP = "antifilter-ip"
	// ProviderAntifilterIPResolve is get_antifilter_ipresolve.sh.
	ProviderAntifilterIPResolve = "antifilter-ipresolve"
	// ProviderAntifilterIPSum is get_antifilter_ipsum.sh.
	ProviderAntifilterIPSum = "antifilter-ipsum"
	// ProviderAntifilterAllYouNeed is get_antifilter_allyouneed.sh.
	ProviderAntifilterAllYouNeed = "antifilter-allyouneed"
	// ProviderAntifilterIPSmart is get_antifilter_ipsmart.sh.
	ProviderAntifilterIPSmart = "antifilter-ipsmart"
	// ProviderRefilterIPSum is get_refilter_ipsum.sh.
	ProviderRefilterIPSum = "refilter-ipsum"
	// ProviderRefilterDomains is get_refilter_domains.sh.
	ProviderRefilterDomains = "refilter-domains"
	// ProviderAntizapretDomains is get_antizapret_domains.sh.
	ProviderAntizapretDomains = "antizapret-domains"
	// ProviderUser is get_user.sh.
	ProviderUser = "user"
	// ProviderExclude is get_exclude.sh.
	ProviderExclude = "exclude"
	// ProviderIPBan is get_ipban.sh.
	ProviderIPBan = "ipban"
	// ProviderLocal is the explicit local import extension.
	ProviderLocal = "local"
	// ProviderEmpty is the safe clear adaptation.
	ProviderEmpty = "empty"

	// AcquisitionRemote fetches the fixed recipe URLs.
	AcquisitionRemote = "remote"
	// AcquisitionLocal imports explicit local snapshots and performs no HTTP.
	AcquisitionLocal = "local"

	// CompressionNone stores datasets as plain text.
	CompressionNone = "none"
	// CompressionGzip stores datasets as deterministic gzip members.
	CompressionGzip = "gzip"

	providerRequestMaxBytes = 1 << 20
	providerSourceMaxBytes  = 512 << 20
	providerLineMaxBytes    = 8192
	providerHeadersMaxBytes = 32 << 10
	providerURLMaxBytes     = 2048
	providerMaxRedirects    = 5
	providerMetaMaxBytes    = 256
	providerDefaultAttempts = 5
)

// ProviderSource is one fixed upstream list of a recipe.
type ProviderSource struct {
	// Dataset is the typed import dataset used by local acquisition:
	// hosts, ip4 or ip6.
	Dataset string
	// URL is the literal pinned URL of the source script.
	URL string
	// Family is 4, 6 or 0 for a domain source.
	Family int
	// MinimumBytes and MaximumBytes bound the raw body.
	MinimumBytes int64
	MaximumBytes int64
	// FilteredMinimumBytes, when non-zero, bounds the filtered IPv4 text after
	// the source cut_local phase (AntiFilter scripts).
	FilteredMinimumBytes int64
	// RequireGzip marks a source whose upstream script requires gzip.
	RequireGzip bool
	// DetectGzip accepts a gzip wire body in addition to text.
	DetectGzip bool
	// AcceptEncoding requests a gzip transfer coding.
	AcceptEncoding bool
	// AllowRedirects follows the upstream -L behaviour within a host allowlist.
	AllowRedirects bool
	// RedirectHosts lists additional exact hosts allowed after a redirect.
	RedirectHosts []string
	// ConnectTimeout and AttemptTimeout bound one connection and one attempt.
	ConnectTimeout time.Duration
	AttemptTimeout time.Duration
	// Attempts is the total HTTP attempt budget of the source.
	Attempts int
}

// ProviderRecipe is one fixed acquisition recipe.
type ProviderRecipe struct {
	ID      string
	Script  string
	Sources []ProviderSource
	// UserPhase is U (user), B (user + ipban), X (exclusions) or - (none).
	UserPhase string
	// AggregatesIPv4 marks the recipes whose script runs ip2net on the provider
	// feed after cut_local.
	AggregatesIPv4 bool
	// LocalOnly recipes never perform HTTP.
	LocalOnly bool
	// AllowsProviderData marks provider recipes that accept local snapshots.
	AllowsProviderData bool
	// RemovesUserPositive marks local/empty style recipes that reject a positive
	// user phase.
	RequiresLocalInputs bool
}

var providerRecipes = map[string]ProviderRecipe{
	ProviderReestrPreresolved: {
		ID:     ProviderReestrPreresolved,
		Script: "get_reestr_preresolved.sh",
		Sources: []ProviderSource{
			{
				Dataset: "ip4", Family: 4,
				URL:          "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_resolved4.txt",
				MinimumBytes: 4096, MaximumBytes: 4194304,
				DetectGzip: true, AcceptEncoding: true,
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 120 * time.Second, Attempts: 5,
			},
			{
				Dataset: "ip6", Family: 6,
				URL:          "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_resolved6.txt",
				MinimumBytes: 2048, MaximumBytes: 4194304,
				DetectGzip: true, AcceptEncoding: true,
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 120 * time.Second, Attempts: 5,
			},
		},
		UserPhase:          "U",
		AllowsProviderData: true,
	},
	ProviderReestrPreresolvedSmart: {
		ID:     ProviderReestrPreresolvedSmart,
		Script: "get_reestr_preresolved_smart.sh",
		Sources: []ProviderSource{
			{
				Dataset: "ip4", Family: 4,
				URL:          "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_smart4.txt",
				MinimumBytes: 4096, MaximumBytes: 4194304,
				DetectGzip: true, AcceptEncoding: true,
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 120 * time.Second, Attempts: 5,
			},
			{
				Dataset: "ip6", Family: 6,
				URL:          "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_smart6.txt",
				MinimumBytes: 2048, MaximumBytes: 4194304,
				DetectGzip: true, AcceptEncoding: true,
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 120 * time.Second, Attempts: 5,
			},
		},
		UserPhase:          "U",
		AllowsProviderData: true,
	},
	ProviderReestrResolvableDomains: {
		ID:     ProviderReestrResolvableDomains,
		Script: "get_reestr_resolvable_domains.sh",
		Sources: []ProviderSource{
			{
				Dataset: "hosts", Family: 0,
				URL:          "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname_resolvable.txt",
				MinimumBytes: 65536, MaximumBytes: 67108864,
				DetectGzip: true, AcceptEncoding: true,
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 120 * time.Second, Attempts: 5,
			},
		},
		UserPhase:          "B",
		AllowsProviderData: true,
	},
	ProviderAntifilterIP:         antifilterRecipe(ProviderAntifilterIP, "get_antifilter_ip.sh", "https://antifilter.download/list/ip.lst"),
	ProviderAntifilterIPResolve:  antifilterRecipe(ProviderAntifilterIPResolve, "get_antifilter_ipresolve.sh", "https://antifilter.download/list/ipresolve.lst"),
	ProviderAntifilterIPSum:      antifilterRecipe(ProviderAntifilterIPSum, "get_antifilter_ipsum.sh", "https://antifilter.download/list/ipsum.lst"),
	ProviderAntifilterAllYouNeed: antifilterRecipe(ProviderAntifilterAllYouNeed, "get_antifilter_allyouneed.sh", "https://antifilter.download/list/allyouneed.lst"),
	ProviderAntifilterIPSmart: antifilterRecipe(
		ProviderAntifilterIPSmart, "get_antifilter_ipsmart.sh", "https://antifilter.network/download/ipsmart.lst",
	),
	ProviderRefilterIPSum: {
		ID:     ProviderRefilterIPSum,
		Script: "get_refilter_ipsum.sh",
		Sources: []ProviderSource{
			{
				Dataset: "ip4", Family: 4,
				URL:          "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ipsum.lst",
				MinimumBytes: 32768, MaximumBytes: 4194304,
				DetectGzip: true, AcceptEncoding: true,
				AllowRedirects: true,
				RedirectHosts:  []string{"release-assets.githubusercontent.com", "objects.githubusercontent.com"},
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 60 * time.Second, Attempts: 5,
			},
		},
		UserPhase:          "U",
		AllowsProviderData: true,
	},
	ProviderRefilterDomains: {
		ID:     ProviderRefilterDomains,
		Script: "get_refilter_domains.sh",
		Sources: []ProviderSource{
			{
				Dataset: "hosts", Family: 0,
				URL:          "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/domains_all.lst",
				MinimumBytes: 32768, MaximumBytes: 4194304,
				DetectGzip: true, AcceptEncoding: true,
				AllowRedirects: true,
				RedirectHosts:  []string{"release-assets.githubusercontent.com", "objects.githubusercontent.com"},
				ConnectTimeout: 10 * time.Second, AttemptTimeout: 60 * time.Second, Attempts: 5,
			},
		},
		UserPhase:          "B",
		AllowsProviderData: true,
	},
	ProviderAntizapretDomains: {
		ID:     ProviderAntizapretDomains,
		Script: "get_antizapret_domains.sh",
		Sources: []ProviderSource{
			{
				Dataset: "hosts", Family: 0,
				URL:          "https://antizapret.prostovpn.org:8443/domains-export.txt",
				MinimumBytes: 0, MaximumBytes: 251658240,
				FilteredMinimumBytes: 102400,
				RequireGzip:          true,
				AcceptEncoding:       true,
				ConnectTimeout:       5 * time.Second, AttemptTimeout: 600 * time.Second, Attempts: 4,
			},
		},
		UserPhase:          "B",
		AllowsProviderData: true,
	},
	ProviderUser: {
		ID: ProviderUser, Script: "get_user.sh", UserPhase: "U", LocalOnly: true,
	},
	ProviderExclude: {
		ID: ProviderExclude, Script: "get_exclude.sh", UserPhase: "X", LocalOnly: true,
	},
	ProviderIPBan: {
		ID: ProviderIPBan, Script: "get_ipban.sh", UserPhase: "B", LocalOnly: true,
	},
	ProviderLocal: {
		ID: ProviderLocal, Script: "explicit import extension", LocalOnly: true,
		AllowsProviderData: true,
	},
	ProviderEmpty: {
		ID: ProviderEmpty, Script: "safe clear adaptation", LocalOnly: true,
	},
}

func antifilterRecipe(id string, script string, sourceURL string) ProviderRecipe {
	return ProviderRecipe{
		ID:     id,
		Script: script,
		Sources: []ProviderSource{
			{
				Dataset: "ip4", Family: 4, URL: sourceURL,
				MinimumBytes: 0, MaximumBytes: 41943040,
				FilteredMinimumBytes: 102400,
				DetectGzip:           true,
				AllowRedirects:       true,
				RedirectHosts:        []string{"antifilter.download", "antifilter.network"},
				ConnectTimeout:       20 * time.Second, AttemptTimeout: 150 * time.Second, Attempts: 1,
			},
		},
		UserPhase:          "U",
		AggregatesIPv4:     true,
		AllowsProviderData: true,
	}
}

// LookupProviderRecipe resolves the strict provider enum.
func LookupProviderRecipe(id string) (ProviderRecipe, error) {
	recipe, ok := providerRecipes[id]
	if !ok {
		return ProviderRecipe{}, E.New("unknown provider recipe ", id)
	}
	return recipe, nil
}

// ProviderRecipeIDs returns every accepted recipe ID in stable order.
func ProviderRecipeIDs() []string {
	return []string{
		ProviderReestrPreresolved, ProviderReestrPreresolvedSmart, ProviderReestrResolvableDomains,
		ProviderAntifilterIP, ProviderAntifilterIPResolve, ProviderAntifilterIPSum,
		ProviderAntifilterAllYouNeed, ProviderAntifilterIPSmart,
		ProviderRefilterIPSum, ProviderRefilterDomains, ProviderAntizapretDomains,
		ProviderUser, ProviderExclude, ProviderIPBan, ProviderLocal, ProviderEmpty,
	}
}

// RefreshSnapshot is one explicit local provider snapshot import.
type RefreshSnapshot struct {
	Dataset string `json:"dataset"`
	Path    string `json:"path"`
}

// RefreshInputs are explicit local inputs of one refresh. Absent means empty.
type RefreshInputs struct {
	UserHosts    []string `json:"user_hosts"`
	ExcludeHosts []string `json:"exclude_hosts"`
	IPBanHosts   []string `json:"ipban_hosts"`
	UserIP4      []string `json:"user_ip4"`
	UserIP6      []string `json:"user_ip6"`
	ExcludeIP4   []string `json:"exclude_ip4"`
	ExcludeIP6   []string `json:"exclude_ip6"`
	IPBanIP4     []string `json:"ipban_ip4"`
	IPBanIP6     []string `json:"ipban_ip6"`
}

// ResolveOptions are the existing mdig options of the user phase.
type ResolveOptions struct {
	Threads       int `json:"threads"`
	EAgain        int `json:"eagain"`
	EAgainDelayMS int `json:"eagain_delay_ms"`
}

// AggregateOptions are typed ip2net options. A zero value is the upstream
// default of the family; flag instances always send checked values.
type AggregateOptions struct {
	IPv4 AggregateFamily `json:"ipv4"`
	IPv6 AggregateFamily `json:"ipv6"`
}

// AggregateFamily is one family of the aggregate request.
type AggregateFamily struct {
	PrefixLength string `json:"prefix_length"`
	Threshold    any    `json:"threshold"`
}

// RefreshLimits bound one refresh invocation.
type RefreshLimits struct {
	MaxEntries        int   `json:"max_entries"`
	MaxExcludeEntries int   `json:"max_exclude_entries"`
	MaxDecodedBytes   int64 `json:"max_decoded_bytes"`
	MaxTotalBytes     int64 `json:"max_total_bytes"`
	TimeoutSeconds    int   `json:"timeout_seconds"`
}

// ListRefreshRequest is the desync.list-refresh/v1 request document.
type ListRefreshRequest struct {
	Format      string            `json:"format"`
	Provider    string            `json:"provider"`
	Acquisition string            `json:"acquisition"`
	Families    []int             `json:"families"`
	Snapshots   []RefreshSnapshot `json:"snapshots"`
	Inputs      RefreshInputs     `json:"inputs"`
	Compression string            `json:"compression"`
	Resolve     ResolveOptions    `json:"resolve"`
	Aggregate   AggregateOptions  `json:"aggregate"`
	Limits      RefreshLimits     `json:"limits"`

	rawJSON []byte
}

// DefaultListRefreshRequest returns the exact documented defaults. The capacity
// default translates config.default SET_MAXELEM (522288), not def.sh's fallback
// 262144 and not Engine.max_leases.
func DefaultListRefreshRequest() ListRefreshRequest {
	return ListRefreshRequest{
		Format:      ListRefreshRequestFormat,
		Provider:    ProviderReestrPreresolved,
		Acquisition: AcquisitionRemote,
		Families:    []int{4, 6},
		Snapshots:   []RefreshSnapshot{},
		Compression: CompressionGzip,
		Resolve: ResolveOptions{
			Threads:       30,
			EAgain:        10,
			EAgainDelayMS: 500,
		},
		Aggregate: AggregateOptions{
			IPv4: AggregateFamily{PrefixLength: "22-30", Threshold: "3/4"},
			IPv6: AggregateFamily{PrefixLength: "56-64", Threshold: 5},
		},
		Limits: RefreshLimits{
			MaxEntries:        522288,
			MaxExcludeEntries: 65536,
			MaxDecodedBytes:   134217728,
			MaxTotalBytes:     536870912,
			TimeoutSeconds:    600,
		},
	}
}

// DecodeListRefreshRequest strictly decodes one request document. Unknown and
// duplicate keys, trailing documents, wrong types and a request above 1 MiB are
// rejected before any file is opened or any request is sent.
func DecodeListRefreshRequest(data []byte) (ListRefreshRequest, error) {
	var request ListRefreshRequest
	if len(data) == 0 {
		return request, E.New("empty list-refresh request")
	}
	if len(data) > providerRequestMaxBytes {
		return request, E.New("list-refresh request exceeds ", providerRequestMaxBytes, " bytes")
	}
	var raw map[string]json.RawMessage
	if err := decodeStrictJSONIntoMap(data, &raw); err != nil {
		return request, err
	}
	defaults := DefaultListRefreshRequest()
	request = defaults
	// Field defaults are applied per absent field so an explicit zero is rejected
	// by the range validation below instead of silently becoming a default.
	if err := decodeStrictJSON(data, &request); err != nil {
		return request, E.Cause(err, "decode list-refresh request")
	}
	if _, present := raw["format"]; !present {
		return request, E.New("list-refresh request is missing format")
	}
	if request.Format != ListRefreshRequestFormat {
		return request, E.New("unexpected list-refresh format ", request.Format)
	}
	if _, present := raw["families"]; !present {
		request.Families = defaults.Families
	}
	if _, present := raw["snapshots"]; !present {
		request.Snapshots = []RefreshSnapshot{}
	}
	if _, present := raw["compression"]; !present {
		request.Compression = defaults.Compression
	}
	if _, present := raw["resolve"]; !present {
		request.Resolve = defaults.Resolve
	}
	if _, present := raw["aggregate"]; !present {
		request.Aggregate = defaults.Aggregate
	}
	if _, present := raw["limits"]; !present {
		request.Limits = defaults.Limits
	}
	if _, present := raw["inputs"]; !present {
		request.Inputs = RefreshInputs{}
	}
	if err := request.Validate(); err != nil {
		return request, err
	}
	request.rawJSON = append([]byte{}, data...)
	return request, nil
}

func decodeStrictJSONIntoMap(data []byte, target *map[string]json.RawMessage) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return E.Cause(err, "decode list-refresh request")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return E.Cause(err, "decode list-refresh request")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return E.New("trailing JSON document")
		}
		return E.Cause(err, "trailing JSON document")
	}
	return nil
}

// Validate applies the exact request bounds and the recipe applicability rules.
func (r *ListRefreshRequest) Validate() error {
	recipe, err := LookupProviderRecipe(r.Provider)
	if err != nil {
		return err
	}
	switch r.Acquisition {
	case AcquisitionRemote:
		if recipe.LocalOnly {
			return E.New("provider ", r.Provider, " requires local acquisition")
		}
		if len(r.Snapshots) != 0 {
			return E.New("remote acquisition does not accept local snapshots")
		}
	case AcquisitionLocal:
		if !recipe.AllowsProviderData && !recipe.LocalOnly {
			return E.New("provider ", r.Provider, " does not accept local acquisition")
		}
	default:
		return E.New("acquisition must be remote or local")
	}
	if len(r.Families) == 0 {
		return E.New("families must not be empty")
	}
	seenFamily := make(map[int]struct{}, len(r.Families))
	for _, family := range r.Families {
		if family != 4 && family != 6 {
			return E.New("families may only contain 4 and 6")
		}
		if _, duplicate := seenFamily[family]; duplicate {
			return E.New("duplicate family ", family)
		}
		seenFamily[family] = struct{}{}
	}
	switch r.Compression {
	case CompressionNone, CompressionGzip:
	default:
		return E.New("compression must be none or gzip")
	}
	if r.Resolve.Threads < 1 || r.Resolve.Threads > 100 {
		return E.New("resolve.threads must be within 1..100")
	}
	if r.Resolve.EAgain < 1 || r.Resolve.EAgain > 1000 {
		return E.New("resolve.eagain must be within 1..1000")
	}
	if r.Resolve.EAgainDelayMS < 0 || r.Resolve.EAgainDelayMS > 100000 {
		return E.New("resolve.eagain_delay_ms must be within 0..100000")
	}
	if r.Limits.MaxEntries < 1 || r.Limits.MaxEntries > listBundleMaxEntries {
		return E.New("limits.max_entries must be within 1..", listBundleMaxEntries)
	}
	if r.Limits.MaxExcludeEntries < 1 || r.Limits.MaxExcludeEntries > listBundleMaxEntries {
		return E.New("limits.max_exclude_entries must be within 1..", listBundleMaxEntries)
	}
	if r.Limits.MaxDecodedBytes < 1 || r.Limits.MaxDecodedBytes > providerSourceMaxBytes {
		return E.New("limits.max_decoded_bytes must be within 1..", providerSourceMaxBytes)
	}
	if r.Limits.MaxTotalBytes < 1 || r.Limits.MaxTotalBytes > providerSourceMaxBytes {
		return E.New("limits.max_total_bytes must be within 1..", providerSourceMaxBytes)
	}
	if r.Limits.TimeoutSeconds < 1 || r.Limits.TimeoutSeconds > 3600 {
		return E.New("limits.timeout_seconds must be within 1..3600")
	}
	if err = r.validateAggregate(recipe); err != nil {
		return err
	}
	if err = r.validateSnapshots(recipe); err != nil {
		return err
	}
	if err = r.validateInputs(recipe); err != nil {
		return err
	}
	return nil
}

func (r *ListRefreshRequest) validateAggregate(recipe ProviderRecipe) error {
	defaults := DefaultListRefreshRequest().Aggregate
	if recipe.AggregatesIPv4 {
		if err := validateAggregateFamily(r.Aggregate.IPv4, 4, defaults.IPv4); err != nil {
			return err
		}
		if !aggregateFamilyIsDefault(r.Aggregate.IPv6, defaults.IPv6) {
			return E.New("aggregate.ipv6 is not applicable to provider ", recipe.ID)
		}
		return nil
	}
	if !aggregateFamilyIsDefault(r.Aggregate.IPv4, defaults.IPv4) ||
		!aggregateFamilyIsDefault(r.Aggregate.IPv6, defaults.IPv6) {
		return E.New("aggregate options are not applicable to provider ", recipe.ID)
	}
	return nil
}

func aggregateFamilyIsDefault(value AggregateFamily, defaults AggregateFamily) bool {
	return value.PrefixLength == defaults.PrefixLength && fmtAny(value.Threshold) == fmtAny(defaults.Threshold)
}

func fmtAny(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'g', -1, 64)
	case int:
		return strconv.Itoa(typed)
	default:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	}
}

func validateAggregateFamily(value AggregateFamily, family int, defaults AggregateFamily) error {
	if value.PrefixLength == defaults.PrefixLength && fmtAny(value.Threshold) == fmtAny(defaults.Threshold) {
		return nil
	}
	minimum, maximum, err := parseProviderPrefixLength(fmtAny(value.PrefixLength), family)
	if err != nil {
		return err
	}
	if minimum == 0 || maximum == 0 || maximum < minimum {
		return E.New("invalid aggregate prefix_length")
	}
	bounds := 32
	if family == 6 {
		bounds = 128
	}
	if maximum > bounds {
		return E.New("aggregate prefix_length exceeds the family width")
	}
	if family == 4 {
		mul, div, err := parseProviderRatio(fmtAny(value.Threshold))
		if err != nil {
			return err
		}
		if mul < 1 || div < 2 || mul >= div {
			return E.New("invalid IPv4 aggregate threshold")
		}
		return nil
	}
	threshold, err := parseProviderUint32(fmtAny(value.Threshold))
	if err != nil || threshold < 1 {
		return E.New("invalid IPv6 aggregate threshold")
	}
	return nil
}

func parseProviderPrefixLength(value string, family int) (int, int, error) {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, E.New("invalid aggregate prefix_length")
	}
	minimum, err := parseProviderUint32(parts[0])
	if err != nil {
		return 0, 0, E.New("invalid aggregate prefix_length")
	}
	maximum, err := parseProviderUint32(parts[1])
	if err != nil {
		return 0, 0, E.New("invalid aggregate prefix_length")
	}
	_ = family
	return int(minimum), int(maximum), nil
}

func parseProviderRatio(value string) (uint32, uint32, error) {
	mulText, divText, found := strings.Cut(value, "/")
	if !found {
		return 0, 0, E.New("invalid aggregate threshold")
	}
	mul, err := parseProviderUint32(mulText)
	if err != nil {
		return 0, 0, E.New("invalid aggregate threshold")
	}
	div, err := parseProviderUint32(divText)
	if err != nil {
		return 0, 0, E.New("invalid aggregate threshold")
	}
	return mul, div, nil
}

func parseProviderUint32(value string) (uint32, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, E.New("empty number")
	}
	parsed, err := strconv.ParseUint(trimmed, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func (r *ListRefreshRequest) validateSnapshots(recipe ProviderRecipe) error {
	if r.Acquisition != AcquisitionLocal {
		if len(r.Snapshots) != 0 {
			return E.New("remote acquisition does not accept local snapshots")
		}
		return nil
	}
	if recipe.LocalOnly && !recipe.AllowsProviderData {
		if len(r.Snapshots) != 0 {
			return E.New("provider ", recipe.ID, " does not accept snapshots")
		}
		return nil
	}
	if len(recipe.Sources) == 0 {
		// The explicit local import extension accepts typed snapshots only.
		seen := make(map[string]struct{}, len(r.Snapshots))
		if len(r.Snapshots) == 0 {
			return E.New("provider ", recipe.ID, " requires typed snapshots")
		}
		for _, snapshot := range r.Snapshots {
			if snapshot.Path == "" {
				return E.New("snapshot path is required")
			}
			switch snapshot.Dataset {
			case "hosts", "ip4", "ip6":
			default:
				return E.New("snapshot dataset must be hosts, ip4 or ip6")
			}
			if _, duplicate := seen[snapshot.Dataset]; duplicate {
				return E.New("duplicate snapshot dataset ", snapshot.Dataset)
			}
			seen[snapshot.Dataset] = struct{}{}
		}
		return nil
	}
	if len(r.Snapshots) == 0 {
		return E.New("local acquisition of provider ", recipe.ID, " requires snapshots for every active source")
	}
	active := make(map[string]struct{})
	for _, source := range recipe.Sources {
		if source.Family == 0 || r.familySelected(source.Family) {
			active[source.Dataset] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(r.Snapshots))
	for _, snapshot := range r.Snapshots {
		if snapshot.Path == "" {
			return E.New("snapshot path is required")
		}
		switch snapshot.Dataset {
		case "hosts", "ip4", "ip6":
		default:
			return E.New("snapshot dataset must be hosts, ip4 or ip6")
		}
		if _, duplicate := seen[snapshot.Dataset]; duplicate {
			return E.New("duplicate snapshot dataset ", snapshot.Dataset)
		}
		seen[snapshot.Dataset] = struct{}{}
		if _, wanted := active[snapshot.Dataset]; !wanted {
			return E.New("snapshot dataset ", snapshot.Dataset, " is not an active source of ", recipe.ID)
		}
	}
	for dataset := range active {
		if _, provided := seen[dataset]; !provided {
			return E.New("missing snapshot for active source ", dataset)
		}
	}
	return nil
}

func (r *ListRefreshRequest) familySelected(family int) bool {
	for _, candidate := range r.Families {
		if candidate == family {
			return true
		}
	}
	return false
}

func (r *ListRefreshRequest) validateInputs(recipe ProviderRecipe) error {
	inputs := r.Inputs
	hasExclude := len(inputs.ExcludeHosts)+len(inputs.ExcludeIP4)+len(inputs.ExcludeIP6) > 0
	hasIPBan := len(inputs.IPBanHosts)+len(inputs.IPBanIP4)+len(inputs.IPBanIP6) > 0
	hasUser := len(inputs.UserHosts)+len(inputs.UserIP4)+len(inputs.UserIP6) > 0
	countLists := func(lists []string) error {
		for _, list := range lists {
			if len(list) == 0 {
				return E.New("empty input path")
			}
		}
		return nil
	}
	for _, lists := range [][]string{
		inputs.UserHosts, inputs.ExcludeHosts, inputs.IPBanHosts,
		inputs.UserIP4, inputs.UserIP6, inputs.ExcludeIP4, inputs.ExcludeIP6,
		inputs.IPBanIP4, inputs.IPBanIP6,
	} {
		if err := countLists(lists); err != nil {
			return err
		}
		if len(lists) > 32 {
			return E.New("an input role accepts at most 32 explicit files")
		}
	}
	switch recipe.ID {
	case ProviderEmpty:
		if hasUser || hasExclude || hasIPBan || len(r.Snapshots) != 0 {
			return E.New("provider empty forbids inputs and snapshots")
		}
	case ProviderUser:
		if hasExclude || hasIPBan || len(r.Snapshots) != 0 {
			return E.New("provider user accepts only user inputs")
		}
	case ProviderExclude:
		if hasUser || hasIPBan || len(r.Snapshots) != 0 {
			return E.New("provider exclude accepts only exclude inputs")
		}
	case ProviderIPBan:
		if hasUser || len(r.Snapshots) != 0 {
			return E.New("provider ipban accepts only exclude and ipban inputs")
		}
	case ProviderLocal:
		if len(r.Snapshots) == 0 && !hasUser && !hasExclude && !hasIPBan {
			return E.New("provider local requires typed snapshots or explicit inputs")
		}
	default:
		_ = recipe
	}
	return nil
}

// ProviderDependencies are the injected acquisition dependencies of one refresh.
// Nil HTTP or resolver required by the selected work is an error at the library
// boundary: there is never an implicit network fallback.
type ProviderDependencies struct {
	HTTP     ProviderHTTPClient
	Resolver MDigResolver
	Clock    MDigClock
}

// ProviderHTTPClient is the injectable HTTP seam. Tests pass a client that fails
// the test when a request is attempted.
type ProviderHTTPClient interface {
	Do(request *http.Request) (*http.Response, error)
}

// SystemProviderClock returns the real clock adapter for the production
// constructors. Tests inject their own clock.
func SystemProviderClock() MDigClock {
	return systemClock{}
}

// ProviderFinalURL removes query and fragment from a final URL. Redirected
// GitHub downloads may carry expiring query credentials; only the origin, path
// and a hash of the complete URL are durable provenance.
func ProviderFinalURL(final *url.URL) string {
	if final == nil {
		return ""
	}
	clone := *final
	clone.RawQuery = ""
	clone.ForceQuery = false
	clone.Fragment = ""
	clone.User = nil
	return clone.String()
}

// providerSourceID is the stable source identifier used in provenance.
func providerSourceID(recipe ProviderRecipe, source ProviderSource, index int) string {
	return recipe.ID + "/" + source.Dataset + "/" + strconv.Itoa(index)
}

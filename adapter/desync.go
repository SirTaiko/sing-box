package adapter

import (
	"context"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Optional outbound diagnostics contract for the direct desync feature.
//
// The adapter owns plain value DTOs only: no Engine pointer, no native handle,
// no callback, no io.Reader and no open map payload. A direct outbound
// implements OutboundDesyncDiagnostics even when desync is disabled, so an
// operator can always ask for its state without instantiating an Engine.

const (
	// DesyncDiagnosticsFormat is the versioned snapshot format.
	DesyncDiagnosticsFormat = "desync.diagnostics/v1"
	// DesyncReloadFormat is the versioned reload result format.
	DesyncReloadFormat = "desync.reload/v1"
	// DesyncErrorFormat is the versioned error document format.
	DesyncErrorFormat = "desync.error/v1"

	// DesyncDefaultDiagnosticsLimit is the default row limit of one section.
	DesyncDefaultDiagnosticsLimit uint16 = 128
	// DesyncMaxDiagnosticsLimit is the accepted explicit row limit.
	DesyncMaxDiagnosticsLimit uint16 = 1024
)

// DesyncDiagnosticKind is the requested diagnostic section.
type DesyncDiagnosticKind uint8

const (
	// DesyncDiagnosticStatus is the zero value and the default section.
	DesyncDiagnosticStatus DesyncDiagnosticKind = iota
	DesyncDiagnosticConntrack
	DesyncDiagnosticFailurePool
	DesyncDiagnosticIPCache
	DesyncDiagnosticWindowsNetwork
	DesyncDiagnosticCaptureFilter
)

// String returns the stable wire spelling of the kind.
func (k DesyncDiagnosticKind) String() string {
	switch k {
	case DesyncDiagnosticStatus:
		return "status"
	case DesyncDiagnosticConntrack:
		return "conntrack"
	case DesyncDiagnosticFailurePool:
		return "failure-pool"
	case DesyncDiagnosticIPCache:
		return "ipcache"
	case DesyncDiagnosticWindowsNetwork:
		return "windows-network"
	case DesyncDiagnosticCaptureFilter:
		return "capture-filter"
	default:
		return "unknown"
	}
}

// ParseDesyncDiagnosticKind parses the wire spelling. The empty string selects
// the status section.
func ParseDesyncDiagnosticKind(value string) (DesyncDiagnosticKind, error) {
	switch value {
	case "", "status":
		return DesyncDiagnosticStatus, nil
	case "conntrack":
		return DesyncDiagnosticConntrack, nil
	case "failure-pool":
		return DesyncDiagnosticFailurePool, nil
	case "ipcache":
		return DesyncDiagnosticIPCache, nil
	case "windows-network":
		return DesyncDiagnosticWindowsNetwork, nil
	case "capture-filter":
		return DesyncDiagnosticCaptureFilter, nil
	default:
		return 0, E.New("unknown desync diagnostic kind ", value)
	}
}

// DesyncDiagnosticsRequest is one validated inspection request.
type DesyncDiagnosticsRequest struct {
	Kind             DesyncDiagnosticKind
	Limit            uint16
	IncludeSensitive bool
	AllNetworks      bool
}

// Validate applies the documented ranges and section applicability. It runs at
// the HTTP boundary and again inside the optional interface implementation.
func (r DesyncDiagnosticsRequest) Validate() (DesyncDiagnosticsRequest, error) {
	if r.Kind > DesyncDiagnosticCaptureFilter {
		return r, E.New("unknown desync diagnostic kind")
	}
	if r.Limit == 0 {
		r.Limit = DesyncDefaultDiagnosticsLimit
	}
	if r.Limit > DesyncMaxDiagnosticsLimit {
		return r, E.New("desync diagnostics limit must be within 1..", DesyncMaxDiagnosticsLimit)
	}
	if r.AllNetworks && r.Kind != DesyncDiagnosticWindowsNetwork {
		return r, E.New("all_networks is only legal for the windows-network section")
	}
	return r, nil
}

// OutboundDesyncDiagnostics is the optional interface a direct outbound
// implements. The handler resolves exactly one outbound by tag and asserts it;
// it never chases a selector, a default outbound or another group.
type OutboundDesyncDiagnostics interface {
	DesyncDiagnostics(ctx context.Context, request DesyncDiagnosticsRequest) (DesyncDiagnosticsSnapshot, error)
	ReloadDesyncLists(ctx context.Context) (DesyncReloadResult, error)
}

// DesyncOutboundState is the lifecycle state of one outbound's desync engine.
type DesyncOutboundState string

const (
	DesyncStateDisabled   DesyncOutboundState = "disabled"
	DesyncStateNotStarted DesyncOutboundState = "not_started"
	DesyncStateRunning    DesyncOutboundState = "running"
	DesyncStateClosed     DesyncOutboundState = "closed"
)

// DesyncDiagnosticsSnapshot is the desync.diagnostics/v1 document. Exactly one
// kind-specific payload is set. Total is null when an exact total is unknown.
type DesyncDiagnosticsSnapshot struct {
	Format         string                       `json:"format"`
	Outbound       string                       `json:"outbound"`
	State          DesyncOutboundState          `json:"state"`
	Kind           string                       `json:"kind"`
	Redacted       bool                         `json:"redacted"`
	CapturedAt     string                       `json:"captured_at"`
	Total          *uint64                      `json:"total"`
	Returned       uint64                       `json:"returned"`
	Truncated      bool                         `json:"truncated"`
	Status         *DesyncStatusPayload         `json:"status,omitempty"`
	Conntrack      *DesyncConntrackPayload      `json:"conntrack,omitempty"`
	FailurePool    *DesyncFailurePoolPayload    `json:"failure_pool,omitempty"`
	IPCache        *DesyncIPCachePayload        `json:"ipcache,omitempty"`
	WindowsNetwork *DesyncWindowsNetworkPayload `json:"windows_network,omitempty"`
	CaptureFilters *DesyncCaptureFilterPayload  `json:"capture_filters,omitempty"`
}

// DesyncBundleGeneration names one loaded immutable bundle generation.
type DesyncBundleGeneration struct {
	Generation string `json:"generation"`
}

// DesyncActivationStatus is the cached native activation view. Active is null
// when the platform reports unknown; a zero LastChecked means unknown.
type DesyncActivationStatus struct {
	Configured  bool    `json:"configured"`
	Active      *bool   `json:"active"`
	LastChecked *string `json:"last_checked"`
	ErrorCode   string  `json:"error_code,omitempty"`
}

// DesyncStatusPayload is the status section.
type DesyncStatusPayload struct {
	PacketEnabled          bool                     `json:"packet_enabled"`
	StreamEnabled          bool                     `json:"stream_enabled"`
	Backend                string                   `json:"backend"`
	ActiveLeases           uint64                   `json:"active_leases"`
	HeldBytes              uint64                   `json:"held_bytes"`
	ListRevision           uint64                   `json:"list_revision"`
	BundleGenerations      []DesyncBundleGeneration `json:"bundle_generations"`
	ConntrackEnabled       bool                     `json:"conntrack_enabled"`
	LearningEnabled        bool                     `json:"learning_enabled"`
	IPCacheHostnameEnabled bool                     `json:"ipcache_hostname_enabled"`
	Activation             DesyncActivationStatus   `json:"activation"`
}

// DesyncCutoffs are the observed stream cutoffs of one conntrack entry.
type DesyncCutoffs struct {
	Desync    uint64 `json:"desync"`
	Original  uint64 `json:"original"`
	Duplicate uint64 `json:"duplicate"`
	Window    uint64 `json:"window"`
}

// DesyncConntrackRow is one conntrack entry snapshot. Endpoint strings are only
// present in sensitive mode.
type DesyncConntrackRow struct {
	Family           uint8         `json:"family"`
	Transport        string        `json:"transport"`
	State            string        `json:"state"`
	AgeMs            uint64        `json:"age_ms"`
	IdleMs           uint64        `json:"idle_ms"`
	ExpiresInMs      uint64        `json:"expires_in_ms"`
	PacketsOrig      uint64        `json:"packets_orig"`
	DataPacketsOrig  uint64        `json:"data_packets_orig"`
	SequenceOrig     uint64        `json:"sequence_orig"`
	PacketsReply     uint64        `json:"packets_reply"`
	DataPacketsReply uint64        `json:"data_packets_reply"`
	SequenceReply    uint64        `json:"sequence_reply"`
	Retransmits      uint64        `json:"retransmits"`
	WindowOrig       uint64        `json:"window_orig"`
	WindowReply      uint64        `json:"window_reply"`
	ScaleOrig        uint64        `json:"scale_orig"`
	ScaleReply       uint64        `json:"scale_reply"`
	HopCount         *uint8        `json:"hop_count"`
	Cutoffs          DesyncCutoffs `json:"cutoffs"`
	Source           *string       `json:"source,omitempty"`
	Destination      *string       `json:"destination,omitempty"`
}

// DesyncConntrackPayload is the conntrack section.
type DesyncConntrackPayload struct {
	Enabled bool                 `json:"enabled"`
	Rows    []DesyncConntrackRow `json:"rows"`
}

// DesyncFailurePoolRow is one learner failure entry. The current key is a host,
// not a rule identifier.
type DesyncFailurePoolRow struct {
	Count       uint64  `json:"count"`
	ExpiresInMs uint64  `json:"expires_in_ms"`
	Host        *string `json:"host,omitempty"`
}

// DesyncFailurePoolPayload is the failure-pool section.
type DesyncFailurePoolPayload struct {
	Enabled bool                   `json:"enabled"`
	Rows    []DesyncFailurePoolRow `json:"rows"`
}

// DesyncIPCacheRow is one hostname cache entry. A null expiry means explicitly
// no expiry, not a zero TTL.
type DesyncIPCacheRow struct {
	HostnamePresent bool    `json:"hostname_present"`
	HostnameIsIP    bool    `json:"hostname_is_ip"`
	Hops            *uint8  `json:"hops"`
	AgeMs           uint64  `json:"age_ms"`
	ExpiresInMs     *uint64 `json:"expires_in_ms"`
	Address         *string `json:"address,omitempty"`
	Interface       *string `json:"interface,omitempty"`
	Hostname        *string `json:"hostname,omitempty"`
}

// DesyncIPCachePayload is the ipcache section.
type DesyncIPCachePayload struct {
	Enabled bool               `json:"enabled"`
	Rows    []DesyncIPCacheRow `json:"rows"`
}

// DesyncWirelessNetwork is one wireless network view.
type DesyncWirelessNetwork struct {
	State         string  `json:"state"`
	InterfaceGUID *string `json:"interface_guid,omitempty"`
	Description   *string `json:"description,omitempty"`
	SSID          *string `json:"ssid,omitempty"`
}

// DesyncNetworkEntry is one NLM network view.
type DesyncNetworkEntry struct {
	Connected bool    `json:"connected"`
	Internet  bool    `json:"internet"`
	Category  string  `json:"category"`
	ID        *string `json:"id,omitempty"`
	Name      *string `json:"name,omitempty"`
	Adapters  *uint64 `json:"adapters,omitempty"`
}

// DesyncNetworkAdapter is one adapter view.
type DesyncNetworkAdapter struct {
	Index *uint32 `json:"index,omitempty"`
	GUID  *string `json:"guid,omitempty"`
	Name  *string `json:"name,omitempty"`
}

// DesyncWindowsNetworkTotals are the per-array totals. Null means the exact
// total is unknown because a native enumeration cap was reached.
type DesyncWindowsNetworkTotals struct {
	Wireless *uint64 `json:"wireless"`
	Networks *uint64 `json:"networks"`
	Adapters *uint64 `json:"adapters"`
}

// DesyncWindowsNetworkPayload is the windows-network section.
type DesyncWindowsNetworkPayload struct {
	QueriedAt string                     `json:"queried_at"`
	Wireless  []DesyncWirelessNetwork    `json:"wireless"`
	Networks  []DesyncNetworkEntry       `json:"networks"`
	Adapters  []DesyncNetworkAdapter     `json:"adapters"`
	Totals    DesyncWindowsNetworkTotals `json:"totals"`
}

// DesyncCaptureFilterRow is one currently owned capture filter. Expressions are
// only present in sensitive mode.
type DesyncCaptureFilterRow struct {
	Family               uint8   `json:"family"`
	Transport            string  `json:"transport"`
	OutboundInstructions uint64  `json:"outbound_instructions"`
	InboundPresent       bool    `json:"inbound_present"`
	Source               *string `json:"source,omitempty"`
	Destination          *string `json:"destination,omitempty"`
	Interface            *string `json:"interface,omitempty"`
	InterfaceIndex       *uint32 `json:"interface_index,omitempty"`
	OutboundExpression   *string `json:"outbound_expression,omitempty"`
	InboundExpression    *string `json:"inbound_expression,omitempty"`
}

// DesyncCaptureFilterPayload is the capture-filter section.
type DesyncCaptureFilterPayload struct {
	Rows []DesyncCaptureFilterRow `json:"rows"`
}

// DesyncReloadResult is the desync.reload/v1 document.
type DesyncReloadResult struct {
	Format            string                   `json:"format"`
	Outbound          string                   `json:"outbound"`
	State             DesyncOutboundState      `json:"state"`
	ListRevision      uint64                   `json:"list_revision"`
	Changed           bool                     `json:"changed"`
	BundleGenerations []DesyncBundleGeneration `json:"bundle_generations"`
	RetainedLastGood  bool                     `json:"retained_last_good"`
}

// DesyncDiagnosticError is the only error shape that is safe for transport.
// Underlying errors stay private and are redacted.
type DesyncDiagnosticError struct {
	Code             string
	RetainedLastGood bool
}

func (e DesyncDiagnosticError) Error() string { return e.Code }

// RedactDesyncDiagnosticsSnapshot removes every optional sensitive field and
// caps oversized strings. It is idempotent and never changes counts.
func RedactDesyncDiagnosticsSnapshot(snapshot DesyncDiagnosticsSnapshot) DesyncDiagnosticsSnapshot {
	snapshot.Redacted = true
	if snapshot.Status != nil {
		snapshot.Status.Activation.ErrorCode = capString(snapshot.Status.Activation.ErrorCode, 64)
	}
	if snapshot.Conntrack != nil {
		rows := make([]DesyncConntrackRow, len(snapshot.Conntrack.Rows))
		copy(rows, snapshot.Conntrack.Rows)
		for index := range rows {
			rows[index].Source = nil
			rows[index].Destination = nil
		}
		payload := *snapshot.Conntrack
		payload.Rows = rows
		snapshot.Conntrack = &payload
	}
	if snapshot.FailurePool != nil {
		rows := make([]DesyncFailurePoolRow, len(snapshot.FailurePool.Rows))
		copy(rows, snapshot.FailurePool.Rows)
		for index := range rows {
			rows[index].Host = nil
		}
		payload := *snapshot.FailurePool
		payload.Rows = rows
		snapshot.FailurePool = &payload
	}
	if snapshot.IPCache != nil {
		rows := make([]DesyncIPCacheRow, len(snapshot.IPCache.Rows))
		copy(rows, snapshot.IPCache.Rows)
		for index := range rows {
			rows[index].Address = nil
			rows[index].Interface = nil
			rows[index].Hostname = nil
		}
		payload := *snapshot.IPCache
		payload.Rows = rows
		snapshot.IPCache = &payload
	}
	if snapshot.WindowsNetwork != nil {
		wireless := make([]DesyncWirelessNetwork, len(snapshot.WindowsNetwork.Wireless))
		copy(wireless, snapshot.WindowsNetwork.Wireless)
		for index := range wireless {
			wireless[index].InterfaceGUID = nil
			wireless[index].Description = nil
			wireless[index].SSID = nil
		}
		networks := make([]DesyncNetworkEntry, len(snapshot.WindowsNetwork.Networks))
		copy(networks, snapshot.WindowsNetwork.Networks)
		for index := range networks {
			networks[index].ID = nil
			networks[index].Name = nil
		}
		adapters := make([]DesyncNetworkAdapter, len(snapshot.WindowsNetwork.Adapters))
		copy(adapters, snapshot.WindowsNetwork.Adapters)
		for index := range adapters {
			adapters[index].GUID = nil
			adapters[index].Name = nil
			adapters[index].Index = nil
		}
		payload := *snapshot.WindowsNetwork
		payload.Wireless = wireless
		payload.Networks = networks
		payload.Adapters = adapters
		snapshot.WindowsNetwork = &payload
	}
	if snapshot.CaptureFilters != nil {
		rows := make([]DesyncCaptureFilterRow, len(snapshot.CaptureFilters.Rows))
		copy(rows, snapshot.CaptureFilters.Rows)
		for index := range rows {
			rows[index].Source = nil
			rows[index].Destination = nil
			rows[index].Interface = nil
			rows[index].InterfaceIndex = nil
			rows[index].OutboundExpression = nil
			rows[index].InboundExpression = nil
		}
		payload := *snapshot.CaptureFilters
		payload.Rows = rows
		snapshot.CaptureFilters = &payload
	}
	return snapshot
}

// CapDesyncSensitiveString applies the documented per-field cap to an optional
// sensitive string supplied by an implementation that chose sensitive mode.
func CapDesyncSensitiveString(value *string, limit int) *string {
	if value == nil {
		return nil
	}
	capped := capString(*value, limit)
	return &capped
}

func capString(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}

// DesyncSensitiveFieldLimits are the documented caps of sensitive strings.
const (
	DesyncSensitiveHostLimit   = 253
	DesyncSensitiveNameLimit   = 256
	DesyncSensitiveFilterLimit = 16384
)

var _ = time.Time{}

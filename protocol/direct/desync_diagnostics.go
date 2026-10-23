package direct

// Optional runtime diagnostics and explicit reload for a direct outbound.
//
// The exported surface is the existing adapter.OutboundDesyncDiagnostics:
// no new RPC, listener, daemon or state owner is introduced. A disabled direct
// outbound still implements the interface and answers `status` with
// state=disabled without allocating an Engine or touching the platform.

import (
	"context"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
)

var _ adapter.OutboundDesyncDiagnostics = (*Outbound)(nil)

func (h *Outbound) desyncOutboundState() adapter.DesyncOutboundState {
	if h.desync == nil && h.stream == nil {
		return adapter.DesyncStateDisabled
	}
	if h.desync != nil && h.desync.Closed() {
		return adapter.DesyncStateClosed
	}
	if !h.desyncStarted.Load() {
		return adapter.DesyncStateNotStarted
	}
	return adapter.DesyncStateRunning
}

func desyncSnapshotError(code string, retainedLastGood bool) error {
	return adapter.DesyncDiagnosticError{Code: code, RetainedLastGood: retainedLastGood}
}

// DesyncDiagnostics returns one bounded typed section of this outbound's
// existing state. Sections are copied under the existing locks and assembled
// after release; no TTL probe, learning step or activation query is performed.
func (h *Outbound) DesyncDiagnostics(ctx context.Context, request adapter.DesyncDiagnosticsRequest) (adapter.DesyncDiagnosticsSnapshot, error) {
	request, err := request.Validate()
	if err != nil {
		return adapter.DesyncDiagnosticsSnapshot{}, desyncSnapshotError("invalid_request", false)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state := h.desyncOutboundState()
	snapshot := adapter.DesyncDiagnosticsSnapshot{
		Format:     adapter.DesyncDiagnosticsFormat,
		Outbound:   h.Tag(),
		State:      state,
		Kind:       request.Kind.String(),
		CapturedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if request.Kind == adapter.DesyncDiagnosticStatus {
		total := uint64(1)
		snapshot.Total = &total
		snapshot.Returned = 1
		if state == adapter.DesyncStateDisabled {
			active := true
			snapshot.Status = &adapter.DesyncStatusPayload{
				Activation: adapter.DesyncActivationStatus{Active: &active},
			}
			return snapshot, nil
		}
		status := h.desync.DiagnosticsStatus()
		snapshot.Status = &status
		return snapshot, nil
	}
	switch state {
	case adapter.DesyncStateDisabled:
		return adapter.DesyncDiagnosticsSnapshot{}, desyncSnapshotError("disabled", false)
	case adapter.DesyncStateNotStarted:
		return adapter.DesyncDiagnosticsSnapshot{}, desyncSnapshotError("not_started", false)
	case adapter.DesyncStateClosed:
		return adapter.DesyncDiagnosticsSnapshot{}, desyncSnapshotError("closed", false)
	}
	limit := int(request.Limit)
	switch request.Kind {
	case adapter.DesyncDiagnosticConntrack:
		rows, total, truncated := h.desync.DiagnosticsConntrack(limit, request.IncludeSensitive)
		snapshot.Conntrack = &adapter.DesyncConntrackPayload{Enabled: rows != nil || total > 0 || h.desync.PacketEnabled(), Rows: rows}
		setDesyncSection(&snapshot, total, len(rows), truncated)
	case adapter.DesyncDiagnosticFailurePool:
		rows, total, truncated := h.desync.DiagnosticsFailurePool(limit, request.IncludeSensitive)
		snapshot.FailurePool = &adapter.DesyncFailurePoolPayload{Enabled: h.desync.LearningEnabled(), Rows: rows}
		setDesyncSection(&snapshot, total, len(rows), truncated)
	case adapter.DesyncDiagnosticIPCache:
		rows, total, truncated := h.desync.DiagnosticsIPCache(limit, request.IncludeSensitive)
		snapshot.IPCache = &adapter.DesyncIPCachePayload{Enabled: true, Rows: rows}
		setDesyncSection(&snapshot, total, len(rows), truncated)
	case adapter.DesyncDiagnosticWindowsNetwork:
		payload, queryErr := h.desync.DiagnosticsWindowsNetwork(ctx, request.AllNetworks, limit, request.IncludeSensitive)
		if queryErr != nil {
			return adapter.DesyncDiagnosticsSnapshot{}, queryErr
		}
		snapshot.WindowsNetwork = &payload
		if payload.Totals.Wireless != nil && payload.Totals.Networks != nil && payload.Totals.Adapters != nil {
			total := *payload.Totals.Wireless + *payload.Totals.Networks + *payload.Totals.Adapters
			snapshot.Total = &total
		}
		returned := uint64(len(payload.Wireless) + len(payload.Networks) + len(payload.Adapters))
		snapshot.Returned = returned
		snapshot.Truncated = snapshot.Total == nil || *snapshot.Total > returned
	case adapter.DesyncDiagnosticCaptureFilter:
		if runtime.GOOS != "windows" {
			return adapter.DesyncDiagnosticsSnapshot{}, desyncSnapshotError("platform_inapplicable", false)
		}
		rows, total, truncated := h.desync.DiagnosticsCaptureFilters(limit, request.IncludeSensitive)
		snapshot.CaptureFilters = &adapter.DesyncCaptureFilterPayload{Rows: rows}
		setDesyncSection(&snapshot, total, len(rows), truncated)
	default:
		return adapter.DesyncDiagnosticsSnapshot{}, desyncSnapshotError("invalid_request", false)
	}
	return snapshot, nil
}

func setDesyncSection(snapshot *adapter.DesyncDiagnosticsSnapshot, total uint64, returned int, truncated bool) {
	snapshot.Total = &total
	snapshot.Returned = uint64(returned)
	snapshot.Truncated = truncated
}

// ReloadDesyncLists stages packet lists, stream lists and the configured
// learned state as one transaction through the existing Engine authority. On
// any failure the previous snapshot and revision remain active.
func (h *Outbound) ReloadDesyncLists(ctx context.Context) (adapter.DesyncReloadResult, error) {
	switch h.desyncOutboundState() {
	case adapter.DesyncStateDisabled:
		return adapter.DesyncReloadResult{}, desyncSnapshotError("disabled", false)
	case adapter.DesyncStateNotStarted:
		return adapter.DesyncReloadResult{}, desyncSnapshotError("not_started", false)
	case adapter.DesyncStateClosed:
		return adapter.DesyncReloadResult{}, desyncSnapshotError("closed", false)
	}
	if h.desync == nil {
		return adapter.DesyncReloadResult{}, desyncSnapshotError("disabled", false)
	}
	changed, err := h.desync.ReloadListsContext(ctx)
	if err != nil {
		if err == desync.ErrReloadBusy {
			return adapter.DesyncReloadResult{}, desyncSnapshotError("busy", false)
		}
		return adapter.DesyncReloadResult{}, desyncSnapshotError("reload_failed", true)
	}
	result := adapter.DesyncReloadResult{
		Format:       adapter.DesyncReloadFormat,
		Outbound:     h.Tag(),
		State:        adapter.DesyncStateRunning,
		ListRevision: h.desync.ListRevision(),
		Changed:      changed,
	}
	for _, generation := range h.desync.BundleGenerations() {
		result.BundleGenerations = append(result.BundleGenerations, adapter.DesyncBundleGeneration{Generation: generation})
	}
	return result, nil
}

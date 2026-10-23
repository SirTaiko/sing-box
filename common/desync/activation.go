package desync

// WLAN SSID / NLM network activation gate and the typed query/dump entrypoints
// that a later explicit tool (D5) can attach to.
//
// Source: nfq/darkmagic.c logical_net_filter_match():
//
//	activation = wlan_filter_match(ssid_filter) && nlm_filter_match(nlm_filter)
//
// Both predicates are "no filter configured means always matches". On any
// query error upstream treats the predicate as false, so capture goes passive
// instead of shutting the process down. The same behaviour is kept here: an
// error deactivates the gate, records the error for the operator, and every
// packet passes untouched. The gate is rate limited to one query per second,
// exactly like logical_net_filter_match_rate_limited().

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// activationQueryInterval is the upstream rate limit of the logical network
// predicate (GetTickCount() / 1000).
const activationQueryInterval = time.Second

// NetworkProbe is the platform seam for WLAN/NLM queries. The production
// implementation on Windows uses the real WLAN API and Network List Manager;
// tests inject a deterministic probe, and non-Windows platforms have no
// production implementation because capture.windows is not applicable there.
type NetworkProbe interface {
	// MatchSSID reports whether one of the connected WLAN SSIDs equals one of
	// the configured SSIDs (exact, case-sensitive, like upstream).
	MatchSSID(ctx context.Context, ssids []string) (bool, error)
	// MatchNLM reports whether one of the connected Network List Manager
	// networks matches one of the configured names or GUIDs.
	MatchNLM(ctx context.Context, networks []string) (bool, error)
	// Snapshot enumerates the current WLAN interfaces, NLM networks and
	// adapters for the typed export entrypoint.
	Snapshot(ctx context.Context) (WindowsNetworkSnapshot, error)
}

// WindowsNetworkSnapshot is the typed, platform-neutral result of the native
// Windows network query. It is deliberately a value snapshot: no handle,
// COM pointer or enumeration state escapes the query.
type WindowsNetworkSnapshot struct {
	Wireless  []WirelessNetwork `json:"wireless,omitempty"`
	Networks  []LogicalNetwork  `json:"networks,omitempty"`
	Adapters  []NetworkAdapter  `json:"adapters,omitempty"`
	QueriedAt time.Time         `json:"queried_at"`
}

// WirelessNetwork is one WLAN interface and its current connection.
type WirelessNetwork struct {
	InterfaceGUID string `json:"interface_guid"`
	Description   string `json:"description,omitempty"`
	State         string `json:"state"`
	SSID          string `json:"ssid,omitempty"`
}

// LogicalNetwork is one Network List Manager network.
type LogicalNetwork struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Connected bool     `json:"connected"`
	Internet  bool     `json:"internet"`
	Category  string   `json:"category"`
	Adapters  []string `json:"adapters,omitempty"`
}

// NetworkAdapter maps an adapter GUID to its human name and interface index,
// which is the same index a WinDivert filter compares against.
type NetworkAdapter struct {
	GUID  string `json:"guid"`
	Name  string `json:"name,omitempty"`
	Index uint32 `json:"index,omitempty"`
}

// ActivationStatus is the typed state of the SSID/NLM activation gate.
type ActivationStatus struct {
	Configured  bool      `json:"configured"`
	Active      bool      `json:"active"`
	LastChecked time.Time `json:"last_checked"`
	LastError   string    `json:"last_error,omitempty"`
}

// CaptureFilterDump is the typed activation dump of the composed kernel
// filters. It is the D5 attachment point for the explicit filter-save tool.
type CaptureFilterDump struct {
	Outbound     string `json:"outbound"`
	Inbound      string `json:"inbound"`
	Instructions int    `json:"outbound_instructions"`
}

// SetNetworkProbe installs the platform seam. It exists for hermetic tests and
// for a platform host that supplies its own query implementation; production
// Windows uses the built-in native probe.
func (e *Engine) SetNetworkProbe(probe NetworkProbe) {
	e.probeMu.Lock()
	e.probe = probe
	e.probeMu.Unlock()
	e.activation.reset()
}

func (e *Engine) networkProbe() NetworkProbe {
	e.probeMu.Lock()
	probe := e.probe
	e.probeMu.Unlock()
	if probe != nil {
		return probe
	}
	return defaultNetworkProbe()
}

// activationConfigured reports whether the configuration asks for SSID/NLM
// gating at all. A configuration without those filters never queries the OS.
func (e *Engine) activationConfigured() bool {
	capture := e.Config().Capture
	if capture.windows == nil {
		return false
	}
	return len(capture.windows.ssidFilter) > 0 || len(capture.windows.nlmFilter) > 0
}

// activationAllows is the per-packet gate. It is cheap when unconfigured
// (a nil check), rate limited when configured, and never fatal: an
// unavailable or failing query means "inactive", so packets pass untouched and
// the capture keeps its cleanup guarantees.
func (e *Engine) activationAllows() bool {
	capture := e.Config().Capture
	if capture.windows == nil {
		return true
	}
	ssids, networks := capture.windows.ssidFilter, capture.windows.nlmFilter
	if len(ssids) == 0 && len(networks) == 0 {
		return true
	}
	return e.activation.check(e, ssids, networks)
}

type activationGate struct {
	mu        sync.Mutex
	checked   bool
	lastCheck time.Time
	active    bool
	lastErr   error
}

func (g *activationGate) reset() {
	g.mu.Lock()
	g.checked = false
	g.lastCheck = time.Time{}
	g.active = false
	g.lastErr = nil
	g.mu.Unlock()
}

func (g *activationGate) check(engine *Engine, ssids, networks []string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := engine.currentTime()
	if g.checked && now.Sub(g.lastCheck) < activationQueryInterval {
		return g.active
	}
	g.checked, g.lastCheck = true, now
	g.active, g.lastErr = evaluateActivation(engine.networkProbe(), ssids, networks)
	return g.active
}

// evaluateActivation applies the upstream AND of the two predicates. A nil
// probe (no platform implementation) or a failed query is inactive and keeps
// the error for diagnostics.
func evaluateActivation(probe NetworkProbe, ssids, networks []string) (bool, error) {
	if len(ssids) == 0 && len(networks) == 0 {
		return true, nil
	}
	if probe == nil {
		return false, fmt.Errorf("desync: WLAN/NLM activation is unavailable on this platform")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*activationQueryInterval)
	defer cancel()
	if len(ssids) > 0 {
		matched, err := probe.MatchSSID(ctx, ssids)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	if len(networks) > 0 {
		matched, err := probe.MatchNLM(ctx, networks)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

// ActivationStatus returns the last known state of the SSID/NLM gate without
// forcing a query.
func (e *Engine) ActivationStatus() ActivationStatus {
	status := ActivationStatus{Configured: e.activationConfigured()}
	e.activation.mu.Lock()
	status.Active = e.activation.active
	status.LastChecked = e.activation.lastCheck
	if e.activation.lastErr != nil {
		status.LastError = e.activation.lastErr.Error()
	}
	e.activation.mu.Unlock()
	if !status.Configured {
		status.Active = true
	}
	return status
}

// QueryWindowsNetwork returns a typed snapshot of the native Windows WLAN/NLM
// state. It is the explicit, operator-initiated query entrypoint for later
// tooling; it never starts a background poller and never writes configuration.
func (e *Engine) QueryWindowsNetwork(ctx context.Context) (WindowsNetworkSnapshot, error) {
	probe := e.networkProbe()
	if probe == nil {
		return WindowsNetworkSnapshot{}, fmt.Errorf("desync: native network query is only available on Windows")
	}
	return probe.Snapshot(ctx)
}

// CaptureFilterDump returns the composed owned capture filter for one endpoint
// as typed text. It is the D5 attachment point for the explicit filter-save
// tool: it performs no write and opens no native resource.
func (e *Engine) CaptureFilterDump(endpoint Endpoint) (CaptureFilterDump, error) {
	capture := e.Config().Capture
	if capture.windows == nil {
		return CaptureFilterDump{}, fmt.Errorf("desync: capture.windows is not configured")
	}
	outbound, err := capture.windows.captureFilter(endpoint, true)
	if err != nil {
		return CaptureFilterDump{}, err
	}
	dump := CaptureFilterDump{Outbound: outbound.Expression(), Instructions: outbound.InstructionCount()}
	if endpoint.Destination.IsValid() {
		inboundEndpoint := endpoint
		inboundEndpoint.Source, inboundEndpoint.Destination = endpoint.Destination, endpoint.Source
		inbound, inboundErr := capture.windows.captureFilter(inboundEndpoint, false)
		if inboundErr != nil {
			return CaptureFilterDump{}, inboundErr
		}
		dump.Inbound = inbound.Expression()
	}
	return dump, nil
}

package desync

// Runtime diagnostics snapshots for the optional adapter interface.
//
// Every snapshot is a bounded, read-only copy of state this Engine already owns:
// packet conntrack, the shared hostlist-auto learner, the per-outbound IP/hop
// cache, the active leases' owned endpoints and the cached activation gate. No
// snapshot purges a table, refreshes a TTL, learns a host, triggers an
// activation query, opens a native handle or widens capture. Copying happens
// under the existing per-structure lock; sorting and DTO assembly happen after
// the lock is released. At most `limit` rows are kept per section through a
// bounded top-K scan, so an unbounded table is never copied merely to trim it.

import (
	"container/heap"
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sort"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

// NetworkQueryOptions is the optional query scope of the explicit
// windows-network diagnostics kind. All extends the default connected-only
// enumeration to every NLM network; Limit bounds each native array.
type NetworkQueryOptions struct {
	All   bool
	Limit uint16
}

// NetworkProbeWithOptions is the optional extension of NetworkProbe. A platform
// probe that can honour an explicit all/bounded query implements it. Existing
// NetworkProbe.Snapshot stays connected-only and compatible.
type NetworkProbeWithOptions interface {
	SnapshotWithOptions(ctx context.Context, options NetworkQueryOptions) (WindowsNetworkSnapshot, error)
}

// ErrNativeScopeUnsupported reports that the configured native probe cannot
// honour an explicit all-networks scope. It is an actionable capability error,
// never a connected-only success.
var ErrNativeScopeUnsupported = E.New("desync: all_networks is not supported by this native probe")

// errNativeQueryBusy reports that another explicit native query owns this
// outbound. Native queries are serialized, never queued.
var errNativeQueryBusy = E.New("desync: native network query already in progress")

// QueryWindowsNetworkWithOptions is the explicit operator query. The connected
// default is unchanged; All is honoured only by a probe that implements the
// optional bounded scope, and is an actionable error otherwise, never a
// connected-only success.
func (e *Engine) QueryWindowsNetworkWithOptions(ctx context.Context, options NetworkQueryOptions) (WindowsNetworkSnapshot, error) {
	if options.Limit > 1024 {
		return WindowsNetworkSnapshot{}, E.New("desync: native query limit exceeds 1024")
	}
	if !e.nativeQueryMu.TryLock() {
		return WindowsNetworkSnapshot{}, errNativeQueryBusy
	}
	defer e.nativeQueryMu.Unlock()
	if err := ctx.Err(); err != nil {
		return WindowsNetworkSnapshot{}, err
	}
	probe := e.networkProbe()
	if probe == nil {
		return WindowsNetworkSnapshot{}, E.New("desync: native network query is only available on Windows")
	}
	if withOptions, ok := probe.(NetworkProbeWithOptions); ok {
		return withOptions.SnapshotWithOptions(ctx, options)
	}
	if options.All {
		return WindowsNetworkSnapshot{}, ErrNativeScopeUnsupported
	}
	return probe.Snapshot(ctx)
}

// PacketEnabled reports whether this outbound owns a native packet backend. A
// stream-only outbound uses the same state owner but no capture backend.
func (e *Engine) PacketEnabled() bool {
	return e.backend != nil && e.backend.Name() != (stateOnlyBackend{}).Name()
}

// HeldBytes is the engine-wide held-byte budget currently in use.
func (e *Engine) HeldBytes() uint64 {
	value := e.heldBytes.Load()
	if value < 0 {
		return 0
	}
	return uint64(value)
}

// DiagnosticsStatus builds the status section from cached state only. It never
// performs an OS probe.
func (e *Engine) DiagnosticsStatus() adapter.DesyncStatusPayload {
	activation := adapter.DesyncActivationStatus{}
	cached := e.ActivationStatus()
	activation.Configured = cached.Configured
	switch {
	case !cached.Configured:
		active := true
		activation.Active = &active
	case cached.LastChecked.IsZero():
		// Unknown: the gate has never been evaluated.
	case cached.LastError != "":
		active := false
		activation.Active = &active
		activation.ErrorCode = "native_query_failed"
	default:
		active := cached.Active
		activation.Active = &active
	}
	if !cached.LastChecked.IsZero() {
		checked := cached.LastChecked.UTC().Format(time.RFC3339Nano)
		activation.LastChecked = &checked
	}
	generations := make([]adapter.DesyncBundleGeneration, 0, len(e.BundleGenerations()))
	for _, generation := range e.BundleGenerations() {
		generations = append(generations, adapter.DesyncBundleGeneration{Generation: generation})
	}
	return adapter.DesyncStatusPayload{
		PacketEnabled:          e.PacketEnabled(),
		StreamEnabled:          e.stream != nil,
		Backend:                e.backendName(),
		ActiveLeases:           uint64(e.ActiveLeases()),
		HeldBytes:              e.HeldBytes(),
		ListRevision:           e.ListRevision(),
		BundleGenerations:      generations,
		ConntrackEnabled:       !e.conntrack.disabled,
		LearningEnabled:        e.learning != nil,
		IPCacheHostnameEnabled: e.ipcache.config.hostnameEnabled,
		Activation:             activation,
	}
}

func (e *Engine) backendName() string {
	if !e.PacketEnabled() {
		return ""
	}
	return e.backend.Name()
}

// sectionResult is one bounded section copy plus its live total.
type sectionResult[T any] struct {
	samples   sampleHeap[T]
	rows      []T
	total     uint64
	truncated bool
}

// boundedSamples keeps at most limit samples with the smallest stable key.
type keyedSample[T any] struct {
	order string
	value T
}

type sampleHeap[T any] []keyedSample[T]

func (h sampleHeap[T]) Len() int           { return len(h) }
func (h sampleHeap[T]) Less(i, j int) bool { return h[i].order > h[j].order }
func (h sampleHeap[T]) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *sampleHeap[T]) Push(value any)    { *h = append(*h, value.(keyedSample[T])) }
func (h *sampleHeap[T]) Pop() any {
	old := *h
	last := old[len(old)-1]
	*h = old[:len(old)-1]
	return last
}

func (r *sectionResult[T]) add(order string, value T, limit int) {
	r.total++
	if limit <= 0 {
		return
	}
	if r.samples == nil {
		r.samples = make(sampleHeap[T], 0, limit)
	}
	if len(r.samples) < limit {
		heap.Push(&r.samples, keyedSample[T]{order: order, value: value})
		return
	}
	if order < r.samples[0].order {
		heap.Pop(&r.samples)
		heap.Push(&r.samples, keyedSample[T]{order: order, value: value})
	}
}

func (r *sectionResult[T]) finish() {
	sort.Slice(r.samples, func(left, right int) bool { return r.samples[left].order < r.samples[right].order })
	r.rows = make([]T, 0, len(r.samples))
	for _, sample := range r.samples {
		r.rows = append(r.rows, sample.value)
	}
	r.truncated = r.total > uint64(len(r.rows))
}

// DiagnosticsConntrack copies at most limit live entries, deterministically
// ordered by tuple. It does not purge, refresh or write the table.
func (e *Engine) DiagnosticsConntrack(limit int, sensitive bool) (rows []adapter.DesyncConntrackRow, total uint64, truncated bool) {
	if e.conntrack == nil || e.conntrack.disabled {
		return nil, 0, false
	}
	samples := sectionResult[adapter.DesyncConntrackRow]{}
	now := e.currentTime()
	e.conntrack.mu.Lock()
	for key, entry := range e.conntrack.entries {
		if entry == nil {
			continue
		}
		entry.mu.Lock()
		if !entry.expired {
			row := conntrackRow(key, entry, now, e.conntrack.timeouts, sensitive)
			samples.add(conntrackKeyOrder(key), row, limit)
		}
		entry.mu.Unlock()
	}
	e.conntrack.mu.Unlock()
	samples.finish()
	return samples.rows, samples.total, samples.truncated
}

func conntrackRow(key conntrackKey, entry *conntrackEntry, now time.Time, timeouts conntrackTimeouts, sensitive bool) adapter.DesyncConntrackRow {
	sem := entry.sem
	row := adapter.DesyncConntrackRow{
		Family:           uint8(key.family),
		Transport:        transportName(key.transport),
		State:            sem.state.String(),
		AgeMs:            positiveMillis(now.Sub(entry.start)),
		IdleMs:           positiveMillis(now.Sub(entry.last)),
		ExpiresInMs:      positiveMillis(timeouts.established - now.Sub(entry.last)),
		PacketsOrig:      sem.counters.packets,
		DataPacketsOrig:  sem.counters.dataPackets,
		SequenceOrig:     sem.counters.sequence,
		PacketsReply:     sem.counters.replyPackets,
		DataPacketsReply: sem.counters.replyData,
		SequenceReply:    sem.counters.replySequence,
		Retransmits:      sem.retransmits,
		WindowOrig:       uint64(sem.winsizeOrig),
		WindowReply:      uint64(sem.winsizeReply),
		ScaleOrig:        unsignedScale(sem.scaleOrig),
		ScaleReply:       unsignedScale(sem.scaleReply),
		Cutoffs: adapter.DesyncCutoffs{
			Desync:    boolCount(sem.latches.desync),
			Original:  boolCount(sem.latches.origMod),
			Duplicate: boolCount(sem.latches.dup),
			Window:    boolCount(sem.latches.wssize),
		},
	}
	if sem.haveHop {
		hop := sem.hopCount
		row.HopCount = &hop
	}
	if sensitive {
		row.Source = stringPointer(netipAddrPort(key.src, key.srcPort))
		row.Destination = stringPointer(netipAddrPort(key.dst, key.dstPort))
	}
	return row
}

// DiagnosticsFailurePool copies the shared learner's current failure entries.
func (e *Engine) DiagnosticsFailurePool(limit int, sensitive bool) (rows []adapter.DesyncFailurePoolRow, total uint64, truncated bool) {
	if e.learning == nil {
		return nil, 0, false
	}
	samples := sectionResult[adapter.DesyncFailurePoolRow]{}
	now := e.currentTime()
	e.learning.mu.Lock()
	for host, counter := range e.learning.fails {
		if counter == nil || !counter.expire.After(now) {
			continue
		}
		row := adapter.DesyncFailurePoolRow{
			Count:       uint64(counter.count),
			ExpiresInMs: positiveMillis(counter.expire.Sub(now)),
		}
		if sensitive {
			row.Host = stringPointer(host)
		}
		samples.add(host, row, limit)
	}
	e.learning.mu.Unlock()
	samples.finish()
	return samples.rows, samples.total, samples.truncated
}

// DiagnosticsIPCache copies the per-outbound hostname/hop cache. A null expiry
// means explicitly no expiry, not a zero TTL.
func (e *Engine) DiagnosticsIPCache(limit int, sensitive bool) (rows []adapter.DesyncIPCacheRow, total uint64, truncated bool) {
	if e.ipcache == nil {
		return nil, 0, false
	}
	samples := sectionResult[adapter.DesyncIPCacheRow]{}
	now := e.currentTime()
	e.ipcache.mu.Lock()
	for key, entry := range e.ipcache.entries {
		if entry == nil {
			continue
		}
		row := adapter.DesyncIPCacheRow{
			HostnamePresent: entry.hostnameSet && entry.hostname != "",
			HostnameIsIP:    entry.hostnameIsIP,
			AgeMs:           positiveMillis(now.Sub(entry.last)),
		}
		if entry.hopsSet {
			hops := entry.hops
			row.Hops = &hops
		}
		if !e.ipcache.config.noExpiry {
			expires := e.ipcache.config.lifetime - now.Sub(entry.last)
			value := positiveMillis(expires)
			row.ExpiresInMs = &value
		}
		if sensitive {
			row.Address = stringPointer(key.address.String())
			row.Interface = stringPointer(key.iface)
			if row.HostnamePresent {
				row.Hostname = stringPointer(entry.hostname)
			}
		}
		samples.add(key.address.String()+"\x00"+key.iface, row, limit)
	}
	e.ipcache.mu.Unlock()
	samples.finish()
	return samples.rows, samples.total, samples.truncated
}

// DiagnosticsCaptureFilters copies the currently owned live endpoints of this
// outbound and asks the existing dump entrypoint for their composed filters. It
// never accepts a caller tuple, widens capture or opens a native handle.
func (e *Engine) DiagnosticsCaptureFilters(limit int, sensitive bool) (rows []adapter.DesyncCaptureFilterRow, total uint64, truncated bool) {
	config := e.Config()
	if config == nil || config.Capture.windows == nil {
		return nil, 0, false
	}
	type ownedEndpoint struct {
		endpoint Endpoint
		order    string
	}
	endpoints := make([]ownedEndpoint, 0, limit)
	e.mu.Lock()
	for lease := range e.leases {
		if lease == nil {
			continue
		}
		lease.mu.Lock()
		closed := lease.closed
		local := lease.local
		intent := lease.intent
		lease.mu.Unlock()
		if closed {
			// A closed lease is a charged admission tombstone, not a live
			// capture registration: it owns no capture to describe.
			continue
		}
		source := local
		if !source.IsValid() {
			source = intent.Source
		}
		if !intent.Destination.IsValid() || !source.IsValid() {
			continue
		}
		endpoint := Endpoint{
			Family:         intent.Family,
			Transport:      intent.Transport,
			Source:         source,
			Interface:      intent.Interface,
			InterfaceIndex: intent.InterfaceIndex,
			Destination:    intent.Destination,
		}
		endpoints = append(endpoints, ownedEndpoint{endpoint: endpoint, order: endpointOrder(endpoint)})
	}
	e.mu.Unlock()
	sort.Slice(endpoints, func(left, right int) bool { return endpoints[left].order < endpoints[right].order })
	total = uint64(len(endpoints))
	if limit > 0 && len(endpoints) > limit {
		endpoints = endpoints[:limit]
		truncated = true
	}
	for _, owned := range endpoints {
		dump, err := e.CaptureFilterDump(owned.endpoint)
		if err != nil {
			continue
		}
		row := adapter.DesyncCaptureFilterRow{
			Family:               uint8(owned.endpoint.Family),
			Transport:            transportName(owned.endpoint.Transport),
			OutboundInstructions: uint64(dump.Instructions),
			InboundPresent:       dump.Inbound != "",
		}
		if sensitive {
			row.Source = stringPointer(addrPortString(owned.endpoint.Source))
			row.Destination = stringPointer(addrPortString(owned.endpoint.Destination))
			row.Interface = stringPointer(owned.endpoint.Interface)
			if owned.endpoint.InterfaceIndex != 0 {
				index := owned.endpoint.InterfaceIndex
				row.InterfaceIndex = &index
			}
			row.OutboundExpression = stringPointer(dump.Outbound)
			if dump.Inbound != "" {
				row.InboundExpression = stringPointer(dump.Inbound)
			}
		}
		rows = append(rows, row)
	}
	return rows, total, truncated
}

// DiagnosticsWindowsNetwork performs the explicit native query. The connected
// default is retained; All is passed only when the request asked for it.
func (e *Engine) DiagnosticsWindowsNetwork(ctx context.Context, allNetworks bool, limit int, sensitive bool) (adapter.DesyncWindowsNetworkPayload, error) {
	if runtime.GOOS != "windows" {
		return adapter.DesyncWindowsNetworkPayload{}, adapter.DesyncDiagnosticError{Code: "platform_inapplicable"}
	}
	if limit < 1 {
		limit = 128
	}
	options := NetworkQueryOptions{Limit: uint16(limit)}
	options.All = allNetworks
	snapshot, err := e.QueryWindowsNetworkWithOptions(ctx, options)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return adapter.DesyncWindowsNetworkPayload{}, err
		}
		if errors.Is(err, errNativeQueryBusy) {
			return adapter.DesyncWindowsNetworkPayload{}, adapter.DesyncDiagnosticError{Code: "busy"}
		}
		if errors.Is(err, ErrNativeScopeUnsupported) {
			return adapter.DesyncWindowsNetworkPayload{}, adapter.DesyncDiagnosticError{Code: "unsupported"}
		}
		return adapter.DesyncWindowsNetworkPayload{}, adapter.DesyncDiagnosticError{Code: "native_query_failed"}
	}
	payload := adapter.DesyncWindowsNetworkPayload{QueriedAt: snapshot.QueriedAt.UTC().Format(time.RFC3339Nano)}
	wirelessTotal := uint64(len(snapshot.Wireless))
	networkTotal := uint64(len(snapshot.Networks))
	adapterTotal := uint64(len(snapshot.Adapters))
	for index, wireless := range snapshot.Wireless {
		if index >= limit {
			break
		}
		entry := adapter.DesyncWirelessNetwork{State: wireless.State}
		if sensitive {
			entry.InterfaceGUID = adapter.CapDesyncSensitiveString(stringPointer(wireless.InterfaceGUID), adapter.DesyncSensitiveNameLimit)
			entry.Description = adapter.CapDesyncSensitiveString(stringPointer(wireless.Description), adapter.DesyncSensitiveNameLimit)
			entry.SSID = adapter.CapDesyncSensitiveString(stringPointer(wireless.SSID), adapter.DesyncSensitiveNameLimit)
		}
		payload.Wireless = append(payload.Wireless, entry)
	}
	for index, network := range snapshot.Networks {
		if index >= limit {
			break
		}
		entry := adapter.DesyncNetworkEntry{
			Connected: network.Connected,
			Internet:  network.Internet,
			Category:  network.Category,
		}
		if sensitive {
			entry.ID = adapter.CapDesyncSensitiveString(stringPointer(network.ID), adapter.DesyncSensitiveNameLimit)
			entry.Name = adapter.CapDesyncSensitiveString(stringPointer(network.Name), adapter.DesyncSensitiveNameLimit)
			count := uint64(len(network.Adapters))
			entry.Adapters = &count
		}
		payload.Networks = append(payload.Networks, entry)
	}
	for index, adapterEntry := range snapshot.Adapters {
		if index >= limit {
			break
		}
		entry := adapter.DesyncNetworkAdapter{}
		if sensitive {
			if adapterEntry.Index != 0 {
				indexValue := adapterEntry.Index
				entry.Index = &indexValue
			}
			entry.GUID = adapter.CapDesyncSensitiveString(stringPointer(adapterEntry.GUID), adapter.DesyncSensitiveNameLimit)
			entry.Name = adapter.CapDesyncSensitiveString(stringPointer(adapterEntry.Name), adapter.DesyncSensitiveNameLimit)
		}
		payload.Adapters = append(payload.Adapters, entry)
	}
	// Only arrays that were returned in full carry an exact total.
	if wirelessTotal <= uint64(limit) {
		payload.Totals.Wireless = &wirelessTotal
	}
	if networkTotal <= uint64(limit) {
		payload.Totals.Networks = &networkTotal
	}
	if adapterTotal <= uint64(limit) {
		payload.Totals.Adapters = &adapterTotal
	}
	return payload, nil
}

func positiveMillis(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value / time.Millisecond)
}

func unsignedScale(value int) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func boolCount(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func stringPointer(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func netipAddrPort(address netip.Addr, port uint16) string {
	if !address.IsValid() {
		return ""
	}
	return netip.AddrPortFrom(address, port).String()
}

func addrPortString(value netip.AddrPort) string {
	if !value.IsValid() {
		return ""
	}
	return value.String()
}

func conntrackKeyOrder(key conntrackKey) string {
	return key.src.String() + "\x00" + key.dst.String() + "\x00" +
		strconv.Itoa(int(key.srcPort)) + "\x00" + strconv.Itoa(int(key.dstPort)) + "\x00" +
		strconv.Itoa(int(key.family)) + "\x00" + transportName(key.transport)
}

func endpointOrder(endpoint Endpoint) string {
	return endpoint.Source.String() + "\x00" + endpoint.Destination.String()
}

func transportName(value Transport) string {
	switch value {
	case TransportTCP:
		return "tcp"
	case TransportUDP:
		return "udp"
	default:
		return "other"
	}
}

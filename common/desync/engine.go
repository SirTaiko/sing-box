package desync

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// ErrReloadBusy is returned when an explicit reload is already staged for this
// outbound. Contention is reported instead of queued.
var ErrReloadBusy = errors.New("desync: reload already in progress")

// ErrAdmissionRefused classifies a native admission refusal: the engine no
// longer admits attempts, the lease's admission gate already closed, or the
// per-engine lease limit is exhausted by charged attempts (including closed
// attempts whose native resources are still owned). The actionable reason stays
// available through errors.Is/Unwrap, so a caller keeps the existing
// engine-closed/lease-closed/capacity diagnosis. A refusal is never an ordinary
// zero-byte send: callers must not fall back to plain I/O or start another
// attempt.
var ErrAdmissionRefused = errors.New("desync: native admission refused")

// admissionRefusal carries the underlying reason of one refusal without
// changing its message, and classifies it for errors.Is.
type admissionRefusal struct {
	reason error
}

func (e *admissionRefusal) Error() string {
	if e.reason == nil {
		return ErrAdmissionRefused.Error()
	}
	return e.reason.Error()
}

func (e *admissionRefusal) Unwrap() error { return e.reason }

func (e *admissionRefusal) Is(target error) bool {
	if target == ErrAdmissionRefused {
		return true
	}
	return e.reason != nil && errors.Is(e.reason, target)
}

func admissionRefused(reason error) error { return &admissionRefusal{reason: reason} }

// RefuseAdmission classifies an admission refusal raised outside this package
// (for example by the direct bridge when its attempt has no engine owner). The
// message of reason is preserved and errors.Is(ErrAdmissionRefused) matches.
func RefuseAdmission(reason error) error { return admissionRefused(reason) }

// Backend is one native capture implementation (Linux NFQUEUE/raw, Windows
// WinDivert). Backends are injectable so tests exercise the whole lease and
// planner lifecycle without privileges or host packets.
type Backend interface {
	Name() string
	Open(lease *Lease) (Capture, error)
}

// Capture is an owned native capture registration. Close must be idempotent.
type Capture interface {
	Close() error
}

// Injector sends one generated packet through the backend's owned injection
// path. It is provided per captured packet callback.
type Injector func(packet []byte) error

// Completer delivers the single terminal native disposition of one captured
// packet. A captured packet that was not held is completed synchronously by the
// caller that owns the verdict; a held packet is completed later, exactly once,
// by the flow's release path (message completion, deadline, budget, cancel or
// close). modified is the in-place replacement bytes of that exact captured
// packet and is non-nil only for VerdictModify; it is never shared through a
// per-lease slot, so concurrent releases cannot consume each other's bytes.
// Implementations must be safe to call from the backend's release goroutine.
type Completer func(verdict Verdict, reason string, modified []byte)

type Engine struct {
	configMu sync.RWMutex
	config   *Config

	backend Backend
	limits  LimitSet

	// One common state owner per outbound: bounded semantic conntrack, the
	// IP/hop cache and the optional hostlist-auto learner. All are
	// independent from native attempt cleanup.
	conntrack *conntrackTable
	ipcache   *ipCache
	learning  *learner

	// heldBytes is the engine-wide held-byte budget shared by every flow.
	heldBytes atomic.Int64
	clock     atomic.Value // func() time.Time

	// probe is the WLAN/NLM platform seam; activation is the rate-limited
	// SSID/NLM activation gate. Both are per engine so two outbounds with
	// different capture.windows blocks never share activation state.
	probeMu    sync.Mutex
	probe      NetworkProbe
	activation activationGate
	// stream is the stream-rule snapshot of this outbound, when configured.
	// It is set once at construction and reloaded together with the packet
	// and learning snapshots; there is no second owner.
	stream *StreamConfig

	// reloadMu serializes explicit reloads with close: at most one reload is
	// staged per outbound and a concurrent request gets a busy result instead
	// of a growing queue.
	reloadMu sync.Mutex
	// listRevision is the monotonic publication counter of this outbound. It
	// starts at 1 after the initial valid snapshot and increments once per
	// successful changed publication.
	listRevision atomic.Uint64
	// bundleGenerations are the immutable bundle generations of the published
	// snapshot (sorted, unique).
	bundleGenerations atomic.Value // []string
	// nativeQueryMu serializes explicit native diagnostics queries per
	// outbound; contention is reported as busy, never queued.
	nativeQueryMu sync.Mutex

	mu     sync.Mutex
	leases map[*Lease]struct{}
	closed bool
	// udpPeers is the aggregate UDP peer-state charge of this engine: one unit
	// per udpFlows entry of every packet-capable lease, listener or connected
	// UDP. It is bounded by limits.MaxLeases independently from attempt
	// admission and is retained until the owning lease retires its map.
	// Guarded by mu.
	udpPeers int
	// udpPeerConstruct is the hermetic constructor-ordering seam: it runs under
	// mu immediately before a reserved peer's flowState is allocated, so the
	// deterministic bound tests can assert that the charge was taken first. It
	// is nil in production.
	udpPeerConstruct func()
}

func NewEngine(config *Config, backend Backend) (*Engine, error) {
	if config == nil {
		return nil, fmt.Errorf("desync: nil config")
	}
	if backend == nil {
		return nil, errCaptureUnavailable
	}
	engine := &Engine{config: config, backend: backend, limits: config.Limits,
		leases: make(map[*Lease]struct{})}
	engine.clock.Store(func() time.Time { return time.Now() })
	engine.conntrack = newConntrackTable(config.Conntrack, engine.currentTime)
	engine.ipcache = newIPCache(config.IPCache, engine.currentTime)
	learning, err := newLearner(config.Learning, engine.currentTime)
	if err != nil {
		return nil, err
	}
	engine.learning = learning
	engine.listRevision.Store(1)
	engine.bundleGenerations.Store(append([]string(nil), config.bundleGenerations...))
	return engine, nil
}

// SetHoldClock replaces the clock used for hold deadlines. It exists so
// hermetic tests can advance time without sleeping; production callers never
// need it. It is safe to call while captures are running.
func (e *Engine) SetHoldClock(now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	e.clock.Store(now)
}

func (e *Engine) currentTime() time.Time {
	return e.clock.Load().(func() time.Time)()
}

func (e *Engine) Config() *Config {
	e.configMu.RLock()
	defer e.configMu.RUnlock()
	return e.config
}

// ReloadLists re-reads every configured domain/IP list file and provider bundle
// dataset, rebuilds the stream rule snapshot and re-reads the configured
// learned-file state, then publishes all of them as one new selection snapshot.
// On any read, format, hash, gzip or budget error the last good snapshot (packet
// lists, stream rules, learned set and revision) stays active and the error is
// returned: upstream exits the process on a failed reload, which would tear down
// unrelated VPN outbounds, so this isolation adaptation is deliberate and
// documented. Existing flows keep the snapshot they selected; new selections
// use the new one.
func (e *Engine) ReloadLists() error {
	_, err := e.ReloadListsContext(context.Background())
	return err
}

// ReloadListsContext is the context-aware explicit reload authority. It
// serializes reload with close and with itself: a concurrent reload returns
// ErrReloadBusy instead of waiting in an unbounded queue. Cancellation before
// publication leaves the last-good state untouched.
func (e *Engine) ReloadListsContext(ctx context.Context) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !e.reloadMu.TryLock() {
		return false, ErrReloadBusy
	}
	defer e.reloadMu.Unlock()
	if e.Closed() {
		return false, errEngineClosed
	}
	e.configMu.RLock()
	current := e.config
	e.configMu.RUnlock()
	if current == nil {
		return false, errEngineClosed
	}
	// One state per publication: current.json is read once per distinct
	// canonical bundle root and the same pinned generation is used by the
	// packet and stream rule builds.
	state := newListBuildState()
	reloaded, err := current.reloadLists(state)
	if err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	// The stream rule snapshot is compiled before anything is published: a
	// stream list error keeps the packet snapshot, the learned set and the
	// stream rules all at their last good state.
	var streamRules []*streamRule
	if e.stream != nil {
		streamRules, err = e.stream.compileSnapshotWith(state)
		if err != nil {
			return false, err
		}
		if len(streamRules) == 0 {
			return false, E.New("desync: reload produced no enabled stream rules")
		}
	}
	// The explicit learning snapshot is part of the same transactional
	// reload: a failed read keeps both the last-good list snapshot and the
	// last-good learned set, never a mixed state.
	if err = e.learning.reload(); err != nil {
		return false, err
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	// Close wins the race: a reload staged before close must not publish into
	// a closed engine.
	if e.Closed() {
		return false, errEngineClosed
	}
	changed := reloaded.listDigest != current.listDigest
	if e.stream != nil {
		e.stream.publishSnapshot(streamRules)
	}
	e.configMu.Lock()
	e.config = reloaded
	e.configMu.Unlock()
	e.bundleGenerations.Store(append([]string(nil), reloaded.bundleGenerations...))
	if changed {
		e.listRevision.Add(1)
	}
	return changed, nil
}

// ListRevision is the monotonic list publication counter of this outbound.
func (e *Engine) ListRevision() uint64 { return e.listRevision.Load() }

// BundleGenerations returns the immutable bundle generations of the published
// snapshot.
func (e *Engine) BundleGenerations() []string {
	value, _ := e.bundleGenerations.Load().([]string)
	return append([]string(nil), value...)
}

// SetBundleGenerations records the generations resolved by an initial compile
// that is shared with a separately compiled stream half.
func (e *Engine) SetBundleGenerations(generations []string) {
	e.bundleGenerations.Store(append([]string(nil), generations...))
}

// Closed reports whether the engine accepted its terminal shutdown.
func (e *Engine) Closed() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed
}

func (e *Engine) BackendName() string {
	if e.backend == nil {
		return ""
	}
	return e.backend.Name()
}

// LearningEnabled reports whether this outbound owns an auto-hostlist learner.
func (e *Engine) LearningEnabled() bool { return e.learning != nil }

// LearnedHosts returns the sorted snapshot of hosts learned by this outbound.
func (e *Engine) LearnedHosts() []string { return e.learning.learnedHosts() }

// LearningLastError exposes the last snapshot/debug publication error for
// lifecycle diagnostics. It never changes packet dispositions.
func (e *Engine) LearningLastError() error { return e.learning.lastError() }

// RecordHostFailure is the engine-owned seam for later stream (D4) reply
// observation. It applies the named rule's learning thresholds and may publish
// the host; it never creates a second store.
func (e *Engine) RecordHostFailure(ruleName, host string) bool {
	if e.learning == nil {
		return false
	}
	config := e.Config()
	if config == nil {
		return false
	}
	var selected *Rule
	for _, rule := range config.Rules {
		if rule.Learning == nil {
			continue
		}
		if ruleName == "" || rule.Name == ruleName {
			selected = rule
			break
		}
	}
	if selected == nil {
		return false
	}
	return e.learning.recordFailure(selected, host)
}

// RecordHostSuccess is the engine-owned seam for a confirmed working host.
func (e *Engine) RecordHostSuccess(host string) { e.learning.recordSuccess(host) }

// CachedHost and CachedHop expose the existing engine-owned IP cache to the
// later stream integration without creating a parallel cache.
func (e *Engine) CachedHost(address netip.Addr) (string, bool) {
	if host, ok := e.ipcache.lookupHostAny(address); ok {
		return host, true
	}
	return "", false
}

// CachedHostOn is the interface-scoped cache lookup. A capture/learned host is
// only valid for the native interface it was observed on.
func (e *Engine) CachedHostOn(address netip.Addr, iface string) (string, bool) {
	host, _, ok := e.ipcache.lookupHost(address, iface)
	return host, ok
}

// lookupHostAny returns the cached hostname of the exact address on any
// interface of this outbound. It is the compatibility lookup for callers that
// do not carry an attempt interface (diagnostics, D4 stream facts); the
// per-attempt path always uses lookupHost with its own interface.
func (c *ipCache) lookupHostAny(address netip.Addr) (string, bool) {
	host, _, ok := c.lookupHostAnyState(address)
	return host, ok
}

func (c *ipCache) lookupHostAnyState(address netip.Addr) (string, bool, bool) {
	if c == nil || !c.config.hostnameEnabled || !address.IsValid() {
		return "", false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	for key, entry := range c.entries {
		if key.address != address || !entry.hostnameSet || entry.hostname == "" {
			continue
		}
		entry.last = c.now()
		return entry.hostname, entry.hostnameIsIP, true
	}
	return "", false, false
}

// CachedHostIsIP reports the upstream hostname_is_ip marker of a cached host.
func (e *Engine) CachedHostIsIP(address netip.Addr, iface string) bool {
	_, isIP, ok := e.ipcache.lookupHost(address, iface)
	return ok && isIP
}

// CachedHostState returns the cached hostname and its upstream
// hostname_is_ip marker in one lookup. It is the compatibility lookup for
// callers that do not carry an attempt interface (stream preconnect facts);
// entries are still scoped to this outbound's engine, never global.
func (e *Engine) CachedHostState(address netip.Addr) (string, bool, bool) {
	host, isIP, ok := e.ipcache.lookupHostAnyState(address)
	return host, isIP, ok
}

// HostLearned reports whether a host is already in this outbound's
// hostlist-auto set. Auto-hostlist applicability (upstream b_ah_check) is
// "the profile matched but the host has not been learned yet".
func (e *Engine) HostLearned(host string) bool {
	if e.learning == nil || host == "" {
		return false
	}
	return e.learning.learned(host)
}

// recordStreamFailure applies one stream rule's learning thresholds on the same
// engine-owned learner as the packet rules. It is reached only from the stream
// reply-observation path and never creates a second store.
func (e *Engine) recordStreamFailure(rule *streamRule, host string) bool {
	if e.learning == nil || rule == nil || rule.learning == nil {
		return false
	}
	return e.learning.recordFailureWith(rule.learning, rule.name, rule.match.DomainsExclude.matches, host)
}

// stateOnlyBackend is the backend of a stream-only outbound. It owns no capture
// and refuses to open one, so a configuration without packet rules can still
// own the ip cache and the learner without any native or privileged handle.
type stateOnlyBackend struct{}

func (stateOnlyBackend) Name() string { return "state-only" }

func (stateOnlyBackend) Open(*Lease) (Capture, error) { return nil, errCaptureUnavailable }

// NewStateEngine compiles the per-outbound state owner for a configuration that
// has stream rules but no packet rules. The shared learning and ip-cache
// configuration goes through the same validators as Compile; no capture
// backend, adapter or config list file is opened here.
func NewStateEngine(options *option.DirectDesyncOptions, streamRules []option.DirectDesyncStreamRule) (*Engine, error) {
	if options == nil {
		return nil, E.New("desync: nil state configuration")
	}
	config := &Config{Limits: defaultLimits(), Conntrack: defaultConntrackConfig(),
		IPCache: defaultIPCacheConfig(), Learning: defaultLearningConfig()}
	if options.IPCache != nil {
		config.IPCache.hostnameEnabled = options.IPCache.Hostname
		if options.IPCache.MaxEntries < 0 {
			return nil, E.New("desync: negative ip_cache max_entries")
		}
		if options.IPCache.MaxEntries > 0 {
			config.IPCache.maxEntries = options.IPCache.MaxEntries
		}
		if options.IPCache.Lifetime != nil {
			lifetime := time.Duration(*options.IPCache.Lifetime)
			if lifetime < 0 {
				return nil, E.New("desync: negative ip_cache lifetime")
			}
			config.IPCache.lifetime = lifetime
			config.IPCache.noExpiry = lifetime == 0
		}
	}
	if options.Learning != nil {
		config.Learning.path = options.Learning.Path
		config.Learning.debugLog = options.Learning.DebugLog
		if options.Learning.MaxHosts < 0 {
			return nil, E.New("desync: negative learning max_hosts")
		}
		if options.Learning.MaxHosts > 0 {
			if options.Learning.MaxHosts > maxLearningMaxHosts {
				return nil, E.New("desync: learning max_hosts exceeds ", maxLearningMaxHosts)
			}
			config.Learning.maxHosts = options.Learning.MaxHosts
		}
	}
	// A stream rule with rule.learning needs the same learner even when the
	// common block is absent; the set then lives only in this engine.
	for index := range streamRules {
		if !streamRules[index].Disabled && streamRules[index].Learning != nil {
			config.Learning.enabled = true
			break
		}
	}
	if options.Learning != nil {
		config.Learning.enabled = true
	}
	return NewEngine(config, stateOnlyBackend{})
}

func (e *Engine) CachedHop(address netip.Addr) (uint8, bool) { return e.ipcache.lookupHop(address) }

func (e *Engine) NewAttempt(intent Intent) (*Lease, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, admissionRefused(errEngineClosed)
	}
	if len(e.leases) >= e.limits.MaxLeases {
		return nil, admissionRefused(fmt.Errorf("desync: active lease limit reached (%d)", e.limits.MaxLeases))
	}
	lease := &Lease{
		engine:     e,
		intent:     intent,
		closeDone:  make(chan struct{}),
		udpFlows:   make(map[string]*flowState),
		generation: leaseGenerations.Add(1),
	}
	if intent.Transport == TransportTCP {
		lease.tcpFlow = newFlowState(e.limits, &e.heldBytes, e.currentTime)
		lease.tcpFlow.closed = &lease.closedFlag
		lease.tcpFlow.attachEngineState(e.conntrack, e.ipcache, e.learning, intent)
	}
	e.leases[lease] = struct{}{}
	return lease, nil
}

// leaseGenerations numbers every native attempt of the process. A captured
// ICMP error is only attributed to the live generation of its lease.
var leaseGenerations atomic.Uint64

// releaseNativeHold discharges one native reference of an already admitted
// attempt. It never admits a new attempt and never frees native memory: it only
// drops this reference and, when the lease's capture/flow teardown already
// finished, removes the original charged slot exactly once. It is safe to call
// after Engine.Close and after the lease was closed; that is exactly the
// retained-tombstone case.
func (e *Engine) releaseNativeHold(lease *Lease) {
	e.mu.Lock()
	if lease.nativeHolds > 0 {
		lease.nativeHolds--
	}
	if lease.nativeHolds == 0 && lease.teardownDone && !lease.retired {
		lease.retired = true
		delete(e.leases, lease)
	}
	e.mu.Unlock()
}

// finishLeaseTeardown records that the capture/flow teardown of one lease
// finished. The charged slot is removed here only when no native reference
// still owns resources of this attempt; otherwise the lease remains a charged
// tombstone whose own release callback performs the final removal.
func (e *Engine) finishLeaseTeardown(lease *Lease) {
	e.mu.Lock()
	lease.teardownDone = true
	e.retireLeasePeerStateLocked(lease)
	if lease.nativeHolds == 0 && !lease.retired {
		lease.retired = true
		delete(e.leases, lease)
	}
	e.mu.Unlock()
}

// retireLeasePeerStateLocked detaches one lease's per-peer map and discharges
// its recorded UDP peer charge exactly once. It runs only after capture/flow
// teardown finished and every borrowed UDP user released, so no callback can
// observe detached state and no capacity is reused while state is still in use.
// The caller holds Engine.mu; lock order is Engine.mu -> Lease.mu.
func (e *Engine) retireLeasePeerStateLocked(lease *Lease) {
	if lease == nil || lease.peersRetired || !lease.teardownDone || lease.udpUsers > 0 {
		return
	}
	lease.peersRetired = true
	e.udpPeers -= lease.udpPeerCharge
	lease.udpPeerCharge = 0
	lease.mu.Lock()
	lease.udpFlows = nil
	lease.mu.Unlock()
}

// ActiveLeases reports the charged attempts of this engine: admitted leases
// plus closed-but-retained tombstones whose native resources are still owned.
// It is not the number of open connections, and it is per engine
// instance/generation, not process-global.
func (e *Engine) ActiveLeases() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.leases)
}

// Close shuts the engine down: it rejects new attempts, closes every lease and
// releases their captures. It never touches foreign native objects.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	leases := make([]*Lease, 0, len(e.leases))
	for lease := range e.leases {
		leases = append(leases, lease)
	}
	e.mu.Unlock()
	var firstErr error
	for _, lease := range leases {
		err := lease.Close(errEngineClosed)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	e.conntrack.close()
	e.ipcache.close()
	e.learning.close()
	return firstErr
}

// Lease is the ownership unit of one native socket attempt. Every dial attempt,
// including losing parallel attempts, owns a distinct lease.
type Lease struct {
	engine *Engine
	intent Intent

	mu                sync.Mutex
	closed            bool
	closedFlag        atomic.Bool
	closeDone         chan struct{}
	capture           Capture
	local             netip.AddrPort
	tcpFlow           *flowState
	udpFlows          map[string]*flowState
	failed            error
	socketMarkValue   int
	socketDeviceValue string
	// interfaceIndexValue is the interface index the owned native socket was
	// actually bound to, queried from the socket itself on Windows. Zero means
	// unknown (the attempt is not interface-bound).
	interfaceIndexValue uint32
	// modified carries the in-place bytes of the last VerdictModify
	// disposition to the native backend, one slot per direction so the
	// inbound and outbound capture loops can never consume each other's bytes.
	modifiedOutbound []byte
	modifiedInbound  []byte
	// generation identifies this lease among all attempts of the process. A
	// captured ICMP error is only attributed to the live generation: after
	// Close (or tuple reuse by a later attempt) the quote is no longer owned
	// and the error passes.
	generation uint64
	// lowHopSent records that this lease actually injected a replacement
	// packet. Only traffic this lease generated can own the time-exceeded
	// errors capture.filter_ttl_expired_icmp suppresses.
	lowHopSent atomic.Bool
	// Admission state below is guarded by Engine.mu, never by Lease.mu: the
	// engine map is the single authority for the charged slot and for native
	// references. A closed lease with nativeHolds > 0 is a charged tombstone,
	// not a live capture registration.
	//
	// admissionClosed is set when Close starts: no new native reference may be
	// acquired after that point.
	admissionClosed bool
	// nativeHolds counts the native resources (sender factory/event, one
	// submission, one retained connect) that reference this already charged
	// attempt. They are references to this one slot, not extra leases.
	nativeHolds int
	// udpPeerCharge is the recorded UDP peer-state charge of this lease: one
	// unit per udpFlows entry this lease inserted. It is discharged exactly
	// once when the lease retires its per-peer state. Guarded by Engine.mu.
	udpPeerCharge int
	// udpUsers counts borrowed users (packet handling and interface
	// snapshots) of this lease's per-peer state. Retirement waits until every
	// user released, so no callback can observe detached state. Guarded by
	// Engine.mu.
	udpUsers int
	// peersRetired reports that udpFlows was detached and its recorded charge
	// discharged exactly once. Guarded by Engine.mu.
	peersRetired bool
	// teardownDone reports that capture/flow teardown finished. The charged
	// entry is removed only when this is true and nativeHolds is zero.
	teardownDone bool
	// retired reports that the map entry was already removed exactly once.
	retired bool
}

func (l *Lease) setModified(direction Direction, raw []byte) {
	l.mu.Lock()
	if direction == DirectionInbound {
		l.modifiedInbound = raw
	} else {
		l.modifiedOutbound = raw
	}
	l.mu.Unlock()
}

// TakeModified returns the in-place bytes that must be delivered with the
// current VerdictModify disposition of this direction, or nil. It clears that
// direction's value so a later verdict cannot reuse stale bytes.
func (l *Lease) TakeModified(direction Direction) []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	if direction == DirectionInbound {
		modified := l.modifiedInbound
		l.modifiedInbound = nil
		return modified
	}
	modified := l.modifiedOutbound
	l.modifiedOutbound = nil
	return modified
}

func (l *Lease) setSocketMark(mark int) {
	l.mu.Lock()
	l.socketMarkValue = mark
	l.mu.Unlock()
}

func (l *Lease) socketMark() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.socketMarkValue
}

func (l *Lease) setSocketDevice(device string) {
	udpFlows, pinned := l.snapshotUDPFlows()
	if pinned {
		defer l.releaseUDPUser()
	}
	l.mu.Lock()
	l.socketDeviceValue = device
	tcpFlow := l.tcpFlow
	l.mu.Unlock()
	// The actual native-attempt device is only known after the dialer's socket
	// controls ran; every flow of this lease adopts it so the ipcache key and
	// capture interface selector use the owned device, never an invented one.
	if tcpFlow != nil {
		tcpFlow.setInterface(device)
	}
	for _, flow := range udpFlows {
		flow.setInterface(device)
	}
}

// setSocketInterface records the interface the native attempt was actually
// bound to: the index comes from the socket, the name is resolved from the
// adapter table. The flows adopt the name so the ipcache interface dimension
// and capture selectors use the owned attempt, never configuration.
func (l *Lease) setSocketInterface(index uint32, device string) {
	udpFlows, pinned := l.snapshotUDPFlows()
	if pinned {
		defer l.releaseUDPUser()
	}
	l.mu.Lock()
	if index != 0 {
		l.interfaceIndexValue = index
	}
	tcpFlow := l.tcpFlow
	l.mu.Unlock()
	if device == "" {
		return
	}
	l.setSocketDevice(device)
	if tcpFlow != nil {
		tcpFlow.setInterface(device)
	}
	for _, flow := range udpFlows {
		flow.setInterface(device)
	}
}

func (l *Lease) interfaceIndex() uint32 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.interfaceIndexValue
}

// captureInterface is the owned attempt's output device: the socket-reported
// value wins over the dialer-supplied intent.
func (l *Lease) captureInterface() string {
	if device := l.socketDevice(); device != "" {
		return device
	}
	return l.intent.Interface
}

// CaptureInterface is the actual interface fact of the owned native attempt:
// the device the socket itself reports, or the dialer-supplied interface when
// the socket reports none. Callers use it to scope per-attempt caches; it is
// never inferred from the destination or from another device.
func (l *Lease) CaptureInterface() string { return l.captureInterface() }

// PreconnectHost resolves the cached host of this attempt's destination on the
// attempt's own interface. The lookup is the engine-owned ip cache (the single
// cache owner) and is scoped by the actual attempt interface, so a host learned
// on another device is never used as a cross-device fallback. A non-interface-
// bound attempt or an interface-scoped miss reports no host.
func (l *Lease) PreconnectHost() (host string, hostIsIP bool, found bool) {
	if l == nil || l.engine == nil {
		return "", false, false
	}
	iface := l.captureInterface()
	if iface == "" || !l.intent.Destination.IsValid() {
		return "", false, false
	}
	host, hostIsIP, found = l.engine.ipcache.lookupHost(l.intent.Destination.Addr(), iface)
	if !found {
		return "", false, false
	}
	return host, hostIsIP, true
}

func (l *Lease) socketDevice() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.socketDeviceValue
}

func (l *Lease) Intent() Intent { return l.intent }

func (l *Lease) Engine() *Engine { return l.engine }

func (l *Lease) SetLocalAddress(address netip.AddrPort) {
	l.mu.Lock()
	l.local = address
	l.mu.Unlock()
}

func (l *Lease) LocalAddress() netip.AddrPort {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.local
}

func (l *Lease) Endpoint() Endpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	endpoint := l.intent.endpoint()
	endpoint.Source = l.local
	// Read the device under the already held lease lock: captureInterface would
	// re-acquire l.mu.
	endpoint.Interface = l.socketDeviceValue
	if endpoint.Interface == "" {
		endpoint.Interface = l.intent.Interface
	}
	endpoint.InterfaceIndex = l.interfaceIndexValue
	if endpoint.InterfaceIndex == 0 {
		endpoint.InterfaceIndex = l.intent.InterfaceIndex
	}
	return endpoint
}

// StartCapture opens the native capture for the current owned endpoint. It is
// called after the exclusive local bind is known and before the first
// connect/send.
func (l *Lease) StartCapture() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return errLeaseClosed
	}
	if l.capture != nil {
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()
	// The portable capture selector is enforced before any native resource is
	// acquired, for every backend (test seams included). It can only narrow
	// the owned envelope: an excluding selector is a configuration error.
	captureConfig := l.engine.Config().Capture
	if err := captureConfig.platformError(); err != nil {
		return err
	}
	endpoint := l.Endpoint()
	if selector := captureConfig.selectors; !selector.allowsEndpoint(endpoint) {
		return fmt.Errorf("desync: capture selectors exclude the owned %v %v tuple",
			endpoint.Transport, endpoint.Destination)
	}
	// The Windows-only narrowing is checked the same way: a family, interface
	// or port selector that provably excludes the owned attempt is refused
	// before the driver is opened, never silently widened.
	if err := captureConfig.windows.excludesOwnedEndpoint(endpoint); err != nil {
		return err
	}
	capture, err := l.engine.backend.Open(l)
	if err != nil {
		return fmt.Errorf("desync: open %s capture: %w", l.engine.backend.Name(), err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		capture.Close()
		return errLeaseClosed
	}
	l.capture = capture
	return nil
}

// PrepareSocket establishes the exclusive local port and capture ownership from
// inside the platform's last-chance socket hook. It is Linux-specific; the
// Windows path binds explicitly in the native connect helper.
func (l *Lease) PrepareSocket(fd uintptr) error {
	return prepareSocket(l, fd)
}

// acquireUDPFlow returns the per-peer state of one outbound UDP destination and
// pins one borrowed user of it. A new peer is charged against the engine-wide
// UDP peer allowance before its flowState/reassembler is allocated, so a
// refusal at saturation constructs and inserts nothing. Existing peers stay
// usable at capacity: the lookup happens before the allowance is consulted.
// The caller must call releaseUDPUser exactly once when it stops borrowing the
// state.
func (l *Lease) acquireUDPFlow(packet *Packet) (*flowState, bool) {
	engine := l.engine
	key := flowKey(netip.AddrPortFrom(packet.Dst, packet.DstPort))
	engine.mu.Lock()
	// The admission gate and the engine shutdown are rechecked under the same
	// lock that owns the peer charge, so Close can never win between a
	// successful insertion and its borrower.
	if engine.closed || l.admissionClosed {
		engine.mu.Unlock()
		return nil, false
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		engine.mu.Unlock()
		return nil, false
	}
	flow, loaded := l.udpFlows[key]
	if !loaded {
		// Reservation precedes construction. A nonpositive allowance admits no
		// peer at all; an exhausted allowance only refuses new state.
		if engine.udpPeers >= engine.limits.MaxLeases {
			l.mu.Unlock()
			engine.mu.Unlock()
			return nil, false
		}
		engine.udpPeers++
		l.udpPeerCharge++
		if engine.udpPeerConstruct != nil {
			engine.udpPeerConstruct()
		}
		flow = newFlowState(engine.limits, &engine.heldBytes, engine.currentTime)
		flow.closed = &l.closedFlag
		flow.attachEngineState(engine.conntrack, engine.ipcache, engine.learning, l.peerIntent(packet))
		l.udpFlows[key] = flow
	}
	l.udpUsers++
	l.mu.Unlock()
	engine.mu.Unlock()
	return flow, true
}

// peerIntent is the semantic owner key of one UDP peer. A destination-less
// listener attempt has no owned tuple yet, so its peers are attached with the
// complete captured datagram tuple (family, source, destination); the attempt
// intent and the destination-less native capture envelope stay untouched.
// Connected UDP keeps its owned tuple.
func (l *Lease) peerIntent(packet *Packet) Intent {
	intent := l.intent
	if intent.Destination.IsValid() {
		return intent
	}
	intent.Family = packet.Family
	intent.Transport = packet.Transport
	intent.Source = netip.AddrPortFrom(packet.Src, packet.SrcPort)
	intent.Destination = netip.AddrPortFrom(packet.Dst, packet.DstPort)
	return intent
}

// releaseUDPUser drops one borrowed reference to this lease's per-peer state and
// retires the map and its charge when teardown already finished. Both teardown
// completion and the last release check the same condition, so either ordering
// retires exactly once.
func (l *Lease) releaseUDPUser() {
	if l == nil || l.engine == nil {
		return
	}
	engine := l.engine
	engine.mu.Lock()
	if l.udpUsers > 0 {
		l.udpUsers--
	}
	engine.retireLeasePeerStateLocked(l)
	engine.mu.Unlock()
}

// snapshotUDPFlows borrows every per-peer state of this lease for one interface
// update. The engine-level user pin keeps retirement (and capacity reuse) off
// until the caller stops mutating the borrowed flows; pinned reports whether a
// release is owed. Lock order is Engine.mu -> Lease.mu.
func (l *Lease) snapshotUDPFlows() (flows []*flowState, pinned bool) {
	if l == nil || l.engine == nil {
		return nil, false
	}
	engine := l.engine
	engine.mu.Lock()
	l.mu.Lock()
	flows = make([]*flowState, 0, len(l.udpFlows))
	for _, flow := range l.udpFlows {
		flows = append(flows, flow)
	}
	if len(flows) > 0 {
		l.udpUsers++
		pinned = true
	}
	l.mu.Unlock()
	engine.mu.Unlock()
	return flows, pinned
}

// HandlePacket processes one captured packet. Injected packets are excluded by
// the backend before this call and therefore never reach the semantic engine.
// handleDirection is the captured direction: inbound replies only feed
// observations and are always passed unchanged, never re-injected.
//
// When VerdictHold is returned the caller must not issue a native disposition
// for this packet; complete (which must be non-nil for held packets) receives
// the terminal verdict later. For every other verdict the caller owns the
// disposition and must not call complete.
func (l *Lease) HandlePacket(raw []byte, direction Direction, inject Injector, complete Completer) Verdict {
	packet, err := ParsePacket(raw)
	if err != nil {
		return VerdictPass
	}
	// Every captured packet is dispatched through the compiled capture
	// selector in addition to the ownership envelope. A selector can only
	// narrow, so a packet outside it passes untouched.
	capture := l.engine.Config().Capture
	// The SSID/NLM activation gate is part of the same narrowing: while the
	// configured wireless/logical network is absent (or the query failed) the
	// capture is passive and the packet passes unchanged, exactly like the
	// upstream logical_net_filter_match gate.
	if !l.engine.activationAllows() {
		return VerdictPass
	}
	port := packet.DstPort
	if direction == DirectionInbound {
		port = packet.SrcPort
	}
	if !capture.selectors.allows(packet.Family, packet.Transport, port) {
		return VerdictPass
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return VerdictPass
	}
	l.mu.Unlock()
	if direction == DirectionInbound {
		// Reply path: observations plus in-place reply transformations. A
		// Linux INPUT packet is never sent back out through the raw injection
		// socket; the modified bytes travel with the native disposition.
		if l.tcpFlow != nil {
			l.tcpFlow.mu.Lock()
			l.tcpFlow.observeReply(packet, l.engine.Config().TCPEmptyACK)
			// Upstream runs maybe_cutoff on reverse packets too, using the
			// ack-based seq_last of the reverse conntrack feed.
			l.tcpFlow.refreshCutoffLatches()
			l.tcpFlow.observeLearningReply(packet)
			modified, replyErr := l.tcpFlow.handleReply(l.engine.Config(), packet)
			l.tcpFlow.mu.Unlock()
			if replyErr == nil && modified != nil {
				l.setModified(DirectionInbound, modified)
				return VerdictModify
			}
		}
		return VerdictPass
	}
	if packet.Transport == TransportTCP {
		verdict, batch := l.tcpFlow.handleTCP(l.engine.Config(), packet, l.intent, inject, complete)
		if verdict == VerdictHold {
			return VerdictHold
		}
		if batch == nil {
			return VerdictPass
		}
		for index, replacement := range batch.Packets {
			if inject == nil {
				return VerdictPass
			}
			if injectErr := inject(replacement); injectErr != nil {
				l.failFlow(packet, fmt.Errorf("desync: inject packet %d: %w", index, injectErr))
				return VerdictPass
			}
		}
		// Never suppress the original without a replacement, and never ask the
		// native layer for a Modify without the bytes to deliver.
		if verdict == VerdictDrop && len(batch.Packets) == 0 {
			return VerdictPass
		}
		if verdict == VerdictModify {
			if batch.Modified == nil {
				return VerdictPass
			}
			l.setModified(DirectionOutbound, batch.Modified)
		}
		return verdict
	}
	// Per-peer state is charged against the engine-wide UDP peer allowance
	// before it is constructed. A refusal at saturation leaves this datagram on
	// the ordinary pass disposition with no state, semantic insertion,
	// injection, hold, completion, flow error or listener closure.
	flow, admitted := l.acquireUDPFlow(packet)
	if !admitted {
		return VerdictPass
	}
	defer l.releaseUDPUser()
	batch, err := flow.handleUDP(l.engine.Config(), packet)
	if err != nil || batch == nil {
		return VerdictPass
	}
	for index, replacement := range batch.Packets {
		if inject == nil {
			return VerdictPass
		}
		if injectErr := inject(replacement); injectErr != nil {
			// A partial replacement batch is never a reason to drop real user
			// bytes: release the original and stop transforming this flow.
			l.failFlow(packet, fmt.Errorf("desync: inject packet %d: %w", index, injectErr))
			return VerdictPass
		}
	}
	if batch.Original == VerdictDrop && len(batch.Packets) == 0 {
		return VerdictPass
	}
	if batch.Original == VerdictModify {
		if batch.Modified == nil {
			return VerdictPass
		}
		l.setModified(DirectionOutbound, batch.Modified)
	}
	return batch.Original
}

func (l *Lease) failFlow(packet *Packet, err error) {
	l.mu.Lock()
	l.failed = err
	l.mu.Unlock()
	var flow *flowState
	if packet.Transport == TransportTCP {
		flow = l.tcpFlow
	} else {
		key := flowKey(netip.AddrPortFrom(packet.Dst, packet.DstPort))
		l.mu.Lock()
		flow = l.udpFlows[key]
		l.mu.Unlock()
	}
	if flow != nil {
		flow.mu.Lock()
		flow.failed = true
		flow.mu.Unlock()
	}
}

func (l *Lease) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed
}

// ReportNativeFailure records one native-retirement failure of a retained
// operation: the attempt outlived its caller, so this lease is the remaining
// diagnostic owner of the attempt. It joins into the same per-lease diagnostic
// that Err exposes and changes no admission state: the descriptor's charge must
// stay exactly as the failed release requires, and only a proven retirement or
// process teardown may release it. It never performs I/O and never touches the
// engine lock.
func (l *Lease) ReportNativeFailure(err error) {
	if l == nil || err == nil {
		return
	}
	l.mu.Lock()
	l.failed = E.Errors(l.failed, err)
	l.mu.Unlock()
}

// PacketEnabled reports whether this lease belongs to an engine that owns a
// native packet backend. Lease presence means admission; this capability means
// packet behavior. A stream-only outbound uses the same state engine but must
// never be turned into a capture/binding request by its admission lease.
func (l *Lease) PacketEnabled() bool {
	return l != nil && l.engine != nil && l.engine.PacketEnabled()
}

// AcquireNativeHold references this already admitted attempt for one native
// resource (a sender factory/event, one submitted send, or one retained native
// connect). It allocates no slot: the returned release only drops the reference
// and, once teardown finished, removes the original entry exactly once.
//
// Acquisition is refused - with ErrAdmissionRefused classification - when the
// engine shut down or this lease's admission gate already closed, so a caller
// can never start a protected native effect on a closed owner. The successful
// release is idempotent and safe to call after Engine.Close; a failed
// acquisition returns no usable release and changes no state.
func (l *Lease) AcquireNativeHold() (func(), error) {
	if l == nil || l.engine == nil {
		return nil, admissionRefused(E.New("desync: native hold requires an admission owner"))
	}
	engine := l.engine
	engine.mu.Lock()
	if engine.closed || l.admissionClosed {
		reason := errLeaseClosed
		if engine.closed {
			reason = errEngineClosed
		}
		engine.mu.Unlock()
		return nil, admissionRefused(reason)
	}
	l.nativeHolds++
	engine.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() { engine.releaseNativeHold(l) })
	}, nil
}

// Close is idempotent and available immediately after the first side effect.
// Held originals are released in capture order before the native registration
// is torn down, so teardown never silently drops buffered user data. A
// concurrent second Close waits for the first teardown to finish, so a
// concurrent Engine.Close cannot report completion while native resources of
// this lease are still being released.
func (l *Lease) Close(reason error) error {
	// Close the admission gate first, under the engine lock that also owns the
	// charged map and the native references: a later AcquireNativeHold must
	// refuse even while capture teardown is still running. Lock order is
	// always Engine.mu before Lease.mu, never the reverse.
	if l.engine != nil {
		l.engine.mu.Lock()
		l.admissionClosed = true
		l.engine.mu.Unlock()
	}
	l.mu.Lock()
	if l.closed {
		done := l.closeDone
		l.mu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	l.closed = true
	l.closedFlag.Store(true)
	if l.closeDone == nil {
		l.closeDone = make(chan struct{})
	}
	closeDone := l.closeDone
	capture := l.capture
	l.capture = nil
	tcpFlow := l.tcpFlow
	udpFlows := make([]*flowState, 0, len(l.udpFlows))
	for _, flow := range l.udpFlows {
		udpFlows = append(udpFlows, flow)
	}
	l.mu.Unlock()
	defer close(closeDone)
	if reason == nil {
		reason = errLeaseClosed
	}
	if tcpFlow != nil {
		tcpFlow.flushHeld(reason.Error())
	}
	for _, flow := range udpFlows {
		flow.flushHeld(reason.Error())
	}
	var err error
	if capture != nil {
		err = capture.Close()
	}
	// closeDone reports that this teardown finished, not that native receipts
	// arrived. A retained native reference keeps the original charged slot
	// alive until its own release callback; Close never waits for it.
	if l.engine != nil {
		l.engine.finishLeaseTeardown(l)
	}
	return err
}

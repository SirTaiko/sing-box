package desync

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// flowCounters are the upstream semantic counters of both directions.
// Injected or replayed packets never increment them. `s` is the unsigned
// relative sequence span `seq_last - seq0` exactly as `nfq/desync.c` returns it,
// where seq_last is the *last observed* original sequence (a retransmission may
// therefore move it backwards, as upstream does) or, for a reply, the ACK
// carried by that reply.
type flowCounters struct {
	packets     uint64
	dataPackets uint64
	sequence    uint64

	replyPackets  uint64
	replyData     uint64
	replySequence uint64
}

// holdEntry is one captured original kept pending while a bounded logical
// message is being assembled. complete is the single terminal disposition of
// that captured packet and is called exactly once: either in the release path
// or when the flow is closed.
type holdEntry struct {
	packet   *Packet
	inject   Injector
	complete Completer
	// origModCutoff/wssizeCutoff snapshot the in-place modifier latches at
	// capture time. Upstream rewrites orig_mod/wssize before delaying the
	// packet, so a later forced or counter cutoff cannot retroactively skip
	// the capture-time rewrite.
	origModCutoff bool
	wssizeCutoff  bool
	counters      flowCounters
}

type flowState struct {
	mu sync.Mutex

	// conntrackSemantics is the semantic conntrack state of this flow. When
	// conntrack is enabled it is shared through the engine's bounded table and
	// survives one native attempt; when it is disabled or an entry expired it
	// points at the flow-local zeroed copy and countersLive is false, exactly
	// like upstream running with a missing t_ctrack (cutoffs can never be
	// reached, start limits block).
	*conntrackSemantics
	localSem conntrackSemantics
	entry    *conntrackEntry
	table    *conntrackTable
	cache    *ipCache
	// iface is the native-attempt interface of this flow (upstream ip4if/ip6if
	// cache key component and capture.oifname selector). Empty means the
	// attempt did not report a device.
	iface        string
	key          conntrackKey
	countersLive bool
	ctAttached   bool
	ctLost       bool
	quic         *quicReassembler

	rule *Rule

	protocol Protocol
	host     string
	facts    Facts

	// Upstream cutoff latches are not flow state: they live on the retained
	// tuple entry (conntrackSemantics.latches) so duplicate/reused attempts
	// on the same tuple share them, ConntrackReInitTrack clears them and
	// entry expiry discards them. See cutoffLatchesSnapshot/update.

	reassembler *reassembler
	failed      bool
	limits      LimitSet
	budget      *atomic.Int64
	now         func() time.Time

	// Auto-hostlist (hostlist-auto) per-flow request tracking. The learned
	// set and the failure cache live on the engine-owned learner; these fields
	// are the upstream per-ctrack hostname_ah_check/req_retrans_counter state
	// of the current owned attempt.
	learning             *learner
	learningHost         string
	learningSkip         bool
	learningReplyChecked bool
	// closed mirrors the owning lease; once true no packet may enter a hold and
	// no release may inject replacements (safe Pass dispositions only).
	closed *atomic.Bool

	// held originals of the current incomplete message, in capture order
	holds        []*holdEntry
	heldBytes    int
	holdDeadline time.Time
	holdTimer    *time.Timer

	// A released-incomplete message latches transformations off for the rest
	// of that message. The latch is cleared by a later structured message
	// that starts beyond the highest released end.
	holdDisabled bool
	resumeSeq    uint32
	resumeCheck  bool
}

func newFlowState(limits LimitSet, budget *atomic.Int64, now func() time.Time) *flowState {
	if now == nil {
		now = time.Now
	}
	state := &flowState{
		reassembler: newReassembler(limits.MaxReassemblyBytes),
		limits:      limits,
		budget:      budget,
		now:         now,
	}
	state.conntrackSemantics = &state.localSem
	return state
}

// attachEngineState binds the per-outbound state owners. It is called once at
// flow construction, before any packet is handled.
func (f *flowState) attachEngineState(table *conntrackTable, cache *ipCache, learn *learner, intent Intent) {
	f.table = table
	f.cache = cache
	f.learning = learn
	f.iface = intent.Interface
	f.key = conntrackKey{family: intent.Family, transport: intent.Transport,
		src: intent.Source.Addr(), dst: intent.Destination.Addr(),
		srcPort: intent.Source.Port(), dstPort: intent.Destination.Port()}
}

// ensureConntrack attaches the bounded table entry for a qualifying packet and
// reports whether semantic counters may be updated. Upstream creates entries
// only for SYN/SYN-ACK/UDP; an expired or absent entry means no counters at
// all, never a silent restart from zero (which would let a cutoff fire twice).
func (f *flowState) ensureConntrack(packet *Packet) bool {
	if f.entry != nil {
		if !f.entry.isExpired() {
			return true
		}
		// The semantic entry timed out. The flow and its held originals keep
		// living; only counter-based features become unavailable.
		f.entry = nil
		f.conntrackSemantics = &f.localSem
		f.countersLive = false
		f.ctLost = true
	}
	if f.table == nil || f.table.disabled {
		return false
	}
	// Source-valid creation: upstream only creates a track for TCP when the
	// packet carries SYN (SYN or SYN-ACK) and for every UDP datagram. A
	// mid-stream owned capture (or an entry lost to expiry) therefore has no
	// semantic counters, never a silent restart from zero. Socket ownership,
	// capture and cleanup stay active regardless.
	if packet.Transport == TransportTCP && !packet.IsSYN() {
		return false
	}
	entry := f.table.acquire(f.key, packet)
	if entry == nil {
		return false
	}
	f.ctAttached = true
	f.ctLost = false
	f.entry = entry
	f.conntrackSemantics = &entry.sem
	f.countersLive = true
	return true
}

func (f *flowState) resetLatches() {
	f.clearCutoffLatches()
}

// cutoffLatchesSnapshot returns the tuple-owned sticky cutoffs. The entry lock
// makes the observation atomic with a concurrent attempt feeding the same
// retained tuple.
func (f *flowState) cutoffLatchesSnapshot() cutoffLatches {
	if f.entry != nil {
		f.entry.mu.Lock()
		defer f.entry.mu.Unlock()
		return f.entry.sem.latches
	}
	return f.localSem.latches
}

// updateCutoffLatches mutates the tuple-owned latches under the entry lock.
func (f *flowState) updateCutoffLatches(update func(*cutoffLatches)) {
	if f.entry != nil {
		f.entry.mu.Lock()
		update(&f.entry.sem.latches)
		f.entry.mu.Unlock()
		return
	}
	update(&f.localSem.latches)
}

func (f *flowState) clearCutoffLatches() {
	f.updateCutoffLatches(func(latches *cutoffLatches) { *latches = cutoffLatches{} })
}

// countersSnapshot reads the semantic counters under the entry lock so a
// second attempt sharing the same tuple cannot race the planning view.
func (f *flowState) countersSnapshot() flowCounters {
	if f.entry != nil {
		f.entry.mu.Lock()
		defer f.entry.mu.Unlock()
		return f.entry.sem.counters
	}
	return f.localSem.counters
}

// observe records one eligible captured original-direction packet.
func (f *flowState) observe(packet *Packet, tcpEmptyACK bool) {
	if !packetEligible(packet, tcpEmptyACK) {
		return
	}
	if f.table == nil {
		// Flow without an engine state owner (direct unit construction): keep
		// the D1-local counting semantics.
		f.countersLive = true
		f.observeLocal(packet)
		return
	}
	if !f.ensureConntrack(packet) {
		return
	}
	if f.entry != nil {
		if f.entry.observe(packet, false, f.now()) {
			// Upstream ConntrackReInitTrack clears the whole track, latches
			// included, on a fresh SYN for a tuple past SYN.
			f.resetLatches()
		}
		return
	}
	f.countersLive = false
}

// observeLocal is the standalone (no shared table) conntrack feed.
func (f *flowState) observeLocal(packet *Packet) {
	sem := f.conntrackSemantics
	sem.counters.packets++
	if len(packet.Payload) > 0 {
		sem.counters.dataPackets++
	}
	if packet.Transport != TransportTCP {
		// Upstream UDP conntrack: seq_last is the previous accumulated payload
		// length, so an `s` limiter sees the bytes seen before this datagram.
		sem.counters.sequence = uint64(sem.posOrig)
		sem.posOrig += uint32(len(packet.Payload))
		return
	}
	if packet.IsSYN() {
		sem.seq0, sem.seq0Set = packet.TCPSeq, true
		sem.state = connStateSYN
	} else {
		if sem.state == connStateSYN {
			sem.state = connStateEstablished
		}
		if !sem.seq0Set {
			sem.seq0 = 0
		}
	}
	if packet.TCPFlags&(tcpFlagFIN|tcpFlagRST) != 0 {
		sem.state = connStateFIN
	}
	sem.seqLast = packet.TCPSeq
	sem.posOrig = sem.seqLast + uint32(len(packet.Payload))
	sem.counters.sequence = uint64(sem.seqLast - sem.seq0)
	sem.winsizeOrig = packet.TCPWindow
}

// observeReplyLocal is the standalone reply feed.
func (f *flowState) observeReplyLocal(packet *Packet) {
	sem := f.conntrackSemantics
	sem.counters.replyPackets++
	if len(packet.Payload) > 0 {
		sem.counters.replyData++
	}
	if !sem.haveHop {
		if guess := HopCountGuess(packet.TTL); guess > 0 {
			sem.hopCount, sem.haveHop = guess, true
		}
	}
	if packet.IsSYN() && packet.TCPFlags&tcpFlagACK != 0 {
		if !sem.ack0Set {
			sem.ack0, sem.ack0Set = packet.TCPAck-1, true
		}
		if !sem.seq0Set {
			sem.seq0, sem.seq0Set = packet.TCPAck-1, true
		}
		sem.ackLast = packet.TCPSeq
		sem.posReply = sem.ackLast + uint32(len(packet.Payload))
		sem.seqLast = packet.TCPAck
		sem.posOrig = sem.seqLast
		sem.counters.sequence = uint64(sem.seqLast - sem.seq0)
		return
	}
	if !sem.ack0Set {
		sem.ack0, sem.ack0Set = packet.TCPSeq, true
	}
	sem.ackLast = packet.TCPSeq
	sem.posReply = sem.ackLast + uint32(len(packet.Payload))
	sem.seqLast = packet.TCPAck
	sem.posOrig = sem.seqLast
	sem.counters.sequence = uint64(sem.seqLast - sem.seq0)
	sem.counters.replySequence = uint64(sem.ackLast - sem.ack0)
}

// observeReply records one eligible captured response packet. Replies feed
// handshake/sequence/ack/window observations; they are never re-injected or
// transformed on the inbound path.
func (f *flowState) observeReply(packet *Packet, tcpEmptyACK bool) {
	if packet.Transport != TransportTCP || !packetEligible(packet, tcpEmptyACK) {
		return
	}
	if f.table == nil {
		f.countersLive = true
		f.observeReplyLocal(packet)
		return
	}
	if !f.ensureConntrack(packet) {
		return
	}
	if f.entry == nil {
		return
	}
	f.entry.observe(packet, true, f.now())
	// autottl discovery uses the observed reply TTL, exactly like upstream's
	// ipcache hop discovery (keyed by the reply source, i.e. our destination).
	if !f.haveHop {
		if hops, ok := f.cache.learnHop(packet.Src, packet.TTL); ok {
			f.entry.mu.Lock()
			f.entry.sem.hopCount, f.entry.sem.haveHop = hops, true
			f.entry.mu.Unlock()
		}
	}
}

// packetEligible applies the portable capture policy: empty outgoing ACKs are
// excluded by default, matching upstream's generated winws filters.
func packetEligible(packet *Packet, tcpEmptyACK bool) bool {
	if packet.IsEmptyACK() && !tcpEmptyACK {
		return false
	}
	return true
}

func (f *flowState) selectRule(config *Config, facts MatchFacts) *Rule {
	if f.rule != nil {
		return f.rule
	}
	for _, rule := range config.Rules {
		if rule.Matches(facts) {
			f.rule = rule
			return rule
		}
	}
	return nil
}

// validateSelection reconsiders a provisional rule when L7 information becomes
// available and the rule's protocol or host predicates no longer hold.
func (f *flowState) validateSelection(facts MatchFacts) bool {
	if f.rule == nil {
		return false
	}
	if !f.rule.AnyProtocol && len(f.rule.Protocols) > 0 {
		found := false
		for _, protocol := range f.rule.Protocols {
			if protocol == facts.Protocol {
				found = true
				break
			}
		}
		if !found && facts.Protocol != ProtocolUnknown {
			f.rule = nil
			return false
		}
	}
	if facts.HostKnown {
		// Excerpt of Rule.Matches host predicates for the reconsideration
		// seam: the full Matches call is not used so an unknown protocol never
		// deselects a rule that was valid before L7. An auto-hostlist profile
		// stays selected when the host is merely not learned yet (upstream
		// keeps the profile and passes the original); it only yields to a user
		// exclusion.
		if f.rule.DomainsExclude.matches(facts.Host) {
			f.rule = nil
			return false
		}
		if f.rule.Learning == nil && !f.rule.Domains.empty() && !f.rule.Domains.matchesHost(facts.Host, facts.HostIsIP) {
			f.rule = nil
			return false
		}
	}
	return true
}

// readLearningState reads the tuple-owned auto-hostlist state under the entry
// lock when a semantic entry exists, so concurrent attempts of the same tuple
// see one consistent counter.
func (f *flowState) readLearningState(read func(*learningSemantics)) {
	if f.entry != nil {
		f.entry.mu.Lock()
		defer f.entry.mu.Unlock()
		read(&f.entry.sem.learn)
		return
	}
	read(&f.localSem.learn)
}

func (f *flowState) updateLearningState(update func(*learningSemantics)) {
	if f.entry != nil {
		f.entry.mu.Lock()
		update(&f.entry.sem.learn)
		f.entry.mu.Unlock()
		return
	}
	update(&f.localSem.learn)
}

// setInterface records the owned native-attempt device discovered from the
// bound socket. It is part of the ipcache key, so a host learned on one
// interface is never served to an attempt on another.
func (f *flowState) setInterface(iface string) {
	f.mu.Lock()
	f.iface = iface
	f.mu.Unlock()
}

// setLearningHost records a validated hostname fact for auto-hostlist
// tracking. A new hostname resets the tuple-owned request retransmission state.
func (f *flowState) setLearningHost(host string) {
	if host == "" {
		return
	}
	current := ""
	f.readLearningState(func(learn *learningSemantics) { current = learn.host })
	if host == current {
		f.learningHost = host
		return
	}
	f.learningHost = host
	f.learningSkip = false
	f.learningReplyChecked = false
	f.updateLearningState(func(learn *learningSemantics) {
		*learn = learningSemantics{host: host}
	})
	f.prepareLearning()
}

// prepareLearning decides whether this host is eligible for auto learning:
// the profile's explicit positive hostlist or the engine learned set stop the
// retransmission counter, user exclusions disable it, and everything else is
// monitored until a failure threshold is reached.
func (f *flowState) prepareLearning() {
	if f.rule == nil || f.rule.Learning == nil || f.learning == nil || f.learningHost == "" {
		f.learningSkip = false
		return
	}
	// Upstream dp_match keeps an auto-hostlist profile selected and defers the
	// host decision: not-yet-listed hosts are monitored but their originals
	// pass untouched, exactly like the send_orig branch of the host check.
	f.learningSkip = true
	if f.rule.DomainsExclude.matches(f.learningHost) {
		f.updateLearningState(func(learn *learningSemantics) { learn.check = false })
		return
	}
	_, learningHostIsIP := parseIPLiteral(f.learningHost)
	if f.learning.learned(f.learningHost) || f.rule.Domains.matchesHost(f.learningHost, learningHostIsIP) {
		// Upstream ctrack_stop_retrans_counter when the hostlist matches.
		f.updateLearningState(func(learn *learningSemantics) {
			learn.stopped = true
			learn.check = false
		})
		f.learningSkip = false
		return
	}
	f.updateLearningState(func(learn *learningSemantics) {
		if !learn.stopped {
			learn.check = true
		}
	})
}

// countLearningRetransmission ports process_retrans_fail: TCP counts a data
// packet whose sequence is inside the already-finalized request range (a
// retransmission); UDP counts a later datagram for the same host. Generated
// and replayed packets never reach this path, so they never recount.
func (f *flowState) countLearningRetransmission(packet *Packet, udp bool) {
	if f.learningHost == "" || f.rule == nil || f.rule.Learning == nil || f.learning == nil {
		return
	}
	const (
		learningActionNone = iota
		learningActionSuccess
		learningActionFailure
	)
	action := learningActionNone
	threshold := f.rule.Learning.retransThreshold
	f.updateLearningState(func(learn *learningSemantics) {
		if !learn.check || learn.stopped {
			return
		}
		if !udp {
			if !learn.reqRange {
				return
			}
			if !sequenceWithin(packet.TCPSeq, learn.reqStart, learn.reqEnd) {
				// Upstream stops tracking and resets the fail counter when the
				// observed sequence leaves the tracked request.
				learn.stopped = true
				action = learningActionSuccess
				return
			}
		}
		learn.retrans++
		if learn.retrans < threshold {
			return
		}
		learn.stopped = true
		action = learningActionFailure
	})
	switch action {
	case learningActionSuccess:
		f.updateLearningState(func(learn *learningSemantics) { learn.check = false })
		f.learning.recordSuccess(f.learningHost)
	case learningActionFailure:
		f.updateLearningState(func(learn *learningSemantics) { learn.check = false })
		if f.learning.recordFailure(f.rule, f.learningHost) {
			// The threshold added the host to the learned set: the rest of this
			// flow may now transform, matching the next upstream host check.
			f.learningSkip = false
		}
	}
}

// markLearningRequestFinalized records the request range the upstream
// req_seq_finalized check uses. It is only called for a complete structured
// message, never for generated packets.
func (f *flowState) markLearningRequestFinalized(start uint32, length int) {
	if length <= 0 {
		return
	}
	f.updateLearningState(func(learn *learningSemantics) {
		if learn.reqRange {
			return
		}
		learn.reqStart = start
		learn.reqEnd = start + uint32(length)
		learn.reqRange = true
	})
}

// observeLearningReply ports the reverse-packet auto-hostlist decision: only
// the first-sequence reply is inspected. A RST or a cross-domain 302/307
// redirect is a DPI failure; any other payload reply proves the host works and
// resets the fail counter.
func (f *flowState) observeLearningReply(packet *Packet) {
	if f.rule == nil || f.rule.Learning == nil || f.learning == nil ||
		f.learningHost == "" || f.learningReplyChecked {
		return
	}
	checking := false
	f.readLearningState(func(learn *learningSemantics) { checking = learn.check })
	if !checking {
		return
	}
	ack0, ackLast, ok := f.ackWindow()
	if !ok || ackLast-ack0 != 1 {
		return
	}
	f.learningReplyChecked = true
	if packet.TCPFlags&tcpFlagRST != 0 {
		f.learning.recordFailure(f.rule, f.learningHost)
		f.updateLearningState(func(learn *learningSemantics) { learn.check = false })
		return
	}
	if len(packet.Payload) == 0 {
		return
	}
	if isHTTPReply(packet.Payload) {
		if httpReplyLooksLikeDPIRedirect(packet.Payload, f.learningHost) {
			f.learning.recordFailure(f.rule, f.learningHost)
			f.updateLearningState(func(learn *learningSemantics) { learn.check = false })
			return
		}
	}
	f.learning.recordSuccess(f.learningHost)
}

func (f *flowState) ackWindow() (uint32, uint32, bool) {
	if f.entry != nil {
		f.entry.mu.Lock()
		defer f.entry.mu.Unlock()
		return f.entry.sem.ack0, f.entry.sem.ackLast, f.entry.sem.ack0Set
	}
	return f.localSem.ack0, f.localSem.ackLast, f.localSem.ack0Set
}

// sequenceWithin ports upstream seq_within (start <= seq <= end).
func sequenceWithin(seq, start, end uint32) bool {
	return int32(seq-start) >= 0 && int32(end-seq) >= 0
}

func (f *flowState) factsFor(packet *Packet) MatchFacts {
	facts := MatchFacts{Family: packet.Family, Transport: TransportTCP,
		Destination: packet.Dst, Port: packet.DstPort, Protocol: f.protocol,
		Host: f.host, HostKnown: f.host != ""}
	if facts.HostKnown {
		_, facts.HostIsIP = parseIPLiteral(facts.Host)
	}
	if !facts.HostKnown {
		// Upstream ipcache_get_hostname: a hostname learned from validated
		// facts for exactly this destination address can drive provisional
		// selection before the current flow reaches L7. It is revalidated once
		// L7 facts arrive, never treated as a terminal match.
		if host, isIP, ok := f.cache.lookupHost(packet.Dst, f.iface); ok {
			facts.Host, facts.HostKnown, facts.HostIsIP = host, true, isIP
		}
	}
	if facts.HostKnown {
		facts.Learned = f.learning.learned(facts.Host)
	}
	return facts
}

// factsForPacket merges the flow's bounded reply observations, the upstream
// limiter state of this captured packet and the packet randomness seam into
// the facts used by planning. Generated or replayed packets never call this.
func (f *flowState) factsForPacket(packet *Packet) Facts {
	facts := f.facts
	facts.HopCount, facts.HaveHop = f.hopCount, f.haveHop
	if !facts.HaveHop {
		// Autottl discovery from the bounded per-outbound hop cache, exactly
		// like upstream ipcacheTouch: a previous reply for this destination
		// supplies the hop count before the current flow sees one.
		if hops, ok := f.cache.lookupHop(packet.Dst); ok {
			facts.HopCount, facts.HaveHop = hops, true
		}
	}
	if facts.Rand == nil {
		facts.Rand = DefaultRand
	}
	counters := f.countersSnapshot()
	facts.counters = counters
	facts.origCounters = counters
	latches := f.cutoffLatchesSnapshot()
	facts.dupCutoffLatched = latches.dup
	facts.origModCutoffLatched = latches.origMod
	facts.wssizeCutoffLatched = latches.wssize
	return facts
}

// refreshCutoffLatches ports `maybe_cutoff` for the currently selected rule.
// The n/d/s limits are evaluated on the orig-direction counters of the current
// packet (which the conntrack feed already incremented). Reaching a cutoff sets
// the upstream latch, which is never cleared even if an s-mode limit later
// moves backwards because of a retransmission.
func (f *flowState) refreshCutoffLatches() {
	if f.rule == nil || !f.countersLive {
		return
	}
	counters := f.countersSnapshot()
	if f.rule.WSSize != nil && f.rule.WSSize.Cutoff.IsSet() && f.rule.WSSize.Cutoff.Reached(counters) {
		f.updateCutoffLatches(func(latches *cutoffLatches) { latches.wssize = true })
	}
	if f.rule.Cutoff.IsSet() && f.rule.Cutoff.Reached(counters) {
		f.updateCutoffLatches(func(latches *cutoffLatches) { latches.desync = true })
	}
	if f.rule.Dup != nil && f.rule.Dup.Cutoff.IsSet() && f.rule.Dup.Cutoff.Reached(counters) {
		f.updateCutoffLatches(func(latches *cutoffLatches) { latches.dup = true })
	}
	if f.rule.Orig != nil && f.rule.Orig.ModCutoff.IsSet() && f.rule.Orig.ModCutoff.Reached(counters) {
		f.updateCutoffLatches(func(latches *cutoffLatches) { latches.origMod = true })
	}
}

// applyForcedWSSizeCutoff ports `forced_wssize_cutoff`: a recognized protocol
// that is complete latches the server-window cutoff off. Upstream applies it
// for an HTTP request and for a full (or single-segment) TLS ClientHello.
func (f *flowState) applyForcedWSSizeCutoff(protocol Protocol, message []byte) {
	if f.rule == nil || f.rule.WSSize == nil || !f.rule.WSSize.ForcedCutoff {
		return
	}
	if protocol == ProtocolUnknown || !messageComplete(protocol, message) {
		return
	}
	f.updateCutoffLatches(func(latches *cutoffLatches) { latches.wssize = true })
}

// handleReply plans in-place reply transformations for one inbound packet.
// Callers hold f.mu. It never injects: the bytes are delivered with the native
// disposition. Only SYN-ACK `wsize` and `synack_split=syn` are reply-side in
// upstream; wssize/orig/dup are original-direction only.
func (f *flowState) handleReply(config *Config, packet *Packet) ([]byte, error) {
	if f.rule == nil || f.failed {
		return nil, nil
	}
	return PlanReply(f.rule, packet)
}

// needsAssembly reports whether the selected rule can only be planned once the
// whole logical message is known.
func (f *flowState) needsAssembly() bool {
	if f.rule == nil || f.holdDisabled {
		return false
	}
	for _, method := range f.rule.Methods {
		switch method.Kind {
		case MethodMultiSplit, MethodMultiDisorder, MethodFakeDSplit, MethodFakeDDisorder, MethodHostFakeSplit:
			// All split families resolve positions against the complete
			// logical request, including hostfakesplit's Host/SNI boundaries.
			return true
		}
	}
	return false
}

// handleTCP processes one captured outbound TCP packet. When it returns
// VerdictHold the caller must not issue a native disposition: the held original
// is released exactly once through its Completer.
func (f *flowState) handleTCP(config *Config, packet *Packet, intent Intent, inject Injector, complete Completer) (Verdict, *Batch) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed {
		return VerdictPass, nil
	}
	if f.leaseClosed() {
		return VerdictPass, nil
	}
	// Counters cover every eligible captured original, independent of when a
	// rule is selected (upstream conntrack feed).
	f.observe(packet, config.TCPEmptyACK)
	if f.rule == nil {
		f.selectRule(config, f.factsFor(packet))
	}
	f.refreshCutoffLatches()
	if len(packet.Payload) > 0 {
		// Upstream calls process_retrans_fail for every forward payload
		// packet, before this packet's host facts are considered.
		f.countLearningRetransmission(packet, false)
	}
	if f.resumeCheck && !sequenceBefore(packet.TCPSeq, f.resumeSeq) && len(packet.Payload) > 0 &&
		looksLikeStructuredMessage(packet.Payload) {
		// A new structured message starts beyond the released one: the
		// bounded fallback latch no longer applies.
		f.resumeCheck = false
		f.holdDisabled = false
		f.reassembler.Reset()
	}
	if f.skipLatched() {
		return VerdictPass, nil
	}
	if packet.IsSYN() || len(packet.Payload) == 0 {
		// The upstream start/cutoff interval is evaluated on every forward
		// packet, after orig_mod/wssize and before the zero stage. A blocked
		// interval skips the stage but still runs the independent dup branch.
		if f.rule == nil {
			return VerdictPass, nil
		}
		if !f.intervalAllows() {
			batch := &Batch{Original: VerdictPass}
			facts := f.factsForPacket(packet)
			working, planErr := planInPlace(f.rule, packet, facts, batch)
			if planErr != nil {
				f.failed = true
				return VerdictPass, &Batch{Original: VerdictPass, Reason: planErr.Error()}
			}
			if planErr = planDup(f.rule, packet, working, facts, batch, facts.Rand); planErr != nil {
				f.failed = true
				return VerdictPass, &Batch{Original: VerdictPass, Reason: planErr.Error()}
			}
			return batch.Original, batch
		}
		batch, err := PlanTCP(f.rule, packet, packet.Payload, 0, f.factsForPacket(packet))
		if err != nil {
			f.failed = true
			return VerdictPass, &Batch{Original: VerdictPass, Reason: err.Error()}
		}
		return batch.Original, batch
	}
	if err := f.reassembler.Add(packet.TCPSeq, packet.Payload); err != nil {
		// Bounded assembly fallback: the held originals are released in
		// capture order and this packet passes unchanged.
		f.releaseHoldsLocked("reassembly limit: " + err.Error())
		f.failed = true
		return VerdictPass, &Batch{Original: VerdictPass, Reason: err.Error()}
	}
	start, message := f.reassembler.Contiguous()
	if len(message) == 0 {
		return VerdictPass, nil
	}
	protocol, host, facts := protocolFacts(message)
	if protocol != ProtocolUnknown {
		f.protocol = protocol
	}
	if host != "" {
		f.host = host
		// Hostname facts are cached only after validated L7 parsing, keyed by
		// the exact destination address (upstream ipcache_put_hostname).
		f.cache.learnHost(packet.Dst, f.iface, host)
		f.setLearningHost(host)
	}
	f.facts = facts
	f.facts.MessageLength = len(message)
	if f.rule != nil && !f.validateSelection(f.factsFor(packet)) {
		f.selectRule(config, f.factsFor(packet))
		f.prepareLearning()
	}
	if f.rule == nil {
		f.releaseHoldsLocked("no matching rule")
		return VerdictPass, nil
	}
	if messageComplete(protocol, message) {
		f.markLearningRequestFinalized(start, len(message))
	}
	if f.learningSkip {
		// Auto-hostlist profile with a known host that is neither explicitly
		// listed nor learned: upstream passes the original unchanged while the
		// failure counters keep running.
		f.releaseHoldsLocked("host not in auto hostlist")
		return VerdictPass, nil
	}
	f.refreshCutoffLatches()
	offset := int(int32(packet.TCPSeq - start))
	if offset < 0 || offset > len(message) {
		offset = 0
	}
	// The desync interval is evaluated before a packet may be held, so a
	// packet captured before `start` or at/after `cutoff` never enters the hold
	// queue and can never be transformed by a later release. A blocked
	// interval still reaches the upstream send_orig path, where orig_mod,
	// wssize and the independent dup limiter apply; the forced wssize cutoff
	// is only learned after this check.
	if !f.intervalAllows() {
		f.releaseHoldsLocked("desync interval ended")
		batch := &Batch{Original: VerdictPass}
		facts := f.factsForPacket(packet)
		working, planErr := planInPlace(f.rule, packet, facts, batch)
		if planErr != nil {
			f.failed = true
			return VerdictPass, &Batch{Original: VerdictPass, Reason: planErr.Error()}
		}
		if planErr = planDup(f.rule, packet, working, facts, batch, facts.Rand); planErr != nil {
			f.failed = true
			return VerdictPass, &Batch{Original: VerdictPass, Reason: planErr.Error()}
		}
		return batch.Original, batch
	}
	// Hold the original while a bounded, structured message is still being
	// assembled. Unknown traffic and complete messages never wait.
	if f.needsAssembly() && !messageComplete(protocol, message) {
		if f.leaseClosed() {
			return VerdictPass, nil
		}
		if f.canHold(len(packet.Raw)) {
			f.holdLocked(packet, inject, complete)
			return VerdictHold, nil
		}
		// Hold budget exhausted: bounded fallback for this message. Every held
		// original is released in capture order first.
		f.releaseHoldsLocked("hold budget exhausted")
		f.holdDisabled = true
		f.resumeCheck = true
		f.resumeSeq = f.posOrig
		return VerdictPass, nil
	}
	if f.holding() {
		// The message completed (or stopped needing assembly): plan the whole
		// batch for every held original in capture order before suppressing
		// any of them, then handle this packet.
		f.releaseHoldsLocked("")
		if f.failed {
			return VerdictPass, nil
		}
	}
	batch, err := PlanTCP(f.rule, packet, message, offset, f.factsForPacket(packet))
	if err != nil {
		f.failed = true
		return VerdictPass, &Batch{Original: VerdictPass, Reason: err.Error()}
	}
	// Upstream applies wssize to this packet before it learns the protocol and
	// only then latches the forced cutoff for later packets.
	f.applyForcedWSSizeCutoff(protocol, message)
	return batch.Original, batch
}

// skipLatched reports whether transformations are latched off for the rest of a
// released message. It only decides that the packet belongs to the released
// message: the latch is cleared exclusively by the structured-message check in
// handleTCP, so an unstructured tail can never resume transformations.
func (f *flowState) skipLatched() bool {
	return f.holdDisabled
}

func (f *flowState) leaseClosed() bool {
	return f.closed != nil && f.closed.Load()
}

func (f *flowState) intervalAllows() bool {
	if f.rule.Start.IsSet() {
		// Upstream check_desync_interval: a configured start with a missing
		// conntrack entry refuses to desync rather than restarting the count.
		if !f.countersLive || !f.rule.Start.Reached(f.countersSnapshot()) {
			return false
		}
	}
	if f.cutoffLatchesSnapshot().desync {
		return false
	}
	return true
}

func (f *flowState) holding() bool { return len(f.holds) > 0 }

func (f *flowState) canHold(size int) bool {
	if f.limits.MaxHeldPackets <= 0 || f.limits.MaxHeldBytes <= 0 || f.budget == nil {
		return true
	}
	if len(f.holds) >= f.limits.MaxHeldPackets {
		return false
	}
	if f.heldBytes+size > f.limits.MaxHeldBytes {
		return false
	}
	return f.reserveBudget(size)
}

func (f *flowState) reserveBudget(bytes int) bool {
	if f.budget == nil || f.limits.MaxHeldBytesTotal <= 0 {
		return true
	}
	total := int64(bytes)
	if total <= 0 {
		return true
	}
	for {
		current := f.budget.Load()
		if current+total > int64(f.limits.MaxHeldBytesTotal) {
			return false
		}
		if f.budget.CompareAndSwap(current, current+total) {
			return true
		}
	}
}

func (f *flowState) holdLocked(packet *Packet, inject Injector, complete Completer) {
	if complete == nil {
		complete = func(Verdict, string, []byte) {}
	}
	latches := f.cutoffLatchesSnapshot()
	f.holds = append(f.holds, &holdEntry{packet: packet, inject: inject, complete: complete,
		origModCutoff: latches.origMod, wssizeCutoff: latches.wssize, counters: f.counters})
	f.heldBytes += len(packet.Raw)
	if f.holdTimer == nil {
		f.holdDeadline = f.now().Add(f.limits.HoldTimeout)
		f.holdTimer = time.AfterFunc(f.limits.HoldTimeout, f.expire)
	}
}

// expire is the autonomous deadline release. It never waits for a later
// packet: held originals are released in capture order even when the initial
// flight will never be completed.
func (f *flowState) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.holds) == 0 {
		return
	}
	if f.now().Before(f.holdDeadline) {
		// Fake clock (hermetic tests): retry at the real deadline offset.
		f.holdTimer = time.AfterFunc(f.holdDeadline.Sub(f.now()), f.expire)
		return
	}
	f.releaseHoldsLocked("incomplete message hold deadline exceeded")
	f.holdDisabled = true
	f.resumeCheck = true
	f.resumeSeq = f.posOrig
}

// releaseHoldsLocked releases every held original in capture order. reason
// non-empty means the logical message was not completed: originals pass
// unchanged, transformations for that message are latched off and no replay is
// counted. reason empty means the message completed and a whole batch is
// planned for all held originals before any original is suppressed.
func (f *flowState) releaseHoldsLocked(reason string) {
	if len(f.holds) == 0 {
		if f.holdTimer != nil {
			f.holdTimer.Stop()
			f.holdTimer = nil
		}
		return
	}
	if f.holdTimer != nil {
		f.holdTimer.Stop()
		f.holdTimer = nil
	}
	holds := f.holds
	f.holds = nil
	if f.budget != nil && f.limits.MaxHeldBytesTotal > 0 {
		f.budget.Add(-int64(f.heldBytes))
	}
	f.heldBytes = 0
	start, message := f.reassembler.Contiguous()
	plan := reason == "" && f.rule != nil && !f.holdDisabled && messageComplete(f.protocol, message)

	type plannedHold struct {
		entry  *holdEntry
		batch  *Batch
		failed bool
	}
	planned := make([]plannedHold, 0, len(holds))
	// Phase 1: plan every held packet. A planning error suppresses nothing.
	for _, entry := range holds {
		item := plannedHold{entry: entry}
		if plan {
			offset := int(int32(entry.packet.TCPSeq - start))
			if offset >= 0 && offset < len(message) {
				facts := f.factsForPacket(entry.packet)
				// In-place modifiers were decided when the packet was
				// captured; duplicates use the current dup latch, exactly like
				// upstream's replay path.
				facts.origModCutoffLatched = entry.origModCutoff
				facts.wssizeCutoffLatched = entry.wssizeCutoff
				facts.origCounters = entry.counters
				batch, err := PlanTCP(f.rule, entry.packet, message, offset, facts)
				if err != nil {
					f.failed = true
					item.failed = true
				} else {
					item.batch = batch
				}
			}
		}
		planned = append(planned, item)
	}
	// Phase 2: send every replacement batch. If any send fails, the original
	// of that packet and of every packet after it still pass, so no real byte
	// is ever dropped after a partial failure (TCP treats the duplicates as
	// harmless). A Modify without replacement bytes is also delivered as the
	// original: the terminal disposition must always be safe on its own.
	terminal := make([]bool, len(planned))
	for index, item := range planned {
		if item.batch == nil || item.failed {
			continue
		}
		if f.leaseClosed() {
			// No late work after close: the original is delivered unchanged and
			// nothing is injected into a torn-down capture.
			item.batch.Reason = "lease closed"
			continue
		}
		ok := true
		for _, replacement := range item.batch.Packets {
			if item.entry.inject == nil {
				ok = false
				break
			}
			if injectErr := item.entry.inject(replacement); injectErr != nil {
				f.failed = true
				ok = false
				item.batch.Reason = "partial replacement failure: " + injectErr.Error()
				break
			}
		}
		switch item.batch.Original {
		case VerdictDrop:
			if len(item.batch.Packets) == 0 {
				ok = false
			}
		case VerdictModify:
			if len(item.batch.Modified) == 0 {
				ok = false
			}
		}
		terminal[index] = ok
	}
	// Phase 3: exactly one terminal disposition per held original, in capture
	// order. A Modify always carries the exact bytes belonging to this captured
	// packet; there is no shared slot that another release could consume.
	for index, item := range planned {
		if terminal[index] {
			modified := item.batch.Modified
			if item.batch.Original != VerdictModify {
				modified = nil
			}
			item.entry.complete(item.batch.Original, item.batch.Reason, modified)
			continue
		}
		reasonText := reason
		if item.batch != nil && item.batch.Reason != "" {
			reasonText = item.batch.Reason
		}
		item.entry.complete(VerdictPass, reasonText, nil)
	}
}

// flushHeld releases held originals for flow teardown without counting replay.
func (f *flowState) flushHeld(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseHoldsLocked(reason)
}

func (f *flowState) handleUDP(config *Config, packet *Packet) (*Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed || f.leaseClosed() {
		return nil, nil
	}
	protocol := classifyUDPPayload(packet)
	// Hostname facts come from the pinned upstream Initial decrypt + CRYPTO
	// reassembly path, never from a plaintext scan or a port guess. CRYPTO
	// fragments may span several Initial datagrams of the same connection;
	// decryption and validation happen before any fact is reported.
	host := ""
	discoveredHost := false
	if protocol == ProtocolQUIC {
		if f.quic == nil {
			f.quic = newQUICReassembler()
		}
		if name, ok := f.quic.add(packet.Payload); ok {
			host = name
			discoveredHost = true
		}
	}
	facts := MatchFacts{Family: packet.Family, Transport: TransportUDP, Destination: packet.Dst,
		Port: packet.DstPort, Protocol: protocol, Host: host, HostKnown: host != ""}
	if facts.HostKnown {
		_, facts.HostIsIP = parseIPLiteral(facts.Host)
	}
	if host == "" {
		// Provisional selection may use a hostname learned for this exact
		// destination address; it is revalidated below once L7 facts arrive.
		if cached, isIP, ok := f.cache.lookupHost(packet.Dst, f.iface); ok {
			facts.Host, facts.HostKnown, facts.HostIsIP = cached, true, isIP
		}
	}
	if facts.HostKnown {
		facts.Learned = f.learning.learned(facts.Host)
	}
	f.observe(packet, config.TCPEmptyACK)
	if f.rule == nil {
		f.selectRule(config, facts)
	} else if host != "" && !f.validateSelection(facts) {
		// A provisional pre-L7 match must be reconsidered when the decrypted
		// ClientHello names a different host or protocol. No permanent match is
		// kept from the no-host SYN/datagram state.
		f.selectRule(config, facts)
	}
	if facts.HostKnown {
		f.setLearningHost(facts.Host)
	}
	if !discoveredHost {
		// Upstream counts a later datagram for an already-known auto-hostlist
		// host as a retransmission trigger.
		f.countLearningRetransmission(packet, true)
	}
	if f.learningSkip {
		return nil, nil
	}
	if f.rule == nil {
		return nil, nil
	}
	if host != "" {
		f.host = host
		f.facts.Host, f.facts.HostKnown = host, true
		f.cache.learnHost(packet.Dst, f.iface, host)
	}
	f.refreshCutoffLatches()
	if !f.intervalAllows() {
		return nil, nil
	}
	batch, err := PlanUDP(f.rule, packet)
	if err != nil {
		f.failed = true
		return &Batch{Original: VerdictPass, Reason: err.Error()}, nil
	}
	if batch == nil || batch.Original == VerdictDrop {
		return batch, nil
	}
	// orig_mod applies to UDP originals too; duplicates follow the upstream
	// udp_orig_send branch. The original datagram is delivered at most once:
	// if any replacement send fails the engine returns Pass, never a second
	// copy through this path.
	planFacts := f.factsForPacket(packet)
	working, modErr := applyOrigMod(f.rule, packet, planFacts, batch)
	if modErr != nil {
		f.failed = true
		return &Batch{Original: VerdictPass, Reason: modErr.Error()}, nil
	}
	if err = planUDPDup(f.rule, packet, working, planFacts, batch, planFacts.Rand); err != nil {
		f.failed = true
		return &Batch{Original: VerdictPass, Reason: err.Error()}, nil
	}
	return batch, nil
}

// Intent is the immutable per-native-attempt description supplied by the
// dialer before any side effect.
type Intent struct {
	Family    Family
	Transport Transport
	Source    netip.AddrPort
	// Interface is the native-attempt output device reported by the dialer
	// (SO_BINDTODEVICE/interface binding, Windows interface index name). It is
	// an owned-attempt fact, never inferred from configuration.
	Interface string
	// InterfaceIndex is the Windows interface index the owned native socket
	// was actually bound to (queried from the socket), zero when unknown.
	InterfaceIndex uint32
	Destination    netip.AddrPort
	Host           string
	TCPEmptyACK    bool
}

// Endpoint is the owned tuple a backend must capture.
type Endpoint struct {
	Family    Family
	Transport Transport
	Source    netip.AddrPort
	// Interface is the owned attempt's output device, when the dialer bound
	// one. Capture selectors never invent a name for an unbound attempt.
	Interface string
	// InterfaceIndex is the owned attempt's Windows interface index, zero when
	// the attempt is not interface-bound. It is the only interface identity a
	// WinDivert envelope may use.
	InterfaceIndex uint32
	Destination    netip.AddrPort
}

func (i Intent) endpoint() Endpoint {
	return Endpoint{Family: i.Family, Transport: i.Transport, Source: i.Source,
		Interface: i.Interface, InterfaceIndex: i.InterfaceIndex, Destination: i.Destination}
}

var errEngineClosed = fmt.Errorf("desync: engine closed")
var errLeaseClosed = fmt.Errorf("desync: lease closed")
var errCaptureUnavailable = fmt.Errorf("desync: native capture unavailable")

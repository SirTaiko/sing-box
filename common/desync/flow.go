package desync

import (
	"bytes"
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
	// holdGen guards the autonomous deadline callback: a timer armed for an
	// older cycle can never release the records of a newer one.
	holdGen uint64
	// holdRelease joins the one detached synchronous release while callbacks
	// run without mu. Outbound handlers, timers and teardown wait without mu
	// before touching the next cycle. It carries no packets or extra ownership:
	// the existing release keeps each reservation until its completer returns.
	holdRelease chan struct{}

	// udpFlow marks this state as one owned outbound UDP peer. The held-packet
	// release is then the QUIC queue/replay implementation instead of the TCP
	// range replay, and no flow-lifetime latch may be set by a cancelled cycle.
	udpFlow bool
	// udpRequestSeen records that this flow already completed one validated
	// QUIC request cycle. Pinned calls process_retrans_fail only for a later
	// completed request (replay offset zero), so the first request must not be
	// counted as a retransmission and pending/refused fragments never are.
	udpRequestSeen bool

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

// reselectRule re-runs the ordered first-match selection from the top of the
// configuration instead of keeping a provisional selection. It ports the
// upstream dp_find() re-evaluation that runs when L7 facts are revealed
// (nfq/desync.c, "desync profile changed by revealed l7 protocol or hostname"):
// a host-scoped rule that could not match a SYN/datagram-time flow because the
// hostname was unknown wins as soon as the first eligible message carries it.
// No rule now matching clears the selection; the caller then delivers the
// original unchanged, exactly like reasm_orig_cancel + send_orig.
func (f *flowState) reselectRule(config *Config, facts MatchFacts) *Rule {
	f.rule = nil
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
	f.lockAfterHoldRelease()
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
	protocolDiscovered := protocol != ProtocolUnknown && f.protocol == ProtocolUnknown
	if protocol != ProtocolUnknown {
		f.protocol = protocol
	}
	hostDiscovered := host != "" && f.host == ""
	if host != "" {
		f.host = host
		// Hostname facts are cached only after validated L7 parsing, keyed by
		// the exact destination address (upstream ipcache_put_hostname).
		f.cache.learnHost(packet.Dst, f.iface, host)
		f.setLearningHost(host)
	}
	f.facts = facts
	f.facts.MessageLength = len(message)
	if protocolDiscovered || hostDiscovered {
		// The revealed L7 facts re-run the ordered selection from the top, so
		// a provisional SYN-time rule cannot lock a host-scoped flow. The
		// limiter latches keep upstream's OR semantics and the counters are
		// untouched; a configuration with no matching rule passes the message
		// unchanged, exactly like reasm_orig_cancel + send_orig.
		previous := f.rule
		if f.reselectRule(config, f.factsFor(packet)) == nil {
			f.releaseHoldsLocked("no matching rule")
			return VerdictPass, nil
		}
		if f.rule != previous {
			f.prepareLearning()
		}
	} else if f.rule != nil && !f.validateSelection(f.factsFor(packet)) {
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
		f.armHoldTimerLocked()
	}
}

// armHoldTimerLocked arms the absolute deadline of the first held record. The
// deadline is never refreshed by a later hold, a retransmission or a duplicate
// frame; the generation captured by the callback prevents a timer of an older
// cycle from releasing a newer one.
func (f *flowState) armHoldTimerLocked() {
	f.holdDeadline = f.now().Add(f.limits.HoldTimeout)
	f.holdGen++
	gen := f.holdGen
	f.holdTimer = time.AfterFunc(f.limits.HoldTimeout, func() { f.expireGen(gen) })
}

// expire is the autonomous deadline release. It never waits for a later
// packet: held originals are released in capture order even when the initial
// flight will never be completed.
func (f *flowState) expire() {
	f.lockAfterHoldRelease()
	defer f.mu.Unlock()
	f.expireLocked(f.holdGen)
}

// expireGen is the timer-callback entry. A callback armed before the last
// re-arm is a no-op: it can only return a long-finished cycle.
func (f *flowState) expireGen(gen uint64) {
	f.lockAfterHoldRelease()
	defer f.mu.Unlock()
	if gen != f.holdGen {
		return
	}
	f.expireLocked(gen)
}

func (f *flowState) expireLocked(gen uint64) {
	if gen != f.holdGen {
		return
	}
	if len(f.holds) == 0 {
		return
	}
	if f.now().Before(f.holdDeadline) {
		// Fake clock (hermetic tests): retry at the real deadline offset.
		f.holdTimer = time.AfterFunc(f.holdDeadline.Sub(f.now()), func() { f.expireGen(gen) })
		return
	}
	f.releaseHoldsLocked("incomplete message hold deadline exceeded")
	if !f.udpFlow {
		// A cancelled TCP message is latched off for the rest of that
		// message; a UDP cycle is independent and must not disable the flow.
		f.holdDisabled = true
		f.resumeCheck = true
		f.resumeSeq = f.posOrig
	}
}

// releaseHoldsLocked releases every held original in capture order. reason
// non-empty means the logical message was not completed: originals pass
// unchanged, transformations for that message are latched off and no replay is
// counted. reason empty means the message completed and a whole batch is
// planned for all held originals before any original is suppressed.
//
// Each held original still receives exactly one terminal disposition. A record
// whose whole payload range is already carried by an earlier held original of
// the same release is the exception: it is a captured retransmission of bytes
// this release is already delivering, so it is released as a drop instead of
// replaying those bytes a second time. Range coverage alone is not enough to
// discard a captured record: a drop also requires that the record add no TCP
// control effect of its own (a FIN must reach the peer) and that every payload
// byte equal the value this release already delivers. A covered record that
// fails either test passes unchanged, because a repeated range is harmless for
// TCP while a lost flag or a substituted byte is not recoverable.
func (f *flowState) releaseHoldsLocked(reason string) {
	if f.udpFlow {
		// UDP datagrams are never deduplicated or range-replayed: the queued
		// records are one QUIC CRYPTO cycle whose replay is planned from the
		// selected rule and delivered in capture order.
		f.releaseUDPHoldsLocked(reason)
		return
	}
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
	f.beginHoldReleaseLocked()
	defer f.endHoldReleaseLocked()
	start, message := f.reassembler.Contiguous()
	plan := reason == "" && f.rule != nil && !f.holdDisabled && messageComplete(f.protocol, message)

	type plannedHold struct {
		entry  *holdEntry
		batch  *Batch
		failed bool
		// covered is set when every payload byte of this captured original is
		// already carried by an earlier held original of the same release and
		// the record adds no control effect or different byte of its own.
		covered bool
		// coveredPass is set when the payload range is already released but the
		// record still owns a control flag or a byte value the release has not
		// delivered. It holds the reason it must pass unchanged instead.
		coveredPass string
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
	// Phase 1b: a native retransmission of pending bytes is captured while the
	// message is still held and therefore becomes a second pending original for
	// a range an earlier pending original already owns. Releasing it would put
	// exactly the same stream bytes on the wire a second time (the flush replay
	// QA478 measured as extra held-prefix records). Every earlier original is
	// dispositioned exactly once and always carries its payload - as the
	// original, as an in-place modification, or as replacement packets that
	// partition the payload - so a later record whose whole range is inside
	// those already released ranges carries no new byte of its own.
	//
	// The range stays the only coverage authority. It is not sufficient to drop
	// the record: a captured retransmission may own a TCP control effect (FIN
	// while the prefix is still unacknowledged) or genuinely different bytes
	// for the same range, and neither is reconstructible from coverage. Such a
	// record passes unchanged; only an exact byte copy with no control flags of
	// its own is released as the covered drop.
	released := make([]payloadInterval, 0, len(planned))
	releasedBytes := make([]releasedPayload, 0, len(planned))
	covered := make([]bool, len(planned))
	for index := range planned {
		packet := planned[index].entry.packet
		interval := payloadInterval{start: packet.TCPSeq, length: len(packet.Payload)}
		if interval.length <= 0 {
			continue
		}
		if payloadIntervalCovered(released, interval) {
			switch {
			case packet.TCPFlags&^(tcpFlagACK|tcpFlagPSH) != 0:
				planned[index].coveredPass = "covered retransmission carries TCP control flags"
			case !payloadReleasedExactly(releasedBytes, packet.TCPSeq, packet.Payload):
				planned[index].coveredPass = "covered retransmission carries bytes not released by an earlier held original"
			default:
				planned[index].covered = true
				covered[index] = true
			}
			continue
		}
		released = append(released, interval)
		releasedBytes = appendReleasedPayload(releasedBytes, packet.TCPSeq, packet.Payload)
	}
	// Phase 2: send every replacement batch. If any send fails, the original
	// of that packet and of every packet after it still pass, so no real byte
	// is ever dropped after a partial failure (TCP treats the duplicates as
	// harmless). A Modify without replacement bytes is also delivered as the
	// original: the terminal disposition must always be safe on its own.
	terminal := make([]bool, len(planned))
	for index, item := range planned {
		if covered[index] || item.coveredPass != "" {
			// Its bytes are already carried by an earlier original of this
			// release, so its own planned replacements must not be sent either:
			// that is the same replay through the replacement path. A covered
			// record that passes unchanged delivers its own captured bytes, so
			// its planned split must equally not be injected.
			continue
		}
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
			if injectErr := f.injectHeldLocked(item.entry.inject, replacement); injectErr != nil {
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
		if covered[index] {
			// One disposition for this captured record: it is dropped because
			// an earlier original of the same release already carries exactly
			// these bytes. The drop is terminal for the record, not a decision
			// to stop delivering the stream: that obligation was discharged
			// above.
			f.completeTCPHoldLocked(item.entry, VerdictDrop, "duplicate of bytes released by an earlier held original", nil)
			continue
		}
		if item.coveredPass != "" {
			// The range is already carried by an earlier original, but this
			// record owns a control effect or a different byte value that a
			// drop would erase. It passes unchanged exactly once.
			f.completeTCPHoldLocked(item.entry, VerdictPass, item.coveredPass, nil)
			continue
		}
		if terminal[index] {
			modified := item.batch.Modified
			if item.batch.Original != VerdictModify {
				modified = nil
			}
			f.completeTCPHoldLocked(item.entry, item.batch.Original, item.batch.Reason, modified)
			continue
		}
		reasonText := reason
		if item.batch != nil && item.batch.Reason != "" {
			reasonText = item.batch.Reason
		}
		f.completeTCPHoldLocked(item.entry, VerdictPass, reasonText, nil)
	}
}

// lockAfterHoldRelease returns with mu held only after an earlier detached
// release is terminal. Merely dropping mu around I/O would let a timer, Close
// or a new cycle overtake that release and retire/reuse its ownership early.
func (f *flowState) lockAfterHoldRelease() {
	f.mu.Lock()
	for f.holdRelease != nil {
		done := f.holdRelease
		f.mu.Unlock()
		<-done
		f.mu.Lock()
	}
}

// begin/end are called under mu by the release owner. The entrypoints above
// already joined any preceding release; UDP's empty-reason arm delegates to
// replayUDPCycleLocked instead of starting a second release.
func (f *flowState) beginHoldReleaseLocked() {
	f.holdRelease = make(chan struct{})
}

func (f *flowState) endHoldReleaseLocked() {
	close(f.holdRelease)
	f.holdRelease = nil
}

// These callbacks can synchronously enter a pinned namespace helper or send a
// native disposition. They receive only the detached plan/record, never mu.
// Reacquire mu before updating state or returning to the locked caller.
func (f *flowState) injectHeldLocked(inject Injector, raw []byte) error {
	f.mu.Unlock()
	defer f.mu.Lock()
	return inject(raw)
}

func (f *flowState) completeHeldLocked(entry *holdEntry, verdict Verdict, reason string, modified []byte) {
	f.mu.Unlock()
	defer f.mu.Lock()
	entry.complete(verdict, reason, modified)
}

// completeTCPHoldLocked retains the detached record's reservation through its
// synchronous terminal disposition. The release receipt joins Close/timers;
// removing a record from holds alone does not return its byte-budget capacity.
func (f *flowState) completeTCPHoldLocked(entry *holdEntry, verdict Verdict, reason string, modified []byte) {
	size := len(entry.packet.Raw)
	f.completeHeldLocked(entry, verdict, reason, modified)
	f.heldBytes -= size
	if f.budget != nil && f.limits.MaxHeldBytesTotal > 0 {
		f.budget.Add(-int64(size))
	}
}

// payloadInterval is one TCP payload range in stream coordinates.
type payloadInterval struct {
	start  uint32
	length int
}

// payloadIntervalCovered reports whether every byte of want is already inside
// the union of the disjoint intervals in released. The held-prefix release uses
// it to recognise a captured retransmission of pending bytes exactly, without a
// payload digest and without refusing any record that carries a new byte.
func payloadIntervalCovered(released []payloadInterval, want payloadInterval) bool {
	if want.length <= 0 {
		return false
	}
	position := want.start
	end := want.start + uint32(want.length)
	for sequenceBefore(position, end) {
		next := position
		found := false
		for _, have := range released {
			haveEnd := have.start + uint32(have.length)
			if sequenceInside(position, have.start, haveEnd) {
				next = haveEnd
				found = true
				break
			}
		}
		if !found {
			return false
		}
		position = next
	}
	return true
}

// releasedPayload is one disjoint run of payload bytes an earlier held original
// of the same release delivers on the wire, in capture order.
type releasedPayload struct {
	start uint32
	data  []byte
}

// appendReleasedPayload records only the bytes of payload that no earlier
// released record already carries, so the authority stays disjoint, bounded by
// the held payload bytes of this release, and byte-exact for later comparisons.
func appendReleasedPayload(released []releasedPayload, sequence uint32, payload []byte) []releasedPayload {
	covered := make([]payloadInterval, 0, len(released))
	for _, entry := range released {
		covered = append(covered, payloadInterval{start: entry.start, length: len(entry.data)})
	}
	for _, piece := range uncoveredPayload(sequence, payload, covered) {
		released = append(released, releasedPayload{start: piece.start, data: piece.data})
	}
	return released
}

// payloadReleasedExactly reports whether every byte of payload at sequence is
// already carried with the same value by an earlier held original of this
// release. A gap or a different byte means the record still owns information
// this release has not delivered, so dropping it would substitute or erase
// captured bytes.
func payloadReleasedExactly(released []releasedPayload, sequence uint32, payload []byte) bool {
	position := sequence
	remaining := payload
	for len(remaining) > 0 {
		matched := false
		for _, entry := range released {
			end := entry.start + uint32(len(entry.data))
			if !sequenceInside(position, entry.start, end) {
				continue
			}
			offset := int(position - entry.start)
			count := len(entry.data) - offset
			if count > len(remaining) {
				count = len(remaining)
			}
			if !bytes.Equal(entry.data[offset:offset+count], remaining[:count]) {
				return false
			}
			position += uint32(count)
			remaining = remaining[count:]
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

// flushHeld releases held originals for flow teardown without counting replay.
func (f *flowState) flushHeld(reason string) {
	f.lockAfterHoldRelease()
	defer f.mu.Unlock()
	f.releaseHoldsLocked(reason)
}

// udpAdmission is the pinned fake-unit admission decision for one outbound UDP
// datagram. Pinned nfq/desync.c admits a QUIC fake unit per completed CRYPTO
// reassembly cycle (delayed queue replay, reasm_offset == 0), not per datagram
// that happens to share the flow: a retransmission or a cached-host match is
// not by itself fake-eligible.
type udpAdmission uint8

const (
	// udpAdmitStages: non-QUIC datagram; every configured UDP stage applies.
	udpAdmitStages udpAdmission = iota
	// udpAdmitCycleComplete: this Initial completed a ClientHello reassembly
	// cycle, so the cycle's single fake burst belongs to it.
	udpAdmitCycleComplete
	// udpAdmitCyclePending: this Initial is part of an incomplete cycle.
	// Upstream delays it and replays it without a fake burst of its own; the
	// original still has to be delivered.
	udpAdmitCyclePending
	// udpAdmitCancel: the datagram was refused by the QUIC session and upstream
	// cancelled the reassembly. Pinned continues to tampering only for a
	// profile whose separate desync_any_proto bit is set; this increment passes
	// the original untouched (see the handleUDP note on that scope).
	udpAdmitCancel
)

// handleUDP processes one captured outbound UDP datagram. When it returns
// VerdictHold the caller must not issue a native disposition: the queued
// original is delivered exactly once through its Completer when the CRYPTO
// cycle completes, is cancelled or times out.
//
// Hostname facts come from the pinned Initial decrypt plus CRYPTO reassembly,
// never from a plaintext scan or a port guess. Fake-unit admission is the
// pinned delayed-replay semantics: a captured partial Initial is queued and its
// cycle owns exactly one fake burst, emitted before the queue head when the
// cycle completes.
func (f *flowState) handleUDP(config *Config, packet *Packet, inject Injector, complete Completer) (Verdict, *Batch, error) {
	f.lockAfterHoldRelease()
	defer f.mu.Unlock()
	if f.failed || f.leaseClosed() {
		return VerdictPass, nil, nil
	}
	// Every captured datagram is counted exactly once, before any admission
	// decision. Replayed originals and generated packets never reach this path.
	f.observe(packet, config.TCPEmptyACK)
	protocol := classifyUDPPayload(packet)
	if protocol != ProtocolQUIC {
		// A non-Initial outbound datagram ends an incomplete cycle before it is
		// processed: no overtaking and no stale parser carry-over.
		f.abortUDPCycleLocked("non-Initial UDP datagram")
		f.resetQUICLocked()
		return f.handleUDPVerdict(config, packet, protocol, udpHostFact{}, false, udpAdmitStages)
	}
	if f.quic == nil {
		f.quic = newQUICReassembler()
	}
	result := f.quic.feedCycle(packet.Payload)
	if result.replaced {
		// The datagram replaced the accumulated cycle identity or superseded its
		// CRYPTO stream: the originals of the replaced cycle are delivered
		// unchanged before this datagram is admitted. The parser already holds
		// this datagram's fragments, so it is not reset here.
		f.abortUDPCycleLocked("QUIC CRYPTO cycle replaced")
	}
	switch result.state {
	case quicCryptoComplete:
		return f.completeUDPCycleLocked(config, packet, udpHostFactOf(result), result.sniPresent, inject, complete)
	case quicCryptoPending:
		return f.holdUDPInitialLocked(config, packet, inject, complete)
	}
	// A parser refusal cancelled the reassembly: the pending cycle is released
	// first and only the explicit any-protocol bit may transform the current
	// datagram. A bounded-resource refusal always passes the original.
	f.abortUDPCycleLocked("QUIC CRYPTO refusal")
	if result.resource {
		return VerdictPass, nil, nil
	}
	return f.handleUDPVerdict(config, packet, protocol, udpHostFact{}, false, udpAdmitCancel)
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

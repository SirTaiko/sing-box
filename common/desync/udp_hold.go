package desync

// Bounded QUIC Initial hold/replay.
//
// Pinned nfq/desync.c queues the Initial datagrams of an incomplete CRYPTO
// reassembly cycle and replays the whole queue when the cycle completes; the
// fake burst belongs to the queue head (reasm_offset == 0) and is therefore
// emitted before the first captured original, not after it. This file adds that
// use of the existing held-packet ownership:
//
//   - holdEntry carries each captured record's single Completer and its
//     capture-time limiter latches (flow.go),
//   - flowState carries the bounded FIFO, the held-byte reservations, the
//     absolute deadline and the timer generation (flow.go),
//   - teardown reaches the queue through flushHeld, and Close/lease fences stay
//     the only close owner.
//
// Nothing here reuses the TCP range replay: a captured UDP datagram is never
// dropped because an earlier one covered the same bytes, and every duplicate
// datagram keeps its own immutable copy and its own native disposition. The
// per-datagram bytes are cloned because ParsePacket aliases its input, so the
// native capture may reuse its frame buffer as soon as the handler returns.

import "fmt"

// abortUDPCycleLocked releases every queued original of the current cycle
// unchanged and disarms the cycle deadline. It never resets the QUIC parser:
// the caller decides whether the accumulated CRYPTO state belongs to a
// replaced identity (keep it), a refused datagram (already reset) or a stale
// interrupted cycle (reset).
func (f *flowState) abortUDPCycleLocked(reason string) {
	if len(f.holds) == 0 {
		if f.holdTimer != nil {
			f.holdTimer.Stop()
			f.holdTimer = nil
			// Publish a new generation so a buffered callback of the disarmed
			// timer cannot release anything that is admitted later.
			f.holdGen++
		}
		return
	}
	f.releaseHoldsLocked(reason)
}

// resetQUICLocked clears the retained CRYPTO state of the flow. It is called
// whenever a cycle ends without a replay (interrupt, refusal, abort) and after
// a completed replay, so a later connection on the same tuple never inherits a
// stale identity, DCID or hostname.
func (f *flowState) resetQUICLocked() {
	if f.quic != nil {
		f.quic.reset()
	}
}

// releaseUDPBudgetLocked returns one held record's reservation. It runs after
// the record's completer returned, so the charged ownership is retained for the
// whole callback and the bounds cannot admit a new record while a native
// disposition is still live.
func (f *flowState) releaseUDPBudgetLocked(bytes int) {
	if bytes <= 0 {
		return
	}
	if f.heldBytes >= bytes {
		f.heldBytes -= bytes
	} else {
		f.heldBytes = 0
	}
	if f.budget != nil && f.limits.MaxHeldBytesTotal > 0 {
		f.budget.Add(-int64(bytes))
	}
}

// cloneHeldPacket copies the captured datagram into independently owned bytes
// and re-parses the copy, so the retained record never aliases the native
// capture buffer and every captured duplicate stays a distinct original.
func cloneHeldPacket(packet *Packet) (*Packet, error) {
	raw := append([]byte(nil), packet.Raw...)
	return ParsePacket(raw)
}

// udpHostFact is the hostname knowledge of one captured QUIC Initial cycle.
// known distinguishes "no hostname fact yet" (an incomplete Initial, or a
// ClientHello without a server_name extension) from a facts-bearing empty
// hostname: a present server_name extension that carries no usable name gives
// pinned bHaveHost == true with an empty value, which is a different state from
// an absent extension.
type udpHostFact struct {
	host  string
	known bool
}

// udpHostFactOf maps the reassembler's completed-cycle outcome to the hostname
// fact of the flow. A present server_name extension that carries no usable name
// is a known-empty fact; an absent extension is no fact at all.
func udpHostFactOf(result quicFeedResult) udpHostFact {
	if result.host != "" || result.sniPresent {
		return udpHostFact{host: result.host, known: true}
	}
	return udpHostFact{}
}

// udpMatchFactsLocked builds the ordered-selection facts of one captured
// datagram. A validated hostname fact is authoritative, even when it is empty;
// otherwise a hostname cached for this exact destination/interface is
// provisional and is revalidated once the ClientHello is complete.
func (f *flowState) udpMatchFactsLocked(packet *Packet, protocol Protocol, fact udpHostFact) MatchFacts {
	facts := MatchFacts{Family: packet.Family, Transport: TransportUDP,
		Destination: packet.Dst, Port: packet.DstPort, Protocol: protocol,
		Host: fact.host, HostKnown: fact.known}
	if fact.known {
		_, facts.HostIsIP = parseIPLiteral(fact.host)
	} else if f.cache != nil {
		if cached, isIP, ok := f.cache.lookupHost(packet.Dst, f.iface); ok {
			facts.Host, facts.HostKnown, facts.HostIsIP = cached, true, isIP
		}
	}
	if facts.HostKnown && f.learning != nil {
		facts.Learned = f.learning.learned(facts.Host)
	}
	return facts
}

// udpPreHostEligible reports whether this rule may own an authenticated
// incomplete QUIC Initial while the hostname is not available yet.
//
// Pinned dp_match() refuses a profile that carries hostlists when the hostname
// is unknown (nfq/desync.c:252-256), but that answer means "cannot be selected
// *now*", not "is definitively ineligible": the missing predicate depends on a
// fact the partial Initial does not carry. The bounded cycle owner therefore
// keeps such a profile and re-runs the authoritative ordered selection, with
// every hostname exclusion, once the ClientHello is complete. Every non-host
// predicate still has to hold now: wrong family, transport, port, IP include
// or exclusion, protocol or interface keeps the datagram definitively
// ineligible and the cycle is not held.
func (r *Rule) udpPreHostEligible(facts MatchFacts) bool {
	if r.Matches(facts) {
		return true
	}
	if facts.HostKnown {
		// The hostname is a validated fact, so Matches is authoritative.
		return false
	}
	if r.Learning == nil && r.Domains.empty() && !r.domainRestrict && r.DomainsExclude.empty() {
		// This rule has no hostname-dependent predicate: the failed Matches
		// above was a definitive nonmatch.
		return false
	}
	return r.matchesUDPNonHostFacts(facts)
}

// matchesUDPNonHostFacts is the part of Rule.Matches that never inspects the
// hostname. It is the provisional-eligibility gate; it changes no matcher
// semantics and is only consulted for an authenticated QUIC Initial whose
// hostname is still unknown.
func (r *Rule) matchesUDPNonHostFacts(facts MatchFacts) bool {
	if r.Network&TransportMaskUDP == 0 || facts.Transport != TransportUDP {
		return false
	}
	if facts.Family == FamilyIPv4 && !r.IPv4 {
		return false
	}
	if facts.Family == FamilyIPv6 && !r.IPv6 {
		return false
	}
	if len(r.Ports) > 0 {
		matched := false
		for _, portRange := range r.Ports {
			if portRange.Contains(facts.Port) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, portRange := range r.PortExclude {
		if portRange.Contains(facts.Port) {
			return false
		}
	}
	if r.IPs.restricts() && !r.IPs.contains(facts.Destination) {
		return false
	}
	if r.IPsExclude.wildcard() || r.IPsExclude.contains(facts.Destination) {
		return false
	}
	if !r.AnyProtocol {
		if facts.Protocol == ProtocolUnknown && r.SkipNoSNI {
			return false
		}
		for _, protocol := range r.Protocols {
			if protocol == facts.Protocol {
				return true
			}
		}
		return false
	}
	return true
}

// selectUDPProvisionalRule picks the bounded owner of an incomplete QUIC cycle.
// A rule that is already selected and still eligible is kept, exactly like
// pinned keeps the conntrack's cached profile; otherwise the ordered list is
// scanned once and the first potentially eligible rule is selected. The result
// is provisional: completeUDPCycleLocked re-runs the authoritative selection
// from the top once the validated hostname is known.
func (f *flowState) selectUDPProvisionalRule(config *Config, facts MatchFacts) *Rule {
	if f.rule != nil && f.rule.udpPreHostEligible(facts) {
		return f.rule
	}
	f.rule = nil
	for _, rule := range config.Rules {
		if rule.udpPreHostEligible(facts) {
			f.rule = rule
			return rule
		}
	}
	return nil
}

// noteUDPRequestLocked records one validated completed QUIC request cycle.
// Pinned calls process_retrans_fail for a checked non-excluded host only at
// replay offset zero and only for a later request, so the first completed
// request is not a retransmission; pending or refused fragments never reach
// this seam at all.
func (f *flowState) noteUDPRequestLocked(packet *Packet, host string) {
	if host != "" {
		f.setLearningHost(host)
	}
	if f.udpRequestSeen {
		f.countLearningRetransmission(packet, true)
	}
	f.udpRequestSeen = true
}

// handleUDPVerdict plans the ordinary (non-held) UDP path for one datagram and
// returns the caller-owned disposition. admission is the pinned fake-unit
// decision of the QUIC CRYPTO state; the four states share one selection and
// planning chain so no path can invent a rule or a payload.
func (f *flowState) handleUDPVerdict(config *Config, packet *Packet, protocol Protocol, fact udpHostFact, discovered bool, admission udpAdmission) (Verdict, *Batch, error) {
	facts := f.udpMatchFactsLocked(packet, protocol, fact)
	if discovered {
		// The decrypted Initial revealed the hostname: upstream re-runs dp_find
		// from the top of the profile list, so a provisional datagram-time rule
		// cannot lock a host-scoped connection, and no fallback to it is kept.
		f.reselectRule(config, facts)
	} else if f.rule == nil {
		f.selectRule(config, facts)
	} else if fact.known && !f.validateSelection(facts) {
		f.selectRule(config, facts)
	}
	if fact.known {
		f.host = fact.host
		f.facts.Host, f.facts.HostKnown = fact.host, true
		if fact.host != "" && f.cache != nil {
			f.cache.learnHost(packet.Dst, f.iface, fact.host)
		}
	}
	if discovered {
		f.noteUDPRequestLocked(packet, fact.host)
	}
	f.refreshCutoffLatches()
	if f.rule == nil || f.learningSkip {
		return VerdictPass, nil, nil
	}
	if !f.intervalAllows() {
		return VerdictPass, nil, nil
	}
	// F3 (selected A contract §5): an unknown payload, or an Initial whose
	// CRYPTO reassembly the parser cancelled, continues to tampering only
	// through the profile's explicit desync_any_proto bit. The permission is
	// checked once, here, before every transform: planUDPStages, applyOrigMod
	// and planUDPDup all follow this gate, so a profile that merely matches
	// unknown traffic (AnyProtocol) cannot transform it. Recognized protocols
	// and a completed Initial keep their unchanged eligibility.
	if (protocol == ProtocolUnknown || admission == udpAdmitCancel) && !f.rule.DesyncAnyProtocol {
		return VerdictPass, nil, nil
	}
	fakeAllowed := true
	switch admission {
	case udpAdmitCyclePending:
		// A delayed replay of an incomplete cycle is injected with a non-zero
		// reassembly offset: only the fake stage is suppressed.
		fakeAllowed = false
	case udpAdmitCancel:
		// A parser-refused Initial continues to tampering only through the
		// explicit desync_any_proto bit (already required above). It stays
		// QUIC for fake selection; it never borrows the unknown-payload path.
	}
	batch, err := planUDPStages(f.rule, packet, fakeAllowed)
	if err != nil {
		f.failed = true
		return VerdictPass, &Batch{Original: VerdictPass, Reason: err.Error()}, err
	}
	if batch == nil || batch.Original == VerdictDrop {
		return VerdictPass, nil, nil
	}
	// orig_mod applies to UDP originals too; duplicates follow the upstream
	// udp_orig_send branch. The captured datagram is delivered at most once: a
	// failed replacement send returns Pass, never a second copy.
	facts2 := f.factsForPacket(packet)
	working, modErr := applyOrigMod(f.rule, packet, facts2, batch)
	if modErr != nil {
		f.failed = true
		return VerdictPass, &Batch{Original: VerdictPass, Reason: modErr.Error()}, modErr
	}
	if dupErr := planUDPDup(f.rule, packet, working, facts2, batch, facts2.Rand); dupErr != nil {
		f.failed = true
		return VerdictPass, &Batch{Original: VerdictPass, Reason: dupErr.Error()}, dupErr
	}
	return batch.Original, batch, nil
}

// holdUDPInitialLocked admits one authenticated partial Initial to the bounded
// cycle queue. It returns VerdictHold: the record's Completer owns its single
// terminal disposition and the native backend must not answer it now.
func (f *flowState) holdUDPInitialLocked(config *Config, packet *Packet, inject Injector, complete Completer) (Verdict, *Batch, error) {
	facts := f.udpMatchFactsLocked(packet, ProtocolQUIC, udpHostFact{})
	// The provisional rule owns the cycle, not a claim that the datagram is
	// transformable now: a hostname-scoped profile stays reachable while only
	// the hostname is unknown. A rule that is definitively ineligible on its
	// family, transport, port, address or protocol predicates is never held.
	if f.selectUDPProvisionalRule(config, facts) == nil {
		// Pinned has no profile for this datagram: cancel the reassembly and
		// pass it, instead of speculating on a hold no rule will replay.
		f.abortUDPCycleLocked("no eligible rule for the incomplete QUIC Initial")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	f.refreshCutoffLatches()
	if !f.intervalAllows() {
		f.abortUDPCycleLocked("desync interval ended")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	if complete == nil {
		// Missing Completer means no hold. Resetting the cycle also guarantees
		// that no fake is ever attached to a partially escaped cycle.
		f.abortUDPCycleLocked("no completer for a delayed QUIC Initial")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	cloned, err := cloneHeldPacket(packet)
	if err != nil {
		f.abortUDPCycleLocked("unusable captured QUIC Initial")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	if !f.canHold(len(cloned.Raw)) {
		// Reservation precedes append: a refused append rolls the reservation
		// back and flushes the earlier originals of the aborted cycle.
		f.abortUDPCycleLocked("hold budget exhausted")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	f.holdLocked(cloned, inject, complete)
	return VerdictHold, nil, nil
}

// completeUDPCycleLocked finalizes one completed ClientHello cycle: the current
// original joins the queue, the rule is selected from the authoritative facts
// and the whole queue is replayed with the configured fake burst before its
// first original.
func (f *flowState) completeUDPCycleLocked(config *Config, packet *Packet, fact udpHostFact, sniPresent bool, inject Injector, complete Completer) (Verdict, *Batch, error) {
	// The profile in scope for pinned's desync_skip_nosni check is the one that
	// owns the cycle: the provisional rule of the incomplete queue, or the
	// datagram-time selection of a standalone Initial (dp before the hostname
	// re-evaluation). A ClientHello with no server_name extension is the
	// pinned "without hostname in the SNI" case; it flushes the whole cycle and
	// passes every original unchanged, and an explicit any-protocol bit does
	// not override it.
	governing := f.rule
	if len(f.holds) == 0 {
		governing = f.selectUDPProvisionalRule(config, f.udpMatchFactsLocked(packet, ProtocolQUIC, udpHostFact{}))
	}
	if !sniPresent && governing != nil && governing.SkipNoSNI {
		f.abortUDPCycleLocked("QUIC ClientHello without hostname in the SNI")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	if len(f.holds) == 0 {
		// A standalone complete Initial is finalised and planned immediately:
		// its burst is emitted before its own original and no asynchronous
		// queue is forced, so no completer is required. A discovered hostname
		// re-runs the authoritative ordered selection; an absent one keeps the
		// provisional profile, exactly like the pinned replay path.
		return f.handleUDPVerdict(config, packet, ProtocolQUIC, fact, fact.known, udpAdmitCycleComplete)
	}
	if complete == nil {
		f.abortUDPCycleLocked("no completer for the completed QUIC cycle")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	facts := f.udpMatchFactsLocked(packet, ProtocolQUIC, fact)
	if fact.known {
		// A validated complete ClientHello reruns the ordered selection from
		// the beginning. An exclusion or a missing final rule flushes the
		// cycle; it never falls back to the disallowed provisional rule.
		f.reselectRule(config, facts)
		f.host = fact.host
		f.facts.Host, f.facts.HostKnown = fact.host, true
		if fact.host != "" && f.cache != nil {
			f.cache.learnHost(packet.Dst, f.iface, fact.host)
		}
	}
	rule := f.rule
	if rule == nil {
		f.abortUDPCycleLocked("no final rule for the completed QUIC cycle")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	if fact.known {
		f.noteUDPRequestLocked(packet, fact.host)
	}
	if f.learningSkip {
		// The auto-hostlist profile stays selected while the host is not yet
		// listed: the completed request is still counted (see
		// noteUDPRequestLocked) but its originals pass unchanged, exactly like
		// the upstream send_orig branch of the host check.
		f.abortUDPCycleLocked("host not in auto hostlist")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	f.refreshCutoffLatches()
	if !f.intervalAllows() {
		f.abortUDPCycleLocked("desync interval ended")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	cloned, err := cloneHeldPacket(packet)
	if err != nil {
		f.abortUDPCycleLocked("unusable completing QUIC Initial")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	if !f.canHold(len(cloned.Raw)) {
		// The completing datagram must also fit, or the whole incomplete cycle
		// is aborted without a fake unit.
		f.abortUDPCycleLocked("hold budget exhausted by the completing Initial")
		f.resetQUICLocked()
		return VerdictPass, nil, nil
	}
	f.holdLocked(cloned, inject, complete)
	if err = f.replayUDPCycleLocked(rule, inject); err != nil {
		return VerdictHold, nil, err
	}
	return VerdictHold, nil, nil
}

// releaseUDPHoldsLocked is the UDP arm of releaseHoldsLocked/flushHeld. An
// empty reason is the completed-cycle replay; every other reason is an abort
// that delivers each held original unchanged in capture order, exactly once.
func (f *flowState) releaseUDPHoldsLocked(reason string) {
	if f.holdTimer != nil {
		f.holdTimer.Stop()
		f.holdTimer = nil
	}
	f.holdGen++
	if len(f.holds) == 0 {
		return
	}
	if reason == "" {
		_ = f.replayUDPCycleLocked(f.rule, nil)
		return
	}
	holds := f.holds
	f.holds = nil
	f.beginHoldReleaseLocked()
	defer f.endHoldReleaseLocked()
	for _, entry := range holds {
		f.completeHeldLocked(entry, VerdictPass, reason, nil)
		f.releaseUDPBudgetLocked(len(entry.packet.Raw))
	}
}

// planUDPReplayEntryLocked plans one queued original's replacements. Only the
// queue head owns the cycle's fake burst; every later entry is planned with the
// fake stage suppressed while its configured non-fake stages, orig_mod and dup
// keep their independent semantics.
func (f *flowState) planUDPReplayEntryLocked(rule *Rule, entry *holdEntry, fakeAllowed bool) (*Batch, error) {
	batch, err := planUDPStages(rule, entry.packet, fakeAllowed)
	if err != nil {
		return nil, err
	}
	if batch == nil {
		return nil, nil
	}
	facts := f.factsForPacket(entry.packet)
	// The in-place latches were decided when the datagram was captured; the dup
	// stage keeps using the current latch, exactly like the immediate path.
	facts.origModCutoffLatched = entry.origModCutoff
	facts.wssizeCutoffLatched = entry.wssizeCutoff
	facts.origCounters = entry.counters
	working, err := applyOrigMod(rule, entry.packet, facts, batch)
	if err != nil {
		return nil, err
	}
	if err = planUDPDup(rule, entry.packet, working, facts, batch, facts.Rand); err != nil {
		return nil, err
	}
	return batch, nil
}

// deliverUDPPlanLocked injects the planned replacements of one queued original
// with the injector of the call that triggered the replay and reports its single
// terminal disposition. A partial send failure never becomes a Drop and never
// retries an already submitted packet: the original is delivered unchanged
// instead.
func (f *flowState) deliverUDPPlanLocked(entry *holdEntry, batch *Batch, inject Injector) (Verdict, []byte, string, error) {
	if batch == nil {
		return VerdictPass, nil, "", nil
	}
	if f.leaseClosed() {
		return VerdictPass, nil, "lease closed", nil
	}
	for index, replacement := range batch.Packets {
		if inject == nil {
			return VerdictPass, nil, "no injector for a replayed QUIC Initial", fmt.Errorf("desync: UDP replay has no injector")
		}
		if err := f.injectHeldLocked(inject, replacement); err != nil {
			return VerdictPass, nil, "partial replacement failure: " + err.Error(),
				fmt.Errorf("desync: inject replayed UDP packet %d: %w", index, err)
		}
	}
	verdict := batch.Original
	if verdict == VerdictDrop && len(batch.Packets) == 0 {
		return VerdictPass, nil, batch.Reason, nil
	}
	if verdict == VerdictModify {
		if batch.Modified == nil {
			return VerdictPass, nil, batch.Reason, nil
		}
		return VerdictModify, batch.Modified, batch.Reason, nil
	}
	return verdict, nil, batch.Reason, nil
}

// replayUDPCycleLocked plans the entire queue before suppressing any original,
// injects the queue head's burst first and then completes each original exactly
// once in capture order. The cycle is finished (parser, queue and timer reset)
// even when the attempted transformation fails, so the next independent
// authenticated cycle can be admitted.
func (f *flowState) replayUDPCycleLocked(rule *Rule, inject Injector) error {
	holds := f.holds
	f.holds = nil
	if f.holdTimer != nil {
		f.holdTimer.Stop()
		f.holdTimer = nil
	}
	f.holdGen++
	f.resetQUICLocked()
	if len(holds) == 0 {
		return nil
	}
	f.beginHoldReleaseLocked()
	defer f.endHoldReleaseLocked()
	if rule == nil {
		for _, entry := range holds {
			f.completeHeldLocked(entry, VerdictPass, "no rule for the completed QUIC cycle", nil)
			f.releaseUDPBudgetLocked(len(entry.packet.Raw))
		}
		return nil
	}
	type udpPlan struct {
		entry *holdEntry
		batch *Batch
	}
	plans := make([]udpPlan, len(holds))
	var planErr error
	for index, entry := range holds {
		batch, err := f.planUDPReplayEntryLocked(rule, entry, index == 0)
		if err != nil {
			planErr = err
			break
		}
		plans[index] = udpPlan{entry: entry, batch: batch}
	}
	if planErr != nil {
		// A planning failure suppresses nothing: every captured original of the
		// aborted cycle passes unchanged, exactly once.
		f.failed = true
		for _, entry := range holds {
			f.completeHeldLocked(entry, VerdictPass, "QUIC replay planning failed: "+planErr.Error(), nil)
			f.releaseUDPBudgetLocked(len(entry.packet.Raw))
		}
		return planErr
	}
	var replayErr error
	for index := range plans {
		verdict, modified, reason, err := f.deliverUDPPlanLocked(plans[index].entry, plans[index].batch, inject)
		if err != nil && replayErr == nil {
			replayErr = err
			f.failed = true
		}
		f.completeHeldLocked(plans[index].entry, verdict, reason, modified)
		f.releaseUDPBudgetLocked(len(plans[index].entry.packet.Raw))
		if replayErr == nil {
			continue
		}
		// The attempted transformation is over: the remaining originals pass
		// unchanged, in capture order, each exactly once.
		for _, rest := range plans[index+1:] {
			f.completeHeldLocked(rest.entry, VerdictPass, "QUIC replay aborted: "+replayErr.Error(), nil)
			f.releaseUDPBudgetLocked(len(rest.entry.packet.Raw))
		}
		break
	}
	return replayErr
}

package desync

// Bounded semantic conntrack, ported from the pinned upstream implementation
// (nfq/conntrack.c, zapret v72.9 c849e55e).
//
// Upstream keeps a process-wide table keyed by the connection 5-tuple with its
// own idle timeouts, independent from socket ownership and from the per-packet
// delayed-replay queue. This file reproduces that separation inside one
// per-outbound engine: the table is bounded, entries expire on the source
// timeouts (SYN/ESTABLISHED/FIN/UDP), and an expired entry never steals state
// from another tuple or another outbound. Desync cutoff latches, held
// originals and owned-attempt cleanup remain owned by the flow/lease and are
// deliberately not part of the table.

import (
	"net/netip"
	"sync"
	"time"
)

type connState uint8

const (
	connStateSYN connState = iota
	connStateEstablished
	connStateFIN
)

func (s connState) String() string {
	switch s {
	case connStateEstablished:
		return "ESTABLISHED"
	case connStateFIN:
		return "FIN"
	default:
		return "SYN"
	}
}

// conntrackSemantics is the upstream t_ctrack state that outlives one native
// attempt. It is embedded by pointer into flowState so the existing planning
// code keeps reading the same field names while the storage is shared by the
// bounded table.
type conntrackSemantics struct {
	state connState

	counters flowCounters

	seq0    uint32
	seq0Set bool
	seqLast uint32

	ack0    uint32
	ack0Set bool
	ackLast uint32

	posOrig  uint32
	posReply uint32

	winsizeOrig  uint16
	winsizeReply uint16
	scaleOrig    int
	scaleReply   int

	hopCount uint8
	haveHop  bool

	// retransmits counts original-direction segments whose sequence is at or
	// before the last observed end: upstream conntrack does not advance state
	// for them (the s limiter can move backwards), it only records them here
	// for diagnostics.
	retransmits uint64
	lastSeq     uint32
	lastSeqSet  bool

	// learn is the upstream t_ctrack auto-hostlist request/retransmission
	// state: the hostname under check, req_retrans_counter and the finalized
	// request range. It lives on the retained tuple so a concurrent or reused
	// native attempt on the same tuple continues the same counter, exactly like
	// the upstream shared ctrack. ConntrackReInitTrack and entry expiry clear
	// it with the rest of the track.
	learn learningSemantics

	// latches are the upstream t_ctrack sticky cutoff flags. Upstream stores
	// them on the tuple-owned conntrack entry, so two native attempts on the
	// same retained tuple share them, a ConntrackReInitTrack clears them and
	// table expiry discards them with the entry.
	latches cutoffLatches
}

// learningSemantics is the tuple-owned hostlist-auto tracking state.
type learningSemantics struct {
	host string
	// check is the upstream hostname_ah_check flag of the track.
	check    bool
	retrans  int
	stopped  bool
	reqStart uint32
	reqEnd   uint32
	reqRange bool
}

// cutoffLatches mirrors the upstream t_ctrack b_*_cutoff flags.
type cutoffLatches struct {
	wssize  bool
	desync  bool
	dup     bool
	origMod bool
}

type conntrackKey struct {
	family    Family
	transport Transport
	src       netip.Addr
	dst       netip.Addr
	srcPort   uint16
	dstPort   uint16
}

type conntrackTimeouts struct {
	syn         time.Duration
	established time.Duration
	fin         time.Duration
	udp         time.Duration
}

func defaultConntrackTimeouts() conntrackTimeouts {
	return conntrackTimeouts{
		syn:         60 * time.Second,
		established: 300 * time.Second,
		fin:         60 * time.Second,
		udp:         60 * time.Second,
	}
}

type conntrackConfig struct {
	disabled   bool
	maxEntries int
	timeouts   conntrackTimeouts
}

func defaultConntrackConfig() conntrackConfig {
	return conntrackConfig{maxEntries: defaultConntrackEntries, timeouts: defaultConntrackTimeouts()}
}

const (
	defaultConntrackEntries = 4096
	maxConntrackEntries     = 1 << 20
	// conntrackPurgeInterval is upstream's fixed purge_interval (10 s).
	conntrackPurgeInterval = 10 * time.Second
)

type conntrackEntry struct {
	mu      sync.Mutex
	key     conntrackKey
	sem     conntrackSemantics
	start   time.Time
	last    time.Time
	expired bool
}

func (e *conntrackEntry) isExpired() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.expired
}

func (e *conntrackEntry) touch(now time.Time) {
	e.last = now
}

// observe ports ConntrackFeedPacket. reverse is the reply direction. It
// returns true when upstream ConntrackReInitTrack ran (a new SYN on a tuple
// whose state had moved past SYN), in which case the caller must clear its
// sticky latches exactly like the memset in ConntrackInitTrack.
func (e *conntrackEntry) observe(packet *Packet, reverse bool, now time.Time) (reinitialized bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.expired {
		return false
	}
	sem := &e.sem
	if reverse {
		sem.counters.replyPackets++
		if len(packet.Payload) > 0 {
			sem.counters.replyData++
		}
	} else {
		sem.counters.packets++
		if len(packet.Payload) > 0 {
			sem.counters.dataPackets++
		}
	}
	if packet.Transport != TransportTCP {
		// UDP conntrack: seq_last is the accumulated position.
		if reverse {
			sem.ackLast = sem.posReply
			sem.posReply += uint32(len(packet.Payload))
		} else {
			sem.seqLast = sem.posOrig
			sem.posOrig += uint32(len(packet.Payload))
		}
		e.last = now
		return false
	}
	if packet.IsSYN() && packet.TCPFlags&tcpFlagACK == 0 {
		if sem.state != connStateSYN {
			e.resetLocked(now)
			sem = &e.sem
			reinitialized = true
		}
		sem.seq0, sem.seq0Set = packet.TCPSeq, true
	} else if packet.IsSYN() && packet.TCPFlags&tcpFlagACK != 0 {
		seq0 := packet.TCPAck - 1
		if sem.state != connStateSYN && sem.seq0Set && sem.seq0 != seq0 {
			e.resetLocked(now)
			sem = &e.sem
			reinitialized = true
		}
		if !sem.seq0Set {
			sem.seq0, sem.seq0Set = seq0, true
		}
		sem.ack0 = packet.TCPSeq
		sem.ack0Set = true
	} else if packet.TCPFlags&(tcpFlagFIN|tcpFlagRST) != 0 {
		sem.state = connStateFIN
	} else if sem.state == connStateSYN {
		sem.state = connStateEstablished
		if !reverse && !sem.ack0Set {
			sem.ack0, sem.ack0Set = packet.TCPAck-1, true
		}
	}
	if packet.WindowScale >= 0 {
		if reverse {
			sem.scaleReply = packet.WindowScale
		} else {
			sem.scaleOrig = packet.WindowScale
		}
	}
	if reverse {
		sem.seqLast = packet.TCPAck
		sem.posOrig = sem.seqLast
		sem.ackLast = packet.TCPSeq
		sem.posReply = sem.ackLast + uint32(len(packet.Payload))
		sem.winsizeReply = packet.TCPWindow
		sem.counters.sequence = uint64(sem.seqLast - sem.seq0)
	} else {
		if sem.lastSeqSet && len(packet.Payload) > 0 &&
			int32(packet.TCPSeq-sem.lastSeq) <= 0 {
			sem.retransmits++
		}
		sem.lastSeq, sem.lastSeqSet = packet.TCPSeq, true
		sem.seqLast = packet.TCPSeq
		sem.posOrig = sem.seqLast + uint32(len(packet.Payload))
		sem.ackLast = packet.TCPAck
		sem.posReply = sem.ackLast
		sem.winsizeOrig = packet.TCPWindow
		sem.counters.sequence = uint64(sem.seqLast - sem.seq0)
	}
	e.last = now
	return reinitialized
}

// resetLocked ports ConntrackReInitTrack: the whole semantic track is cleared,
// including the cutoff latches that live on t_ctrack upstream. The entry
// identity (key) and the lock itself survive.
func (e *conntrackEntry) resetLocked(now time.Time) {
	e.sem = conntrackSemantics{}
	e.start = now
	e.last = now
}

// conntrackTable is the bounded owner. One table exists per engine (i.e. per
// direct outbound), which keeps state from leaking between outbounds.
type conntrackTable struct {
	mu          sync.Mutex
	entries     map[conntrackKey]*conntrackEntry
	maxEntries  int
	timeouts    conntrackTimeouts
	disabled    bool
	now         func() time.Time
	lastPurge   time.Time
	lastEntries map[conntrackKey]*conntrackEntry // guard against accidental reuse
}

func newConntrackTable(config conntrackConfig, now func() time.Time) *conntrackTable {
	if now == nil {
		now = time.Now
	}
	if config.maxEntries <= 0 {
		config.maxEntries = defaultConntrackEntries
	}
	if config.maxEntries > maxConntrackEntries {
		config.maxEntries = maxConntrackEntries
	}
	if !config.timeouts.valid() {
		config.timeouts = defaultConntrackTimeouts()
	}
	return &conntrackTable{
		entries:    make(map[conntrackKey]*conntrackEntry),
		maxEntries: config.maxEntries,
		timeouts:   config.timeouts,
		disabled:   config.disabled,
		now:        now,
		lastPurge:  now(),
	}
}

func (t conntrackTimeouts) valid() bool {
	return t.syn > 0 && t.established > 0 && t.fin > 0 && t.udp > 0
}

func makeConntrackKey(packet *Packet, intent Intent) conntrackKey {
	if intent.Source.IsValid() {
		return conntrackKey{family: intent.Family, transport: intent.Transport,
			src: intent.Source.Addr(), dst: intent.Destination.Addr(),
			srcPort: intent.Source.Port(), dstPort: intent.Destination.Port()}
	}
	return conntrackKey{family: packet.Family, transport: packet.Transport,
		src: packet.Src, dst: packet.Dst, srcPort: packet.SrcPort, dstPort: packet.DstPort}
}

// acquire returns the live entry for key, creating it only when upstream
// would (TCP with the SYN flag set, i.e. SYN or SYN-ACK, and every UDP
// datagram). Non-qualifying packets get nil: upstream conntrack never creates
// an entry for a mid-stream TCP packet, so such a capture has no semantic
// counters at all. Existing entries are always returned, whatever the packet.
func (t *conntrackTable) acquire(key conntrackKey, packet *Packet) *conntrackEntry {
	if t == nil || t.disabled {
		return nil
	}
	if key.transport == TransportTCP && !packet.IsSYN() {
		// Source-valid first attach: no track exists for a tuple whose first
		// observed packet carries no SYN. Looking it up is still required so a
		// concurrent attempt that did create the track shares it.
		t.mu.Lock()
		defer t.mu.Unlock()
		if entry, found := t.entries[key]; found && entry != nil {
			return entry
		}
		return nil
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastPurge) >= conntrackPurgeInterval {
		t.purgeLocked(now)
		t.lastPurge = now
	}
	if entry, found := t.entries[key]; found && entry != nil {
		return entry
	}
	if len(t.entries) >= t.maxEntries {
		t.evictOldestLocked()
	}
	entry := &conntrackEntry{key: key, start: now, last: now}
	t.entries[key] = entry
	return entry
}

// purgeLocked ports ConntrackPoolPurge timeout selection.
func (t *conntrackTable) purgeLocked(now time.Time) {
	for key, entry := range t.entries {
		entry.mu.Lock()
		idle := now.Sub(entry.last)
		expired := false
		if entry.sem.state == connStateFIN {
			expired = idle >= t.timeouts.fin
		} else if entry.key.transport == TransportUDP {
			expired = idle >= t.timeouts.udp
		} else if entry.sem.state == connStateSYN {
			expired = idle >= t.timeouts.syn
		} else {
			expired = idle >= t.timeouts.established
		}
		if expired {
			entry.expired = true
		}
		entry.mu.Unlock()
		if expired {
			delete(t.entries, key)
		}
	}
}

func (t *conntrackTable) evictOldestLocked() {
	var oldestKey conntrackKey
	var oldest *conntrackEntry
	for key, entry := range t.entries {
		if oldest == nil {
			oldestKey, oldest = key, entry
			continue
		}
		entry.mu.Lock()
		older := entry.last.Before(oldest.last)
		entry.mu.Unlock()
		if older {
			oldestKey, oldest = key, entry
		}
	}
	if oldest == nil {
		return
	}
	oldest.mu.Lock()
	oldest.expired = true
	oldest.mu.Unlock()
	delete(t.entries, oldestKey)
}

// purge forces one purge pass. It exists for the deterministic clock seam and
// for tests; packet paths purge rate-limited inside acquire.
func (t *conntrackTable) purge() {
	if t == nil || t.disabled {
		return
	}
	t.mu.Lock()
	t.purgeLocked(t.now())
	t.lastPurge = t.now()
	t.mu.Unlock()
}

// len reports the current bounded entry count.
func (t *conntrackTable) len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// close drops every entry. It is called on engine shutdown; owned-attempt
// cleanup is independent and always runs.
func (t *conntrackTable) close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	for key, entry := range t.entries {
		entry.mu.Lock()
		entry.expired = true
		entry.mu.Unlock()
		delete(t.entries, key)
	}
	t.mu.Unlock()
}

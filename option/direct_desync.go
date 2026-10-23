package option

import (
	"strconv"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

// DirectDesyncOptions is the optional packet desync configuration of an
// ordinary direct outbound. It is a direct-outbound property only: there is no
// separate outbound type, no profile selector and no tag interpretation.
type DirectDesyncOptions struct {
	// Enabled defaults to true when the object is present.
	Enabled *bool `json:"enabled,omitempty"`
	// Rules is the ordered packet rule list. The first matching, enabled rule
	// owns the flow.
	Rules []DirectDesyncRule `json:"rules,omitempty"`
	// StreamRules is the ordered tpws-equivalent stream rule list. It is
	// compiled independently from Rules and applied to owned TCP connections
	// before kernel serialization; packet rules (if any) observe the resulting
	// packets. Stream-only configurations are valid and need no packet backend
	// or capture privileges.
	StreamRules []DirectDesyncStreamRule `json:"stream_rules,omitempty"`
	// Capture narrows the eligibility of captured packets. It can only narrow
	// the owned-socket envelope, never widen it.
	Capture *DirectDesyncCapture `json:"capture,omitempty"`
	// Limits bounds per-outbound native resources.
	Limits *DirectDesyncLimits `json:"limits,omitempty"`
	// Conntrack is the upstream semantic-conntrack configuration
	// (`--ctrack-timeouts`/`--ctrack-disable`). Disabling semantic conntrack
	// never disables socket ownership or cleanup.
	Conntrack *DirectDesyncConntrack `json:"conntrack,omitempty"`
	// IPCache is the upstream IP->hostname and hop cache configuration
	// (`--ipcache-lifetime`/`--ipcache-hostname`), scoped to this outbound.
	IPCache *DirectDesyncIPCache `json:"ip_cache,omitempty"`
	// Learning is the per-outbound hostlist-auto common configuration
	// (`--hostlist-auto` family). It is opt-in: without an explicit path the
	// learned set lives only in this outbound's engine and is never persisted
	// or logged. Rule-specific applicability and thresholds live in
	// rule.learning.
	Learning *DirectDesyncLearning `json:"learning,omitempty"`
}

// DirectDesyncLearning is the per-outbound auto-hostlist configuration shared
// by every rule that enables rule.learning.
type DirectDesyncLearning struct {
	// Path is the explicit snapshot file. Absent means in-memory only.
	Path string `json:"path,omitempty"`
	// DebugLog is the explicit upstream --hostlist-auto-debug file. Absent
	// means no host logging at all.
	DebugLog string `json:"debug_log,omitempty"`
	// MaxHosts bounds this outbound's learned set. Absent keeps 4096.
	MaxHosts int `json:"max_hosts,omitempty"`
}

// DirectDesyncConntrack mirrors the upstream ctrack options. Absent keeps
// conntrack enabled with the source default timeouts.
type DirectDesyncConntrack struct {
	// Disabled is the upstream --ctrack-disable switch.
	Disabled bool `json:"disabled,omitempty"`
	// MaxEntries bounds this outbound's conntrack table.
	MaxEntries int `json:"max_entries,omitempty"`
	// Timeouts is the upstream --ctrack-timeouts=S:E:F[:U] tuple. Absent uses
	// 60s/300s/60s/60s.
	Timeouts *DirectDesyncConntrackTimeouts `json:"timeouts,omitempty"`
}

type DirectDesyncConntrackTimeouts struct {
	SYN         *badoption.Duration `json:"syn,omitempty"`
	Established *badoption.Duration `json:"established,omitempty"`
	FIN         *badoption.Duration `json:"fin,omitempty"`
	UDP         *badoption.Duration `json:"udp,omitempty"`
}

// DirectDesyncIPCache mirrors the upstream ipcache options. It never persists
// state and never performs a lookup outside this outbound.
type DirectDesyncIPCache struct {
	// Hostname is the upstream --ipcache-hostname switch (default off).
	Hostname bool `json:"hostname,omitempty"`
	// Lifetime is the upstream --ipcache-lifetime; an explicit zero means no
	// expiration, absent keeps the source default of 7200 s.
	Lifetime *badoption.Duration `json:"lifetime,omitempty"`
	// MaxEntries bounds the cache.
	MaxEntries int `json:"max_entries,omitempty"`
}

type DirectDesyncCapture struct {
	// TCPEmptyACK makes empty outgoing ACKs eligible. Absent follows upstream:
	// empty ACKs are eligible exactly when a method modifies or duplicates
	// originals, which requires their headers to be observed.
	TCPEmptyACK *bool `json:"tcp_empty_ack,omitempty"`
	// Network, IPVersion and the port selectors are the portable capture
	// narrowing (upstream --wf-l3/--wf-tcp/--wf-udp equivalent). They are
	// intersected with the owned tuple: a selector that excludes the owned
	// native attempt is a configuration error, never a silent widening or an
	// invented flow.
	Network          badoption.Listable[string] `json:"network,omitempty" enum:"tcp,udp"`
	IPVersion        badoption.Listable[int]    `json:"ip_version,omitempty"`
	Port             badoption.Listable[uint16] `json:"port,omitempty"`
	PortRange        badoption.Listable[string] `json:"port_range,omitempty"`
	PortExclude      badoption.Listable[uint16] `json:"port_exclude,omitempty"`
	PortRangeExclude badoption.Listable[string] `json:"port_range_exclude,omitempty"`
	// Linux holds the Linux-only NFQUEUE/injection controls.
	Linux *DirectDesyncCaptureLinux `json:"linux,omitempty"`
	// Windows holds the Windows-only WinDivert filter controls and the
	// WLAN/NLM activation filters. Every field narrows the owned socket.
	Windows *DirectDesyncCaptureWindows `json:"windows,omitempty"`
	// FilterTTLExpiredICMP suppresses ICMP/ICMPv6 time-exceeded errors that
	// quote this outbound's own injected low-hop packet (upstream
	// FILTER_TTL_EXPIRED_ICMP). It is default false. A captured error is
	// dropped only after the quoted inner tuple is validated against the
	// owned, live generation of the attempt; foreign tuples, malformed or
	// truncated quotes, reply-side quotes and parameter-problem/PMTU messages
	// always pass unchanged. It never installs a global ICMP drop rule.
	FilterTTLExpiredICMP *bool `json:"filter_ttl_expired_icmp,omitempty"`
}

// DirectDesyncCaptureWindows is the typed Windows capture extension (upstream
// --wf-iface/--wf-l3/--wf-tcp/--wf-udp/--wf-raw/--wf-raw-part/--wf-filter-lan/
// --wf-save plus --ssid-filter/--nlm-filter). An absent field keeps the
// upstream default; a malformed or unsupported raw expression is a
// configuration error, never a silently ignored filter.
type DirectDesyncCaptureWindows struct {
	// WFIface is the numeric interface/subinterface filter, upstream
	// `--wf-iface=<int>[.<int>]`. It is intersected with the interface index
	// the owned native attempt was actually bound to.
	WFIface string `json:"wf_iface,omitempty"`
	// WFL3 selects the L3 families, upstream `--wf-l3=ipv4,ipv6`. Absent
	// enables both, like upstream.
	WFL3 badoption.Listable[string] `json:"wf_l3,omitempty" enum:"ipv4,ipv6"`
	// WFTCP/WFUDP are upstream `[~]port[-port]` comma lists, matched against
	// the destination port for outbound and the source port for inbound.
	WFTCP badoption.Listable[string] `json:"wf_tcp,omitempty"`
	WFUDP badoption.Listable[string] `json:"wf_udp,omitempty"`
	// WFRaw is a full raw WinDivert filter (upstream --wf-raw). It replaces
	// wf_tcp/wf_udp/wf_raw_part and is always AND-ed with the owned envelope.
	WFRaw string `json:"wf_raw,omitempty"`
	// WFRawPart is a partial raw filter (upstream --wf-raw-part); several
	// parts are OR-ed together and then AND-ed with the owned envelope.
	WFRawPart badoption.Listable[string] `json:"wf_raw_part,omitempty"`
	// FilterLAN excludes non-global destination (outbound) and source
	// (inbound) addresses, upstream `--wf-filter-lan` (default true).
	FilterLAN *bool `json:"filter_lan,omitempty"`
	// FilterSave writes the composed filter text to this path when capture is
	// activated, upstream `--wf-save`. It is an explicit opt-in bounded dump;
	// absent means no file is written, and configuration compilation never
	// writes.
	FilterSave string `json:"filter_save,omitempty"`
	// SSIDFilter activates the capture only while one of these WLAN SSIDs is
	// connected (upstream --ssid-filter, exact case-sensitive match).
	SSIDFilter badoption.Listable[string] `json:"ssid_filter,omitempty"`
	// NLMFilter activates the capture only while one of these Network List
	// Manager networks is connected, by name or GUID (upstream --nlm-filter).
	NLMFilter badoption.Listable[string] `json:"nlm_filter,omitempty"`
}

// DirectDesyncCaptureLinux is the typed Linux capture extension. Every field
// only narrows or re-identifies the already owned native attempt; none can
// widen capture beyond the owned socket tuple.
type DirectDesyncCaptureLinux struct {
	// Qnum is the explicit NFQUEUE identity (upstream --qnum, 0..65535). It
	// must be free, unique among live captures and outside the managed
	// allocation range; a collision is a configuration error, never a silent
	// fallback.
	Qnum *int `json:"qnum,omitempty"`
	// Fwmark is added (OR) to the routing mark carried by the owned socket for
	// generated packets (upstream desync_fwmark). Dialer-owned bits are never
	// cleared.
	Fwmark *uint32 `json:"fwmark,omitempty"`
	// BindFix4/BindFix6 mirror upstream --bind-fix4/--bind-fix6: bind the raw
	// injection socket to the generated packet's source address for that
	// family. A refused bind keeps the socket usable, as upstream does.
	BindFix4 *bool `json:"bind_fix4,omitempty"`
	BindFix6 *bool `json:"bind_fix6,omitempty"`
	// PacketLimits is the upstream NFQWS_TCP_PKT_OUT/IN and
	// NFQWS_UDP_PKT_OUT/IN family: an inclusive bound on the kernel conntrack
	// packet counter of one direction. It is applied in the owned capture rule,
	// before any semantic rule eligibility.
	PacketLimits *DirectDesyncCapturePacketLimits `json:"packet_limits,omitempty"`
	// TCPKeepalivePortRange mirrors NFQWS_PORTS_TCP_KEEPALIVE: for destination
	// ports in this range only the outgoing packet bound is removed, exactly
	// like the source's separate `keepalive` rule set. The inbound bound, when
	// configured, is unchanged.
	TCPKeepalivePortRange badoption.Listable[string] `json:"tcp_keepalive_port_range,omitempty"`
	// UDPKeepalivePortRange mirrors NFQWS_PORTS_UDP_KEEPALIVE with the same
	// outgoing-only bound removal.
	UDPKeepalivePortRange badoption.Listable[string] `json:"udp_keepalive_port_range,omitempty"`
}

// DirectDesyncCapturePacketLimits is the typed NFQWS_*_PKT_* packet-limit set.
// Every field is optional: absent means unlimited capture of that direction,
// zero disables capture of that direction, and N keeps the first N packets as
// counted inclusively by the kernel conntrack (source `ct ... packets 1-N`
// rules). The counter is the kernel's, never the semantic rule cutoff.
type DirectDesyncCapturePacketLimits struct {
	TCPOut *int `json:"tcp_out,omitempty"`
	TCPIn  *int `json:"tcp_in,omitempty"`
	UDPOut *int `json:"udp_out,omitempty"`
	UDPIn  *int `json:"udp_in,omitempty"`
}

type DirectDesyncLimits struct {
	MaxLeases          int                 `json:"max_leases,omitempty"`
	MaxReassemblyBytes int                 `json:"max_reassembly_bytes,omitempty"`
	MaxHeldPackets     int                 `json:"max_held_packets,omitempty"`
	MaxHeldBytes       int                 `json:"max_held_bytes,omitempty"`
	MaxHeldBytesTotal  int                 `json:"max_held_bytes_total,omitempty"`
	HoldTimeout        *badoption.Duration `json:"hold_timeout,omitempty"`
}

type DirectDesyncRule struct {
	Name     string `json:"name,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`

	Network   badoption.Listable[string] `json:"network,omitempty" enum:"tcp,udp"`
	IPVersion badoption.Listable[int]    `json:"ip_version,omitempty"`

	Port              badoption.Listable[uint16] `json:"port,omitempty"`
	PortRange         badoption.Listable[string] `json:"port_range,omitempty"`
	PortExclude       badoption.Listable[uint16] `json:"port_exclude,omitempty"`
	PortRangeExclude  badoption.Listable[string] `json:"port_range_exclude,omitempty"`
	Protocol          badoption.Listable[string] `json:"protocol,omitempty"`
	Domain            badoption.Listable[string] `json:"domain,omitempty"`
	DomainFile        badoption.Listable[string] `json:"domain_file,omitempty"`
	DomainExclude     badoption.Listable[string] `json:"domain_exclude,omitempty"`
	DomainExcludeFile badoption.Listable[string] `json:"domain_exclude_file,omitempty"`
	IPCIDR            badoption.Listable[string] `json:"ip_cidr,omitempty"`
	IPCIDRFile        badoption.Listable[string] `json:"ip_cidr_file,omitempty"`
	IPCIDRExclude     badoption.Listable[string] `json:"ip_cidr_exclude,omitempty"`
	IPCIDRExcludeFile badoption.Listable[string] `json:"ip_cidr_exclude_file,omitempty"`

	// ListBundle selects immutable datasets of a provider list bundle. It is
	// additive with the inline/file fields above and is read once per
	// canonical bundle root per compile/reload.
	ListBundle *DirectDesyncListBundle `json:"list_bundle,omitempty"`

	// Methods is the ordered upstream `<mode0>,<mode>[,<mode2>]` stage list
	// with upstream names and deprecated aliases. Every accepted name is
	// planned by common/desync; unknown names, invalid stage order/transport
	// combinations and unimplemented fields are rejected, never ignored.
	Methods badoption.Listable[string] `json:"methods,omitempty"`

	// First-stage objects.
	Fake      *DirectDesyncFakeOptions `json:"fake,omitempty"`
	FakeKnown *DirectDesyncFakeOptions `json:"fakeknown,omitempty"`
	// Second-stage objects. The same typed split object drives the coupled
	// multisplit/multidisorder algorithms; fakedsplit/fakeddisorder add the
	// upstream fake pattern and altorder modifiers.
	MultiSplit    *DirectDesyncSplitOptions         `json:"multisplit,omitempty"`
	MultiDisorder *DirectDesyncSplitOptions         `json:"multidisorder,omitempty"`
	FakeDSplit    *DirectDesyncSplitOptions         `json:"fakedsplit,omitempty"`
	FakeDDisorder *DirectDesyncSplitOptions         `json:"fakeddisorder,omitempty"`
	HostFakeSplit *DirectDesyncHostFakeSplitOptions `json:"hostfakesplit,omitempty"`

	// Packet modifiers. They are rule-owned; a split method never requires an
	// unrelated fake object to use them.
	TTL             int                        `json:"ttl,omitempty"`
	TTL6            int                        `json:"ttl6,omitempty"`
	AutoTTL         string                     `json:"autottl,omitempty"`
	AutoTTL6        string                     `json:"autottl6,omitempty"`
	TCPFlagsSet     string                     `json:"tcp_flags_set,omitempty"`
	TCPFlagsUnset   string                     `json:"tcp_flags_unset,omitempty"`
	Fooling         badoption.Listable[string] `json:"fooling,omitempty"`
	Repeats         int                        `json:"repeats,omitempty"`
	TSIncrement     *int32                     `json:"ts_increment,omitempty"`
	BadSeqIncrement *int32                     `json:"badseq_increment,omitempty"`
	BadAckIncrement *int32                     `json:"badack_increment,omitempty"`

	// IPFragPosTCP/IPFragPosUDP are transport-relative, 8-byte aligned IPv4
	// fragment positions for ipfrag2.
	IPFragPosTCP int `json:"ipfrag_pos_tcp,omitempty"`
	IPFragPosUDP int `json:"ipfrag_pos_udp,omitempty"`

	UDPLen *DirectDesyncUDPLenOptions `json:"udplen,omitempty"`

	// Original-packet modifiers (upstream --orig-*).
	Orig *DirectDesyncOrigOptions `json:"orig,omitempty"`
	// Duplicate-packet modifiers (upstream --dup-*).
	Dup *DirectDesyncDupOptions `json:"dup,omitempty"`
	// WSize rewrites the advertised window of an observed SYN-ACK
	// (upstream --wsize; the obsolete SYN-ACK-only selector).
	WSize *DirectDesyncWSizeOptions `json:"wsize,omitempty"`
	// WSSize rewrites the advertised window of original-direction packets
	// (upstream --wssize/--wssize-cutoff/--wssize-forced-cutoff).
	WSSize *DirectDesyncWSSizeOptions `json:"wssize,omitempty"`
	// SynackSplit splits an observed SYN-ACK in place (`syn`) or into its SYN
	// and ACK parts (`synack`/`acksyn`).
	SynackSplit string `json:"synack_split,omitempty" enum:"syn,synack,acksyn,,"`

	// Start and Cutoff use upstream source-compatible nN/dN/sN spelling.
	Start  string `json:"start,omitempty"`
	Cutoff string `json:"cutoff,omitempty"`

	AnyProtocol bool  `json:"any_protocol,omitempty"`
	SkipNoSNI   *bool `json:"skip_no_sni,omitempty"`
	// IPID accepts upstream IPv4 ID modes.
	IPID string `json:"ip_id,omitempty" enum:"zero,seq,seqgroup,rnd,same,,"`

	// Learning enables the per-host auto-hostlist behavior of this rule
	// (upstream --hostlist-auto profile semantics). Thresholds default to
	// 3 failures / 60 s / 3 retransmissions.
	Learning *DirectDesyncRuleLearning `json:"learning,omitempty"`
}

// DirectDesyncRuleLearning is the rule-level hostlist-auto applicability and
// threshold set. The source option names are snake_cased.
type DirectDesyncRuleLearning struct {
	// FailThreshold is --hostlist-auto-fail-threshold (1..20, default 3).
	// A pointer keeps an explicit zero distinct from an absent value so the
	// source range validation is not silently bypassed.
	FailThreshold *int `json:"fail_threshold,omitempty"`
	// FailTime is --hostlist-auto-fail-time seconds (1..255, default 60).
	FailTime *badoption.Duration `json:"fail_time,omitempty"`
	// RetransThreshold is --hostlist-auto-retrans-threshold (2..10,
	// default 3). Explicit zero is rejected like upstream.
	RetransThreshold *int `json:"retrans_threshold,omitempty"`
}

type DirectDesyncFakeOptions struct {
	Payloads    []DirectDesyncPayload      `json:"payloads,omitempty"`
	Repeats     int                        `json:"repeats,omitempty"`
	Fooling     badoption.Listable[string] `json:"fooling,omitempty"`
	TSIncrement *int32                     `json:"ts_increment,omitempty"`
	TTL         int                        `json:"ttl,omitempty"`
	TTL6        int                        `json:"ttl6,omitempty"`
	AutoTTL     string                     `json:"autottl,omitempty"`
	AutoTTL6    string                     `json:"autottl6,omitempty"`
	// Seq selects upstream fake TCP sequence mode: every fake advances by the
	// previous fake length instead of overlapping the original.
	Seq bool `json:"seq,omitempty"`
}

type DirectDesyncPayload struct {
	Protocol string `json:"protocol,omitempty" enum:"http,tls,quic,wireguard,dht,discord,stun,unknown"`
	File     string `json:"file,omitempty"`
	Hex      string `json:"hex,omitempty"`
	Base64   string `json:"base64,omitempty"`
	// Offset skips bytes at the start of the resolved byte source.
	Offset int `json:"offset,omitempty"`
	// TLSMod applies the upstream fake TLS ClientHello modifiers to this
	// payload when it is a TLS payload.
	TLSMod string `json:"tls_mod,omitempty"`
}

type DirectDesyncSplitOptions struct {
	SplitPos       badoption.Listable[string] `json:"split_pos,omitempty"`
	SeqOverlap     *DesyncByteOrPosition      `json:"seqovl,omitempty"`
	SeqOverlapFile string                     `json:"seqovl_pattern,omitempty"`
	// FakePattern is the upstream fakedsplit/fakeddisorder fake byte pattern.
	FakePattern string `json:"fake_pattern,omitempty"`
	// FakeMod accepts `none` and `altorder=N` ordering selectors.
	FakeMod string `json:"fake_mod,omitempty"`
}

type DirectDesyncHostFakeSplitOptions struct {
	// MidHost additionally splits the real hostname at an upstream marker
	// relative to the Host/SNI value or its second-level domain. The two
	// mandatory splits are always the Host/SNI value boundaries.
	MidHost string `json:"midhost,omitempty" enum:"host+0,host-1,midhost+0,midhost-1,,"`
	// Mod accepts `none`, `host=<hostname>` and `altorder=0|1`.
	Mod string `json:"mod,omitempty"`
}

type DirectDesyncUDPLenOptions struct {
	Increment int    `json:"increment,omitempty"`
	Pattern   string `json:"pattern,omitempty"`
}

type DirectDesyncOrigOptions struct {
	TTL           int    `json:"ttl,omitempty"`
	TTL6          int    `json:"ttl6,omitempty"`
	AutoTTL       string `json:"autottl,omitempty"`
	AutoTTL6      string `json:"autottl6,omitempty"`
	TCPFlagsSet   string `json:"tcp_flags_set,omitempty"`
	TCPFlagsUnset string `json:"tcp_flags_unset,omitempty"`
	// ModStart/ModCutoff gate the original TTL/flags rewrite with the exact
	// upstream --orig-mod-start/--orig-mod-cutoff n/d/s spelling.
	ModStart  string `json:"mod_start,omitempty"`
	ModCutoff string `json:"mod_cutoff,omitempty"`
}

type DirectDesyncDupOptions struct {
	Count           int                        `json:"count,omitempty"`
	TTL             int                        `json:"ttl,omitempty"`
	TTL6            int                        `json:"ttl6,omitempty"`
	AutoTTL         string                     `json:"autottl,omitempty"`
	AutoTTL6        string                     `json:"autottl6,omitempty"`
	TCPFlagsSet     string                     `json:"tcp_flags_set,omitempty"`
	TCPFlagsUnset   string                     `json:"tcp_flags_unset,omitempty"`
	Fooling         badoption.Listable[string] `json:"fooling,omitempty"`
	TSIncrement     *int32                     `json:"ts_increment,omitempty"`
	BadSeqIncrement *int32                     `json:"badseq_increment,omitempty"`
	BadAckIncrement *int32                     `json:"badack_increment,omitempty"`
	Replace         bool                       `json:"replace,omitempty"`
	IPID            string                     `json:"ip_id,omitempty" enum:"zero,seq,rnd,same,,"`
	Start           string                     `json:"start,omitempty"`
	Cutoff          string                     `json:"cutoff,omitempty"`
}

// DirectDesyncWSizeOptions is the upstream `--wsize=<size>[:<scale>]`
// SYN-ACK-only window selector.
type DirectDesyncWSizeOptions struct {
	Size  int  `json:"size,omitempty"`
	Scale *int `json:"scale,omitempty"`
}

// DirectDesyncWSSizeOptions is the upstream `--wssize` original-direction
// window selector with its server-window cutoff family.
type DirectDesyncWSSizeOptions struct {
	Size  int  `json:"size,omitempty"`
	Scale *int `json:"scale,omitempty"`
	// Cutoff uses nN/dN/sN packet counters, exactly like
	// --wssize-cutoff.
	Cutoff string `json:"cutoff,omitempty"`
	// ForcedCutoff mirrors --wssize-forced-cutoff (default true): latch the
	// cutoff off as soon as a recognized protocol is complete.
	ForcedCutoff *bool `json:"forced_cutoff,omitempty"`
}

// DesyncByteOrPosition accepts an integer byte count or a symbolic/numeric
// position string, preserving the upstream distinction.
type DesyncByteOrPosition struct {
	Bytes    *int
	Position string
}

func (v *DesyncByteOrPosition) UnmarshalJSON(content []byte) error {
	if len(content) == 0 {
		return E.New("empty seqovl")
	}
	if content[0] == '"' {
		var position string
		err := json.Unmarshal(content, &position)
		if err != nil {
			return err
		}
		if position == "" {
			return E.New("empty seqovl position")
		}
		v.Position = position
		return nil
	}
	bytes, err := strconv.Atoi(string(content))
	if err != nil {
		return E.Cause(err, "invalid seqovl")
	}
	if bytes < 0 {
		return E.New("negative seqovl")
	}
	v.Bytes = &bytes
	return nil
}

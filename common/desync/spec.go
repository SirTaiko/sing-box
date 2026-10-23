package desync

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

const (
	// maxPayloadSize is the upstream fake buffer limit (nfq/desync.h).
	maxPayloadSize = 9216
	// maxSplitPositions is the upstream limit (nfq/params.h).
	maxSplitPositions = 64
	// maxOverlapPattern is the upstream pattern limit.
	maxOverlapPattern = 16384
	// maxReassemblyBytes is the bounded extension of upstream TCP_MAX_REASM.
	maxReassemblyBytes = 256 * 1024

	// Architecture §4 bounded hold defaults.
	defaultMaxHeldPackets    = 256
	defaultMaxHeldBytes      = 256 * 1024
	defaultMaxHeldBytesTotal = 64 * 1024 * 1024
	defaultHoldTimeout       = 250 * time.Millisecond
	maxHoldTimeout           = 10 * time.Second
	// maxListFileBytes bounds configuration list files.
	maxListFileBytes = 4 << 20
)

// Protocol is the L7 protocol used for payload selection and matching.
type Protocol uint8

const (
	ProtocolUnknown Protocol = iota
	ProtocolHTTP
	ProtocolTLS
	ProtocolQUIC
	ProtocolWireGuard
	ProtocolDHT
	ProtocolDiscord
	ProtocolSTUN
)

var protocolNames = map[string]Protocol{
	"http": ProtocolHTTP, "tls": ProtocolTLS, "quic": ProtocolQUIC,
	"wireguard": ProtocolWireGuard, "dht": ProtocolDHT, "discord": ProtocolDiscord,
	"stun": ProtocolSTUN, "unknown": ProtocolUnknown,
}

func (p Protocol) String() string {
	for name, value := range protocolNames {
		if value == p {
			return name
		}
	}
	return "unknown"
}

type IntervalMode uint8

const (
	IntervalNone IntervalMode = iota
	IntervalPackets
	IntervalData
	IntervalSequence
)

// Interval is a start/cutoff limiter in upstream n/d/s spelling.
type Interval struct {
	Mode  IntervalMode
	Value uint64
}

func (i Interval) IsSet() bool { return i.Mode != IntervalNone }

func (i Interval) Reached(counters flowCounters) bool {
	if !i.IsSet() {
		return false
	}
	var value uint64
	switch i.Mode {
	case IntervalPackets:
		value = counters.packets
	case IntervalData:
		value = counters.dataPackets
	case IntervalSequence:
		value = counters.sequence
	}
	return value >= i.Value
}

func parseInterval(value string) (Interval, error) {
	if value == "" {
		return Interval{}, nil
	}
	mode := IntervalPackets
	number := value
	switch value[0] {
	case 'n':
		mode, number = IntervalPackets, value[1:]
	case 'd':
		mode, number = IntervalData, value[1:]
	case 's':
		mode, number = IntervalSequence, value[1:]
	}
	parsed, err := strconv.ParseUint(number, 10, 64)
	if err != nil {
		return Interval{}, E.Cause(err, "invalid counter interval ", value)
	}
	if parsed == 0 {
		return Interval{}, nil
	}
	return Interval{Mode: mode, Value: parsed}, nil
}

type TransportMask uint8

const (
	TransportMaskTCP TransportMask = 1 << iota
	TransportMaskUDP
)

type PortRange struct {
	From, To uint16
}

func (r PortRange) Contains(port uint16) bool { return port >= r.From && port <= r.To }

func parsePortRange(value string) (PortRange, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return PortRange{}, E.New("empty port range")
	}
	if from, to, found := strings.Cut(value, "-"); found {
		fromPort, err := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
		if err != nil {
			return PortRange{}, E.Cause(err, "invalid port range ", value)
		}
		toPort, err := strconv.ParseUint(strings.TrimSpace(to), 10, 16)
		if err != nil {
			return PortRange{}, E.Cause(err, "invalid port range ", value)
		}
		if fromPort > toPort {
			return PortRange{}, E.New("invalid port range ", value)
		}
		return PortRange{From: uint16(fromPort), To: uint16(toPort)}, nil
	}
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return PortRange{}, E.Cause(err, "invalid port ", value)
	}
	return PortRange{From: uint16(port), To: uint16(port)}, nil
}

type domainSet struct {
	entries    []string
	suffixOnly []string
}

func (s *domainSet) add(value string) error {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" {
		return E.New("empty domain list entry")
	}
	if strings.HasPrefix(value, ".") {
		s.suffixOnly = append(s.suffixOnly, strings.TrimPrefix(value, "."))
	} else {
		s.entries = append(s.entries, value)
	}
	return nil
}

// matchesHost applies hostlist matching with the upstream hostname_is_ip rule:
// an IP literal can only match an entry exactly, never through a suffix.
func (s *domainSet) matchesHost(host string, isIP bool) bool {
	if !isIP {
		return s.matches(host)
	}
	if s == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range s.entries {
		if host == entry {
			return true
		}
	}
	return false
}

// parseIPLiteral reports whether host is an IP literal and returns the address.
func parseIPLiteral(host string) (netip.Addr, bool) {
	host = strings.TrimSpace(host)
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address, true
}

func (s *domainSet) matches(host string) bool {
	if s == nil || (len(s.entries) == 0 && len(s.suffixOnly) == 0) {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, entry := range s.entries {
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	for _, entry := range s.suffixOnly {
		if strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

func (s *domainSet) empty() bool {
	return s == nil || len(s.entries) == 0 && len(s.suffixOnly) == 0
}

type ipSet struct {
	any      bool
	prefixes []netip.Prefix
}

func (s *ipSet) add(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return E.New("empty IP list entry")
	}
	if strings.EqualFold(value, "any") {
		s.any = true
		return nil
	}
	if prefix, err := netip.ParsePrefix(value); err == nil {
		s.prefixes = append(s.prefixes, prefix.Masked())
		return nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return E.Cause(err, "invalid IP or CIDR ", value)
	}
	s.prefixes = append(s.prefixes, netip.PrefixFrom(address, address.BitLen()))
	return nil
}

// restricts reports whether a positive IP restriction is present. "any" and
// an empty set both remove the positive restriction.
func (s *ipSet) restricts() bool {
	return s != nil && !s.any && len(s.prefixes) > 0
}

// wildcard reports whether the operator "any" entry is present. A positive
// wildcard removes the IP restriction entirely (explicit prefixes become
// redundant); a negative wildcard excludes every destination. Other
// predicates and the other list category are never affected.
func (s *ipSet) wildcard() bool {
	return s != nil && s.any
}

func (s *ipSet) contains(address netip.Addr) bool {
	if s == nil {
		return false
	}
	for _, prefix := range s.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

type LimitSet struct {
	MaxLeases          int
	MaxReassemblyBytes int
	// MaxHeldPackets and MaxHeldBytes bound the originals of one flow that may
	// stay pending while a logical message is assembled.
	MaxHeldPackets int
	MaxHeldBytes   int
	// MaxHeldBytesTotal is the engine-wide budget shared by all leases.
	MaxHeldBytesTotal int
	// HoldTimeout bounds an incomplete-message hold; expiry releases every
	// held original in capture order.
	HoldTimeout time.Duration
}

func defaultLimits() LimitSet {
	return LimitSet{
		MaxLeases:          4096,
		MaxReassemblyBytes: maxReassemblyBytes,
		MaxHeldPackets:     defaultMaxHeldPackets,
		MaxHeldBytes:       defaultMaxHeldBytes,
		MaxHeldBytesTotal:  defaultMaxHeldBytesTotal,
		HoldTimeout:        defaultHoldTimeout,
	}
}

// Config is the immutable compiled snapshot of a desync object.
type Config struct {
	Rules       []*Rule
	Limits      LimitSet
	TCPEmptyACK bool
	// Conntrack is the bounded semantic-conntrack configuration.
	Conntrack conntrackConfig
	// IPCache is the bounded per-outbound IP->host and hop cache.
	IPCache ipCacheConfig
	// Learning is the bounded per-outbound hostlist-auto learning config.
	Learning learningConfig
	// Capture is the compiled OS-specific capture narrowing (capture.linux /
	// capture.windows). It only narrows the owned-socket envelope.
	Capture captureConfig
	// bundleGenerations are the immutable provider bundle generations selected
	// by this snapshot, sorted and unique.
	bundleGenerations []string
	// listDigest identifies the exact list sources of this snapshot. A reload
	// compares it with the new digest: only a changed successful publication
	// increments the outbound list revision.
	listDigest [32]byte
	// baseDir resolves relative list files on reload, exactly like the
	// initial compile (configuration base-path context).
	baseDir string
}

type Rule struct {
	Name           string
	Network        TransportMask
	IPv4           bool
	IPv6           bool
	Ports          []PortRange
	PortExclude    []PortRange
	Protocols      []Protocol
	AnyProtocol    bool
	Domains        *domainSet
	DomainsExclude *domainSet
	IPs            *ipSet
	IPsExclude     *ipSet

	Methods   []Method
	Start     Interval
	Cutoff    Interval
	SkipNoSNI bool
	IPID      IPIDMode
	// IPIDSet distinguishes the upstream default (seq) from an explicit
	// zero/rnd/seqgroup/same selection.
	IPIDSet bool

	Fake          *FakeSpec
	FakeKnown     *FakeSpec
	MultiSplit    *SplitSpec
	MultiDisorder *SplitSpec
	FakeSplit     *FakeSplitSpec
	FakeDisorder  *FakeSplitSpec
	HostFakeSplit *HostFakeSplitSpec
	IPFragPosTCP  int
	IPFragPosUDP  int
	UDPLen        *UDPLenSpec

	// Mods are the rule-owned packet modifiers (TTL, flags, fooling, signed
	// increments). Every method uses the same typed set; no method requires an
	// unrelated fake object to configure them.
	Mods *ModifierSet
	// Orig and Dup modify the captured original and its duplicates.
	Orig *OrigSpec
	Dup  *DupSpec
	// WSize rewrites the advertised window of an observed SYN-ACK
	// (upstream --wsize).
	WSize *WSizeSpec
	// WSSize rewrites the advertised window of original-direction packets
	// (upstream --wssize family, including its cutoff latches).
	WSSize *WSSizeSpec
	// SynackSplit splits an outbound SYN-ACK into SYN and ACK parts.
	SynackSplit SynAckSplit
	// TCPEmptyACKRequired is set when any enabled rule needs empty ACKs
	// observed (original modification or duplication).
	TCPEmptyACKRequired bool
	// Learning enables hostlist-auto applicability for this rule. The shared
	// learned set lives on the engine.
	Learning *ruleLearning

	// List sources are retained so Engine.ReloadLists can rebuild the same
	// compiled sets from the same files without re-reading the option tree.
	domainInline        []string
	domainExcludeInline []string
	ipInline            []string
	ipExcludeInline     []string
	domainFiles         []string
	domainExcludeFiles  []string
	ipFiles             []string
	ipExcludeFiles      []string
	// domainRestrict/ipRestrict record that a positive list was configured,
	// even when every configured source is empty. An empty positive snapshot
	// matches nothing; it does not silently remove the restriction.
	domainRestrict bool
	ipRestrict     bool
	// bundleSelection is the path-resolved provider bundle selector of this
	// rule. domainBundle/... carry the entries read from that generation; they
	// are rebuilt from the selector on every reload.
	bundleSelection      *bundleRuleSelection
	domainBundle         []string
	domainExcludeBundle  []string
	ipBundle             []string
	ipExcludeBundle      []string
	bundleDomainRestrict bool
	bundleIPRestrict     bool
}

// IPIDMode is the upstream IPv4 ID handling mode of generated packets.
type IPIDMode uint8

const (
	IPIDIncrement IPIDMode = iota
	IPIDZero
	IPIDSeq
	IPIDSeqGroup
	IPIDRandom
	IPIDSame
)

type Payload struct {
	Protocol Protocol
	Data     []byte
	Source   string
	SHA256   string
	// TLSMod is the compiled upstream fake-tls-mod of this payload.
	TLSMod TLSMod
}

// TLSMod is the compiled upstream `--dpi-desync-fake-tls-mod` selector.
type TLSMod struct {
	Randomize    bool
	RandomizeSNI bool
	SNI          string
	DupSID       bool
	PadEncap     bool
}

func (m TLSMod) IsZero() bool {
	return !m.Randomize && !m.RandomizeSNI && m.SNI == "" && !m.DupSID && !m.PadEncap
}

// FakeSpec is the compiled first-stage fake configuration. fakeknown uses the
// same payload list but requires a recognized L7 protocol.
type FakeSpec struct {
	Payloads    []Payload
	Repeats     int
	Fooling     Fooling
	TSIncrement int32
	TTL         int
	TTL6        int
	AutoTTL     AutoTTL
	AutoTTL6    AutoTTL
	Seq         bool
}

type Fooling struct {
	Timestamp    bool
	BadSequence  bool
	BadChecksum  bool
	MD5Signature bool
	DataNoACK    bool
	HopByHop     bool
	HopByHop2    bool
}

// HasIPOption reports whether any fooling mode changes the generated IPv6
// header chain. hopbyhop2 implies two hop-by-hop headers (upstream standard
// violation).
func (f Fooling) HasIPOption() bool { return f.HopByHop || f.HopByHop2 }

type SplitSpec struct {
	Positions       []Position
	Overlap         int
	OverlapIsPos    bool
	OverlapPosition Position
	OverlapPattern  []byte
}

// FakeSplitSpec is the shared fakedsplit/fakeddisorder configuration: the
// upstream fake pattern (`--dpi-desync-fakedsplit-pattern`) and the altorder
// selector (`--dpi-desync-fakedsplit-mod`).
type FakeSplitSpec struct {
	Split SplitSpec
	// Pattern is the fake byte pattern, repeated to the payload length.
	Pattern []byte
	// Ordering is the upstream 3-bit ordering nibble. Bit 0-1 are the
	// split-position ordering, bits 3-4 the no-split-position ordering.
	Ordering byte
}

// HostFakeSplitSpec is the compiled hostfakesplit configuration. The two
// mandatory real splits are the Host/SNI value boundaries; MidHost, when it
// resolves strictly inside them, adds the upstream third split.
type HostFakeSplitSpec struct {
	MidHost *Position
	// Host is the configured fake hostname (upstream hfs_mod.host); empty
	// means a generated random host.
	Host string
	// HostSize is len(Host), cached exactly like upstream hfs_mod.host_size.
	HostSize int
	// Ordering is the upstream hostfakesplit altorder selector (0 or 1).
	Ordering byte
}

type UDPLenSpec struct {
	Increment int
	Pattern   []byte
}

// SynAckSplit is the upstream --synack-split selector.
type SynAckSplit uint8

const (
	SynAckSplitNone SynAckSplit = iota
	// SynAckSplitSYN clears TH_ACK of an observed SYN-ACK in place (upstream
	// `synack-split=syn`).
	SynAckSplitSYN
	// SynAckSplitSYNFirst sends the SYN part before the ACK part (upstream
	// `synack-split=synack`).
	SynAckSplitSYNFirst
	// SynAckSplitACKFirst sends the ACK part before the SYN part (upstream
	// `synack-split=acksyn`).
	SynAckSplitACKFirst
)

// Compile validates and compiles a desync object. It performs no I/O outside
// reading configured payload/list files relative to baseDir.
func Compile(options *option.DirectDesyncOptions, baseDir string) (*Config, error) {
	return compileConfig(options, baseDir, newListBuildState())
}

// CompileWithState compiles against a caller-owned list build state so the
// packet and stream halves of one outbound share one pinned bundle generation
// and one selection budget. It is the integration entrypoint; Compile keeps the
// single-call behavior for existing callers.
func CompileWithState(options *option.DirectDesyncOptions, baseDir string, state *listBuildState) (*Config, error) {
	if state == nil {
		state = newListBuildState()
	}
	return compileConfig(options, baseDir, state)
}

func compileConfig(options *option.DirectDesyncOptions, baseDir string, state *listBuildState) (*Config, error) {
	if options == nil {
		return nil, nil
	}
	if options.Enabled != nil && !*options.Enabled {
		return nil, nil
	}
	if len(options.Rules) == 0 {
		return nil, E.New("desync: enabled without rules")
	}
	config := &Config{Limits: defaultLimits(), baseDir: baseDir,
		Conntrack: defaultConntrackConfig(), IPCache: defaultIPCacheConfig()}
	if options.Conntrack != nil {
		if options.Conntrack.Disabled {
			config.Conntrack.disabled = true
		}
		if options.Conntrack.MaxEntries < 0 {
			return nil, E.New("desync: negative conntrack max_entries")
		}
		if options.Conntrack.MaxEntries > 0 {
			config.Conntrack.maxEntries = options.Conntrack.MaxEntries
		}
		if timeouts := options.Conntrack.Timeouts; timeouts != nil {
			set := func(target *time.Duration, source *badoption.Duration) error {
				if source == nil {
					return nil
				}
				value := time.Duration(*source)
				if value <= 0 {
					return E.New("desync: conntrack timeouts must be positive")
				}
				*target = value
				return nil
			}
			if err := set(&config.Conntrack.timeouts.syn, timeouts.SYN); err != nil {
				return nil, err
			}
			if err := set(&config.Conntrack.timeouts.established, timeouts.Established); err != nil {
				return nil, err
			}
			if err := set(&config.Conntrack.timeouts.fin, timeouts.FIN); err != nil {
				return nil, err
			}
			if err := set(&config.Conntrack.timeouts.udp, timeouts.UDP); err != nil {
				return nil, err
			}
		}
	}
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
			// An explicit zero is the documented "no expiration"; absent keeps
			// the source default.
			config.IPCache.lifetime = lifetime
			config.IPCache.noExpiry = lifetime == 0
		}
	}
	config.Learning = defaultLearningConfig()
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
	if options.Capture != nil && options.Capture.TCPEmptyACK != nil {
		config.TCPEmptyACK = *options.Capture.TCPEmptyACK
	}
	if options.Capture != nil {
		capture, err := compileNativeCapture(options.Capture)
		if err != nil {
			return nil, err
		}
		config.Capture = capture
	}
	if options.Limits != nil {
		limits := options.Limits
		if limits.MaxLeases < 0 || limits.MaxReassemblyBytes < 0 ||
			limits.MaxHeldPackets < 0 || limits.MaxHeldBytes < 0 ||
			limits.MaxHeldBytesTotal < 0 {
			return nil, E.New("desync: negative resource limit")
		}
		if limits.HoldTimeout != nil && *limits.HoldTimeout < 0 {
			return nil, E.New("desync: negative hold_timeout")
		}
		if limits.MaxLeases > 0 {
			config.Limits.MaxLeases = limits.MaxLeases
		}
		if limits.MaxReassemblyBytes > 0 {
			config.Limits.MaxReassemblyBytes = limits.MaxReassemblyBytes
		}
		if limits.MaxHeldPackets > 0 {
			config.Limits.MaxHeldPackets = limits.MaxHeldPackets
		}
		if limits.MaxHeldBytes > 0 {
			config.Limits.MaxHeldBytes = limits.MaxHeldBytes
			if config.Limits.MaxHeldBytes < 1500 {
				return nil, E.New("desync: max_held_bytes must hold at least one MTU")
			}
		}
		if limits.MaxHeldBytesTotal > 0 {
			config.Limits.MaxHeldBytesTotal = limits.MaxHeldBytesTotal
		}
		if limits.HoldTimeout != nil {
			timeout := time.Duration(*limits.HoldTimeout)
			if timeout <= 0 || timeout > maxHoldTimeout {
				return nil, E.New("desync: hold_timeout must be within (0, ", maxHoldTimeout, "]")
			}
			config.Limits.HoldTimeout = timeout
		}
		if config.Limits.MaxHeldBytesTotal < config.Limits.MaxHeldBytes {
			return nil, E.New("desync: max_held_bytes_total is smaller than max_held_bytes")
		}
	}
	for index := range options.Rules {
		rule, err := compileRule(&options.Rules[index], baseDir, config.Limits, state)
		if err != nil {
			name := options.Rules[index].Name
			if name == "" {
				name = "#" + strconv.Itoa(index)
			}
			return nil, E.Cause(err, "desync rule ", name)
		}
		if rule != nil {
			config.Rules = append(config.Rules, rule)
		}
	}
	if len(config.Rules) == 0 {
		return nil, E.New("desync: no enabled rules")
	}
	requiresEmptyACK := false
	for _, rule := range config.Rules {
		if rule.TCPEmptyACKRequired {
			requiresEmptyACK = true
			break
		}
	}
	if requiresEmptyACK {
		if options.Capture != nil && options.Capture.TCPEmptyACK != nil && !*options.Capture.TCPEmptyACK {
			return nil, E.New("desync: capture.tcp_empty_ack=false conflicts with a method that modifies or duplicates originals")
		}
		config.TCPEmptyACK = true
	}
	for _, rule := range config.Rules {
		if rule.Learning != nil {
			config.Learning.enabled = true
			break
		}
	}
	config.bundleGenerations = state.bundleGenerations()
	config.listDigest = state.digestValue()
	return config, nil
}

func compileRule(source *option.DirectDesyncRule, baseDir string, limits LimitSet, state *listBuildState) (*Rule, error) {
	if source.Disabled {
		return nil, nil
	}
	rule := &Rule{
		Name:           source.Name,
		Network:        TransportMaskTCP,
		IPv4:           true,
		IPv6:           true,
		SkipNoSNI:      true,
		Domains:        &domainSet{},
		DomainsExclude: &domainSet{},
		IPs:            &ipSet{},
		IPsExclude:     &ipSet{},
	}
	if source.SkipNoSNI != nil {
		rule.SkipNoSNI = *source.SkipNoSNI
	}
	if len(source.Network) > 0 {
		rule.Network = 0
		for _, network := range source.Network {
			switch network {
			case "tcp":
				rule.Network |= TransportMaskTCP
			case "udp":
				rule.Network |= TransportMaskUDP
			default:
				return nil, E.New("unknown network ", network)
			}
		}
	}
	if len(source.IPVersion) > 0 {
		rule.IPv4, rule.IPv6 = false, false
		for _, version := range source.IPVersion {
			switch version {
			case 4:
				rule.IPv4 = true
			case 6:
				rule.IPv6 = true
			default:
				return nil, E.New("unknown ip_version ", version)
			}
		}
	}
	for _, port := range source.Port {
		rule.Ports = append(rule.Ports, PortRange{From: port, To: port})
	}
	for _, rangeValue := range source.PortRange {
		parsed, err := parsePortRange(rangeValue)
		if err != nil {
			return nil, err
		}
		rule.Ports = append(rule.Ports, parsed)
	}
	for _, port := range source.PortExclude {
		rule.PortExclude = append(rule.PortExclude, PortRange{From: port, To: port})
	}
	for _, rangeValue := range source.PortRangeExclude {
		parsed, err := parsePortRange(rangeValue)
		if err != nil {
			return nil, err
		}
		rule.PortExclude = append(rule.PortExclude, parsed)
	}
	for _, protocol := range source.Protocol {
		value, found := protocolNames[protocol]
		if !found {
			return nil, E.New("unknown protocol ", protocol)
		}
		rule.Protocols = append(rule.Protocols, value)
	}
	for _, domain := range source.Domain {
		rule.domainInline = append(rule.domainInline, domain)
	}
	for _, path := range source.DomainFile {
		rule.domainFiles = append(rule.domainFiles, resolveListPath(baseDir, path))
	}
	for _, domain := range source.DomainExclude {
		rule.domainExcludeInline = append(rule.domainExcludeInline, domain)
	}
	for _, path := range source.DomainExcludeFile {
		rule.domainExcludeFiles = append(rule.domainExcludeFiles, resolveListPath(baseDir, path))
	}
	for _, cidr := range source.IPCIDR {
		rule.ipInline = append(rule.ipInline, cidr)
	}
	for _, path := range source.IPCIDRFile {
		rule.ipFiles = append(rule.ipFiles, resolveListPath(baseDir, path))
	}
	for _, cidr := range source.IPCIDRExclude {
		rule.ipExcludeInline = append(rule.ipExcludeInline, cidr)
	}
	for _, path := range source.IPCIDRExcludeFile {
		rule.ipExcludeFiles = append(rule.ipExcludeFiles, resolveListPath(baseDir, path))
	}
	if state == nil {
		state = newListBuildState()
	}
	if source.ListBundle != nil {
		selection, selectionErr := state.resolveSelection(source.ListBundle, baseDir, rule)
		if selectionErr != nil {
			return nil, selectionErr
		}
		rule.bundleSelection = selection
	}
	if err := rule.rebuildListSets(state); err != nil {
		return nil, err
	}
	if len(rule.Protocols) > 0 {
		rule.AnyProtocol = false
	} else {
		rule.AnyProtocol = true
	}
	if source.AnyProtocol {
		rule.AnyProtocol = true
	}
	switch source.IPID {
	case "":
		// Upstream's zero-initialised profile defaults to IPID_SEQ: generated
		// packets keep the original non-zero ID and advance it.
		rule.IPID = IPIDSeq
	case "zero":
		rule.IPID, rule.IPIDSet = IPIDZero, true
	case "seq":
		rule.IPID, rule.IPIDSet = IPIDSeq, true
	case "seqgroup":
		rule.IPID, rule.IPIDSet = IPIDSeqGroup, true
	case "rnd":
		rule.IPID, rule.IPIDSet = IPIDRandom, true
	case "same":
		rule.IPID, rule.IPIDSet = IPIDSame, true
	default:
		return nil, E.New("unknown ip_id mode ", source.IPID)
	}
	var err error
	rule.Start, err = parseInterval(source.Start)
	if err != nil {
		return nil, err
	}
	rule.Cutoff, err = parseInterval(source.Cutoff)
	if err != nil {
		return nil, err
	}
	if err = compileStages(rule, source, baseDir, limits); err != nil {
		return nil, err
	}
	if source.Learning != nil {
		learning, err := compileRuleLearning(source.Learning)
		if err != nil {
			return nil, err
		}
		rule.Learning = learning
	}
	return rule, nil
}

// compileRuleLearning compiles the shared hostlist-auto rule config. Packet and
// stream rules use the same accepted ranges and the same per-outbound learner;
// there is no second threshold set.
func compileRuleLearning(source *option.DirectDesyncRuleLearning) (*ruleLearning, error) {
	if source == nil {
		return nil, nil
	}
	learning := defaultRuleLearning()
	if source.FailThreshold != nil {
		value := *source.FailThreshold
		if value < 1 || value > 20 {
			return nil, E.New("learning fail_threshold must be within 1..20")
		}
		learning.failThreshold = value
	}
	if source.FailTime != nil {
		window := time.Duration(*source.FailTime)
		if window < minLearningFailWindow || window > maxLearningFailWindow {
			return nil, E.New("learning fail_time must be within 1..255 seconds")
		}
		learning.failWindow = window
	}
	if source.RetransThreshold != nil {
		value := *source.RetransThreshold
		if value < 2 || value > 10 {
			return nil, E.New("learning retrans_threshold must be within 2..10")
		}
		learning.retransThreshold = value
	}
	return learning, nil
}

func compileFake(source *option.DirectDesyncFakeOptions, baseDir string) (*FakeSpec, error) {
	if len(source.Payloads) == 0 {
		return nil, E.New("fake without payloads")
	}
	fake := &FakeSpec{Repeats: source.Repeats, TTL: source.TTL, Seq: source.Seq}
	if source.TSIncrement != nil {
		fake.TSIncrement = *source.TSIncrement
	}
	if source.TTL < 0 || source.TTL > 255 || source.TTL6 < 0 || source.TTL6 > 255 {
		return nil, E.New("fake ttl out of range 0..255")
	}
	fake.TTL6 = source.TTL6
	var err error
	fake.AutoTTL, err = parseAutoTTL(source.AutoTTL)
	if err != nil {
		return nil, err
	}
	fake.AutoTTL6, err = parseAutoTTL(source.AutoTTL6)
	if err != nil {
		return nil, err
	}
	if fake.Repeats == 0 {
		fake.Repeats = 1
	}
	if fake.Repeats < 0 || fake.Repeats > 64 {
		return nil, E.New("fake repeats out of range 1..64")
	}
	if fake.TSIncrement == 0 {
		fake.TSIncrement = -600000
	}
	for _, fooling := range source.Fooling {
		switch fooling {
		case "none":
		case "ts":
			fake.Fooling.Timestamp = true
		case "badseq":
			fake.Fooling.BadSequence = true
		case "badsum":
			fake.Fooling.BadChecksum = true
		case "md5sig":
			fake.Fooling.MD5Signature = true
		case "datanoack":
			fake.Fooling.DataNoACK = true
		case "hopbyhop":
			fake.Fooling.HopByHop = true
		case "hopbyhop2":
			fake.Fooling.HopByHop2 = true
		default:
			return nil, E.New("unknown fooling mode ", fooling)
		}
	}
	for index := range source.Payloads {
		payload, err := compilePayload(&source.Payloads[index], baseDir)
		if err != nil {
			return nil, err
		}
		fake.Payloads = append(fake.Payloads, payload)
	}
	return fake, nil
}

func compilePayload(source *option.DirectDesyncPayload, baseDir string) (Payload, error) {
	var (
		data       []byte
		sourceName string
		err        error
	)
	sources := 0
	if source.File != "" {
		sources++
	}
	if source.Hex != "" {
		sources++
	}
	if source.Base64 != "" {
		sources++
	}
	if sources != 1 {
		return Payload{}, E.New("payload must set exactly one of file, hex or base64")
	}
	if source.Offset < 0 {
		return Payload{}, E.New("negative payload offset")
	}
	switch {
	case source.File != "":
		path := source.File
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return Payload{}, E.Cause(readErr, "read payload")
		}
		if len(content) > maxPayloadSize {
			return Payload{}, E.New("payload ", source.File, " exceeds ", maxPayloadSize, " bytes")
		}
		data = content
		sourceName = source.File
	case source.Hex != "":
		data, err = hex.DecodeString(source.Hex)
		if err != nil {
			return Payload{}, E.Cause(err, "decode hex payload")
		}
		sourceName = "hex"
	default:
		data, err = base64.StdEncoding.DecodeString(source.Base64)
		if err != nil {
			return Payload{}, E.Cause(err, "decode base64 payload")
		}
		sourceName = "base64"
	}
	if source.Offset > len(data) {
		return Payload{}, E.New("payload offset exceeds payload size")
	}
	data = data[source.Offset:]
	if len(data) == 0 {
		return Payload{}, E.New("empty payload")
	}
	protocol, found := protocolNames[source.Protocol]
	if !found {
		return Payload{}, E.New("unknown payload protocol ", source.Protocol)
	}
	tlsMod, err := parseTLSMod(source.TLSMod)
	if err != nil {
		return Payload{}, err
	}
	if !tlsMod.IsZero() && protocol != ProtocolTLS {
		return Payload{}, E.New("tls_mod is only valid for a tls payload")
	}
	return Payload{
		Protocol: protocol,
		Data:     append([]byte(nil), data...),
		Source:   sourceName,
		SHA256:   hashBytes(data),
		TLSMod:   tlsMod,
	}, nil
}

// parseTLSMod parses the upstream fake-tls-mod list.
func parseTLSMod(value string) (TLSMod, error) {
	var mod TLSMod
	value = strings.TrimSpace(value)
	if value == "" || value == "none" {
		return mod, nil
	}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "" || entry == "none":
		case entry == "rnd":
			mod.Randomize = true
		case entry == "rndsni":
			mod.RandomizeSNI = true
		case entry == "dupsid":
			mod.DupSID = true
		case entry == "padencap":
			mod.PadEncap = true
		case strings.HasPrefix(entry, "sni="):
			mod.SNI = strings.TrimPrefix(entry, "sni=")
			if mod.SNI == "" {
				return TLSMod{}, E.New("empty tls_mod sni")
			}
		default:
			return TLSMod{}, E.New("unknown tls_mod ", entry)
		}
	}
	if mod.RandomizeSNI && mod.SNI != "" {
		return TLSMod{}, E.New("tls_mod rndsni conflicts with sni=")
	}
	return mod, nil
}

func compileSplit(source *option.DirectDesyncSplitOptions, baseDir string, limits LimitSet) (*SplitSpec, error) {
	if len(source.SplitPos) == 0 {
		return nil, E.New("split without split_pos")
	}
	if len(source.SplitPos) > maxSplitPositions {
		return nil, E.New("split_pos exceeds ", maxSplitPositions, " entries")
	}
	split := &SplitSpec{}
	for _, value := range source.SplitPos {
		position, err := ParsePosition(value)
		if err != nil {
			return nil, err
		}
		split.Positions = append(split.Positions, position)
	}
	if source.SeqOverlap != nil {
		if source.SeqOverlap.Bytes != nil {
			split.Overlap = *source.SeqOverlap.Bytes
		} else {
			position, err := ParsePosition(source.SeqOverlap.Position)
			if err != nil {
				return nil, err
			}
			split.OverlapIsPos = true
			split.OverlapPosition = position
		}
		if split.Overlap > maxPayloadSize {
			return nil, E.New("seqovl exceeds ", maxPayloadSize)
		}
	}
	if source.SeqOverlapFile != "" {
		path := source.SeqOverlapFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, E.Cause(err, "read seqovl_pattern")
		}
		if len(content) == 0 || len(content) > maxOverlapPattern {
			return nil, E.New("seqovl_pattern must contain 1..", maxOverlapPattern, " bytes")
		}
		split.OverlapPattern = content
	}
	if split.Overlap != 0 && len(split.OverlapPattern) == 0 {
		return nil, E.New("seqovl requires seqovl_pattern for the overlap bytes")
	}
	if limits.MaxReassemblyBytes <= 0 {
		return nil, E.New("invalid reassembly limit")
	}
	return split, nil
}

func loadListFile(baseDir string, path string, add func(string) error) error {
	lines, err := readListFile(resolveListPath(baseDir, path))
	if err != nil {
		return err
	}
	for _, line := range lines {
		if err := add(line); err != nil {
			return E.Cause(err, "list file ", path)
		}
	}
	return nil
}

func resolveListPath(baseDir string, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

// readListFile reads one provider snapshot, accepts gzip with a bounded
// expansion, and normalizes comments/CRLF. Multiple include files are unioned
// by the caller; an empty file stays an empty positive snapshot.
//
// The read is bounded before allocation: the regular-file size is checked
// first and the byte stream is then limited, so an oversized snapshot is
// rejected without first materialising it.
func readListFile(resolved string) ([]string, error) {
	content, err := readBoundedFile(resolved, maxListFileBytes)
	if err != nil {
		return nil, E.Cause(err, "read list file")
	}
	return parseListContent(resolved, content)
}

// parseListContent decodes one bounded list snapshot (plain text or gzip by
// magic) into its non-empty, non-comment records.
func parseListContent(resolved string, content []byte) ([]string, error) {
	if len(content) >= 2 && content[0] == 0x1f && content[1] == 0x8b {
		reader, gzipErr := gzip.NewReader(bytes.NewReader(content))
		if gzipErr != nil {
			return nil, E.Cause(gzipErr, "list file ", resolved, " is not valid gzip")
		}
		expanded, readErr := io.ReadAll(io.LimitReader(reader, maxListFileBytes+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, E.Cause(readErr, "expand gzip list file ", resolved)
		}
		if closeErr != nil {
			return nil, E.Cause(closeErr, "expand gzip list file ", resolved)
		}
		if len(expanded) > maxListFileBytes {
			return nil, E.New("expanded gzip list file exceeds ", maxListFileBytes, " bytes")
		}
		content = expanded
	}
	lines := make([]string, 0, bytes.Count(content, []byte{'\n'})+1)
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// rebuildListSets compiles the inline entries and every file union into fresh
// sets. It is used by the initial compile and by the transactional reload, so
// both paths apply exactly the same normalization. An empty positive list is
// still a positive restriction: a configured-but-empty snapshot matches
// nothing instead of silently matching everything.
func (r *Rule) rebuildListSets(state *listBuildState) error {
	if state == nil {
		state = newListBuildState()
	}
	if err := r.applyBundle(state); err != nil {
		return err
	}
	domains := &domainSet{}
	for _, value := range r.domainInline {
		if err := domains.add(value); err != nil {
			return err
		}
	}
	for _, value := range r.domainBundle {
		if err := domains.add(value); err != nil {
			return E.Cause(err, "list bundle domain dataset")
		}
	}
	for _, path := range r.domainFiles {
		lines, err := state.readLegacyList(path)
		if err != nil {
			return err
		}
		for _, line := range lines {
			if err := domains.add(line); err != nil {
				return E.Cause(err, "list file ", path)
			}
		}
	}
	domainsExclude := &domainSet{}
	for _, value := range r.domainExcludeInline {
		if err := domainsExclude.add(value); err != nil {
			return err
		}
	}
	for _, value := range r.domainExcludeBundle {
		if err := domainsExclude.add(value); err != nil {
			return E.Cause(err, "list bundle domain_exclude dataset")
		}
	}
	for _, path := range r.domainExcludeFiles {
		lines, err := state.readLegacyList(path)
		if err != nil {
			return err
		}
		for _, line := range lines {
			if err := domainsExclude.add(line); err != nil {
				return E.Cause(err, "list file ", path)
			}
		}
	}
	ips := &ipSet{}
	for _, value := range r.ipInline {
		if err := ips.add(value); err != nil {
			return err
		}
	}
	for _, value := range r.ipBundle {
		if err := ips.add(value); err != nil {
			return E.Cause(err, "list bundle ip dataset")
		}
	}
	for _, path := range r.ipFiles {
		lines, err := state.readLegacyList(path)
		if err != nil {
			return err
		}
		for _, line := range lines {
			if err := ips.add(line); err != nil {
				return E.Cause(err, "list file ", path)
			}
		}
	}
	ipsExclude := &ipSet{}
	for _, value := range r.ipExcludeInline {
		if err := ipsExclude.add(value); err != nil {
			return err
		}
	}
	for _, value := range r.ipExcludeBundle {
		if err := ipsExclude.add(value); err != nil {
			return E.Cause(err, "list bundle ip_cidr_exclude dataset")
		}
	}
	for _, path := range r.ipExcludeFiles {
		lines, err := state.readLegacyList(path)
		if err != nil {
			return err
		}
		for _, line := range lines {
			if err := ipsExclude.add(line); err != nil {
				return E.Cause(err, "list file ", path)
			}
		}
	}
	r.Domains, r.DomainsExclude = domains, domainsExclude
	r.IPs, r.IPsExclude = ips, ipsExclude
	r.domainRestrict = len(r.domainInline) > 0 || len(r.domainFiles) > 0 || r.bundleDomainRestrict
	r.ipRestrict = len(r.ipInline) > 0 || len(r.ipFiles) > 0 || r.bundleIPRestrict
	return nil
}

// reloadLists builds a new immutable Config with every list re-read. It never
// mutates the current snapshot: on error the caller keeps the last-good one.
// Every unrelated field, including the compiled native capture configuration,
// activation options and all resource limits, is preserved.
func (c *Config) reloadLists(state *listBuildState) (*Config, error) {
	if state == nil {
		state = newListBuildState()
	}
	next := &Config{
		Rules:       make([]*Rule, 0, len(c.Rules)),
		Limits:      c.Limits,
		TCPEmptyACK: c.TCPEmptyACK,
		Conntrack:   c.Conntrack,
		IPCache:     c.IPCache,
		Learning:    c.Learning,
		Capture:     c.Capture,
		baseDir:     c.baseDir,
	}
	for _, rule := range c.Rules {
		copied := *rule
		copied.domainInline = append([]string(nil), rule.domainInline...)
		copied.domainExcludeInline = append([]string(nil), rule.domainExcludeInline...)
		copied.ipInline = append([]string(nil), rule.ipInline...)
		copied.ipExcludeInline = append([]string(nil), rule.ipExcludeInline...)
		copied.domainFiles = append([]string(nil), rule.domainFiles...)
		copied.domainExcludeFiles = append([]string(nil), rule.domainExcludeFiles...)
		copied.ipFiles = append([]string(nil), rule.ipFiles...)
		copied.ipExcludeFiles = append([]string(nil), rule.ipExcludeFiles...)
		if err := copied.rebuildListSets(state); err != nil {
			return nil, err
		}
		next.Rules = append(next.Rules, &copied)
	}
	next.bundleGenerations = state.bundleGenerations()
	next.listDigest = state.digestValue()
	return next, nil
}

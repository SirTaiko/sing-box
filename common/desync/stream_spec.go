package desync

import (
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// streamBlockSize mirrors tpws RD_BLOCK_SIZE: at most this many bytes are
	// tampered and split as one data block.
	streamBlockSize = 65536
	// streamBlockCapacity mirrors the tpws segment buffer
	// (RD_BLOCK_SIZE + 6); transformations may grow a block to this size.
	streamBlockCapacity = streamBlockSize + 6
	// streamMaxFirstBlock bounds deferred first-block parsing. It is the same
	// as one tpws receive block; a host that has not appeared by then is
	// treated as unknown, exactly like a block whose Host header is absent.
	streamMaxFirstBlock = streamBlockSize
	// streamMaxFixSeg mirrors the tpws `--fix-seg` bound: 0..1000 ms.
	streamMaxFixSeg = 1000
	// streamDefaultFixSeg mirrors FIX_SEG_DEFAULT_MAX_WAIT (params.h): a bare
	// `--fix-seg` without a value waits 50 ms. It is deliberately distinct
	// from an explicit `--fix-seg=0`, which only inspects the send queue.
	streamDefaultFixSeg = 50
	// streamMaxSplitPositions mirrors tpws params.h MAX_SPLITS: the total
	// number of split positions of one profile, including the deprecated
	// `--split-http-req`/`--split-tls` entries. It is deliberately separate
	// from the packet-side maxSplitPositions (nfq 64).
	streamMaxSplitPositions = 16
	// streamHTTPProbe bounds how long an HTTP prefix without a Host header is
	// held for deferred rule selection.
	streamHTTPProbe = 2048
	// streamTLSProbe bounds the deferred ClientHello wait.
	streamTLSProbe = 16384
)

// StreamConfig is the immutable compiled snapshot of direct.desync.stream_rules.
// It holds no mutable connection state and no global cache. ReloadLists swaps
// the rule snapshot ("last good") under rulesMu; every connection keeps the
// rule it selected.
type StreamConfig struct {
	rulesMu sync.RWMutex
	rules   []*streamRule
	native  streamNative
	// random is a test seam for the tpws hostpad/random header bytes. Nil uses
	// crypto/rand.Reader. It is read only while a connection writes.
	random io.Reader
	// engine is the single per-outbound state owner (ip cache and learner).
	// It is attached once during outbound construction; nil keeps the
	// standalone CompileStream/WrapConn path free of any shared state.
	engine *Engine
	// sources and baseDir are retained so a reload rebuilds exactly the same
	// compiled sets from the same files, without re-reading the option tree.
	sources []option.DirectDesyncStreamRule
	baseDir string
}

// snapshotRules returns the current compiled rule snapshot. Reload publication
// swaps the slice header atomically; readers never see a partially built set.
func (c *StreamConfig) snapshotRules() []*streamRule {
	if c == nil {
		return nil
	}
	c.rulesMu.RLock()
	defer c.rulesMu.RUnlock()
	return c.rules
}

// AttachEngine binds this stream snapshot to the per-outbound Engine that owns
// the ip cache and the learned set. It is called once during outbound
// construction and never creates a second store; a nil engine leaves the
// standalone path unchanged.
func (c *StreamConfig) AttachEngine(engine *Engine) error {
	if c == nil {
		return nil
	}
	if c.engine != nil && c.engine != engine {
		return E.New("desync: stream configuration already attached to another engine")
	}
	c.engine = engine
	if engine != nil {
		engine.stream = c
	}
	return nil
}

// annotateFacts fills the preconnect host facts from the engine-owned ip cache
// when the dial path carried no domain, and records the hostlist-auto
// eligibility for both cached and revealed hosts. The cached host is
// provisional: the first block's Host/SNI re-selects the rule (processBlock),
// exactly like upstream apply_desync_profile after a discovered hostname. The
// lookup is scoped to this outbound's engine; callers that know the attempt
// interface use Engine.CachedHostOn for the interface-scoped entry.
func (c *StreamConfig) annotateFacts(facts MatchFacts) MatchFacts {
	if c == nil || c.engine == nil {
		return facts
	}
	if !facts.HostKnown && facts.Destination.IsValid() {
		if host, isIP, ok := c.engine.CachedHostState(facts.Destination); ok {
			facts.Host = host
			facts.HostKnown = true
			facts.HostIsIP = isIP
		}
	}
	if facts.HostKnown {
		facts.Learned = c.engine.HostLearned(facts.Host)
	}
	return facts
}

// dependsOnHost reports whether any rule needs the L7 hostname to select. When
// false the wrapper never delays the first block to wait for a Host header.
func (c *StreamConfig) dependsOnHost() bool {
	if c == nil {
		return false
	}
	for _, rule := range c.snapshotRules() {
		if !rule.match.Domains.empty() || !rule.match.DomainsExclude.empty() {
			return true
		}
	}
	return false
}

type streamRule struct {
	name       string
	match      *Rule
	httpTamper *httpTamperSpec
	tlsRecord  *tlsRecordSpec
	split      *streamSplitSpec
	start      streamInterval
	cutoff     streamInterval

	mss         int
	skipNoDelay bool
	fixSeg      time.Duration
	fixSegSet   bool
	// learning is the shared hostlist-auto applicability of this stream rule.
	// The learned set itself lives on the outbound Engine, never here.
	learning *ruleLearning
}

// streamInterval is a tpws tamper-start/tamper-cutoff bound. Block numbers are
// 1-based; byte positions are counted over the outbound stream before the
// current block.
type streamInterval struct {
	block bool
	value uint64
}

func (i streamInterval) reached(blockNumber uint64, streamPosition uint64) bool {
	value := streamPosition
	if i.block {
		value = blockNumber
	}
	return value >= i.value
}

// inRange mirrors tpws in_tamper_out_range: the range is tested once per block
// at the block start, and a block that starts inside the range is fully
// tampered even when it extends past the cutoff.
func (r *streamRule) inRange(blockNumber uint64, streamPosition uint64) bool {
	if r.start.value != 0 && !r.start.reached(blockNumber, streamPosition) {
		return false
	}
	if r.cutoff.value != 0 && r.cutoff.reached(blockNumber, streamPosition) {
		return false
	}
	return true
}

type httpTamperSpec struct {
	hostCase    bool
	hostSpell   [4]byte
	hostDot     bool
	hostTab     bool
	hostNoSpace bool
	hostPad     int
	domCase     bool
	methodSpace bool
	methodEOL   bool
	unixEOL     bool
}

func (s *httpTamperSpec) empty() bool {
	return !s.hostCase && !s.hostDot && !s.hostTab && !s.hostNoSpace &&
		s.hostPad == 0 && !s.domCase && !s.methodSpace && !s.methodEOL && !s.unixEOL
}

type tlsRecordSpec struct {
	position Position
}

type streamSplitSpec struct {
	positions      []Position
	anyProtocol    bool
	disorder       splitScope
	oob            splitScope
	oobByte        byte
	deprecatedHTTP string
	deprecatedTLS  string
}

type splitScope uint8

const (
	splitScopeNone splitScope = iota
	splitScopeAny
	splitScopeHTTP
	splitScopeTLS
)

func (s splitScope) matches(protocol Protocol) bool {
	switch s {
	case splitScopeAny:
		return true
	case splitScopeHTTP:
		return protocol == ProtocolHTTP
	case splitScopeTLS:
		return protocol == ProtocolTLS
	default:
		return false
	}
}

func parseSplitScope(name string) (splitScope, error) {
	switch name {
	case "":
		return splitScopeNone, nil
	case "any":
		return splitScopeAny, nil
	case "http":
		return splitScopeHTTP, nil
	case "tls":
		return splitScopeTLS, nil
	default:
		return splitScopeNone, E.New("unknown disorder/oob scope ", name)
	}
}

// CompileStream validates and compiles the tpws stream rule list. An empty or
// fully disabled list compiles to a nil config: the integration then performs
// no stream work at all. It performs no I/O outside reading configured list
// files relative to baseDir.
func CompileStream(rules []option.DirectDesyncStreamRule, baseDir string) (*StreamConfig, error) {
	return CompileStreamWithState(rules, baseDir, newListBuildState())
}

// CompileStreamWithState compiles the stream half against a caller-owned list
// build state so it shares one pinned bundle generation and one selection
// budget with the packet half of the same outbound.
func CompileStreamWithState(rules []option.DirectDesyncStreamRule, baseDir string, state *listBuildState) (*StreamConfig, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if state == nil {
		state = newListBuildState()
	}
	compiled, err := compileStreamRules(rules, baseDir, state)
	if err != nil {
		return nil, err
	}
	if len(compiled) == 0 {
		return nil, nil
	}
	return &StreamConfig{
		rules:   compiled,
		native:  newPlatformStreamNative(),
		sources: append([]option.DirectDesyncStreamRule(nil), rules...),
		baseDir: baseDir,
	}, nil
}

// compileStreamRules compiles one rule snapshot without publishing it. It is
// shared by the initial compile and the transactional reload.
func compileStreamRules(rules []option.DirectDesyncStreamRule, baseDir string, state *listBuildState) ([]*streamRule, error) {
	limits := defaultLimits()
	compiled := make([]*streamRule, 0, len(rules))
	for index := range rules {
		rule, err := compileStreamRule(&rules[index], baseDir, limits, state)
		if err != nil {
			name := rules[index].Name
			if name == "" {
				name = "#" + strconv.Itoa(index)
			}
			return nil, E.Cause(err, "desync stream rule ", name)
		}
		if rule != nil {
			compiled = append(compiled, rule)
		}
	}
	return compiled, nil
}

// compileSnapshot rebuilds the rule set from the retained sources. It does not
// publish anything: Engine.ReloadLists publishes the packet, stream and
// learning snapshots together.
func (c *StreamConfig) compileSnapshot() ([]*streamRule, error) {
	return c.compileSnapshotWith(newListBuildState())
}

func (c *StreamConfig) compileSnapshotWith(state *listBuildState) ([]*streamRule, error) {
	if c == nil {
		return nil, nil
	}
	if state == nil {
		state = newListBuildState()
	}
	return compileStreamRules(c.sources, c.baseDir, state)
}

// publishSnapshot installs a fully compiled rule set. The slice header swap is
// the publication point; a reader sees the old or the new set, never a mix.
func (c *StreamConfig) publishSnapshot(rules []*streamRule) {
	if c == nil {
		return
	}
	c.rulesMu.Lock()
	c.rules = rules
	c.rulesMu.Unlock()
}

func compileStreamRule(source *option.DirectDesyncStreamRule, baseDir string, limits LimitSet, state *listBuildState) (*streamRule, error) {
	if source.Disabled {
		return nil, nil
	}
	for _, network := range source.Network {
		if network != "tcp" {
			return nil, E.New("stream rules are TCP-only, got network ", network)
		}
	}
	matchSource := &option.DirectDesyncRule{
		Network:           []string{"tcp"},
		IPVersion:         source.IPVersion,
		Port:              source.Port,
		PortRange:         source.PortRange,
		PortExclude:       source.PortExclude,
		PortRangeExclude:  source.PortRangeExclude,
		Protocol:          source.Protocol,
		Domain:            source.Domain,
		DomainFile:        source.DomainFile,
		DomainExclude:     source.DomainExclude,
		DomainExcludeFile: source.DomainExcludeFile,
		IPCIDR:            source.IPCIDR,
		IPCIDRFile:        source.IPCIDRFile,
		IPCIDRExclude:     source.IPCIDRExclude,
		IPCIDRExcludeFile: source.IPCIDRExcludeFile,
		ListBundle:        source.ListBundle,
	}
	match, err := compileRule(matchSource, baseDir, limits, state)
	if err != nil {
		return nil, err
	}
	rule := &streamRule{name: source.Name, match: match}
	rule.learning, err = compileRuleLearning(source.Learning)
	if err != nil {
		return nil, err
	}
	rule.start, err = parseStreamInterval(source.Start)
	if err != nil {
		return nil, err
	}
	rule.cutoff, err = parseStreamInterval(source.Cutoff)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	order := make([]string, 0, len(source.Methods))
	for _, method := range source.Methods {
		switch method {
		case "http_tamper", "tls_record", "split":
		default:
			return nil, E.New("stream method ", method, " is not implemented")
		}
		if seen[method] {
			return nil, E.New("duplicate stream method ", method)
		}
		seen[method] = true
		order = append(order, method)
	}
	for index, method := range order {
		if method == "split" {
			if index != len(order)-1 {
				return nil, E.New("split must be the last stream method")
			}
			if index != 0 && order[index-1] != "http_tamper" && order[index-1] != "tls_record" {
				return nil, E.New("split must follow a tamper method")
			}
		}
	}
	if seen["http_tamper"] {
		if source.HTTPTamper == nil {
			return nil, E.New("methods contains http_tamper without an http_tamper object")
		}
		rule.httpTamper, err = compileHTTPTamper(source.HTTPTamper)
		if err != nil {
			return nil, err
		}
		if !match.AnyProtocol && !protocolListContains(match.Protocols, ProtocolHTTP) {
			return nil, E.New("http_tamper cannot apply: the rule protocol filter excludes http")
		}
	} else if source.HTTPTamper != nil {
		return nil, E.New("http_tamper object without the http_tamper method")
	}
	if seen["tls_record"] {
		if source.TLSRecord == nil {
			return nil, E.New("methods contains tls_record without a tls_record object")
		}
		rule.tlsRecord, err = compileTLSRecord(source.TLSRecord)
		if err != nil {
			return nil, err
		}
		if !match.AnyProtocol && !protocolListContains(match.Protocols, ProtocolTLS) {
			return nil, E.New("tls_record cannot apply: the rule protocol filter excludes tls")
		}
	} else if source.TLSRecord != nil {
		return nil, E.New("tls_record object without the tls_record method")
	}
	if seen["split"] {
		if source.Split == nil {
			return nil, E.New("methods contains split without a split object")
		}
		rule.split, err = compileStreamSplit(source.Split)
		if err != nil {
			return nil, err
		}
	}
	if source.Split != nil && !seen["split"] {
		return nil, E.New("split object without the split method")
	}
	if rule.httpTamper == nil && rule.tlsRecord == nil && rule.split == nil {
		// A matcher-only rule is a deliberate first-match terminator, like an
		// upstream profile with no tamper flags. It performs no work.
	}
	if source.MSS < 0 {
		return nil, E.New("negative mss")
	}
	if source.MSS > 0 && (source.MSS < 88 || source.MSS > 32767) {
		return nil, E.New("mss must be within 88..32767, the Linux TCP_MAXSEG range")
	}
	if source.MSS > 0 && !streamCaps().mss {
		return nil, E.New("mss is only implemented on Linux (TCP_MAXSEG); this platform rejects it instead of ignoring it")
	}
	rule.mss = source.MSS
	rule.skipNoDelay = source.SkipNoDelay
	if source.FixSeg != nil {
		fixSeg := source.FixSeg
		if fixSeg.Default && fixSeg.Milliseconds != 0 {
			return nil, E.New("fix_seg cannot combine the upstream default flag with an explicit value")
		}
		milliseconds := fixSeg.Milliseconds
		if fixSeg.Default {
			milliseconds = streamDefaultFixSeg
		}
		if milliseconds < 0 || milliseconds > streamMaxFixSeg {
			return nil, E.New("fix_seg must be within 0..", streamMaxFixSeg, " ms")
		}
		if !streamCaps().fixSeg {
			return nil, E.New("fix_seg is only implemented on Linux (TCP_INFO tcpi_notsent_bytes)")
		}
		if rule.split == nil {
			return nil, E.New("fix_seg requires the split method")
		}
		rule.fixSeg = time.Duration(milliseconds) * time.Millisecond
		rule.fixSegSet = true
	}
	if rule.skipNoDelay && rule.split != nil {
		return nil, E.New("skip_nodelay is incompatible with split, as upstream tpws")
	}
	return rule, nil
}

func protocolListContains(protocols []Protocol, protocol Protocol) bool {
	for _, candidate := range protocols {
		if candidate == protocol {
			return true
		}
	}
	return false
}

func compileHTTPTamper(source *option.DirectDesyncStreamHTTPTamper) (*httpTamperSpec, error) {
	spec := &httpTamperSpec{
		hostCase:    source.HostCase,
		hostDot:     source.HostDot,
		hostTab:     source.HostTab,
		hostNoSpace: source.HostNoSpace,
		hostPad:     source.HostPad,
		domCase:     source.DomCase,
		methodSpace: source.MethodSpace,
		methodEOL:   source.MethodEOL,
		unixEOL:     source.UnixEOL,
	}
	copy(spec.hostSpell[:], "host")
	if source.HostSpell != "" {
		if len(source.HostSpell) != 4 {
			return nil, E.New("hostspell must be exactly 4 characters")
		}
		spec.hostCase = true
		copy(spec.hostSpell[:], source.HostSpell)
	}
	if spec.hostDot && spec.hostTab {
		return nil, E.New("hostdot and hosttab are mutually exclusive")
	}
	if spec.hostPad < 0 {
		return nil, E.New("negative hostpad")
	}
	if spec.hostPad > streamBlockCapacity {
		return nil, E.New("hostpad exceeds the tpws segment buffer (", streamBlockCapacity, " bytes)")
	}
	if spec.empty() {
		return nil, E.New("http_tamper object enables no transformation")
	}
	return spec, nil
}

// parseTLSRecordPosition accepts the tpws `tlsrec` grammar: numeric N/-N,
// marker±N, plus the deprecated tpws aliases sni (host+1) and snisld.
func parseTLSRecordPosition(value string, numeric int) (Position, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		if numeric == 0 {
			return Position{}, E.New("tls_record requires pos")
		}
		if numeric < 0 {
			return Position{Kind: positionFromEnd, Offset: -numeric, Raw: strconv.Itoa(numeric)}, nil
		}
		return Position{Kind: positionAbsolute, Offset: numeric, Raw: strconv.Itoa(numeric)}, nil
	}
	if numeric != 0 {
		return Position{}, E.New("tls_record accepts either pos or record_pos, not both")
	}
	switch value {
	case "sni":
		return Position{Kind: positionHost, Offset: 1, Raw: value}, nil
	case "snisld":
		return Position{Kind: positionMidSLD, Offset: 0, Raw: value}, nil
	}
	position, err := ParsePosition(value)
	if err != nil {
		return Position{}, err
	}
	return position, nil
}

func compileTLSRecord(source *option.DirectDesyncStreamTLSRecord) (*tlsRecordSpec, error) {
	position, err := parseTLSRecordPosition(source.Pos, source.RecordPos)
	if err != nil {
		return nil, err
	}
	return &tlsRecordSpec{position: position}, nil
}

func compileStreamSplit(source *option.DirectDesyncStreamSplit) (*streamSplitSpec, error) {
	spec := &streamSplitSpec{oobByte: 0}
	if len(source.SplitPos) == 0 && source.SplitHTTPReq == "" && source.SplitTLS == "" {
		return nil, E.New("split requires split_pos or a deprecated split form")
	}
	for _, value := range source.SplitPos {
		position, err := ParsePosition(value)
		if err != nil {
			return nil, err
		}
		spec.positions = append(spec.positions, position)
	}
	switch source.SplitHTTPReq {
	case "":
	case "method":
		spec.positions = append(spec.positions, Position{Kind: positionMethod, Offset: 2, Raw: source.SplitHTTPReq})
	case "host":
		spec.positions = append(spec.positions, Position{Kind: positionHost, Offset: 1, Raw: source.SplitHTTPReq})
	default:
		return nil, E.New("invalid split_http_req ", source.SplitHTTPReq)
	}
	switch source.SplitTLS {
	case "":
	case "sni":
		spec.positions = append(spec.positions, Position{Kind: positionHost, Offset: 1, Raw: source.SplitTLS})
	case "sniext":
		spec.positions = append(spec.positions, Position{Kind: positionSNIExt, Offset: 1, Raw: source.SplitTLS})
	case "snisld":
		spec.positions = append(spec.positions, Position{Kind: positionMidSLD, Offset: 0, Raw: source.SplitTLS})
	default:
		return nil, E.New("invalid split_tls ", source.SplitTLS)
	}
	if len(spec.positions) == 0 {
		return nil, E.New("split requires split positions")
	}
	if len(spec.positions) > streamMaxSplitPositions {
		return nil, E.New("split positions exceed ", streamMaxSplitPositions, ", the upstream tpws MAX_SPLITS limit")
	}
	var err error
	spec.disorder, err = parseSplitScope(source.Disorder)
	if err != nil {
		return nil, err
	}
	spec.oob, err = parseSplitScope(source.OOB)
	if err != nil {
		return nil, err
	}
	if source.OOBData != nil {
		if spec.oob == splitScopeNone {
			return nil, E.New("oob_data requires oob")
		}
		spec.oobByte = source.OOBData.Value
	}
	spec.anyProtocol = source.SplitAnyProtocol
	if !streamCaps().oob && spec.oob != splitScopeNone {
		return nil, E.New("oob is not implemented on this platform")
	}
	if !streamCaps().disorder && spec.disorder != splitScopeNone {
		return nil, E.New("disorder is not implemented on this platform")
	}
	if !streamCaps().oobDisorder && oobDisorderConflict(spec.oob, spec.disorder) {
		return nil, E.New("oob and disorder work simultaneously only on Linux, as upstream tpws")
	}
	return spec, nil
}

// oobDisorderConflict mirrors tpws check_oob_disorder.
func oobDisorderConflict(oob splitScope, disorder splitScope) bool {
	oobAny := oob == splitScopeAny
	oobHTTP := oob == splitScopeHTTP
	oobTLS := oob == splitScopeTLS
	disorderAny := disorder == splitScopeAny
	disorderHTTP := disorder == splitScopeHTTP
	disorderTLS := disorder == splitScopeTLS
	return oobAny && (disorderAny || disorderHTTP || disorderTLS) ||
		oobHTTP && (disorderAny || disorderHTTP) ||
		oobTLS && (disorderAny || disorderTLS)
}

// parseStreamInterval parses tpws tamper-start/tamper-cutoff: `[n]<digits>`.
func parseStreamInterval(value string) (streamInterval, error) {
	if value == "" {
		return streamInterval{}, nil
	}
	interval := streamInterval{}
	number := value
	if value[0] == 'n' {
		interval.block = true
		number = value[1:]
	}
	if number == "" {
		return streamInterval{}, E.New("invalid stream interval ", value)
	}
	for _, character := range number {
		if character < '0' || character > '9' {
			return streamInterval{}, E.New("invalid stream interval ", value)
		}
	}
	parsed, err := strconv.ParseUint(number, 10, 64)
	if err != nil {
		return streamInterval{}, E.Cause(err, "invalid stream interval ", value)
	}
	interval.value = parsed
	return interval, nil
}

// selectRule applies ordered first-match selection. A disabled rule was
// already dropped at compile time. Stream rules are matched with the same
// predicate as packet rules; no action fields participate.
func (c *StreamConfig) selectRule(facts MatchFacts) *streamRule {
	if c == nil {
		return nil
	}
	facts.Transport = TransportTCP
	for _, rule := range c.snapshotRules() {
		if rule.match.Matches(facts) {
			return rule
		}
	}
	return nil
}

// selectRuleAnnotated applies the engine-owned cached/preconnect host facts
// before the ordered first-match selection.
func (c *StreamConfig) selectRuleAnnotated(facts MatchFacts) *streamRule {
	return c.selectRule(c.annotateFacts(facts))
}

// PrepareSocket applies configured preconnect native stream controls after the
// existing native controls of the dialer. fd remains owned by the dialer, and
// only preconnect-known facts are used: a rule filtered by domain cannot be
// selected from future SNI here.
func (c *StreamConfig) PrepareSocket(ctx context.Context, fd uintptr, facts MatchFacts) error {
	if c == nil || len(c.snapshotRules()) == 0 || fd == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rule := c.selectRuleAnnotated(facts)
	if rule == nil {
		return nil
	}
	config := streamSocketConfig{
		mss:         rule.mss,
		skipNoDelay: rule.skipNoDelay,
	}
	if config.mss == 0 && !config.skipNoDelay {
		return nil
	}
	return c.native.Prepare(fd, config)
}

// hasNativeSend reports whether a rule needs per-segment native sends rather
// than plain TCP writes.
func (r *streamRule) hasNativeSend() bool {
	if r == nil || r.split == nil {
		return false
	}
	return r.split.disorder != splitScopeNone || r.split.oob != splitScopeNone || r.fixSegSet
}

func (r *streamRule) effectiveDisorder(protocol Protocol) bool {
	return r != nil && r.split != nil && r.split.disorder.matches(protocol)
}

func (r *streamRule) effectiveOOB(protocol Protocol) bool {
	return r != nil && r.split != nil && r.split.oob.matches(protocol)
}

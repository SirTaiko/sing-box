package desync

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// compileStages compiles and validates the ordered stage list and the typed
// objects owned by each stage.
func compileStages(rule *Rule, source *option.DirectDesyncRule, baseDir string, limits LimitSet) error {
	methods, err := CompileMethods(source.Methods, rule.Network)
	if err != nil {
		return err
	}
	rule.Methods = methods
	zero, first, second := stageMethods(methods)
	_ = zero

	mods, err := compileModifiers(source)
	if err != nil {
		return err
	}
	rule.Mods = mods

	if first != nil {
		switch first.Kind {
		case MethodFake, MethodFakeKnown:
			object := source.Fake
			if first.Kind == MethodFakeKnown && source.FakeKnown != nil {
				object = source.FakeKnown
			}
			if object == nil {
				return E.New("method ", first.Name, " requires a fake payload object")
			}
			compiled, fakeErr := compileFake(object, baseDir)
			if fakeErr != nil {
				return fakeErr
			}
			compiled.Fooling = mergeFooling(compiled.Fooling, mods.Fooling)
			// Pinned startup runs dp_fake_defaults (nfqws.c:3509): fill
			// missing UDP protocol collections, never append a default to
			// an explicitly configured collection. Selection stays typed;
			// Unknown's configured payload is not a recognized fallback.
			if rule.Network&TransportMaskUDP != 0 {
				addDefaultQUICPayload(compiled)
				addDefaultRecognizedUDPPayloads(compiled)
			}
			rule.Fake = compiled
			if first.Kind == MethodFakeKnown {
				rule.FakeKnown = compiled
			}
		case MethodRST, MethodRSTACK, MethodHopByHop, MethodDestOpt, MethodIPFrag1:
			// These stages are fully parameterised by the rule modifiers.
		}
		if source.Fake != nil && first.Kind != MethodFake && first.Kind != MethodFakeKnown {
			return E.New("fake object without the fake/fakeknown method")
		}
		if source.FakeKnown != nil && first.Kind != MethodFakeKnown {
			return E.New("fakeknown object without the fakeknown method")
		}
	} else if source.Fake != nil || source.FakeKnown != nil {
		return E.New("fake payload object without a first-stage fake method")
	}

	if second != nil {
		switch second.Kind {
		case MethodMultiSplit:
			if source.MultiSplit == nil {
				return E.New("multisplit requires a multisplit object")
			}
			rule.MultiSplit, err = compileSplit(source.MultiSplit, baseDir, limits)
			if err != nil {
				return err
			}
		case MethodMultiDisorder:
			if source.MultiDisorder == nil {
				return E.New("multidisorder requires a multidisorder object")
			}
			rule.MultiDisorder, err = compileSplit(source.MultiDisorder, baseDir, limits)
			if err != nil {
				return err
			}
		case MethodFakeDSplit, MethodFakeDDisorder:
			object := source.FakeDSplit
			if second.Kind == MethodFakeDDisorder {
				object = source.FakeDDisorder
			}
			if object == nil {
				return E.New("method ", second.Name, " requires its split object")
			}
			split, splitErr := compileSplit(object, baseDir, limits)
			if splitErr != nil {
				return splitErr
			}
			fakeSplit := &FakeSplitSpec{Split: *split}
			fakeSplit.Pattern, err = loadPattern(object.FakePattern, baseDir)
			if err != nil {
				return err
			}
			if len(fakeSplit.Pattern) == 0 && split.Overlap > 0 && len(split.OverlapPattern) == 0 {
				return E.New("fakedsplit requires fake_pattern or seqovl_pattern")
			}
			fakeSplit.Ordering, err = parseOrdering(object.FakeMod)
			if err != nil {
				return err
			}
			if second.Kind == MethodFakeDSplit {
				rule.FakeSplit = fakeSplit
			} else {
				rule.FakeDisorder = fakeSplit
			}
		case MethodHostFakeSplit:
			if source.HostFakeSplit == nil {
				return E.New("hostfakesplit requires a hostfakesplit object")
			}
			rule.HostFakeSplit, err = compileHostFakeSplit(source.HostFakeSplit, baseDir)
			if err != nil {
				return err
			}
		case MethodIPFrag2:
			rule.IPFragPosTCP = defaultIPFragTCP
			rule.IPFragPosUDP = defaultIPFragUDP
			if source.IPFragPosTCP != 0 {
				rule.IPFragPosTCP = source.IPFragPosTCP
			}
			if source.IPFragPosUDP != 0 {
				rule.IPFragPosUDP = source.IPFragPosUDP
			}
			if rule.IPFragPosTCP%8 != 0 || rule.IPFragPosTCP < 8 || rule.IPFragPosTCP > 65535 {
				return E.New("ipfrag_pos_tcp must be a multiple of 8 within 8..65535")
			}
			if rule.IPFragPosUDP%8 != 0 || rule.IPFragPosUDP < 8 || rule.IPFragPosUDP > 65535 {
				return E.New("ipfrag_pos_udp must be a multiple of 8 within 8..65535")
			}
		case MethodUDPLen:
			if source.UDPLen == nil {
				return E.New("udplen requires a udplen object")
			}
			if source.UDPLen.Increment < -65535 || source.UDPLen.Increment > 65535 {
				return E.New("udplen increment out of range")
			}
			rule.UDPLen = &UDPLenSpec{Increment: source.UDPLen.Increment}
			rule.UDPLen.Pattern, err = loadPattern(source.UDPLen.Pattern, baseDir)
			if err != nil {
				return err
			}
		case MethodTamper:
			// Tamper is fully parameterised by the captured payload.
		}
	}
	if err = validateSecondStageObjects(source, second); err != nil {
		return err
	}
	if source.Orig != nil {
		rule.Orig, err = compileOrig(source.Orig)
		if err != nil {
			return err
		}
	}
	if source.Dup != nil {
		rule.Dup, err = compileDup(source.Dup)
		if err != nil {
			return err
		}
	}
	if source.WSize != nil {
		rule.WSize, err = compileWSize(source.WSize)
		if err != nil {
			return err
		}
	}
	if source.WSSize != nil {
		rule.WSSize, err = compileWSSize(source.WSSize)
		if err != nil {
			return err
		}
	}
	switch source.SynackSplit {
	case "":
	case "syn":
		rule.SynackSplit = SynAckSplitSYN
	case "synack":
		rule.SynackSplit = SynAckSplitSYNFirst
	case "acksyn":
		rule.SynackSplit = SynAckSplitACKFirst
	default:
		return E.New("unknown synack_split ", source.SynackSplit)
	}
	if source.Orig != nil {
		rule.TCPEmptyACKRequired = true
	}
	if source.Dup != nil && source.Dup.Count > 0 {
		rule.TCPEmptyACKRequired = true
	}
	return nil
}

func validateSecondStageObjects(source *option.DirectDesyncRule, second *Method) error {
	objects := map[string]bool{
		"multisplit":    source.MultiSplit != nil,
		"multidisorder": source.MultiDisorder != nil,
		"fakedsplit":    source.FakeDSplit != nil,
		"fakeddisorder": source.FakeDDisorder != nil,
		"hostfakesplit": source.HostFakeSplit != nil,
		"udplen":        source.UDPLen != nil,
	}
	for name, present := range objects {
		if !present {
			continue
		}
		if second == nil || second.Name != name {
			return E.New(name, " object without the ", name, " method")
		}
	}
	return nil
}

// pinnedQUICDefaultPayload is the source-derived dp_fake_defaults QUIC payload:
// exactly 620 bytes, 0x40 followed by 619 zero bytes (zapret v72.9
// params.c:265-271, reached from nfqws.c:3509). It is a source constant, not a
// native observation; SHA256
// 6e996949e69b2e99dba41b83660f43268527b8b4434f1ab33d61b4cfa1c89d1b.
var pinnedQUICDefaultPayload = func() []byte {
	payload := make([]byte, 620)
	payload[0] = 0x40
	return payload
}()

// addDefaultQUICPayload appends the pinned default QUIC payload to a compiled
// fake stage that is reachable for UDP and has no QUIC payload of its own. An
// explicit QUIC payload replaces the default; the default is protocol-specific
// and independent of the explicit desync_any_proto bit.
func addDefaultQUICPayload(fake *FakeSpec) {
	if fake == nil {
		return
	}
	for _, payload := range fake.Payloads {
		if payload.Protocol == ProtocolQUIC {
			return
		}
	}
	fake.Payloads = append(fake.Payloads, Payload{
		Protocol: ProtocolQUIC,
		Data:     pinnedQUICDefaultPayload,
		Source:   "pinned:dp_fake_defaults",
	})
}

// Pinned v72.9 params.c:272-280 fills each absent recognized UDP collection
// with one 64-zero-byte payload. desync.c:3198-3218 selects that collection,
// not fake_unknown_udp. Preserve explicit items (including duplicates) and
// their order; repeats/admission/cutoffs remain the existing stage's concern.
func addDefaultRecognizedUDPPayloads(fake *FakeSpec) {
	if fake == nil {
		return
	}
	for _, protocol := range [...]Protocol{ProtocolWireGuard, ProtocolDHT, ProtocolDiscord, ProtocolSTUN} {
		configured := false
		for _, payload := range fake.Payloads {
			if payload.Protocol == protocol {
				configured = true
				break
			}
		}
		if !configured {
			fake.Payloads = append(fake.Payloads, Payload{
				Protocol: protocol,
				Data:     make([]byte, 64),
				Source:   "pinned:dp_fake_defaults",
			})
		}
	}
}

func mergeFooling(a, b Fooling) Fooling {
	return Fooling{
		Timestamp:    a.Timestamp || b.Timestamp,
		BadSequence:  a.BadSequence || b.BadSequence,
		BadChecksum:  a.BadChecksum || b.BadChecksum,
		MD5Signature: a.MD5Signature || b.MD5Signature,
		DataNoACK:    a.DataNoACK || b.DataNoACK,
		HopByHop:     a.HopByHop || b.HopByHop,
		HopByHop2:    a.HopByHop2 || b.HopByHop2,
	}
}

func compileModifiers(source *option.DirectDesyncRule) (*ModifierSet, error) {
	mods := &ModifierSet{
		TTL:             source.TTL,
		TTL6:            source.TTL6,
		TSIncrement:     -600000,
		BadSeqIncrement: -10000,
		BadAckIncrement: -66000,
	}
	if source.TTL < 0 || source.TTL > 255 || source.TTL6 < 0 || source.TTL6 > 255 {
		return nil, E.New("ttl out of range 0..255")
	}
	var err error
	mods.AutoTTL, err = parseAutoTTL(source.AutoTTL)
	if err != nil {
		return nil, err
	}
	mods.AutoTTL6, err = parseAutoTTL(source.AutoTTL6)
	if err != nil {
		return nil, err
	}
	mods.FlagsSet, err = parseTCPFlags(source.TCPFlagsSet)
	if err != nil {
		return nil, err
	}
	mods.FlagsUnset, err = parseTCPFlags(source.TCPFlagsUnset)
	if err != nil {
		return nil, err
	}
	if source.TSIncrement != nil {
		mods.TSIncrement = *source.TSIncrement
	}
	if source.BadSeqIncrement != nil {
		mods.BadSeqIncrement = *source.BadSeqIncrement
	}
	if source.BadAckIncrement != nil {
		mods.BadAckIncrement = *source.BadAckIncrement
	}
	for _, fooling := range source.Fooling {
		switch fooling {
		case "none":
		case "ts":
			mods.Fooling.Timestamp = true
		case "badseq":
			mods.Fooling.BadSequence = true
		case "badsum":
			mods.Fooling.BadChecksum = true
		case "md5sig":
			mods.Fooling.MD5Signature = true
		case "datanoack":
			mods.Fooling.DataNoACK = true
		case "hopbyhop":
			mods.Fooling.HopByHop = true
		case "hopbyhop2":
			mods.Fooling.HopByHop2 = true
		default:
			return nil, E.New("unknown fooling mode ", fooling)
		}
	}
	mods.Repeats = source.Repeats
	if mods.Repeats == 0 {
		mods.Repeats = 1
	}
	if mods.Repeats < 0 || mods.Repeats > 64 {
		return nil, E.New("repeats out of range 1..64")
	}
	return mods, nil
}

func compileOrig(source *option.DirectDesyncOrigOptions) (*OrigSpec, error) {
	if source.TTL < 0 || source.TTL > 255 || source.TTL6 < 0 || source.TTL6 > 255 {
		return nil, E.New("orig ttl out of range")
	}
	spec := &OrigSpec{TTL: source.TTL, TTL6: source.TTL6}
	var err error
	spec.AutoTTL, err = parseAutoTTL(source.AutoTTL)
	if err != nil {
		return nil, err
	}
	spec.AutoTTL6, err = parseAutoTTL(source.AutoTTL6)
	if err != nil {
		return nil, err
	}
	spec.FlagsSet, err = parseTCPFlags(source.TCPFlagsSet)
	if err != nil {
		return nil, err
	}
	spec.FlagsUnset, err = parseTCPFlags(source.TCPFlagsUnset)
	if err != nil {
		return nil, err
	}
	if spec.ModStart, err = parseInterval(source.ModStart); err != nil {
		return nil, err
	}
	if spec.ModCutoff, err = parseInterval(source.ModCutoff); err != nil {
		return nil, err
	}
	return spec, nil
}

func compileDup(source *option.DirectDesyncDupOptions) (*DupSpec, error) {
	spec := &DupSpec{
		Count: source.Count, TTL: source.TTL, TTL6: source.TTL6,
		Replace: source.Replace, TSIncrement: -600000,
		BadSeqIncrement: -10000, BadAckIncrement: -66000,
	}
	if spec.Count <= 0 {
		return nil, E.New("dup count must be positive")
	}
	if spec.Count > 1024 {
		return nil, E.New("dup count exceeds 1024")
	}
	if source.TTL < 0 || source.TTL > 255 || source.TTL6 < 0 || source.TTL6 > 255 {
		return nil, E.New("dup ttl out of range")
	}
	var err error
	spec.AutoTTL, err = parseAutoTTL(source.AutoTTL)
	if err != nil {
		return nil, err
	}
	spec.AutoTTL6, err = parseAutoTTL(source.AutoTTL6)
	if err != nil {
		return nil, err
	}
	spec.FlagsSet, err = parseTCPFlags(source.TCPFlagsSet)
	if err != nil {
		return nil, err
	}
	spec.FlagsUnset, err = parseTCPFlags(source.TCPFlagsUnset)
	if err != nil {
		return nil, err
	}
	for _, fooling := range source.Fooling {
		switch fooling {
		case "none":
		case "ts":
			spec.Fooling.Timestamp = true
		case "badseq":
			spec.Fooling.BadSequence = true
		case "badsum":
			spec.Fooling.BadChecksum = true
		case "md5sig":
			spec.Fooling.MD5Signature = true
		case "datanoack":
			spec.Fooling.DataNoACK = true
		case "hopbyhop":
			spec.Fooling.HopByHop = true
		case "hopbyhop2":
			spec.Fooling.HopByHop2 = true
		default:
			return nil, E.New("unknown dup fooling mode ", fooling)
		}
	}
	if source.TSIncrement != nil {
		spec.TSIncrement = *source.TSIncrement
	}
	if source.BadSeqIncrement != nil {
		spec.BadSeqIncrement = *source.BadSeqIncrement
	}
	if source.BadAckIncrement != nil {
		spec.BadAckIncrement = *source.BadAckIncrement
	}
	switch source.IPID {
	case "":
		// Upstream dp_init() sets dup_ip_id_mode to IPID_SAME.
		spec.IPID, spec.IPIDSet = IPIDSame, false
	case "zero":
		spec.IPID, spec.IPIDSet = IPIDZero, true
	case "seq":
		spec.IPID, spec.IPIDSet = IPIDSeq, true
	case "rnd":
		spec.IPID, spec.IPIDSet = IPIDRandom, true
	case "same":
		spec.IPID, spec.IPIDSet = IPIDSame, true
	default:
		return nil, E.New("unknown dup ip_id ", source.IPID)
	}
	if spec.Start, err = parseInterval(source.Start); err != nil {
		return nil, err
	}
	if spec.Cutoff, err = parseInterval(source.Cutoff); err != nil {
		return nil, err
	}
	return spec, nil
}

func compileWSize(source *option.DirectDesyncWSizeOptions) (*WSizeSpec, error) {
	spec := &WSizeSpec{Size: source.Size}
	if spec.Size <= 0 || spec.Size > 65535 {
		return nil, E.New("wsize size must be within 1..65535")
	}
	if source.Scale != nil {
		if *source.Scale < 0 || *source.Scale > 14 {
			return nil, E.New("wsize scale out of range 0..14")
		}
		spec.Scale, spec.ScaleSet = *source.Scale, true
	}
	return spec, nil
}

func compileWSSize(source *option.DirectDesyncWSSizeOptions) (*WSSizeSpec, error) {
	spec := &WSSizeSpec{Size: source.Size, ForcedCutoff: true}
	if spec.Size <= 0 || spec.Size > 65535 {
		return nil, E.New("wssize size must be within 1..65535")
	}
	if source.Scale != nil {
		if *source.Scale < 0 || *source.Scale > 14 {
			return nil, E.New("wssize scale out of range 0..14")
		}
		spec.Scale, spec.ScaleSet = *source.Scale, true
	}
	var err error
	if spec.Cutoff, err = parseInterval(source.Cutoff); err != nil {
		return nil, err
	}
	if source.ForcedCutoff != nil {
		spec.ForcedCutoff = *source.ForcedCutoff
	}
	return spec, nil
}

// compileHostFakeSplit compiles the upstream hostfakesplit object. The two
// mandatory real splits are always the Host/SNI value boundaries resolved from
// the request; midhost adds the optional third split. Upstream has no
// hostfakesplit split-position list, so accepting one would be a silent no-op.
func compileHostFakeSplit(source *option.DirectDesyncHostFakeSplitOptions, _ string) (*HostFakeSplitSpec, error) {
	if source == nil {
		return nil, E.New("hostfakesplit requires a hostfakesplit object")
	}
	spec := &HostFakeSplitSpec{}
	if source.MidHost != "" {
		position, err := ParsePosition(source.MidHost)
		if err != nil {
			return nil, err
		}
		spec.MidHost = &position
	}
	var err error
	spec.Ordering, spec.Host, err = parseHostFakeMod(source.Mod)
	if err != nil {
		return nil, err
	}
	spec.HostSize = len(spec.Host)
	return spec, nil
}

func parseHostFakeMod(value string) (byte, string, error) {
	var ordering byte
	var host string
	value = strings.TrimSpace(value)
	if value == "" || value == "none" {
		return 0, "", nil
	}
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		switch {
		case entry == "" || entry == "none":
		case strings.HasPrefix(entry, "host="):
			host = strings.TrimPrefix(entry, "host=")
			if host == "" {
				return 0, "", E.New("empty hostfakesplit host")
			}
			if len(host) > 126 {
				// Upstream hfs_mod.host is a 128-byte buffer whose last
				// byte is always forced to NUL.
				return 0, "", E.New("hostfakesplit host is too long")
			}
		case strings.HasPrefix(entry, "altorder="):
			// Upstream hostfakesplit accepts only 0 or 1 here (unlike the
			// 3-bit fakedsplit ordering).
			parsed, err := strconv.ParseUint(strings.TrimPrefix(entry, "altorder="), 10, 8)
			if err != nil || parsed > 1 {
				return 0, "", E.New("hostfakesplit altorder must be 0 or 1")
			}
			ordering = byte(parsed)
		default:
			return 0, "", E.New("unknown hostfakesplit mod ", entry)
		}
	}
	return ordering, host, nil
}

// parseOrdering parses the upstream altorder selector. `altorder=N` packs the
// two 3-bit ordering nibbles (N and N+8 or N+16 style values are accepted
// directly as a decimal byte, matching the upstream parser).
func parseOrdering(value string) (byte, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "none" {
		return 0, nil
	}
	if strings.HasPrefix(value, "altorder=") {
		value = strings.TrimPrefix(value, "altorder=")
	}
	parsed, err := strconv.ParseUint(value, 0, 8)
	if err != nil {
		return 0, E.New("invalid altorder ", value)
	}
	return byte(parsed), nil
}

func loadPattern(value string, baseDir string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	if strings.HasPrefix(value, "0x") {
		data, err := hex.DecodeString(value[2:])
		if err != nil {
			return nil, E.Cause(err, "decode pattern")
		}
		return data, nil
	}
	if len(value) > 2 && value[0] == '"' && value[len(value)-1] == '"' {
		return []byte(value[1 : len(value)-1]), nil
	}
	path := filepath.Join(baseDir, value)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, E.Cause(err, "read pattern")
	}
	return data, nil
}

const (
	defaultIPFragTCP = 32
	defaultIPFragUDP = 8
)

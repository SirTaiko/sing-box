package desync

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RandSource is the injected randomness seam of the packet model. Hermetic
// tests supply a deterministic sequence; production uses the process RNG.
type RandSource interface {
	Uint32() uint32
	Intn(n int) int
}

type processRandom struct {
	mu  sync.Mutex
	src *rand.Rand
}

func (r *processRandom) Uint32() uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.src.Uint32()
}

func (r *processRandom) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.src.Intn(n)
}

// DefaultRand is the process-wide packet randomness source.
var DefaultRand RandSource = &processRandom{src: rand.New(rand.NewSource(time.Now().UnixNano()))}

// AutoTTL is the compiled upstream autottl selector
// `<delta>[:<min>[-<max>]]`. A nil/zero value is disabled.
type AutoTTL struct {
	Set   bool
	Delta int
	Min   int
	Max   int
}

func parseAutoTTL(value string) (AutoTTL, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "-" {
		return AutoTTL{}, nil
	}
	result := AutoTTL{Set: true}
	rangePart := ""
	if deltaPart, rest, found := strings.Cut(value, ":"); found {
		delta, err := strconv.Atoi(deltaPart)
		if err != nil {
			return AutoTTL{}, fmt.Errorf("invalid autottl delta %q", value)
		}
		result.Delta = delta
		rangePart = rest
	} else {
		delta, err := strconv.Atoi(value)
		if err != nil {
			return AutoTTL{}, fmt.Errorf("invalid autottl %q", value)
		}
		result.Delta = delta
	}
	if rangePart != "" {
		minPart, maxPart, hasMax := strings.Cut(rangePart, "-")
		minValue, err := strconv.Atoi(minPart)
		if err != nil || minValue < 0 || minValue > 255 {
			return AutoTTL{}, fmt.Errorf("invalid autottl minimum %q", value)
		}
		result.Min = minValue
		if hasMax {
			maxValue, err := strconv.Atoi(maxPart)
			if err != nil || maxValue < 0 || maxValue > 255 || maxValue < minValue {
				return AutoTTL{}, fmt.Errorf("invalid autottl maximum %q", value)
			}
			result.Max = maxValue
		}
	}
	if result.Min == 0 {
		result.Min = 3
	}
	if result.Max == 0 {
		result.Max = 20
	}
	if result.Max < result.Min {
		return AutoTTL{}, fmt.Errorf("autottl maximum is smaller than minimum")
	}
	return result, nil
}

// HopCountGuess is the exact upstream `hop_count_guess`.
func HopCountGuess(ttl uint8) uint8 {
	var original uint8
	switch {
	case ttl > 223:
		original = 255
	case ttl < 128 && ttl > 96:
		original = 128
	case ttl < 64 && ttl > 32:
		original = 64
	default:
		return 0
	}
	return original - ttl
}

// Eval is the exact upstream `autottl_eval`. ok=false means the guess was
// unsuccessful and autottl fooling must not be applied.
func (a AutoTTL) Eval(hopCount uint8) (uint8, bool) {
	if !a.Set {
		return 0, false
	}
	value := int(hopCount) + a.Delta
	switch {
	case value < a.Min:
		value = a.Min
	case value > a.Max:
		value = a.Max
	}
	if a.Delta < 0 && value >= int(hopCount) {
		return 0, false
	}
	if a.Delta >= 0 && value < int(hopCount) {
		return 0, false
	}
	return uint8(value), true
}

// TCP flag names accepted by the upstream flag-list parser.
var tcpFlagNames = map[string]uint16{
	"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08, "ACK": 0x10,
	"URG": 0x20, "ECE": 0x40, "CWR": 0x80, "AE": 0x100, "R1": 0x200,
	"R2": 0x400, "R3": 0x800,
}

func parseTCPFlags(value string) (uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	if number, err := strconv.ParseUint(value, 0, 16); err == nil {
		return uint16(number), nil
	}
	var flags uint16
	for _, name := range strings.Split(value, ",") {
		flag, found := tcpFlagNames[strings.ToUpper(strings.TrimSpace(name))]
		if !found {
			return 0, fmt.Errorf("unknown tcp flag %q", name)
		}
		flags |= flag
	}
	return flags, nil
}

// ModifierSet is the compiled rule-owned packet modifier set.
type ModifierSet struct {
	TTL             int
	TTL6            int
	AutoTTL         AutoTTL
	AutoTTL6        AutoTTL
	FlagsSet        uint16
	FlagsUnset      uint16
	Fooling         Fooling
	Repeats         int
	TSIncrement     int32
	BadSeqIncrement int32
	BadAckIncrement int32
}

// AutoTTLFor selects the IPv6 or IPv4 autottl selector. Upstream copies the
// IPv4 selector into the IPv6 slot when --*-autottl6 is not enabled.
func (m *ModifierSet) AutoTTLFor(family Family) AutoTTL {
	if m == nil {
		return AutoTTL{}
	}
	if family == FamilyIPv6 && m.AutoTTL6.Set {
		return m.AutoTTL6
	}
	return m.AutoTTL
}

// defaultModifiers mirrors the upstream defaults for rules constructed without
// a compiled modifier set (tests and programmatic callers).
func defaultModifiers() *ModifierSet {
	return &ModifierSet{Repeats: 1, TSIncrement: -600000, BadSeqIncrement: -10000, BadAckIncrement: -66000}
}

func (m *ModifierSet) orDefault() *ModifierSet {
	if m == nil {
		return defaultModifiers()
	}
	return m
}

// TTLFor resolves the fake TTL: explicit IPv6/IPv4 TTL, otherwise the autottl
// guess from the bounded reply hop observation, otherwise the original TTL.
func (m *ModifierSet) TTLFor(family Family, original uint8, hopCount uint8, haveHop bool) uint8 {
	if m == nil {
		return original
	}
	explicit := m.TTL
	if family == FamilyIPv6 && m.TTL6 != 0 {
		explicit = m.TTL6
	}
	if auto := m.AutoTTLFor(family); auto.Set && haveHop {
		if value, ok := auto.Eval(hopCount); ok {
			return value
		}
	}
	if explicit > 0 && explicit <= 255 {
		return uint8(explicit)
	}
	return original
}

// RewriteFlags applies the upstream set/unset mask.
func (m *ModifierSet) RewriteFlags(flags uint8) uint8 {
	if m == nil || m.FlagsSet == 0 && m.FlagsUnset == 0 {
		return flags
	}
	return uint8((uint16(flags)&^m.FlagsUnset | m.FlagsSet) & 0xff)
}

// OrigSpec is the compiled upstream --orig-* configuration.
type OrigSpec struct {
	TTL        int
	TTL6       int
	AutoTTL    AutoTTL
	AutoTTL6   AutoTTL
	FlagsSet   uint16
	FlagsUnset uint16
	// ModStart/ModCutoff are the upstream --orig-mod-start/--orig-mod-cutoff
	// limiters. There is no separate orig start/cutoff in upstream.
	ModStart  Interval
	ModCutoff Interval
}

// DupSpec is the compiled upstream --dup-* configuration.
type DupSpec struct {
	Count           int
	TTL             int
	TTL6            int
	AutoTTL         AutoTTL
	AutoTTL6        AutoTTL
	FlagsSet        uint16
	FlagsUnset      uint16
	Fooling         Fooling
	TSIncrement     int32
	BadSeqIncrement int32
	BadAckIncrement int32
	Replace         bool
	IPID            IPIDMode
	IPIDSet         bool
	Start           Interval
	Cutoff          Interval
}

// WSizeSpec is the compiled upstream `--wsize` selector. It applies to an
// observed SYN-ACK only and has no cutoff of its own.
type WSizeSpec struct {
	Size     int
	Scale    int
	ScaleSet bool
}

// WSSizeSpec is the compiled upstream `--wssize` family. It rewrites the
// advertised window of original-direction packets and owns the server-window
// cutoff latch (`--wssize-cutoff`) plus the protocol-triggered forced cutoff
// (`--wssize-forced-cutoff`).
type WSSizeSpec struct {
	Size         int
	Scale        int
	ScaleSet     bool
	Cutoff       Interval
	ForcedCutoff bool
}

// IPAllocator produces the upstream IPv4 ID sequence of generated packets.
// The allocator is per-planning-call; it never mutates the original counters.
type IPAllocator struct {
	mode    IPIDMode
	random  RandSource
	current uint16
	have    bool
}

func newIPAllocator(rule *Rule, packet *Packet, random RandSource) *IPAllocator {
	mode := IPIDSeq
	if rule != nil {
		mode = rule.IPID
	}
	allocator := &IPAllocator{mode: mode, random: random}
	if allocator.random == nil {
		allocator.random = DefaultRand
	}
	// IP4_IP_ID_FIX: seq/seqgroup use the original non-zero ID, rnd is a fresh
	// non-zero random value, same copies the original and zero/increment use 0.
	switch mode {
	case IPIDSeq, IPIDSeqGroup:
		if packet != nil && packet.IPID != 0 {
			allocator.current, allocator.have = packet.IPID, true
		} else {
			allocator.current = uint16(allocator.random.Uint32())
			allocator.current = nonZeroID(allocator.current)
			allocator.have = true
		}
	case IPIDRandom:
		allocator.current = nonZeroID(uint16(allocator.random.Uint32() % 0xffff))
		allocator.have = true
	case IPIDSame:
		if packet != nil {
			allocator.current, allocator.have = packet.IPID, true
		}
	}
	return allocator
}

func nonZeroID(id uint16) uint16 {
	if id == 0 {
		return 1
	}
	return id
}

// Value returns the ID for one generated packet and advances the sequence.
func (a *IPAllocator) Value() (uint16, bool) {
	if a == nil {
		return 0, false
	}
	value := a.current
	switch a.mode {
	case IPIDZero, IPIDIncrement:
		return 0, true
	case IPIDRandom:
		value = nonZeroID(uint16(a.random.Uint32() % 0xffff))
	case IPIDSeq, IPIDSeqGroup:
		if a.have {
			a.current++
			if a.current == 0 {
				a.current = 1
			}
		}
	case IPIDSame:
		return a.current, true
	}
	return value, true
}

// fillPattern repeats pattern over dst starting at phase offset.
func fillPattern(dst []byte, pattern []byte, phase int) {
	if len(pattern) == 0 {
		for index := range dst {
			dst[index] = 0
		}
		return
	}
	for index := range dst {
		dst[index] = pattern[(phase+index)%len(pattern)]
	}
}

// tlsHelloLayout records the length fields of a TLS ClientHello that the
// upstream fake TLS modifiers rewrite.
type tlsHelloLayout struct {
	recordLen      int
	handshakeLen   int
	sessionIDLen   int
	sessionID      int
	sniLen         int
	sni            int
	sniListLen     int
	sniExtLen      int
	extensionsLen  int
	extensionCount int
	paddingLen     int
}

// parseTLSHelloLayout parses the first TLS handshake record and locates the
// length fields needed by the upstream modifiers. ok=false means the payload is
// not a ClientHello with the required structure.
func parseTLSHelloLayout(data []byte) (tlsHelloLayout, bool) {
	var layout tlsHelloLayout
	if len(data) < 44 || data[0] != 0x16 || data[1] != 0x03 {
		return layout, false
	}
	layout.recordLen = 3
	layout.handshakeLen = 6
	if data[5] != 0x01 {
		return layout, false
	}
	layout.sessionIDLen = 43
	layout.sessionID = 44
	handshakeEnd := 5 + 4 + readUint24(data[6:9])
	if handshakeEnd > len(data) {
		return layout, false
	}
	cursor := 44 + int(data[43])
	if cursor+2 > handshakeEnd {
		return layout, false
	}
	cursor += 2 + int(readUint16(data[cursor:]))
	if cursor+1 > handshakeEnd {
		return layout, false
	}
	cursor += 1 + int(data[cursor])
	if cursor+2 > handshakeEnd {
		return layout, false
	}
	layout.extensionsLen = cursor
	extensionsEnd := cursor + 2 + int(readUint16(data[cursor:]))
	if extensionsEnd > handshakeEnd {
		return layout, false
	}
	cursor += 2
	for cursor+4 <= extensionsEnd {
		extensionType := readUint16(data[cursor:])
		extensionLength := int(readUint16(data[cursor+2:]))
		if cursor+4+extensionLength > extensionsEnd {
			return layout, false
		}
		switch extensionType {
		case 0: // server_name
			if extensionLength >= 5 {
				nameLen := int(readUint16(data[cursor+4+3:]))
				layout.sniLen = cursor + 4 + 3
				layout.sni = cursor + 4 + 5
				layout.sniListLen = cursor + 4
				layout.sniExtLen = cursor + 2
				if layout.sni+nameLen > extensionsEnd {
					return layout, false
				}
			}
		case 21: // padding
			layout.paddingLen = cursor + 2
		}
		layout.extensionCount++
		cursor += 4 + extensionLength
	}
	return layout, true
}

func readUint16(data []byte) uint16 { return uint16(data[0])<<8 | uint16(data[1]) }
func readUint24(data []byte) int {
	return int(data[0])<<16 | int(data[1])<<8 | int(data[2])
}
func putUint16(data []byte, value int) { data[0], data[1] = byte(value>>8), byte(value) }
func putUint24(data []byte, value int) {
	data[0], data[1], data[2] = byte(value>>16), byte(value>>8), byte(value)
}

func randomLetters(count int, random RandSource) []byte {
	out := make([]byte, count)
	for index := range out {
		out[index] = byte('a' + random.Intn(26))
	}
	return out
}

// applyTLSMod is the port of upstream `runtime_tls_mod` plus the one-time SNI
// modifiers. It returns a modified copy and whether the modification applied.
// original is the captured TLS ClientHello used by dupsid; it may be nil.
func applyTLSMod(fake []byte, mod TLSMod, original []byte, random RandSource) ([]byte, bool) {
	if mod.IsZero() {
		return fake, false
	}
	if random == nil {
		random = DefaultRand
	}
	layout, ok := parseTLSHelloLayout(fake)
	if !ok {
		return fake, false
	}
	out := append([]byte(nil), fake...)
	applied := false
	if mod.PadEncap {
		if layout.paddingLen == 0 {
			return fake, false
		}
		delta := len(original)
		recordLength := int(readUint16(out[layout.recordLen:]))
		handshakeLength := readUint24(out[layout.handshakeLen:])
		extensionLength := int(readUint16(out[layout.extensionsLen:]))
		paddingLength := int(readUint16(out[layout.paddingLen:]))
		if recordLength+delta > 0xffff || handshakeLength+delta > 0xffffff ||
			extensionLength+delta > 0xffff || paddingLength+delta > 0xffff {
			return fake, false
		}
		putUint16(out[layout.recordLen:], recordLength+delta)
		putUint24(out[layout.handshakeLen:], handshakeLength+delta)
		putUint16(out[layout.extensionsLen:], extensionLength+delta)
		putUint16(out[layout.paddingLen:], paddingLength+delta)
		applied = true
	}
	if mod.Randomize {
		for index := 11; index < 43; index++ {
			out[index] = byte(random.Uint32())
		}
		sessionLength := int(out[layout.sessionIDLen])
		if layout.sessionID+sessionLength <= len(out) {
			for index := 0; index < sessionLength; index++ {
				out[layout.sessionID+index] = byte(random.Uint32())
			}
		}
		applied = true
	}
	if mod.DupSID && original != nil {
		// Upstream runtime_tls_mod only logs a refused dupsid: the session id
		// is copied when the captured ClientHello carries one of the same
		// length, otherwise the modifier is skipped and rnd/sni still apply
		// (nfq/desync.c). Discarding the already-modified payload here would
		// emit the unmodified fake on any client whose ClientHello has a
		// different session-id length (e.g. schannel sends an empty one).
		if len(original) >= 44 && original[43] == out[layout.sessionIDLen] &&
			len(original) >= 44+int(original[43]) &&
			layout.sessionID+int(out[layout.sessionIDLen]) <= len(out) {
			copy(out[layout.sessionID:], original[44:44+int(original[43])])
			applied = true
		}
	}
	if mod.RandomizeSNI || mod.SNI != "" {
		if layout.sni == 0 {
			return fake, applied
		}
		currentLength := int(readUint16(out[layout.sniLen:]))
		if layout.sni+currentLength > len(out) {
			return fake, applied
		}
		var replacement []byte
		if mod.SNI != "" {
			replacement = []byte(mod.SNI)
		} else {
			replacement = randomLetters(currentLength, random)
		}
		delta := len(replacement) - currentLength
		if delta == 0 {
			copy(out[layout.sni:], replacement)
		} else {
			if int(readUint16(out[layout.recordLen:]))+delta > 0xffff ||
				readUint24(out[layout.handshakeLen:])+delta > 0xffffff ||
				int(readUint16(out[layout.extensionsLen:]))+delta > 0xffff {
				return fake, applied
			}
			rebuilt := make([]byte, 0, len(out)+delta)
			rebuilt = append(rebuilt, out[:layout.sni]...)
			rebuilt = append(rebuilt, replacement...)
			rebuilt = append(rebuilt, out[layout.sni+currentLength:]...)
			out = rebuilt
			putUint16(out[layout.recordLen:], int(readUint16(out[layout.recordLen:]))+delta)
			putUint24(out[layout.handshakeLen:], readUint24(out[layout.handshakeLen:])+delta)
			putUint16(out[layout.extensionsLen:], int(readUint16(out[layout.extensionsLen:]))+delta)
			putUint16(out[layout.sniLen:], len(replacement))
			putUint16(out[layout.sniListLen:], int(readUint16(out[layout.sniListLen:]))+delta)
			putUint16(out[layout.sniExtLen:], int(readUint16(out[layout.sniExtLen:]))+delta)
		}
		applied = true
	}
	return out, applied
}

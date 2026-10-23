package desync

import (
	"encoding/binary"
	"fmt"
)

// planFirstStage ports the first-stage switch of `dpi_desync_tcp_packet_play`.
// It returns true when the stage consumed the packet (upstream's extension
// header modes are final and drop the original only when no valid second stage
// follows). origExt carries the fooling_orig extension chain that a following
// second stage must propagate to every real segment.
func planFirstStage(rule *Rule, packet *Packet, facts Facts, batch *Batch, random RandSource) (bool, []uint8, error) {
	_, first, second := stageMethods(rule.Methods)
	if first == nil {
		return false, nil, nil
	}
	mods := rule.Mods.orDefault()
	allocator := newIPAllocator(rule, packet, random)
	ttl := mods.TTLFor(packet.Family, packet.TTL, facts.HopCount, facts.HaveHop)
	switch first.Kind {
	case MethodFake, MethodFakeKnown:
		fake := rule.Fake
		if fake == nil {
			return false, nil, nil
		}
		if first.Kind == MethodFakeKnown && facts.Protocol == ProtocolUnknown {
			batch.Reason = "fakeknown requires a recognized protocol"
			return false, nil, nil
		}
		protocol := facts.Protocol
		if len(rule.Protocols) > 0 {
			protocol = ruleProtocol(rule, facts)
		}
		sent := 0
		for _, payload := range fake.Payloads {
			if payload.Protocol != protocol {
				continue
			}
			data := payload.Data
			if !payload.TLSMod.IsZero() {
				modified, applied := applyTLSMod(data, payload.TLSMod, packet.Payload, random)
				if applied {
					data = modified
				}
			}
			sequence := packet.TCPSeq - uint32(len(data))
			for repeat := 0; repeat < fake.Repeats; repeat++ {
				if fake.Seq {
					sequence = packet.TCPSeq + uint32(repeat*len(data))
				}
				id, _ := allocator.Value()
				flags := mods.RewriteFlags(packet.TCPFlags)
				spec := BuildSpec{
					Seq: &sequence, Flags: &flags, TTL: ttlValue(fake, packet, facts), TTLSet: true,
					IPID: id, IPIDSet: true, CopyOptions: true, Rand: random,
					TSIncrement: fake.TSIncrement, Fooling: mergeFooling(fake.Fooling, mods.Fooling),
					BadSeq: mods.BadSeqIncrement, BadAck: mods.BadAckIncrement,
					CorruptSum: fake.Fooling.BadChecksum || mods.Fooling.BadChecksum,
					Payload:    data, ExtHeaders: foolingExtHeaders(packet.Family, mergeFooling(fake.Fooling, mods.Fooling)),
				}
				generated, err := BuildTCPEx(packet, spec)
				if err != nil {
					return false, nil, err
				}
				for copyIndex := 0; copyIndex < mods.Repeats; copyIndex++ {
					batch.Packets = append(batch.Packets, generated)
				}
				sent++
			}
		}
		if sent == 0 {
			batch.Reason = "no fake payload for protocol " + protocol.String()
		}
		return false, nil, nil
	case MethodRST, MethodRSTACK:
		flags := uint8(tcpFlagRST)
		if first.Kind == MethodRSTACK {
			flags |= tcpFlagACK
		}
		id, _ := allocator.Value()
		spec := BuildSpec{Flags: &flags, TTL: ttl, TTLSet: true, IPID: id, IPIDSet: true,
			CopyOptions: true, Rand: random, TSIncrement: mods.TSIncrement,
			Fooling: mods.Fooling, BadSeq: mods.BadSeqIncrement, BadAck: mods.BadAckIncrement,
			CorruptSum: mods.Fooling.BadChecksum, ExtHeaders: foolingExtHeaders(packet.Family, mods.Fooling)}
		generated, err := BuildTCPEx(packet, spec)
		if err != nil {
			return false, nil, err
		}
		for repeat := 0; repeat < mods.Repeats; repeat++ {
			batch.Packets = append(batch.Packets, generated)
		}
		return false, nil, nil
	case MethodHopByHop, MethodDestOpt, MethodIPFrag1:
		if packet.Family != FamilyIPv6 {
			batch.Reason = "IPv6 extension-header stage applies only to IPv6"
			return false, nil, nil
		}
		header := uint8(0)
		if first.Kind == MethodDestOpt {
			header = 60
		} else if first.Kind == MethodIPFrag1 {
			header = 44
		}
		if second != nil && validSecondStageForOrigExtension(second.Kind, header) {
			// Upstream keeps fooling_orig set and falls through to the second
			// stage: every real segment of that stage carries the extension
			// header, while fakes keep their own fooling mode.
			return false, []uint8{header}, nil
		}
		if second != nil {
			// The configured second stage cannot be combined with this header
			// mode upstream; it takes the final resend path below.
			batch.Reason = "IPv6 extension-header stage is final for this second stage"
		}
		inserted, err := InsertIPv6Extension(packet.Raw, header)
		if err != nil {
			return false, nil, err
		}
		batch.Packets = append(batch.Packets, inserted)
		batch.Original = VerdictDrop
		return true, nil, nil
	}
	return false, nil, nil
}

// validSecondStageForOrigExtension mirrors the upstream condition that keeps
// fooling_orig for the second stage. The split families always qualify; ipfrag2
// qualifies only for the simple hop-by-hop/destination-options chain (upstream
// inserts those before fragmenting and does not nest a fragment header).
func validSecondStageForOrigExtension(kind MethodKind, header uint8) bool {
	switch kind {
	case MethodMultiSplit, MethodMultiDisorder, MethodFakeDSplit, MethodFakeDDisorder, MethodHostFakeSplit:
		return true
	case MethodIPFrag2:
		return header == 0 || header == 60
	}
	return false
}

// extHeaderForStage maps a first-stage extension mode to its IPv6 header type.
func extHeaderForStage(kind MethodKind) (uint8, bool) {
	switch kind {
	case MethodHopByHop:
		return 0, true
	case MethodDestOpt:
		return 60, true
	case MethodIPFrag1:
		return 44, true
	}
	return 0, false
}

// udpSecondStageUsesOrigExt ports the UDP side of the upstream question. Every
// UDP second stage keeps fooling_orig; udplen/tamper replicate the chain
// through prepare_udp_segment6 (including a single fragment header for
// ipfrag1), while ipfrag2 inserts only the simple hop-by-hop/destination-
// options header before fragmenting and never nests a fragment header.
func udpSecondStageUsesOrigExt(kind MethodKind, header uint8) bool {
	switch kind {
	case MethodUDPLen, MethodTamper:
		return true
	case MethodIPFrag2:
		return header == 0 || header == 60
	}
	return false
}

func ttlValue(fake *FakeSpec, packet *Packet, facts Facts) uint8 {
	if packet.Family == FamilyIPv6 {
		if fake.TTL6 != 0 {
			return uint8(fake.TTL6)
		}
		auto := fake.AutoTTL
		if fake.AutoTTL6.Set {
			auto = fake.AutoTTL6
		}
		if auto.Set && facts.HaveHop {
			if value, ok := auto.Eval(facts.HopCount); ok {
				return value
			}
		}
	}
	if fake.TTL != 0 {
		return uint8(fake.TTL)
	}
	if fake.AutoTTL.Set && facts.HaveHop {
		if value, ok := fake.AutoTTL.Eval(facts.HopCount); ok {
			return value
		}
	}
	return packet.TTL
}

// planSecondStage ports the second-stage switch.
func planSecondStage(rule *Rule, packet *Packet, facts Facts, batch *Batch, offset int, random RandSource) error {
	_, _, second := stageMethods(rule.Methods)
	if second == nil {
		return nil
	}
	mods := rule.Mods.orDefault()
	_ = mods
	switch second.Kind {
	case MethodMultiSplit, MethodMultiDisorder:
		spec := rule.MultiSplit
		if second.Kind == MethodMultiDisorder {
			spec = rule.MultiDisorder
		}
		if spec == nil {
			return nil
		}
		var (
			segments [][]byte
			err      error
		)
		if second.Kind == MethodMultiSplit {
			segments, err = planMultiSplit(spec, packet, facts, offset, offset+len(packet.Payload))
		} else {
			segments, err = planMultiDisorder(spec, packet, facts, offset, offset+len(packet.Payload))
		}
		if err != nil {
			return err
		}
		if len(segments) > 0 {
			batch.Packets = append(batch.Packets, segments...)
			batch.Original = VerdictDrop
		}
	case MethodFakeDSplit, MethodFakeDDisorder:
		spec := rule.FakeSplit
		if second.Kind == MethodFakeDDisorder {
			spec = rule.FakeDisorder
		}
		if spec == nil {
			return nil
		}
		segments, err := planFakeSplit(rule, packet, facts, spec, second.Kind, batch, random, offset)
		if err != nil {
			return err
		}
		if len(segments) > 0 {
			batch.Packets = append(batch.Packets, segments...)
			batch.Original = VerdictDrop
		}
	case MethodHostFakeSplit:
		if rule.HostFakeSplit == nil {
			return nil
		}
		segments, err := planHostFakeSplit(rule, packet, facts, rule.HostFakeSplit, batch, random, offset)
		if err != nil {
			return err
		}
		if len(segments) > 0 {
			batch.Packets = append(batch.Packets, segments...)
			batch.Original = VerdictDrop
		}
	case MethodIPFrag2:
		position := rule.IPFragPosTCP
		raw := packet.Raw
		if len(facts.OrigExtHeaders) > 0 {
			// Upstream ip6_insert_simple_hdr before ip_frag: the real
			// fragments carry the hop-by-hop/destination-options chain.
			var insertErr error
			for index := len(facts.OrigExtHeaders) - 1; index >= 0; index-- {
				raw, insertErr = InsertIPv6Extension(raw, facts.OrigExtHeaders[index])
				if insertErr != nil {
					return insertErr
				}
			}
		}
		first, secondFragment, err := FragmentPair(raw, position, 0, random)
		if err != nil {
			return err
		}
		batch.Packets = append(batch.Packets, first, secondFragment)
		batch.Original = VerdictDrop
	default:
		return fmt.Errorf("desync: second stage %s is not applicable to TCP", second.Name)
	}
	return nil
}

func planFakeSplit(rule *Rule, packet *Packet, facts Facts, spec *FakeSplitSpec, kind MethodKind, batch *Batch, random RandSource, offset int) ([][]byte, error) {
	positions := localizePositions(&spec.Split, facts, offset, offset+len(packet.Payload))
	splitPos := 0
	if len(positions) > 0 {
		splitPos = positions[0]
	}
	order := spec.Ordering & 3
	if splitPos == 0 {
		order = (spec.Ordering >> 3) & 3
		splitPos = len(packet.Payload)
	}
	pattern := make([]byte, len(packet.Payload))
	fillPattern(pattern, spec.Pattern, 0)
	mods := rule.Mods.orDefault()
	ttlFake := mods.TTLFor(packet.Family, packet.TTL, facts.HopCount, facts.HaveHop)
	allocator := newIPAllocator(rule, packet, random)
	fakeSegment := func(sequence uint32, data []byte, ttl uint8, flags uint8) ([]byte, error) {
		id, _ := allocator.Value()
		spec := BuildSpec{Seq: &sequence, Flags: &flags, TTL: ttl, TTLSet: true, IPID: id, IPIDSet: true,
			CopyOptions: true, Rand: random, TSIncrement: mods.TSIncrement,
			Fooling: mods.Fooling, BadSeq: mods.BadSeqIncrement, BadAck: mods.BadAckIncrement,
			CorruptSum: mods.Fooling.BadChecksum, Payload: data}
		return BuildTCPEx(packet, spec)
	}
	realSegment := func(sequence uint32, data []byte, flags uint8) ([]byte, error) {
		id, _ := allocator.Value()
		return BuildTCPEx(packet, BuildSpec{Seq: &sequence, Flags: &flags, IPID: id, IPIDSet: true,
			CopyOptions: true, Rand: random, Payload: data, ExtHeaders: facts.OrigExtHeaders})
	}
	fakeFlags := mods.RewriteFlags(packet.TCPFlags)
	realFlags := packet.TCPFlags
	var out [][]byte
	if kind == MethodFakeDSplit {
		firstFake, err := fakeSegment(packet.TCPSeq, pattern[:splitPos], ttlFake, fakeFlags)
		if err != nil {
			return nil, err
		}
		if order == 0 {
			out = append(out, firstFake)
		}
		realFirst, err := realSegment(packet.TCPSeq, packet.Payload[:splitPos], realFlags)
		if err != nil {
			return nil, err
		}
		out = append(out, realFirst)
		if order <= 1 {
			out = append(out, firstFake)
		}
		if splitPos < len(packet.Payload) {
			secondFake, err := fakeSegment(packet.TCPSeq+uint32(splitPos), pattern[splitPos:], ttlFake, fakeFlags)
			if err != nil {
				return nil, err
			}
			if order == 0 || order == 1 {
				out = append(out, secondFake)
			}
			realSecond, err := realSegment(packet.TCPSeq+uint32(splitPos), packet.Payload[splitPos:], realFlags)
			if err != nil {
				return nil, err
			}
			out = append(out, realSecond)
			if order <= 2 {
				out = append(out, secondFake)
			}
		}
		return out, nil
	}
	// fakeddisorder: the second (out-of-order) segment is sent before the first
	// real segment, with an optional fake copy on either side.
	secondFake, err := fakeSegment(packet.TCPSeq+uint32(splitPos), pattern[splitPos:], ttlFake, fakeFlags)
	if err != nil {
		return nil, err
	}
	if order == 0 {
		out = append(out, secondFake)
	}
	realSecond, err := realSegment(packet.TCPSeq+uint32(splitPos), packet.Payload[splitPos:], realFlags)
	if err != nil {
		return nil, err
	}
	out = append(out, realSecond)
	if order <= 1 {
		out = append(out, secondFake)
	}
	if splitPos > 0 {
		firstFake, err := fakeSegment(packet.TCPSeq, pattern[:splitPos], ttlFake, fakeFlags)
		if err != nil {
			return nil, err
		}
		out = append(out, firstFake)
		realFirst, err := realSegment(packet.TCPSeq, packet.Payload[:splitPos], realFlags)
		if err != nil {
			return nil, err
		}
		out = append(out, realFirst)
		if order <= 2 {
			out = append(out, firstFake)
		}
	}
	return out, nil
}

// resolveOrigTTL ports orig_mod's TTL selection: the bounded autottl guess
// first, then the explicit TTL, otherwise the captured TTL.
func resolveOrigTTL(spec *OrigSpec, packet *Packet, facts Facts) uint8 {
	if packet.Family == FamilyIPv6 {
		auto := spec.AutoTTL
		if spec.AutoTTL6.Set {
			auto = spec.AutoTTL6
		}
		if auto.Set && facts.HaveHop {
			if value, ok := auto.Eval(facts.HopCount); ok {
				return value
			}
		}
		// Upstream normalizes orig_mod_ttl6=0xFF to orig_mod_ttl.
		if spec.TTL6 != 0 {
			return uint8(spec.TTL6)
		}
		if spec.TTL != 0 {
			return uint8(spec.TTL)
		}
		return packet.TTL
	}
	if spec.AutoTTL.Set && facts.HaveHop {
		if value, ok := spec.AutoTTL.Eval(facts.HopCount); ok {
			return value
		}
	}
	if spec.TTL != 0 {
		return uint8(spec.TTL)
	}
	return packet.TTL
}

// applyOrigMod ports upstream `orig_mod`: TTL/hop-limit and TCP flags of the
// captured original are rewritten in place, gated by orig-mod-start/cutoff.
// It returns a planning view carrying the modified header values so generated
// segments use the post-modification ttl_orig/flags_orig, exactly as upstream.
func applyOrigMod(rule *Rule, packet *Packet, facts Facts, batch *Batch) (*Packet, error) {
	if rule == nil || rule.Orig == nil {
		return packet, nil
	}
	if rule.Orig.ModStart.IsSet() && !rule.Orig.ModStart.Reached(facts.origCounters) {
		return packet, nil
	}
	if facts.origModCutoffLatched ||
		(rule.Orig.ModCutoff.IsSet() && rule.Orig.ModCutoff.Reached(facts.origCounters)) {
		return packet, nil
	}
	ttl := resolveOrigTTL(rule.Orig, packet, facts)
	flags := packet.TCPFlags
	flagsChanged := false
	if packet.Transport == TransportTCP {
		updated := uint8((uint16(packet.TCPFlags)&^rule.Orig.FlagsUnset | rule.Orig.FlagsSet) & 0xff)
		flagsChanged = updated != packet.TCPFlags
		flags = updated
	}
	if ttl == packet.TTL && !flagsChanged {
		return packet, nil
	}
	modified := append([]byte(nil), packet.Raw...)
	if packet.Family == FamilyIPv6 {
		modified[7] = ttl
	} else {
		modified[8] = ttl
	}
	if flagsChanged {
		modified[packet.IPHeaderLen+13] = flags
	}
	if err := refreshChecksums(modified, packet); err != nil {
		return nil, err
	}
	batch.Modified = modified
	batch.Original = VerdictModify
	working := *packet
	working.Raw = modified
	working.TTL = ttl
	working.TCPFlags = flags
	return &working, nil
}

// rewriteWindowInPlace ports tcp_rewrite_winsize: the advertised window is
// always replaced, and a configured window scale can only be lowered (upstream
// refuses to increase it). Only the exact bytes change; option order and every
// other TCP option are preserved.
func rewriteWindowInPlace(raw []byte, packet *Packet, size uint16, scale int, scaleSet bool) (bool, error) {
	tcp := packet.IPHeaderLen
	changed := false
	if binary.BigEndian.Uint16(raw[tcp+14:tcp+16]) != size {
		binary.BigEndian.PutUint16(raw[tcp+14:tcp+16], size)
		changed = true
	}
	if scaleSet {
		options := raw[tcp+20 : tcp+packet.TransportHeaderLen]
		for index := 0; index < len(options); {
			kind := options[index]
			if kind == 0 {
				break
			}
			if kind == 1 {
				index++
				continue
			}
			if index+1 >= len(options) {
				break
			}
			length := int(options[index+1])
			if length < 2 || index+length > len(options) {
				break
			}
			if kind == 3 && length == 3 {
				if byte(scale) < options[index+2] {
					options[index+2] = byte(scale)
					changed = true
				}
				break
			}
			index += length
		}
	}
	if !changed {
		return false, nil
	}
	if err := refreshChecksums(raw, packet); err != nil {
		return false, err
	}
	return true, nil
}

// applyWSSize ports the original-direction `wssize` rewrite. It is gated by
// the latched wssize cutoff (explicit n/d/s limit or the protocol-triggered
// forced cutoff).
func applyWSSize(rule *Rule, packet *Packet, facts Facts, batch *Batch) (*Packet, error) {
	if rule == nil || rule.WSSize == nil {
		return packet, nil
	}
	if facts.wssizeCutoffLatched ||
		(rule.WSSize.Cutoff.IsSet() && rule.WSSize.Cutoff.Reached(facts.origCounters)) {
		return packet, nil
	}
	var raw []byte
	if batch.Modified != nil {
		raw = append([]byte(nil), batch.Modified...)
	} else {
		raw = append([]byte(nil), packet.Raw...)
	}
	changed, err := rewriteWindowInPlace(raw, packet, uint16(rule.WSSize.Size), rule.WSSize.Scale, rule.WSSize.ScaleSet)
	if err != nil {
		return nil, err
	}
	if !changed {
		return packet, nil
	}
	batch.Modified = raw
	batch.Original = VerdictModify
	working := *packet
	working.Raw = raw
	working.TCPWindow = binary.BigEndian.Uint16(raw[packet.IPHeaderLen+14 : packet.IPHeaderLen+16])
	return &working, nil
}

// dupIsZeroFooling reports whether the duplicate fooling set is empty.
func dupIsZeroFooling(fooling Fooling) bool { return fooling == Fooling{} }

// dupIPIDFix ports IP4_IP_ID_FIX with the rule's main ip_id mode.
func dupIPIDFix(mode IPIDMode, packet *Packet, random RandSource) uint16 {
	switch mode {
	case IPIDSeq, IPIDSeqGroup:
		if packet.IPID != 0 {
			return packet.IPID
		}
		return nonZeroID(uint16(random.Uint32()))
	case IPIDSame:
		return packet.IPID
	case IPIDRandom:
		return nonZeroID(uint16(random.Uint32() % 0xffff))
	default:
		return 0
	}
}

// dupIPIDNext ports IP4_IP_ID_NEXT with the dup-owned ip_id mode.
func dupIPIDNext(current uint16, mode IPIDMode, random RandSource) uint16 {
	switch mode {
	case IPIDSeq, IPIDSeqGroup:
		if current != 0 {
			current++
			if current == 0 {
				current = 1
			}
		}
		return current
	case IPIDSame:
		return current
	case IPIDRandom:
		return nonZeroID(uint16(random.Uint32() % 0xffff))
	default:
		return 0
	}
}

func resolveDupTTL(spec *DupSpec, packet *Packet, ttlOriginal uint8, facts Facts) uint8 {
	if packet.Family == FamilyIPv6 {
		auto := spec.AutoTTL
		if spec.AutoTTL6.Set {
			auto = spec.AutoTTL6
		}
		if auto.Set && facts.HaveHop {
			if value, ok := auto.Eval(facts.HopCount); ok {
				return value
			}
		}
		if spec.TTL6 != 0 {
			return uint8(spec.TTL6)
		}
		if spec.TTL != 0 {
			return uint8(spec.TTL)
		}
		return ttlOriginal
	}
	if spec.AutoTTL.Set && facts.HaveHop {
		if value, ok := spec.AutoTTL.Eval(facts.HopCount); ok {
			return value
		}
	}
	if spec.TTL != 0 {
		return uint8(spec.TTL)
	}
	return ttlOriginal
}

// planDup ports the upstream `tcp_orig_send` duplicate branch: duplicates are
// sent first (reconstructed only when a header/fooling/IP-ID change requires
// it, otherwise the exact original bytes with only TTL rewritten), then the
// original is passed unless dup_replace suppresses it.
func planDup(rule *Rule, packet *Packet, working *Packet, facts Facts, batch *Batch, random RandSource) error {
	if rule == nil || rule.Dup == nil || rule.Dup.Count == 0 {
		return nil
	}
	if rule.Dup.Start.IsSet() && !rule.Dup.Start.Reached(facts.counters) {
		return nil
	}
	if facts.dupCutoffLatched || (rule.Dup.Cutoff.IsSet() && rule.Dup.Cutoff.Reached(facts.counters)) {
		return nil
	}
	if batch.Original == VerdictDrop {
		return nil
	}
	if random == nil {
		random = DefaultRand
	}
	spec := rule.Dup
	ttl := resolveDupTTL(spec, working, working.TTL, facts)
	flags := uint8((uint16(working.TCPFlags)&^spec.FlagsUnset | spec.FlagsSet) & 0xff)
	reconstruct := flags != packet.TCPFlags || !dupIsZeroFooling(spec.Fooling) ||
		(packet.Family == FamilyIPv4 && spec.IPID != IPIDSame)
	currentID := uint16(0)
	if packet.Family == FamilyIPv4 {
		currentID = dupIPIDFix(rule.IPID, packet, random)
	}
	for index := 0; index < spec.Count; index++ {
		var generated []byte
		var err error
		if reconstruct {
			window := working.TCPWindow
			generated, err = BuildTCPEx(packet, BuildSpec{
				Flags: &flags, TTL: ttl, TTLSet: true, IPID: currentID, IPIDSet: true,
				Window:      &window,
				CopyOptions: true, Rand: random, Payload: packet.Payload,
				Fooling: spec.Fooling, TSIncrement: spec.TSIncrement,
				BadSeq: spec.BadSeqIncrement, BadAck: spec.BadAckIncrement,
				CorruptSum: spec.Fooling.BadChecksum,
				ExtHeaders: foolingExtHeaders(packet.Family, spec.Fooling),
			})
		} else {
			// Upstream orig_send_rewrite: duplicate the exact captured bytes
			// (after orig_mod/wssize) and only rewrite TTL, preserving the
			// complete option structure.
			generated = append([]byte(nil), working.Raw...)
			if packet.Family == FamilyIPv6 {
				generated[7] = ttl
			} else {
				generated[8] = ttl
			}
			err = refreshChecksums(generated, packet)
		}
		if err != nil {
			return err
		}
		batch.Packets = append(batch.Packets, generated)
		if packet.Family == FamilyIPv4 {
			currentID = dupIPIDNext(currentID, spec.IPID, random)
		}
	}
	if spec.Replace {
		batch.Original = VerdictDrop
		batch.Modified = nil
	}
	return nil
}

// fakeHostTLDs is the exact upstream tld[] table used by hostfakesplit.
var fakeHostTLDs = []string{"com", "org", "net", "edu", "gov", "biz"}

// fillRandomAZ ports upstream fill_random_az: 'a'..'y' (the upstream modulus
// is 'z'-'a', so 'z' is never produced).
func fillRandomAZ(dst []byte, random RandSource) {
	for index := range dst {
		dst[index] = byte('a' + random.Intn('z'-'a'))
	}
}

// fillRandomAZ09 ports upstream fill_random_az09: 0-9 then a-z.
func fillRandomAZ09(dst []byte, random RandSource) {
	for index := range dst {
		value := random.Intn(10 + 'z' - 'a' + 1)
		if value < 10 {
			dst[index] = byte('0' + value)
		} else {
			dst[index] = byte('a' + value - 10)
		}
	}
}

// buildFakeHost is the byte-exact upstream hostfakesplit fake host generator.
func buildFakeHost(spec *HostFakeSplitSpec, hostSize int, random RandSource) []byte {
	fake := make([]byte, hostSize)
	if spec.Host != "" {
		if hostSize <= spec.HostSize {
			// "google.com" => "gle.com"
			copy(fake, spec.Host[spec.HostSize-hostSize:])
			return fake
		}
		// "google.com" => "nb4auv9.google.com"
		size := hostSize - spec.HostSize
		copy(fake[size:], spec.Host)
		size--
		fake[size] = '.'
		if size > 0 {
			fillRandomAZ(fake[:1], random)
			size--
			fillRandomAZ09(fake[1:1+size], random)
		}
		return fake
	}
	fillRandomAZ(fake[:1], random)
	fillRandomAZ09(fake[1:], random)
	if hostSize >= 7 {
		fake[hostSize-4] = '.'
		copy(fake[hostSize-3:], fakeHostTLDs[random.Intn(len(fakeHostTLDs))])
	}
	return fake
}

// normalizeHostPosition is upstream pos_normalize: a boundary is usable only
// when it lies strictly inside this packet's payload.
func normalizeHostPosition(absolute int, offset int, length int) int {
	if absolute > offset && absolute-offset < length {
		return absolute - offset
	}
	return 0
}

// planHostFakeSplit ports the DESYNC_HOSTFAKESPLIT second stage. Upstream has
// exactly two mandatory real splits (Host/SNI value boundaries) and an optional
// third (midhost). altorder selects fake/after ordering and the IPv4 ID
// sequence follows the upstream look-ahead rules.
func planHostFakeSplit(rule *Rule, packet *Packet, facts Facts, spec *HostFakeSplitSpec, batch *Batch, random RandSource, offset int) ([][]byte, error) {
	if facts.HostStart <= 0 || facts.HostEnd <= facts.HostStart || facts.HostEnd > facts.MessageLength {
		return nil, nil
	}
	posHost := normalizeHostPosition(facts.HostStart, offset, len(packet.Payload))
	posEnd := normalizeHostPosition(facts.HostEnd, offset, len(packet.Payload))
	if posHost == 0 || posEnd == 0 || posEnd <= posHost {
		return nil, nil
	}
	posSplit := 0
	if spec.MidHost != nil {
		if absolute, ok := spec.MidHost.Resolve(facts); ok {
			posSplit = normalizeHostPosition(absolute, offset, len(packet.Payload))
			if posSplit <= posHost || posSplit >= posEnd {
				posSplit = 0
			}
		}
	}
	payload := packet.Payload
	if posEnd > len(payload) {
		return nil, nil
	}
	if random == nil {
		random = DefaultRand
	}
	mods := rule.Mods.orDefault()
	ttlOrig := packet.TTL
	ttlFake := mods.TTLFor(packet.Family, packet.TTL, facts.HopCount, facts.HaveHop)
	flagsOrig := packet.TCPFlags
	flagsFake := mods.RewriteFlags(packet.TCPFlags)
	hostSize := posEnd - posHost
	fakeHost := buildFakeHost(spec, hostSize, random)

	// IPv4 ID cursor, exactly as IP4_IP_ID_FIX/IP4_IP_ID_NEXT on the profile
	// mode: the initial value is the original ID for seq/seqgroup.
	id := uint16(0)
	nextID := func(value uint16) uint16 { return value }
	if packet.Family == FamilyIPv4 {
		id = dupIPIDFix(rule.IPID, packet, random)
		nextID = func(value uint16) uint16 { return dupIPIDNext(value, rule.IPID, random) }
	}
	beforeID := id
	id = nextID(id)
	fakeID := id
	if rule.IPID != IPIDSeqGroup {
		id = nextID(id)
	}
	afterID := nextID(id)
	if posSplit != 0 {
		afterID = nextID(afterID)
	}
	realFirstID := id
	id = nextID(id)
	var realSecondID uint16
	if posSplit != 0 {
		realSecondID = id
		id = nextID(id)
	}
	fakeSecondID := fakeID
	afterSecondID := afterID
	if spec.Ordering == 0 && rule.IPID != IPIDSeqGroup {
		fakeSecondID = id
		id = nextID(id)
		afterSecondID = id
	}

	realSegment := func(sequence uint32, data []byte, id uint16) ([]byte, error) {
		return BuildTCPEx(packet, BuildSpec{Flags: &flagsOrig, Seq: &sequence,
			IPID: id, IPIDSet: true, TTL: ttlOrig, TTLSet: true,
			CopyOptions: true, Rand: random, Payload: data,
			ExtHeaders: facts.OrigExtHeaders})
	}
	fakeSegment := func(sequence uint32, data []byte, id uint16) ([]byte, error) {
		return BuildTCPEx(packet, BuildSpec{Flags: &flagsFake, Seq: &sequence,
			IPID: id, IPIDSet: true, TTL: ttlFake, TTLSet: true,
			CopyOptions: true, Rand: random, Payload: data,
			Fooling: mods.Fooling, TSIncrement: mods.TSIncrement,
			BadSeq: mods.BadSeqIncrement, BadAck: mods.BadAckIncrement,
			CorruptSum: mods.Fooling.BadChecksum,
			ExtHeaders: foolingExtHeaders(packet.Family, mods.Fooling)})
	}
	beforeHost, err := realSegment(packet.TCPSeq, payload[:posHost], beforeID)
	if err != nil {
		return nil, err
	}
	fakeHostPart, err := fakeSegment(packet.TCPSeq+uint32(posHost), fakeHost, fakeID)
	if err != nil {
		return nil, err
	}
	afterHost, err := realSegment(packet.TCPSeq+uint32(posEnd), payload[posEnd:], afterID)
	if err != nil {
		return nil, err
	}
	realFirst, err := realSegment(packet.TCPSeq+uint32(posHost), payload[posHost:posEnd], realFirstID)
	if err != nil {
		return nil, err
	}
	var realSecond []byte
	if posSplit != 0 {
		realSecond, err = realSegment(packet.TCPSeq+uint32(posSplit), payload[posSplit:posEnd], realSecondID)
		if err != nil {
			return nil, err
		}
		realFirst, err = realSegment(packet.TCPSeq+uint32(posHost), payload[posHost:posSplit], realFirstID)
		if err != nil {
			return nil, err
		}
	}
	fakeCopy := func(id uint16) ([]byte, error) {
		return fakeSegment(packet.TCPSeq+uint32(posHost), fakeHost, id)
	}
	afterCopy := func(id uint16) ([]byte, error) {
		return realSegment(packet.TCPSeq+uint32(posEnd), payload[posEnd:], id)
	}

	out := make([][]byte, 0, 8)
	out = append(out, beforeHost)
	for repeat := 0; repeat < mods.Repeats; repeat++ {
		out = append(out, fakeHostPart)
	}
	if spec.Ordering == 1 {
		out = append(out, afterHost, realFirst)
		if realSecond != nil {
			out = append(out, realSecond)
		}
		return out, nil
	}
	out = append(out, realFirst)
	if realSecond != nil {
		out = append(out, realSecond)
	}
	fakeSecond, err := fakeCopy(fakeSecondID)
	if err != nil {
		return nil, err
	}
	for repeat := 0; repeat < mods.Repeats; repeat++ {
		out = append(out, fakeSecond)
	}
	afterSecond, err := afterCopy(afterSecondID)
	if err != nil {
		return nil, err
	}
	out = append(out, afterSecond)
	return out, nil
}

// planUDPDup ports the upstream `udp_orig_send` duplicate branch.
func planUDPDup(rule *Rule, packet *Packet, working *Packet, facts Facts, batch *Batch, random RandSource) error {
	if rule == nil || rule.Dup == nil || rule.Dup.Count == 0 {
		return nil
	}
	if rule.Dup.Start.IsSet() && !rule.Dup.Start.Reached(facts.counters) {
		return nil
	}
	if facts.dupCutoffLatched || (rule.Dup.Cutoff.IsSet() && rule.Dup.Cutoff.Reached(facts.counters)) || batch.Original == VerdictDrop {
		return nil
	}
	if random == nil {
		random = DefaultRand
	}
	spec := rule.Dup
	ttl := resolveDupTTL(spec, working, working.TTL, facts)
	reconstruct := !dupIsZeroFooling(spec.Fooling) ||
		(packet.Family == FamilyIPv4 && spec.IPID != IPIDSame)
	currentID := uint16(0)
	if packet.Family == FamilyIPv4 {
		currentID = dupIPIDFix(rule.IPID, packet, random)
	}
	for index := 0; index < spec.Count; index++ {
		var generated []byte
		var err error
		if reconstruct {
			generated, err = BuildUDPEx(packet, BuildSpec{
				TTL: ttl, TTLSet: true, IPID: currentID, IPIDSet: true,
				Rand: random, Payload: packet.Payload, Fooling: spec.Fooling,
				CorruptSum: spec.Fooling.BadChecksum,
				ExtHeaders: foolingExtHeaders(packet.Family, spec.Fooling),
			})
		} else {
			generated = append([]byte(nil), working.Raw...)
			if packet.Family == FamilyIPv6 {
				generated[7] = ttl
			} else {
				generated[8] = ttl
			}
			err = refreshChecksums(generated, packet)
		}
		if err != nil {
			return err
		}
		batch.Packets = append(batch.Packets, generated)
		if packet.Family == FamilyIPv4 {
			currentID = dupIPIDNext(currentID, spec.IPID, random)
		}
	}
	if spec.Replace {
		batch.Original = VerdictDrop
	}
	return nil
}

// refreshChecksums recomputes the IPv4/TCP, IPv6/TCP, IPv4/UDP or IPv6/UDP
// checksum after an in-place header modification of a captured packet.
func refreshChecksums(raw []byte, packet *Packet) error {
	transport := packet.IPHeaderLen
	if packet.Family == FamilyIPv4 {
		raw[10], raw[11] = 0, 0
		binaryPutUint16(raw[10:12], inetChecksum(raw[:transport], 0))
	}
	sum, err := pseudoHeaderSum(raw, packet, len(raw)-transport)
	if err != nil {
		return err
	}
	if packet.Transport == TransportUDP {
		raw[transport+6], raw[transport+7] = 0, 0
		udpSum := inetChecksum(raw[transport:], sum)
		if udpSum == 0 {
			udpSum = 0xffff
		}
		binaryPutUint16(raw[transport+6:transport+8], udpSum)
		return nil
	}
	raw[transport+16], raw[transport+17] = 0, 0
	binaryPutUint16(raw[transport+16:transport+18], inetChecksum(raw[transport:], sum))
	return nil
}

func binaryPutUint16(dst []byte, value uint16) {
	dst[0] = byte(value >> 8)
	dst[1] = byte(value)
}

// foolingExtHeaders ports the IPv6 `prepare_tcp_segment6` fooling chain:
// hopbyhop inserts one hop-by-hop header, hopbyhop2 inserts two (an intentional
// standard violation), exactly as upstream.
func foolingExtHeaders(family Family, fooling Fooling) []uint8 {
	if family != FamilyIPv6 {
		return nil
	}
	if fooling.HopByHop2 {
		return []uint8{0, 0}
	}
	if fooling.HopByHop {
		return []uint8{0}
	}
	return nil
}

// planInPlace applies the original-direction in-place modifiers in upstream
// order: orig_mod, wssize, then the SYN-ACK wsize/syn clear. It returns the
// planning view of the modified captured packet.
func planInPlace(rule *Rule, packet *Packet, facts Facts, batch *Batch) (*Packet, error) {
	working, err := applyOrigMod(rule, packet, facts, batch)
	if err != nil {
		return nil, err
	}
	working, err = applyWSSize(rule, working, facts, batch)
	if err != nil {
		return nil, err
	}
	working, err = applyObservedSynAck(rule, working, batch)
	if err != nil {
		return nil, err
	}
	return working, nil
}

// PlanTCP is the stage-aware TCP planner. It applies the original-direction
// in-place modifiers in upstream order (orig_mod, wssize), then the stage
// grammar, then duplicates. Generated packets never touch the counters.
// The desync start/cutoff interval is owned by the caller: upstream evaluates
// it only for payload packets, after orig_mod/wssize, and a blocked interval
// still reaches the dup branch.
func PlanTCP(rule *Rule, packet *Packet, message []byte, offset int, facts Facts) (*Batch, error) {
	random := facts.Rand
	if random == nil {
		random = DefaultRand
	}
	batch := &Batch{Original: VerdictPass}
	if rule == nil {
		return batch, nil
	}
	working, err := planInPlace(rule, packet, facts, batch)
	if err != nil {
		return nil, err
	}
	if packet.IsSYN() {
		if packet.TCPFlags&tcpFlagACK == 0 {
			// Upstream tcp_syn_segment excludes SYN-ACK.
			if _, err = planZeroStage(rule, working, batch, random); err != nil {
				return nil, err
			}
		} else if rule.SynackSplit == SynAckSplitSYNFirst || rule.SynackSplit == SynAckSplitACKFirst {
			// The two-packet split consumes the original before the dup
			// branch; synack_split=syn was already applied in place.
			packets, splitErr := SynAckSplitPackets(rule, working)
			if splitErr != nil {
				return nil, splitErr
			}
			if len(packets) > 0 {
				mods := rule.Mods.orDefault()
				for _, part := range packets {
					for repeat := 0; repeat < mods.Repeats; repeat++ {
						batch.Packets = append(batch.Packets, part)
					}
				}
				batch.Original = VerdictDrop
				batch.Modified = nil
				return batch, nil
			}
		}
		if err = planDup(rule, packet, working, facts, batch, random); err != nil {
			return nil, err
		}
		return batch, nil
	}
	if len(packet.Payload) == 0 {
		// Empty ACKs are observed originals too: dup applies, and orig_mod /
		// wssize may rewrite header-only state.
		if err = planDup(rule, packet, working, facts, batch, random); err != nil {
			return nil, err
		}
		return batch, nil
	}
	if facts.MessageLength == 0 {
		facts.MessageLength = offset + len(packet.Payload)
	}
	if offset == 0 {
		consumed, origExt, err := planFirstStage(rule, working, facts, batch, random)
		if err != nil {
			return nil, fmt.Errorf("desync: first stage: %w", err)
		}
		if consumed {
			return batch, nil
		}
		if len(origExt) > 0 {
			facts.OrigExtHeaders = origExt
		}
	}
	if err := planSecondStage(rule, working, facts, batch, offset, random); err != nil {
		return nil, fmt.Errorf("desync: second stage: %w", err)
	}
	if err := planDup(rule, packet, working, facts, batch, random); err != nil {
		return nil, err
	}
	return batch, nil
}

// planZeroStage ports the mode0 SYN switch.
func planZeroStage(rule *Rule, packet *Packet, batch *Batch, random RandSource) (*Batch, error) {
	zero, _, _ := stageMethods(rule.Methods)
	if zero == nil {
		return batch, nil
	}
	mods := rule.Mods.orDefault()
	ttl := mods.TTLFor(packet.Family, packet.TTL, 0, false)
	allocator := newIPAllocator(rule, packet, random)
	switch zero.Kind {
	case MethodSynAck:
		flags := uint8(tcpFlagSYN | tcpFlagACK)
		id, _ := allocator.Value()
		spec := BuildSpec{Flags: &flags, TTL: ttl, TTLSet: true, IPID: id, IPIDSet: true,
			CopyOptions: true, Rand: random, Fooling: mods.Fooling,
			TSIncrement: mods.TSIncrement, BadSeq: mods.BadSeqIncrement, BadAck: mods.BadAckIncrement,
			CorruptSum: mods.Fooling.BadChecksum, ExtHeaders: foolingExtHeaders(packet.Family, mods.Fooling)}
		generated, err := BuildTCPEx(packet, spec)
		if err != nil {
			return nil, err
		}
		for repeat := 0; repeat < mods.Repeats; repeat++ {
			batch.Packets = append(batch.Packets, generated)
		}
	case MethodSynData:
		if packet.HasFastOpen {
			batch.Reason = "SYN has TCP fast open: syndata is not applied"
			return batch, nil
		}
		if len(packet.Payload) > 0 {
			batch.Reason = "SYN has payload: syndata is not applied"
			return batch, nil
		}
		// Upstream default fake_syndata is 16 bytes (params.c initialisation).
		fake := make([]byte, 16)
		flags := packet.TCPFlags
		id, _ := allocator.Value()
		spec := BuildSpec{Flags: &flags, IPID: id, IPIDSet: true, CopyOptions: true,
			Rand: random, Payload: fake}
		generated, err := BuildTCPEx(packet, spec)
		if err != nil {
			return nil, err
		}
		for repeat := 0; repeat < mods.Repeats; repeat++ {
			batch.Packets = append(batch.Packets, generated)
		}
		batch.Original = VerdictDrop
	default:
		return nil, fmt.Errorf("desync: zero stage %s is not applicable to TCP", zero.Name)
	}
	return batch, nil
}

// PlanUDP is the stage-aware UDP planner.
func PlanUDP(rule *Rule, packet *Packet) (*Batch, error) {
	batch := &Batch{Original: VerdictPass}
	if len(packet.Payload) == 0 || rule == nil {
		return batch, nil
	}
	random := DefaultRand
	protocol := classifyUDPPayload(packet)
	mods := rule.Mods.orDefault()
	_, first, second := stageMethods(rule.Methods)
	allocator := newIPAllocator(rule, packet, random)
	// origExt is the upstream fooling_orig extension-header chain that a
	// first-stage hopbyhop/destopt/ipfrag1 hands to the UDP second stage.
	// Upstream only reaches the final "resend original with header" path when
	// there is no second stage (every UDP second stage is combinable), so a
	// configured second stage always keeps fooling_orig for its real packets.
	var origExt []uint8
	if first != nil && packet.Family == FamilyIPv6 {
		if header, ok := extHeaderForStage(first.Kind); ok {
			if second != nil && udpSecondStageUsesOrigExt(second.Kind, header) {
				origExt = []uint8{header}
			}
		}
	}
	if first != nil {
		switch first.Kind {
		case MethodFake, MethodFakeKnown:
			fake := rule.Fake
			if fake == nil {
				break
			}
			if first.Kind == MethodFakeKnown && protocol == ProtocolUnknown {
				batch.Reason = "fakeknown requires a recognized protocol"
				break
			}
			for _, payload := range fake.Payloads {
				if payload.Protocol != protocol {
					continue
				}
				for repeat := 0; repeat < fake.Repeats; repeat++ {
					id, _ := allocator.Value()
					generated, err := BuildUDPEx(packet, BuildSpec{TTL: ttlValue(fake, packet, Facts{}), TTLSet: true,
						IPID: id, IPIDSet: true, Rand: random, Payload: payload.Data,
						Fooling:    mergeFooling(fake.Fooling, mods.Fooling),
						CorruptSum: fake.Fooling.BadChecksum || mods.Fooling.BadChecksum})
					if err != nil {
						return nil, err
					}
					batch.Packets = append(batch.Packets, generated)
				}
			}
		case MethodHopByHop, MethodDestOpt, MethodIPFrag1:
			if packet.Family != FamilyIPv6 {
				batch.Reason = "IPv6 extension-header stage applies only to IPv6"
				break
			}
			if second != nil {
				// Upstream keeps fooling_orig and falls through to the
				// second stage; every real second-stage datagram carries
				// the header (see origExt above).
				break
			}
			header := uint8(0)
			if first.Kind == MethodDestOpt {
				header = 60
			} else if first.Kind == MethodIPFrag1 {
				header = 44
			}
			inserted, err := InsertIPv6Extension(packet.Raw, header)
			if err != nil {
				return nil, err
			}
			batch.Packets = append(batch.Packets, inserted)
			batch.Original = VerdictDrop
			return batch, nil
		}
	}
	if second != nil {
		switch second.Kind {
		case MethodUDPLen:
			if rule.UDPLen == nil {
				break
			}
			payload := packet.Payload
			increment := rule.UDPLen.Increment
			if increment > 0 {
				if len(payload)+increment > 0xffff {
					// Upstream clamps the padded datagram to the u16 range;
					// reject instead of emitting a wrapped length.
					batch.Reason = "udplen increment exceeds the maximum UDP length"
					return batch, nil
				}
				padded := make([]byte, len(payload)+increment)
				copy(padded, payload)
				fillPattern(padded[len(payload):], rule.UDPLen.Pattern, 0)
				payload = padded
			} else if increment < 0 {
				// Upstream prepare_udp_segment6 clamps a decrement so the
				// payload keeps at least one byte.
				minimum := 1
				if len(payload)+increment < minimum {
					payload = payload[:minimum]
				} else {
					payload = payload[:len(payload)+increment]
				}
			}
			for repeat := 0; repeat < mods.Repeats; repeat++ {
				id, _ := allocator.Value()
				// Upstream udplen/tamper use ttl_orig (not desync_ttl), so the
				// captured TTL is preserved. Only the fooling_orig extension
				// chain is added on IPv6.
				generated, err := BuildUDPEx(packet, BuildSpec{IPID: id, IPIDSet: true,
					Rand: random, Payload: payload, ExtHeaders: origExt})
				if err != nil {
					return nil, err
				}
				batch.Packets = append(batch.Packets, generated)
			}
		case MethodTamper:
			if !IsDhtD1(packet.Payload) {
				batch.Reason = "payload is not a tamperable DHT D1 query"
				return batch, nil
			}
			tampered := append([]byte("d2:001:x"), packet.Payload[1:]...)
			for repeat := 0; repeat < mods.Repeats; repeat++ {
				id, _ := allocator.Value()
				generated, err := BuildUDPEx(packet, BuildSpec{IPID: id, IPIDSet: true,
					Rand: random, Payload: tampered, ExtHeaders: origExt})
				if err != nil {
					return nil, err
				}
				batch.Packets = append(batch.Packets, generated)
			}
		case MethodIPFrag2:
			raw := packet.Raw
			if len(origExt) > 0 {
				// Upstream inserts the simple hop-by-hop/destination-options
				// header before ip_frag. ipfrag1 is not nested (it would add
				// a second fragment header), exactly like the TCP path.
				var insertErr error
				for index := len(origExt) - 1; index >= 0; index-- {
					raw, insertErr = InsertIPv6Extension(raw, origExt[index])
					if insertErr != nil {
						return nil, insertErr
					}
				}
			}
			firstFragment, secondFragment, err := FragmentPair(raw, rule.IPFragPosUDP, 0, random)
			if err != nil {
				return nil, err
			}
			batch.Packets = append(batch.Packets, firstFragment, secondFragment)
			batch.Original = VerdictDrop
		default:
			return nil, fmt.Errorf("desync: second stage %s is not applicable to UDP", second.Name)
		}
	}
	return batch, nil
}

package desync

import (
	"fmt"
)

// Batch is one ordered replacement plan for a single captured original packet.
type Batch struct {
	// Packets are raw packets to send before the original disposition.
	Packets [][]byte
	// Original is the terminal disposition of the captured packet.
	Original Verdict
	// Modified is this captured packet with in-place header changes. It is
	// required when Original is VerdictModify and must otherwise be nil.
	Modified []byte
	// Reason describes why a transformation was skipped or reduced.
	Reason string
}

// PlanTCP plans fake and split transformations for one captured TCP packet.
// message is the reassembled logical message and offset is the packet's
// payload offset inside it.
func planTCPLegacy(rule *Rule, packet *Packet, message []byte, offset int, facts Facts) (*Batch, error) {
	batch := &Batch{Original: VerdictPass}
	if len(packet.Payload) == 0 {
		return batch, nil
	}
	baseSeq := packet.TCPSeq
	packetEnd := offset + len(packet.Payload)
	for _, method := range rule.Methods {
		switch method.Kind {
		case MethodFake:
			fake := rule.Fake
			if fake == nil {
				continue
			}
			protocol := ProtocolUnknown
			if facts.HostKnown {
				protocol = ruleProtocol(rule, facts)
			}
			sent := 0
			// Same upstream placement as the staged planner: fakes ride the
			// captured packet's sequence; tcp_mod.seq advances per payload item
			// after its repeats (nfq/desync.c:1972, :2002-2008).
			sequence := baseSeq
			for _, payload := range fake.Payloads {
				if payload.Protocol != protocol {
					continue
				}
				for repeat := 0; repeat < fake.Repeats; repeat++ {
					mods := TCPMods{Seq: &sequence, TTL: uint8(fake.TTL), IPIDSet: true, CorruptSum: fake.Fooling.BadChecksum}
					if fake.Fooling.Timestamp {
						mods.TSIncrement = fake.TSIncrement
					}
					if rule.IPID == IPIDZero {
						mods.IPID = 0
					}
					if fake.Fooling.BadSequence {
						badAck := packet.TCPAck
						mods.Ack = &badAck
					}
					generated, err := BuildTCP(packet, payload.Data, mods)
					if err != nil {
						// Upstream does not synthesize timestamps: a ts
						// fooling request on a packet without the option is
						// ineffective rather than fatal.
						if fake.Fooling.Timestamp {
							mods.TSIncrement = 0
							generated, err = BuildTCP(packet, payload.Data, mods)
						}
						if err != nil {
							return nil, fmt.Errorf("desync: build fake packet: %w", err)
						}
					}
					batch.Packets = append(batch.Packets, generated)
					sent++
				}
				if fake.Seq {
					sequence += uint32(len(payload.Data))
				}
			}
			if sent == 0 {
				batch.Reason = "no fake payload for protocol " + protocol.String()
			}
		case MethodMultiSplit:
			spec := rule.MultiSplit
			if spec == nil {
				continue
			}
			segments, err := planMultiSplit(spec, packet, facts, offset, packetEnd)
			if err != nil {
				return nil, err
			}
			if len(segments) > 0 {
				batch.Packets = append(batch.Packets, segments...)
				batch.Original = VerdictDrop
			}
		case MethodMultiDisorder:
			spec := rule.MultiDisorder
			if spec == nil {
				continue
			}
			segments, err := planMultiDisorder(spec, packet, facts, offset, packetEnd)
			if err != nil {
				return nil, err
			}
			if len(segments) > 0 {
				batch.Packets = append(batch.Packets, segments...)
				batch.Original = VerdictDrop
			}
		}
	}
	return batch, nil
}

func ruleProtocol(rule *Rule, facts Facts) Protocol {
	if len(rule.Protocols) > 0 {
		for _, protocol := range rule.Protocols {
			if protocol == facts.Protocol {
				return protocol
			}
		}
		return rule.Protocols[0]
	}
	return facts.Protocol
}

// localizePositions resolves symbolic positions against the whole message and
// then keeps only boundaries strictly inside this packet's payload.
func localizePositions(spec *SplitSpec, facts Facts, offset int, packetEnd int) []int {
	absolute := ResolvePositions(spec.Positions, facts)
	local := make([]int, 0, len(absolute))
	for _, position := range absolute {
		if position <= offset || position >= packetEnd {
			continue
		}
		local = append(local, position-offset)
	}
	return local
}

func overlapBytes(spec *SplitSpec, length int) []byte {
	if length <= 0 || len(spec.OverlapPattern) == 0 {
		return nil
	}
	pattern := make([]byte, length)
	for index := range pattern {
		pattern[index] = spec.OverlapPattern[index%len(spec.OverlapPattern)]
	}
	return pattern
}

func planMultiSplit(spec *SplitSpec, packet *Packet, facts Facts, offset int, packetEnd int) ([][]byte, error) {
	payload := packet.Payload
	positions := localizePositions(spec, facts, offset, packetEnd)
	if len(positions) == 0 {
		return nil, nil
	}
	overlap := spec.Overlap
	if spec.OverlapIsPos {
		overlap = ResolveSeqOverlap(spec.OverlapPosition, facts, facts.MessageLength)
	}
	segments := make([][]byte, 0, len(positions)+1)
	from := 0
	for index := 0; index <= len(positions); index++ {
		to := len(payload)
		if index < len(positions) {
			to = positions[index]
		}
		if to <= from {
			continue
		}
		segment := payload[from:to]
		sequence := packet.TCPSeq + uint32(from)
		// Upstream applies seqovl only to the first interval of the
		// reassembled request (i == 0 && reasm_offset == 0).
		if index == 0 && offset == 0 && overlap > 0 {
			prefix := overlapBytes(spec, overlap)
			segment = append(prefix, segment...)
			sequence -= uint32(overlap)
		}
		mods := TCPMods{Seq: &sequence, ExtHeaders: facts.OrigExtHeaders}
		if spec.OverlapIsPos {
			mods.IPIDSet = true
		}
		generated, err := BuildTCP(packet, segment, mods)
		if err != nil {
			return nil, fmt.Errorf("desync: build multisplit segment: %w", err)
		}
		segments = append(segments, generated)
		from = to
	}
	return segments, nil
}

func planMultiDisorder(spec *SplitSpec, packet *Packet, facts Facts, offset int, packetEnd int) ([][]byte, error) {
	payload := packet.Payload
	positions := localizePositions(spec, facts, offset, packetEnd)
	if len(positions) == 0 {
		return nil, nil
	}
	overlap := spec.Overlap
	if spec.OverlapIsPos {
		overlap = ResolveSeqOverlap(spec.OverlapPosition, facts, facts.MessageLength)
	}
	segments := make([][]byte, 0, len(positions)+1)
	// Descending loop: i = count-1 .. -1, with from=positions[i] (0 for -1)
	// and to inherited from the previous iteration. Upstream applies the
	// overlap to the interval whose loop index is 0, i.e. the interval that
	// begins at the first split boundary - not the first transmitted packet.
	for index := len(positions) - 1; index >= -1; index-- {
		from := 0
		if index >= 0 {
			from = positions[index]
		}
		to := len(payload)
		if index+1 < len(positions) {
			to = positions[index+1]
		}
		if to <= from {
			continue
		}
		segment := payload[from:to]
		sequence := packet.TCPSeq + uint32(from)
		if index == 0 && overlap > 0 {
			if overlap >= from {
				// Upstream cancels the overlap rather than producing a
				// negative sequence interval.
				overlap = 0
			} else {
				prefix := overlapBytes(spec, overlap)
				segment = append(prefix, segment...)
				sequence -= uint32(overlap)
			}
		}
		mods := TCPMods{Seq: &sequence, IPIDSet: true, ExtHeaders: facts.OrigExtHeaders}
		generated, err := BuildTCP(packet, segment, mods)
		if err != nil {
			return nil, fmt.Errorf("desync: build multidisorder segment: %w", err)
		}
		segments = append(segments, generated)
	}
	return segments, nil
}

// PlanUDP plans the UDP fake stage. The original datagram is always delivered:
// UDP fakes are decoys, not replacements.
func planUDPFakeLegacy(rule *Rule, packet *Packet) (*Batch, error) {
	batch := &Batch{Original: VerdictPass}
	if len(packet.Payload) == 0 {
		return batch, nil
	}
	protocol := classifyUDPPayload(packet)
	for _, method := range rule.Methods {
		if method.Kind != MethodFake {
			return nil, fmt.Errorf("desync: method %d is not applicable to UDP", method.Kind)
		}
		fake := rule.Fake
		for _, payload := range fake.Payloads {
			if payload.Protocol != protocol {
				continue
			}
			for repeat := 0; repeat < fake.Repeats; repeat++ {
				mods := TCPMods{TTL: uint8(fake.TTL), IPIDSet: true, CorruptSum: fake.Fooling.BadChecksum}
				if rule.IPID == IPIDZero {
					mods.IPID = 0
				}
				generated, err := BuildUDP(packet, payload.Data, mods)
				if err != nil {
					return nil, fmt.Errorf("desync: build udp fake: %w", err)
				}
				batch.Packets = append(batch.Packets, generated)
			}
		}
	}
	return batch, nil
}

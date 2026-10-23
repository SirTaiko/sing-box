package desync

import (
	"encoding/binary"
	"fmt"
)

// PlanReply computes the in-place reply-direction transformations of one
// captured packet, exactly the subset upstream applies before its
// `if (bReverse) return verdict`:
//
//   - `wsize` rewrites the advertised window (and may lower the window scale)
//     of an observed SYN-ACK only;
//   - `synack_split=syn` clears TH_ACK of an observed SYN-ACK, replacing it in
//     place with a SYN segment.
//
// `wssize`, `orig`, `dup` and the fake/split families are original-direction
// only and are never applied here. The caller must never re-egress the packet
// through a raw injection socket on the inbound path: the modified bytes are
// delivered in place by the native disposition.
func PlanReply(rule *Rule, packet *Packet) ([]byte, error) {
	if rule == nil || packet.Transport != TransportTCP {
		return nil, nil
	}
	synAck := packet.TCPFlags&tcpFlagSYN != 0 && packet.TCPFlags&tcpFlagACK != 0
	if !synAck {
		return nil, nil
	}
	var (
		modified []byte
		changed  bool
	)
	if rule.WSize != nil {
		modified = append([]byte(nil), packet.Raw...)
		windowChanged, err := rewriteWindowInPlace(modified, packet, uint16(rule.WSize.Size), rule.WSize.Scale, rule.WSize.ScaleSet)
		if err != nil {
			return nil, fmt.Errorf("desync: reply window rewrite: %w", err)
		}
		changed = windowChanged
	}
	if rule.SynackSplit == SynAckSplitSYN {
		if modified == nil {
			modified = append([]byte(nil), packet.Raw...)
		}
		tcp := packet.IPHeaderLen
		if modified[tcp+13]&tcpFlagACK != 0 {
			modified[tcp+13] &^= tcpFlagACK
			changed = true
		}
	}
	if !changed {
		return nil, nil
	}
	if err := refreshChecksums(modified, packet); err != nil {
		return nil, fmt.Errorf("desync: reply rewrite checksum: %w", err)
	}
	return modified, nil
}

// applyObservedSynAck ports the SYN-ACK block upstream evaluates before its
// direction branch: `wsize` rewriting and the in-place `synack-split=syn`
// TH_ACK clear. It mutates the batch in place (Modify) and never injects.
func applyObservedSynAck(rule *Rule, packet *Packet, batch *Batch) (*Packet, error) {
	if rule == nil || packet.Transport != TransportTCP ||
		packet.TCPFlags&tcpFlagSYN == 0 || packet.TCPFlags&tcpFlagACK == 0 {
		return packet, nil
	}
	if rule.WSize == nil && rule.SynackSplit != SynAckSplitSYN {
		return packet, nil
	}
	var raw []byte
	if batch.Modified != nil {
		raw = append([]byte(nil), batch.Modified...)
	} else {
		raw = append([]byte(nil), packet.Raw...)
	}
	changed := false
	if rule.WSize != nil {
		windowChanged, err := rewriteWindowInPlace(raw, packet, uint16(rule.WSize.Size), rule.WSize.Scale, rule.WSize.ScaleSet)
		if err != nil {
			return nil, err
		}
		changed = windowChanged
	}
	if rule.SynackSplit == SynAckSplitSYN && raw[packet.IPHeaderLen+13]&tcpFlagACK != 0 {
		raw[packet.IPHeaderLen+13] &^= tcpFlagACK
		changed = true
	}
	if !changed {
		return packet, nil
	}
	if err := refreshChecksums(raw, packet); err != nil {
		return nil, err
	}
	batch.Modified = raw
	if batch.Original != VerdictDrop {
		batch.Original = VerdictModify
	}
	working := *packet
	working.Raw = raw
	working.TCPFlags = raw[packet.IPHeaderLen+13]
	working.TCPWindow = binary.BigEndian.Uint16(raw[packet.IPHeaderLen+14 : packet.IPHeaderLen+16])
	return &working, nil
}

// SynAckSplitPackets ports the upstream `--synack-split=synack|acksyn`
// replacement of an original-direction SYN-ACK: the captured packet is cleared
// of TH_ACK (the SYN part) and an ACK-only segment is generated from it, then
// both are sent in the configured order and the original is dropped. The
// `syn` selector is an in-place modification (PlanReply), not a two-packet
// split; upstream applies it in both directions while the two-packet split is
// only reachable on a forward SYN-ACK.
func SynAckSplitPackets(rule *Rule, packet *Packet) ([][]byte, error) {
	if rule == nil || rule.SynackSplit == SynAckSplitNone || packet.Transport != TransportTCP {
		return nil, nil
	}
	if packet.TCPFlags&tcpFlagSYN == 0 || packet.TCPFlags&tcpFlagACK == 0 {
		return nil, nil
	}
	if rule.SynackSplit == SynAckSplitSYN {
		return nil, nil
	}
	synPacket := append([]byte(nil), packet.Raw...)
	synPacket[packet.IPHeaderLen+13] &^= tcpFlagACK
	if err := refreshChecksums(synPacket, packet); err != nil {
		return nil, err
	}
	ackFlags := uint8(tcpFlagACK)
	seq := packet.TCPSeq
	ack := packet.TCPAck
	window := packet.TCPWindow
	ackPacket, err := BuildTCPEx(packet, BuildSpec{
		Flags: &ackFlags, Seq: &seq, Ack: &ack, Window: &window,
		CopyOptions: true, Payload: nil,
	})
	if err != nil {
		return nil, fmt.Errorf("desync: synack split ACK part: %w", err)
	}
	// Upstream builds the ACK part with IP4_IP_ID_FIX(dis->ip, dp->ip_id_mode):
	// the observed original ID for seq/same, zero for the zero mode and a fresh
	// value for rnd.
	if packet.Family == FamilyIPv4 {
		binary.BigEndian.PutUint16(ackPacket[4:6], dupIPIDFix(rule.IPID, packet, DefaultRand))
		ackPacket[10], ackPacket[11] = 0, 0
		binary.BigEndian.PutUint16(ackPacket[10:12], inetChecksum(ackPacket[:packet.IPHeaderLen], 0))
	}
	if rule.SynackSplit == SynAckSplitACKFirst {
		return [][]byte{ackPacket, synPacket}, nil
	}
	return [][]byte{synPacket, ackPacket}, nil
}

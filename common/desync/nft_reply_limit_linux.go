//go:build linux

package desync

// NFQWS_*_PKT_IN: the reply-direction kernel conntrack packet bound.
//
// The pinned github.com/sagernet/nftables v0.3.0-mod.4 marshals
// NFTA_CT_DIRECTION only for the SRC/DST/PROTOSRC/PROTODST ct keys
// (expr/ct.go marshalData). `ct reply packets` therefore cannot be expressed
// through expr.Ct, and every other layer of that expression is closed to
// external packages (expr.Any requires the unexported expr.marshal method).
//
// The smallest reproducible correction that keeps the dependency, its version
// and the existing rule path untouched is to encode exactly the one missing
// expression here and emit the complete rule as a single nftables batch on an
// owned NETLINK_NETFILTER socket. Every other expression of the rule is
// produced by the pinned library itself (expr.Marshal), so only the direction
// attribute differs from what the library would emit for NFT_CT_PKTS.
//
// Encoding follows the kernel UAPI (linux/netfilter/nf_tables.h enum
// nft_ct_attributes: NFTA_CT_DREG=1, NFTA_CT_KEY=2, NFTA_CT_DIRECTION=3) and
// the pinned library's attribute order (KEY, DREG, DIRECTION). Direction is a
// 32-bit big-endian value, exactly like the library's own direction emission
// for the keys it supports (libnftnl nftnl_expr_ct_set_u32/htonl shape).

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

// nftCtDirection values of the kernel nft_ct direction attribute
// (IP_CT_DIR_ORIGINAL / IP_CT_DIR_REPLY).
const (
	nftCtDirectionOriginal = 0
	nftCtDirectionReply    = 1
)

// Sequence numbers of the three messages of one owned batch. Only the rule
// message requests an acknowledgement; the reply must carry the same sequence.
const (
	nftBatchSeqBegin  = 1
	nftBatchSeqRule   = 2
	nftBatchSeqEnd    = 3
	nftBatchAckBytes  = 20
	nftBatchRecvQueue = 8192
)

// marshalCtExpression encodes one `ct key [direction] dreg <register>`
// expression. It is byte-identical to expr.Marshal of the pinned library for
// the keys where the library emits a direction (Src/Dst/ProtoSrc/ProtoDst);
// for NFT_CT_PKTS it is the library output plus the missing direction
// attribute.
func marshalCtExpression(key expr.CtKey, direction uint32, register uint32) ([]byte, error) {
	data, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_CT_KEY, Data: binary.BigEndian.AppendUint32(nil, uint32(key))},
		{Type: unix.NFTA_CT_DREG, Data: binary.BigEndian.AppendUint32(nil, register)},
		{Type: unix.NFTA_CT_DIRECTION, Data: binary.BigEndian.AppendUint32(nil, direction)},
	})
	if err != nil {
		return nil, err
	}
	return netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_EXPR_NAME, Data: []byte("ct\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, Data: data},
	})
}

// appendNetlinkMessage appends one nlmsghdr + payload, padded to the netlink
// message alignment.
func appendNetlinkMessage(dst []byte, typ uint16, flags netlink.HeaderFlags, seq uint32, data []byte) []byte {
	offset := len(dst)
	dst = append(dst, make([]byte, 16)...)
	binary.NativeEndian.PutUint32(dst[offset:], uint32(16+len(data)))
	binary.NativeEndian.PutUint16(dst[offset+4:], typ)
	binary.NativeEndian.PutUint16(dst[offset+6:], uint16(flags))
	binary.NativeEndian.PutUint32(dst[offset+8:], seq)
	binary.NativeEndian.PutUint32(dst[offset+12:], 0)
	dst = append(dst, data...)
	for len(dst)%4 != 0 {
		dst = append(dst, 0)
	}
	return dst
}

// nfgenmsg is the 4-byte nfnetlink message header (family, version, res_id).
func nfgenmsg(family byte, resID uint16) []byte {
	data := make([]byte, 4)
	data[0] = family
	data[1] = unix.NFNETLINK_V0
	binary.BigEndian.PutUint16(data[2:], resID)
	return data
}

// marshalRuleBatch encodes one atomic nftables batch that adds a single rule to
// an existing table/chain. The table and chain must already have been
// committed by the library transaction.
func marshalRuleBatch(family byte, table string, chain string, expressions [][]byte) ([]byte, error) {
	exprAttributes := make([]netlink.Attribute, 0, len(expressions))
	for _, expression := range expressions {
		if len(expression) == 0 {
			return nil, errors.New("desync: empty nftables expression")
		}
		exprAttributes = append(exprAttributes, netlink.Attribute{
			Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM,
			Data: expression,
		})
	}
	expressionData, err := netlink.MarshalAttributes(exprAttributes)
	if err != nil {
		return nil, err
	}
	ruleData, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: expressionData},
	})
	if err != nil {
		return nil, err
	}

	batch := make([]byte, 0, len(ruleData)+64)
	batch = appendNetlinkMessage(batch, unix.NFNL_MSG_BATCH_BEGIN, netlink.Request,
		nftBatchSeqBegin, nfgenmsg(0, unix.NFNL_SUBSYS_NFTABLES))
	batch = appendNetlinkMessage(batch, uint16((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE),
		netlink.Request|netlink.Acknowledge|netlink.Create, nftBatchSeqRule,
		append(nfgenmsg(family, 0), ruleData...))
	batch = appendNetlinkMessage(batch, unix.NFNL_MSG_BATCH_END, netlink.Request,
		nftBatchSeqEnd, nfgenmsg(0, unix.NFNL_SUBSYS_NFTABLES))
	return batch, nil
}

// nftBatchSender is the transport seam of one rule batch. Production sends on a
// dedicated NETLINK_NETFILTER socket; tests feed a recording implementation so
// the exact kernel bytes are verifiable without netfilter privileges.
type nftBatchSender interface {
	Send(batch []byte) error
	Close() error
}

var newNftBatchSender = func() (nftBatchSender, error) { return openNftBatchSender() }

type netlinkBatchSender struct {
	fd int
}

func openNftBatchSender() (nftBatchSender, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("desync: open nftables netlink socket: %w", err)
	}
	if err = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("desync: bind nftables netlink socket: %w", err)
	}
	timeout := unix.Timeval{Sec: 2}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("desync: set nftables netlink timeout: %w", err)
	}
	return &netlinkBatchSender{fd: fd}, nil
}

func (s *netlinkBatchSender) Close() error {
	return unix.Close(s.fd)
}

// Send writes the whole batch as one datagram (a batch must not be split
// across datagrams) and waits for the rule acknowledgement, returning the
// kernel errno when the rule was rejected.
func (s *netlinkBatchSender) Send(batch []byte) error {
	if err := unix.Sendto(s.fd, batch, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("desync: send nftables rule batch: %w", err)
	}
	buffer := make([]byte, nftBatchRecvQueue)
	for {
		length, _, err := unix.Recvfrom(s.fd, buffer, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				return errors.New("desync: nftables rule batch was not acknowledged")
			}
			return fmt.Errorf("desync: receive nftables rule acknowledgement: %w", err)
		}
		acknowledged, ackErr := scanNftAcks(buffer[:length], nftBatchSeqRule)
		if ackErr != nil {
			return ackErr
		}
		if acknowledged {
			return nil
		}
	}
}

// scanNftAcks scans one received netlink datagram. A zero NLMSG_ERROR for the
// wanted sequence is the rule acknowledgement; any non-zero error is returned
// as the kernel rejection of the batch.
func scanNftAcks(data []byte, wantSeq uint32) (bool, error) {
	acknowledged := false
	for offset := 0; offset+16 <= len(data); {
		length := int(binary.NativeEndian.Uint32(data[offset:]))
		if length < 16 || offset+length > len(data) {
			return false, errors.New("desync: malformed nftables netlink reply")
		}
		typ := binary.NativeEndian.Uint16(data[offset+4:])
		seq := binary.NativeEndian.Uint32(data[offset+8:])
		if typ == unix.NLMSG_ERROR && length >= nftBatchAckBytes {
			code := int32(binary.NativeEndian.Uint32(data[offset+16:]))
			if code != 0 {
				return false, fmt.Errorf("desync: nftables rejected the reply packet limit: %w", unix.Errno(-code))
			}
			if seq == wantSeq {
				acknowledged = true
			}
		}
		offset += (length + 3) &^ 3
	}
	return acknowledged, nil
}

// replyLimitExpressions returns the kernel conntrack bound of the reply
// direction: the inclusive reply packet set 1..N. It is the exact counterpart
// of the source `ct reply packets 1-N` inbound rule. The direction attribute is
// always REPLY; the original direction is never substituted.
func replyLimitExpressions(limit packetLimit) (ctExpression []byte, comparison []byte, err error) {
	ctExpression, err = marshalCtExpression(expr.CtKeyPKTS, nftCtDirectionReply, 1)
	if err != nil {
		return nil, nil, err
	}
	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, uint64(limit.value))
	comparison, err = expr.Marshal(0, &expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: value})
	if err != nil {
		return nil, nil, err
	}
	return ctExpression, comparison, nil
}

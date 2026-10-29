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
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

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

// ---------------------------------------------------------------------------
// Persistent-anchor metadata transport.
//
// The selected-A contract needs four things the pinned library does not offer:
// chain userdata, exclusive (NLM_F_EXCL) table/chain creation, full chain
// attribute readback, and a typed negative acknowledgement of the
// BEGIN/GETGEN/END fence. All four are plain nfnetlink attributes, so this
// section adds one bounded metadata client over an owned NETLINK_NETFILTER
// socket. It is not a general nftables stack: it encodes only the attributes
// listed below, and every packet-path rule still uses the pinned expression
// encoders.
//
// Port classes are the contract's explicit split: a control-only metadata
// socket binds a nonzero port with the high bit clear, a queue socket binds a
// nonzero port with the high bit set. Neither class ever autobinds, so a
// crashing control socket can never collide with a cooperating queue socket.
const (
	// nftQueuePortBit is set in every queue-socket port.
	nftQueuePortBit = uint32(1) << 31
	// nftControlPortBit marks the control-only half of the port space.
	nftControlPortBit = uint32(1) << 30
	// nftControlPortSpan bounds the control candidate search.
	nftControlPortSpan = uint32(1) << 12
	// nftQueuePortSpan bounds the queue candidate search.
	nftQueuePortSpan = uint32(1) << 12

	// Attribute numbers of the kernel UAPI that the pinned x/sys version does
	// not describe (linux/netfilter/nf_tables.h, v6.8):
	// nft_table_attributes NFTA_TABLE_USERDATA, nft_chain_attributes
	// NFTA_CHAIN_FLAGS/NFTA_CHAIN_USERDATA.
	nftAttrTableUserdata = 0x6
	nftAttrChainFlags    = 0xa
	nftAttrChainUserdata = 0xc

	// nftTableFlagsDormant is NFT_TABLE_F_DORMANT: an anchor table must never
	// carry it.
	nftTableFlagsDormant = 0x1
	// nftChainFlagHWOffload is NFT_CHAIN_HW_OFFLOAD, the only chain flag the
	// kernel reports back; an anchor base chain may not have it.
	nftChainFlagHWOffload = 0x2

	// nftVerdictAccept is NF_ACCEPT, the explicit base-chain policy of the
	// fixed anchors. x/sys does not export the netfilter verdict enum.
	nftVerdictAccept = uint32(1)

	// nftMetadataTimeout bounds one metadata request/reply exchange.
	nftMetadataTimeout = 2 * time.Second

	// nftMetadataBuffer bounds one received netlink datagram.
	nftMetadataBuffer = 1 << 16
	// nftMetadataCandidates bounds explicit port allocation attempts.
	nftMetadataCandidates = 64
)

// nftRequest is one message of a metadata batch (or a single dump request).
type nftRequest struct {
	typ   uint16
	flags netlink.HeaderFlags
	data  []byte
}

// nftReply is one received netlink message of a metadata exchange.
type nftReply struct {
	typ  uint16
	seq  uint32
	port uint32
	data []byte
}

// nftNetlink is one short-lived metadata socket of the control class.
type nftNetlink struct {
	fd     int
	port   uint32
	seq    uint32
	buffer []byte
	// datagram is the raw datagram boundary of this socket. Production leaves
	// it nil and uses the bound netlink fd. The model tests script their own
	// datagrams and sender addresses through the same receive/batch code, so
	// no test-only peer acceptor or second demultiplexer exists.
	datagram nftDatagramIO
}

// nftDatagramIO is the syscall-level send/receive boundary of one metadata
// socket. It exists only for deterministic model tests: production leaves
// nftNetlink.datagram nil and reaches the real NETLINK_NETFILTER socket.
type nftDatagramIO interface {
	send(datagram []byte) error
	recv(buffer []byte) (int, *unix.SockaddrNetlink, error)
}

// reserveNftPort returns one explicit port of the requested class. The bind
// itself is the authority: a candidate the kernel refuses is skipped without
// touching anything else. No autobind path exists.
func reserveNftPort(fd int, queueClass bool) (uint32, error) {
	var start uint32
	if queueClass {
		buffer := make([]byte, 4)
		if _, err := rand.Read(buffer); err != nil {
			return 0, fmt.Errorf("desync: entropy for netlink port selection: %w", err)
		}
		start = binary.BigEndian.Uint32(buffer) % nftQueuePortSpan
		start |= nftQueuePortBit
	} else {
		buffer := make([]byte, 4)
		if _, err := rand.Read(buffer); err != nil {
			return 0, fmt.Errorf("desync: entropy for netlink port selection: %w", err)
		}
		start = nftControlPortBit | binary.BigEndian.Uint32(buffer)%nftControlPortSpan
	}
	for index := uint32(0); index < nftMetadataCandidates; index++ {
		candidate := start + index*2654435761
		if queueClass {
			candidate &= ^uint32(0x7fffffff)
			candidate |= nftQueuePortBit
			if candidate == 0 {
				continue
			}
		} else {
			candidate &= 0x3fffffff
			candidate |= nftControlPortBit
		}
		err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: candidate})
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, unix.EADDRINUSE) && !errors.Is(err, unix.EINVAL) {
			return 0, fmt.Errorf("desync: bind netlink metadata port %#x: %w", candidate, err)
		}
	}
	return 0, errors.New("desync: no free netlink metadata port in the selected class")
}

// openNftNetlink opens one metadata socket of the control class. It never uses
// the pinned library's dial path, so no ForkLock fallback is reachable from a
// caller that already holds the fork-read token.
func openNftNetlink() (*nftNetlink, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("desync: open nftables metadata socket: %w", err)
	}
	port, err := reserveNftPort(fd, false)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("desync: read nftables metadata port: %w", err)
	}
	bound, ok := name.(*unix.SockaddrNetlink)
	if !ok || bound.Pid != port {
		unix.Close(fd)
		return nil, fmt.Errorf("desync: nftables metadata port %#x was not bound", port)
	}
	timeout := unix.Timeval{Sec: int64(nftMetadataTimeout / time.Second)}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("desync: set nftables metadata timeout: %w", err)
	}
	return &nftNetlink{fd: fd, port: port, buffer: make([]byte, nftMetadataBuffer)}, nil
}

func (c *nftNetlink) Close() error {
	if c == nil || c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

func (c *nftNetlink) nextSeq() uint32 {
	c.seq++
	return c.seq
}

// send writes one whole datagram. A batch is never split.
func (c *nftNetlink) send(datagram []byte) error {
	if c.datagram != nil {
		if err := c.datagram.send(datagram); err != nil {
			return fmt.Errorf("desync: send nftables metadata request: %w", err)
		}
		return nil
	}
	if err := unix.Sendto(c.fd, datagram, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("desync: send nftables metadata request: %w", err)
	}
	return nil
}

// recvDatagram reads exactly one datagram and returns a private copy plus the
// kernel sender address. The copy is required by the fence receipt, which must
// retain the actual request/reply bytes.
func (c *nftNetlink) recvDatagram() ([]byte, *unix.SockaddrNetlink, error) {
	var (
		length int
		sender *unix.SockaddrNetlink
		err    error
	)
	if c.datagram != nil {
		length, sender, err = c.datagram.recv(c.buffer)
	} else {
		var raw unix.Sockaddr
		length, raw, err = unix.Recvfrom(c.fd, c.buffer, 0)
		if raw != nil {
			sender, _ = raw.(*unix.SockaddrNetlink)
		}
	}
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, errNftMetadataTimeout
		}
		return nil, nil, fmt.Errorf("desync: receive nftables metadata reply: %w", err)
	}
	if sender == nil {
		return nil, nil, errors.New("desync: nftables metadata reply came from a foreign netlink peer")
	}
	if length == len(c.buffer) {
		return nil, sender, errors.New("desync: nftables metadata reply was truncated")
	}
	return append([]byte(nil), c.buffer[:length]...), sender, nil
}

// receive reads one datagram of a strict ordinary exchange (a dump or a
// standalone GETGEN read) and parses its messages. Only the plain kernel peer
// (pid0/groups0) is accepted here: a nonzero sender group is never a dump
// record or an acknowledgement. The batch lane, which legitimately receives
// the kernel's request-bound NLM_F_ECHO copies, has its own receiveBatch.
func (c *nftNetlink) receive() ([]nftReply, error) {
	data, address, err := c.recvDatagram()
	if err != nil {
		return nil, err
	}
	if classifyNftPeer(address) != nftPeerKernel {
		return nil, errNftForeignMetadataPeer
	}
	return parseNftDatagram(data)
}

// nftNfTablesGroup is NFNLGRP_NFTABLES (linux/netfilter/nfnetlink.h, v6.8): the
// nf_tables notification group. An NLM_F_ECHO request is answered by the
// kernel notification copy delivered to the requesting port; the captured
// reply (Q run545) carries sender sockaddr_nl pid=0 and nl_groups=64, i.e.
// netlink_group_mask(NFNLGRP_NFTABLES) == 1<<6, even though this socket never
// subscribed to the group, and its outer nlmsg_pid is the socket's bound port.
// That is the only nonzero sender group an ordinary metadata reply may carry;
// any other group, and any nonzero sender pid, is a foreign peer.
const (
	nftNfTablesGroup = 7
	nftEchoGroupMask = uint32(1) << (nftNfTablesGroup - 1)
)

// nftPeerClass is the origin class of one ordinary metadata datagram.
type nftPeerClass uint8

const (
	nftPeerForeign nftPeerClass = iota
	nftPeerKernel
	nftPeerKernelEcho
)

// classifyNftPeer classifies the sender address of one received metadata
// datagram. Only the kernel (nl_pid=0) may answer; the echo class additionally
// requires exactly the nftables notification group mask.
func classifyNftPeer(peer *unix.SockaddrNetlink) nftPeerClass {
	switch {
	case peer == nil || peer.Pid != 0:
		return nftPeerForeign
	case peer.Groups == 0:
		return nftPeerKernel
	case peer.Groups == nftEchoGroupMask:
		return nftPeerKernelEcho
	default:
		return nftPeerForeign
	}
}

var errNftForeignMetadataPeer = errors.New("desync: nftables metadata reply came from a foreign netlink peer")

// receiveBatch reads one datagram of an ordinary metadata batch. The kernel
// answers with plain ACKs (pid0/groups0) and, for a request sent with
// NLM_F_ECHO, queues the request-bound notification copy before the batch
// acknowledgement list. receiveBatch admits that one kernel echo class and
// reports it so batch can require a rule notification, not an ACK, on that
// lane.
func (c *nftNetlink) receiveBatch() ([]nftReply, bool, error) {
	data, address, err := c.recvDatagram()
	if err != nil {
		return nil, false, err
	}
	switch classifyNftPeer(address) {
	case nftPeerKernel:
		replies, parseErr := parseNftDatagram(data)
		return replies, false, parseErr
	case nftPeerKernelEcho:
		replies, parseErr := c.parseNftEchoDatagram(data)
		return replies, true, parseErr
	default:
		return nil, false, errNftForeignMetadataPeer
	}
}

// parseNftEchoDatagram parses one kernel ECHO notification copy. NEWRULE is the
// only ordinary metadata message this client sends with NLM_F_ECHO, so every
// message of this lane must be an nftables NEWRULE notification addressed to
// this bound port with a nonzero sequence. An ACK, another subsystem or
// message type, a foreign recipient port, a zero sequence or a
// malformed/truncated length is never an echo: a nonzero sender group does not
// widen what a reply is.
func (c *nftNetlink) parseNftEchoDatagram(data []byte) ([]nftReply, error) {
	replies, err := parseNftDatagram(data)
	if err != nil {
		return nil, err
	}
	if len(replies) == 0 {
		return nil, errors.New("desync: empty nftables metadata echo reply")
	}
	for _, reply := range replies {
		if reply.typ&0xff != uint16(unix.NFT_MSG_NEWRULE) {
			return nil, errors.New("desync: nftables metadata echo reply is not a rule notification")
		}
		if reply.typ&0xff00 != uint16(unix.NFNL_SUBSYS_NFTABLES<<8) {
			return nil, errors.New("desync: nftables metadata echo reply is not an nftables message")
		}
		if reply.port != c.port {
			return nil, errors.New("desync: nftables metadata echo reply is addressed to another port")
		}
		if reply.seq == 0 {
			return nil, errors.New("desync: nftables metadata echo reply has no sequence")
		}
	}
	return replies, nil
}

var errNftMetadataTimeout = errors.New("desync: nftables metadata request was not answered")

// parseNftDatagram splits one datagram into messages. A malformed length is an
// error, never a silent truncation.
func parseNftDatagram(data []byte) ([]nftReply, error) {
	replies := make([]nftReply, 0, 4)
	offset := 0
	for offset+16 <= len(data) {
		length := int(binary.NativeEndian.Uint32(data[offset:]))
		if length < 16 || offset+length > len(data) {
			return nil, errors.New("desync: malformed nftables metadata reply length")
		}
		typ := binary.NativeEndian.Uint16(data[offset+4:])
		seq := binary.NativeEndian.Uint32(data[offset+8:])
		port := binary.NativeEndian.Uint32(data[offset+12:])
		switch typ {
		case unix.NLMSG_ERROR:
			if length < 20 {
				return nil, errors.New("desync: truncated nftables metadata error")
			}
			code := int32(binary.NativeEndian.Uint32(data[offset+16:]))
			replies = append(replies, nftReply{typ: typ, seq: seq, port: port, data: data[offset+16 : offset+length]})
			if code != 0 {
				replies[len(replies)-1].data = nil
				return nil, &nftKernelError{sequence: seq, errno: unix.Errno(-code)}
			}
		case unix.NLMSG_DONE:
			replies = append(replies, nftReply{typ: typ, seq: seq, port: port})
		default:
			replies = append(replies, nftReply{typ: typ, seq: seq, port: port, data: data[offset+16 : offset+length]})
		}
		offset += (length + 3) &^ 3
	}
	if offset != len(data) {
		return nil, errors.New("desync: malformed nftables metadata reply length")
	}
	return replies, nil
}

// nftKernelError is one kernel rejection with the sequence that produced it.
type nftKernelError struct {
	sequence uint32
	errno    unix.Errno
}

func (e *nftKernelError) Error() string {
	return fmt.Sprintf("desync: nftables metadata request %d rejected: %v", e.sequence, e.errno)
}

func (e *nftKernelError) Unwrap() error { return e.errno }

// batch sends BEGIN + requests + END as one datagram and waits for every
// acknowledgement. Echo replies (a request sent with NLM_F_ECHO) are returned
// so a caller can read the handle of a freshly created rule.
//
// The kernel queues the ECHO notification copies during commit, before the
// batch acknowledgement list, so a well-formed exchange sees every echo before
// its own ACK. An echo therefore must answer one outstanding ECHO request of
// exactly this batch (same sequence, same nftables message type, this socket's
// recipient port, with a real rule handle); an echo for another or duplicate
// sequence, a non-notification on the echo lane and an ACK for a sequence this
// batch did not send are protocol anomalies, never completions.
func (c *nftNetlink) batch(requests []nftRequest) ([]nftReply, error) {
	if len(requests) == 0 {
		return nil, nil
	}
	datagram := make([]byte, 0, 256*len(requests)+64)
	datagram = appendNetlinkMessage(datagram, unix.NFNL_MSG_BATCH_BEGIN, netlink.Request,
		c.nextSeq(), nfgenmsg(0, unix.NFNL_SUBSYS_NFTABLES))
	pending := make(map[uint32]bool, len(requests))
	echoRequests := make(map[uint32]uint16, len(requests))
	for _, request := range requests {
		sequence := c.nextSeq()
		flags := request.flags | netlink.Request | netlink.Acknowledge
		datagram = appendNetlinkMessage(datagram, uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|request.typ,
			flags, sequence, request.data)
		pending[sequence] = true
		if flags&netlink.Echo != 0 {
			echoRequests[sequence] = request.typ
		}
	}
	datagram = appendNetlinkMessage(datagram, unix.NFNL_MSG_BATCH_END, netlink.Request,
		c.nextSeq(), nfgenmsg(0, unix.NFNL_SUBSYS_NFTABLES))
	if err := c.send(datagram); err != nil {
		return nil, err
	}
	echoes := make([]nftReply, 0, len(requests))
	for len(pending) > 0 {
		replies, echoLane, err := c.receiveBatch()
		if err != nil {
			return echoes, err
		}
		for _, reply := range replies {
			if reply.port != c.port {
				return echoes, errors.New("desync: nftables metadata reply is addressed to another port")
			}
			if echoLane {
				wantType, expected := echoRequests[reply.seq]
				if !expected || !pending[reply.seq] {
					return echoes, fmt.Errorf("desync: nftables metadata echo for an unexpected sequence %d", reply.seq)
				}
				if reply.typ&0xff != wantType {
					return echoes, fmt.Errorf("desync: nftables metadata echo %d has type %#x, want %#x",
						reply.seq, reply.typ&0xff, wantType)
				}
				if _, ok := nftEchoedRuleHandle(reply); !ok {
					return echoes, fmt.Errorf("desync: nftables metadata echo %d has no rule handle", reply.seq)
				}
				delete(echoRequests, reply.seq)
				echoes = append(echoes, reply)
				continue
			}
			switch reply.typ {
			case unix.NLMSG_ERROR:
				if !pending[reply.seq] {
					return echoes, fmt.Errorf("desync: nftables metadata acknowledgement for an unexpected sequence %d", reply.seq)
				}
				delete(pending, reply.seq)
			case unix.NLMSG_DONE:
				return echoes, errors.New("desync: unexpected nftables metadata dump completion in a batch")
			default:
				return echoes, errors.New("desync: nftables metadata batch reply is not an acknowledgement")
			}
		}
	}
	return echoes, nil
}

// dump sends one DUMP request and returns every data message before DONE.
func (c *nftNetlink) dump(typ uint16, family byte, attrs []netlink.Attribute) ([]nftReply, error) {
	payload, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nil, err
	}
	datagram := appendNetlinkMessage(nil, uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|typ,
		netlink.Request|netlink.Dump, c.nextSeq(), append(nfgenmsg(family, 0), payload...))
	if err = c.send(datagram); err != nil {
		return nil, err
	}
	var records []nftReply
	for {
		replies, receiveErr := c.receive()
		if receiveErr != nil {
			return records, receiveErr
		}
		finished := false
		for _, reply := range replies {
			switch reply.typ {
			case unix.NLMSG_ERROR:
				return records, errors.New("desync: unexpected nftables dump acknowledgement")
			case unix.NLMSG_DONE:
				finished = true
			default:
				records = append(records, reply)
			}
		}
		if finished {
			return records, nil
		}
	}
}

// nftRuleRecord is the readback of one rule of the anchor marker chain.
type nftRuleRecord struct {
	table    string
	chain    string
	handle   uint64
	userdata []byte
}

// nftChainRecord is the readback of one chain of the anchor table.
type nftChainRecord struct {
	table    string
	name     string
	family   byte
	hasHook  bool
	hooknum  uint32
	priority int32
	policy   uint32
	hasType  bool
	kind     string
	flags    uint32
	userdata []byte
}

// nftTableRecord is the readback of the anchor table itself.
type nftTableRecord struct {
	name   string
	family byte
	flags  uint32
}

// nftMessageData is the nfgenmsg of one reply.
func nftMessageData(reply nftReply) (byte, []netlink.Attribute, error) {
	if len(reply.data) < 4 {
		return 0, nil, errors.New("desync: truncated nftables metadata message")
	}
	attrs, err := netlink.UnmarshalAttributes(reply.data[4:])
	if err != nil {
		return 0, nil, fmt.Errorf("desync: parse nftables metadata attributes: %w", err)
	}
	return reply.data[0], attrs, nil
}

func nftAttrBytes(attrs []netlink.Attribute, want uint16) ([]byte, bool) {
	for _, attr := range attrs {
		if attr.Type&0x3fff == want {
			return attr.Data, true
		}
	}
	return nil, false
}

func nftAttrString(attrs []netlink.Attribute, want uint16) (string, bool) {
	data, ok := nftAttrBytes(attrs, want)
	if !ok {
		return "", false
	}
	if len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	return string(data), true
}

func nftAttrUint32(attrs []netlink.Attribute, want uint16) (uint32, bool) {
	data, ok := nftAttrBytes(attrs, want)
	if !ok || len(data) != 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(data), true
}

func nftAttrUint64(attrs []netlink.Attribute, want uint16) (uint64, bool) {
	data, ok := nftAttrBytes(attrs, want)
	if !ok || len(data) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(data), true
}

// listNftTables returns the tables of one family.
func (c *nftNetlink) listNftTables(family byte) ([]nftTableRecord, error) {
	replies, err := c.dump(unix.NFT_MSG_GETTABLE, family, nil)
	if err != nil {
		return nil, err
	}
	tables := make([]nftTableRecord, 0, len(replies))
	for _, reply := range replies {
		_, attrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		name, ok := nftAttrString(attrs, unix.NFTA_TABLE_NAME)
		if !ok {
			return nil, errors.New("desync: nftables table readback without a name")
		}
		flags, _ := nftAttrUint32(attrs, unix.NFTA_TABLE_FLAGS)
		tables = append(tables, nftTableRecord{name: name, family: family, flags: flags})
	}
	return tables, nil
}

// listNftChains returns the chains of one table.
func (c *nftNetlink) listNftChains(family byte, table string) ([]nftChainRecord, error) {
	replies, err := c.dump(unix.NFT_MSG_GETCHAIN, family, []netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(table + "\x00")},
	})
	if err != nil {
		return nil, err
	}
	chains := make([]nftChainRecord, 0, len(replies))
	for _, reply := range replies {
		msgFamily, attrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		name, ok := nftAttrString(attrs, unix.NFTA_CHAIN_NAME)
		if !ok {
			return nil, errors.New("desync: nftables chain readback without a name")
		}
		record := nftChainRecord{table: table, name: name, family: msgFamily}
		if hookData, hasHook := nftAttrBytes(attrs, unix.NFTA_CHAIN_HOOK); hasHook {
			hookAttrs, hookErr := netlink.UnmarshalAttributes(hookData)
			if hookErr != nil {
				return nil, fmt.Errorf("desync: parse nftables chain hook: %w", hookErr)
			}
			hooknum, hasHooknum := nftAttrUint32(hookAttrs, unix.NFTA_HOOK_HOOKNUM)
			priority, hasPriority := nftAttrUint32(hookAttrs, unix.NFTA_HOOK_PRIORITY)
			if !hasHooknum || !hasPriority {
				return nil, errors.New("desync: nftables base chain without hook/priority")
			}
			record.hasHook, record.hooknum, record.priority = true, hooknum, int32(priority)
		}
		if policy, hasPolicy := nftAttrUint32(attrs, unix.NFTA_CHAIN_POLICY); hasPolicy {
			record.policy = policy
		}
		if kind, hasKind := nftAttrString(attrs, unix.NFTA_CHAIN_TYPE); hasKind {
			record.hasType, record.kind = true, kind
		}
		if flags, hasFlags := nftAttrUint32(attrs, nftAttrChainFlags); hasFlags {
			record.flags = flags
		}
		if userdata, hasUserdata := nftAttrBytes(attrs, nftAttrChainUserdata); hasUserdata {
			record.userdata = append([]byte(nil), userdata...)
		}
		chains = append(chains, record)
	}
	return chains, nil
}

// listNftRules returns the rules of one chain (the whole table when chain is
// empty). The anchor validation needs the exact userdata and handle of every
// rule of the marker chain, so the readback is always complete.
func (c *nftNetlink) listNftRules(family byte, table string, chain string) ([]nftRuleRecord, error) {
	attrs := []netlink.Attribute{{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")}}
	if chain != "" {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")})
	}
	replies, err := c.dump(unix.NFT_MSG_GETRULE, family, attrs)
	if err != nil {
		return nil, err
	}
	rules := make([]nftRuleRecord, 0, len(replies))
	for _, reply := range replies {
		_, msgAttrs, parseErr := nftMessageData(reply)
		if parseErr != nil {
			return nil, parseErr
		}
		record := nftRuleRecord{table: table}
		record.chain, _ = nftAttrString(msgAttrs, unix.NFTA_RULE_CHAIN)
		record.handle, _ = nftAttrUint64(msgAttrs, unix.NFTA_RULE_HANDLE)
		if userdata, ok := nftAttrBytes(msgAttrs, unix.NFTA_RULE_USERDATA); ok {
			record.userdata = append([]byte(nil), userdata...)
		}
		rules = append(rules, record)
	}
	return rules, nil
}

// nftTableMessage builds one NEWTABLE request.
func nftTableMessage(family byte, table string, userdata []byte) nftRequest {
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_TABLE_NAME, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_TABLE_FLAGS, Data: binary.BigEndian.AppendUint32(nil, 0)},
	}
	if userdata != nil {
		attrs = append(attrs, netlink.Attribute{Type: nftAttrTableUserdata, Data: userdata})
	}
	payload, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		payload = nil
	}
	return nftRequest{typ: unix.NFT_MSG_NEWTABLE, flags: netlink.Create | netlink.Excl,
		data: append(nfgenmsg(family, 0), payload...)}
}

// nftBaseChainMessage builds one NEWCHAIN request for a base chain. The
// explicit policy is NF_ACCEPT (1): an anchor base chain must never drop
// traffic that no capture rule selected.
func nftBaseChainMessage(family byte, table, chain, kind string, hooknum int, priority int32, userdata []byte) nftRequest {
	hookAttrs, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: binary.BigEndian.AppendUint32(nil, uint32(hooknum))},
		{Type: unix.NFTA_HOOK_PRIORITY, Data: binary.BigEndian.AppendUint32(nil, uint32(priority))},
	})
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(chain + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_CHAIN_HOOK, Data: hookAttrs},
		{Type: unix.NFTA_CHAIN_POLICY, Data: binary.BigEndian.AppendUint32(nil, nftVerdictAccept)},
		{Type: unix.NFTA_CHAIN_TYPE, Data: []byte(kind + "\x00")},
	}
	if userdata != nil {
		attrs = append(attrs, netlink.Attribute{Type: nftAttrChainUserdata, Data: userdata})
	}
	payload, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		payload = nil
	}
	return nftRequest{typ: unix.NFT_MSG_NEWCHAIN, flags: netlink.Create | netlink.Excl,
		data: append(nfgenmsg(family, 0), payload...)}
}

// nftRegularChainMessage builds one NEWCHAIN request for a regular chain.
func nftRegularChainMessage(family byte, table, chain string) nftRequest {
	payload, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(chain + "\x00")},
	})
	return nftRequest{typ: unix.NFT_MSG_NEWCHAIN, flags: netlink.Create | netlink.Excl,
		data: append(nfgenmsg(family, 0), payload...)}
}

// nftRuleMessage builds one NEWRULE request with the given encoded expressions
// and optional userdata. The append flag keeps an existing rule order.
func nftRuleMessage(family byte, table, chain string, expressions [][]byte, userdata []byte) (nftRequest, error) {
	return nftRuleMessageWithOrder(family, table, chain, expressions, userdata, true)
}

// nftRuleMessageHead builds one NEWRULE request inserted at the head of the
// chain. Without NLM_F_APPEND the kernel list_add_rcu's the rule, which is how
// every exact-tag injection entry stays before all ordinary dispatch entries.
func nftRuleMessageHead(family byte, table, chain string, expressions [][]byte, userdata []byte) (nftRequest, error) {
	return nftRuleMessageWithOrder(family, table, chain, expressions, userdata, false)
}

func nftRuleMessageWithOrder(family byte, table, chain string, expressions [][]byte, userdata []byte, appendRule bool) (nftRequest, error) {
	elements := make([]netlink.Attribute, 0, len(expressions))
	for _, expression := range expressions {
		if len(expression) == 0 {
			return nftRequest{}, errors.New("desync: empty nftables expression")
		}
		elements = append(elements, netlink.Attribute{
			Type: unix.NLA_F_NESTED | unix.NFTA_LIST_ELEM, Data: expression})
	}
	expressionData, err := netlink.MarshalAttributes(elements)
	if err != nil {
		return nftRequest{}, err
	}
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
		{Type: unix.NLA_F_NESTED | unix.NFTA_RULE_EXPRESSIONS, Data: expressionData},
	}
	if userdata != nil {
		attrs = append(attrs, netlink.Attribute{Type: unix.NFTA_RULE_USERDATA, Data: userdata})
	}
	payload, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		return nftRequest{}, err
	}
	flags := netlink.Create | netlink.Echo
	if appendRule {
		flags |= netlink.Append
	}
	return nftRequest{typ: unix.NFT_MSG_NEWRULE,
		flags: flags,
		data:  append(nfgenmsg(family, 0), payload...)}, nil
}

// nftDeleteRuleMessage builds one DELRULE request by exact handle. A delete
// without a handle would remove every rule of the chain, which is never what a
// shared marker chain may do.
func nftDeleteRuleMessage(family byte, table, chain string, handle uint64) nftRequest {
	payload, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_RULE_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_RULE_CHAIN, Data: []byte(chain + "\x00")},
		{Type: unix.NFTA_RULE_HANDLE, Data: binary.BigEndian.AppendUint64(nil, handle)},
	})
	return nftRequest{typ: unix.NFT_MSG_DELRULE, data: append(nfgenmsg(family, 0), payload...)}
}

// nftDeleteChainMessage builds one DELCHAIN request.
func nftDeleteChainMessage(family byte, table, chain string) nftRequest {
	payload, _ := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(chain + "\x00")},
	})
	return nftRequest{typ: unix.NFT_MSG_DELCHAIN, data: append(nfgenmsg(family, 0), payload...)}
}

// nftEchoedRuleHandle reads the handle of one echoed NEWRULE reply. The message
// must belong to the nftables subsystem; a rule handle is never fabricated.
func nftEchoedRuleHandle(echo nftReply) (uint64, bool) {
	if echo.typ != uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE {
		return 0, false
	}
	_, attrs, err := nftMessageData(echo)
	if err != nil {
		return 0, false
	}
	return nftAttrUint64(attrs, unix.NFTA_RULE_HANDLE)
}

// nftNetlink identifies itself by its explicit control-class port.
func (c *nftNetlink) boundPort() uint32 { return c.port }

// nftMsgNewgen is the kernel's data reply type of a standalone GETGEN read
// ((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWGEN).
const nftMsgNewgen = uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWGEN

// validateGenerationAck validates the successful acknowledgement of the exact
// standalone GETGEN request. The kernel may echo only the request header
// (NLM_F_CAPPED) or the complete message; either must be byte-identical to
// what this operation sent. A success acknowledgement with a different
// embedded request is a conflicting identity, not a completion.
func validateGenerationAck(reply nftReply, request []byte, sequence uint32) error {
	if len(reply.data) < 4 {
		return errors.New("desync: truncated nftables GETGEN acknowledgement")
	}
	if code := int32(binary.NativeEndian.Uint32(reply.data[:4])); code != 0 {
		return &nftKernelError{sequence: sequence, errno: unix.Errno(-code)}
	}
	echo := reply.data[4:]
	switch len(echo) {
	case 16:
		if !bytes.Equal(echo, request[:16]) {
			return errors.New("desync: nftables GETGEN acknowledgement request echo differs from the sent request")
		}
	case len(request):
		if !bytes.Equal(echo, request) {
			return errors.New("desync: nftables GETGEN acknowledgement request echo differs from the sent request")
		}
	default:
		return fmt.Errorf("desync: nftables GETGEN acknowledgement carries %d echoed request bytes", len(echo))
	}
	return nil
}

// generation reads NFT_MSG_GETGEN as one standalone request. It is not a dump
// and never part of a batch (a batched GETGEN is the N-A1 fence, not a read).
//
// The request asks for an acknowledgement, so the operation owns the complete
// data+ACK exchange before it returns: the kernel may deliver NEWGEN and ACK0
// in one datagram or in two, in either order. Leaving the ACK queued would
// hand it to the next dump, which would reject it as an unexpected dump
// acknowledgement. The exchange is bounded by the socket timeout and by the
// two datagrams that can carry it; every request data message must be the
// exact NEWGEN reply and every ACK must echo the exact sent request.
func (c *nftNetlink) generation(family byte) (uint32, error) {
	sequence := c.nextSeq()
	request := appendNetlinkMessage(nil, uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_GETGEN,
		netlink.Request|netlink.Acknowledge, sequence, nfgenmsg(family, 0))
	if err := c.send(request); err != nil {
		return 0, err
	}
	var (
		generation uint32
		dataSeen   bool
		ackSeen    bool
	)
	for datagrams := 0; datagrams < 2 && !(dataSeen && ackSeen); datagrams++ {
		replies, err := c.receive()
		if err != nil {
			return 0, err
		}
		if len(replies) == 0 {
			return 0, errors.New("desync: empty nftables GETGEN reply datagram")
		}
		for _, reply := range replies {
			if reply.port != c.port {
				return 0, errors.New("desync: nftables GETGEN reply is addressed to another port")
			}
			if reply.seq != sequence {
				return 0, fmt.Errorf("desync: nftables GETGEN reply has sequence %d, want %d", reply.seq, sequence)
			}
			switch reply.typ {
			case unix.NLMSG_ERROR:
				if ackSeen {
					return 0, errors.New("desync: duplicate nftables GETGEN acknowledgement")
				}
				if ackErr := validateGenerationAck(reply, request, sequence); ackErr != nil {
					return 0, ackErr
				}
				ackSeen = true
			case unix.NLMSG_DONE:
				return 0, errors.New("desync: unexpected nftables GETGEN completion")
			case nftMsgNewgen:
				if dataSeen {
					return 0, errors.New("desync: duplicate nftables GETGEN reply")
				}
				_, attrs, parseErr := nftMessageData(reply)
				if parseErr != nil {
					return 0, parseErr
				}
				id, ok := nftAttrUint32(attrs, unix.NFTA_GEN_ID)
				if !ok {
					return 0, errors.New("desync: nftables GETGEN reply has no generation id")
				}
				generation = id
				dataSeen = true
			default:
				return 0, fmt.Errorf("desync: unexpected nftables GETGEN reply type %#x", reply.typ)
			}
		}
	}
	if !dataSeen || !ackSeen {
		return 0, errors.New("desync: nftables GETGEN exchange is incomplete")
	}
	return generation, nil
}

// anchorSession is one short-lived NETLINK_NETFILTER metadata socket of the
// control class. Every operation of the persistent-anchor lifecycle runs over
// exactly one such session, inside the pinned actual namespace. It is a seam:
// the model tests substitute an in-memory nftables object model so the
// lifecycle is exercisable without CAP_NET_ADMIN, while production uses
// *nftNetlink and the real kernel.
type anchorSession interface {
	Close() error
	boundPort() uint32
	batch(requests []nftRequest) ([]nftReply, error)
	dump(typ uint16, family byte, attrs []netlink.Attribute) ([]nftReply, error)
	// generation returns the nftables generation counter of the namespace.
	// It is used to make a multi-dump readback generation-consistent: a
	// detach acknowledgement, a rule dump and the m/p lookup must observe one
	// unchanged generation.
	generation(family byte) (uint32, error)
}

// openAnchorSession opens one short-lived control-class metadata session. It is
// always called while the caller holds the single fork-read token, so a child
// can never inherit the unbound/partially bound metadata fd.
var openAnchorSession = func() (anchorSession, error) { return openNftNetlink() }

// ---------------------------------------------------------------------------
// N-A1 enqueue fence: the exact zero-mutation BEGIN / invalid-in-batch GETGEN /
// END batch of implementation-contract-v1.3.1 §3.1.
//
// The batch performs no ruleset mutation. GETGEN inside a batch is a valid nft
// operation but not a batch callback, so the kernel queues -EINVAL, marks the
// batch failed and aborts it; the empty abort path still runs synchronize_rcu
// before the error list is delivered. That negative ACK is a typed positive
// receipt that every reader able to use the detached entries reached the
// enqueue (or error) point. Success ACK0, a sleep, an empty queue or a delete
// receipt never qualify.
// ---------------------------------------------------------------------------

const (
	// nfnlMsgBatchEnd is NFNL_MSG_BATCH_END (nfnetlink.h).
	nfnlMsgBatchEnd = 0x11
	// nftMsgGetgen is (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETGEN.
	nftMsgGetgen = uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_GETGEN
	// fenceGetgenSequence is the sequence of the only message whose negative
	// acknowledgement is the selected receipt.
	fenceGetgenSequence = 2
	// fenceMessageBytes is one 16-byte nlmsghdr plus the 4-byte nfgenmsg.
	fenceMessageBytes = 20
)

// enqueueFenceRequest keeps the exact bytes of the one datagram and the exact
// GETGEN header/nfgenmsg the reply must echo byte-identically.
type enqueueFenceRequest struct {
	datagram    []byte
	getgenBytes []byte
}

// buildEnqueueFenceRequest encodes the selected three-message batch. Every
// nlmsg carries the 16-byte header plus the 4-byte nfgenmsg; outgoing
// nlmsg_pid is zero; no attributes and no padding beyond 4-byte alignment.
func buildEnqueueFenceRequest() enqueueFenceRequest {
	begin := appendNetlinkMessage(nil, unix.NFNL_MSG_BATCH_BEGIN, netlink.Request,
		1, nfgenmsg(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES))
	getgen := appendNetlinkMessage(nil, nftMsgGetgen, netlink.Request|netlink.Acknowledge,
		fenceGetgenSequence, nfgenmsg(unix.AF_UNSPEC, 0))
	end := appendNetlinkMessage(nil, nfnlMsgBatchEnd, netlink.Request,
		3, nfgenmsg(unix.AF_UNSPEC, unix.NFNL_SUBSYS_NFTABLES))
	datagram := make([]byte, 0, len(begin)+len(getgen)+len(end))
	datagram = append(datagram, begin...)
	datagram = append(datagram, getgen...)
	datagram = append(datagram, end...)
	return enqueueFenceRequest{datagram: datagram, getgenBytes: append([]byte(nil), getgen...)}
}

// enqueueFenceReceipt is the typed positive receipt of §3.1. It is valid only
// for the single selected -EINVAL reply whose embedded request echo is
// byte-identical to our GETGEN header and nfgenmsg.
type enqueueFenceReceipt struct {
	sequence  uint32
	boundPort uint32
	errno     unix.Errno
	request   []byte
	reply     []byte
}

// errEnqueueFenceNoReceipt is the one failure class of the fence: no reply in
// this operation qualifies as the selected receipt. A caller must not treat it
// as a successful fence, and must never substitute a sleep or an empty queue.
var errEnqueueFenceNoReceipt = errors.New("desync: no N-A1 enqueue fence receipt")

func fenceNoReceipt(reason string) error {
	return fmt.Errorf("%w: %s", errEnqueueFenceNoReceipt, reason)
}

// parseEnqueueFenceReply validates one received datagram against the exact
// request. Peer must be the kernel (pid0/groups0); datagram must contain
// exactly one untruncated NLMSG_ERROR of sequence 2, outer header port equal to
// our bound port, signed -EINVAL, with the byte-identical embedded GETGEN
// header and nfgenmsg, and no CAPPED/ACK_TLVS flag or trailing data.
func parseEnqueueFenceReply(datagram []byte, peer *unix.SockaddrNetlink, boundPort uint32, request enqueueFenceRequest) (enqueueFenceReceipt, error) {
	if peer == nil || peer.Pid != 0 || peer.Groups != 0 {
		return enqueueFenceReceipt{}, fenceNoReceipt("reply did not come from the kernel peer")
	}
	if len(request.getgenBytes) != fenceMessageBytes || len(request.datagram) != 3*fenceMessageBytes {
		return enqueueFenceReceipt{}, fenceNoReceipt("malformed request identity")
	}
	if len(datagram) == 0 {
		return enqueueFenceReceipt{}, fenceNoReceipt("empty reply")
	}
	var receipt enqueueFenceReceipt
	seen := 0
	for offset := 0; offset+16 <= len(datagram); {
		length := int(binary.NativeEndian.Uint32(datagram[offset:]))
		if length < 16 || offset+length > len(datagram) {
			return enqueueFenceReceipt{}, fenceNoReceipt("malformed reply length")
		}
		typ := binary.NativeEndian.Uint16(datagram[offset+4:])
		flags := binary.NativeEndian.Uint16(datagram[offset+6:])
		sequence := binary.NativeEndian.Uint32(datagram[offset+8:])
		port := binary.NativeEndian.Uint32(datagram[offset+12:])
		if typ != unix.NLMSG_ERROR {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply contains a non-error message")
		}
		if flags&(unix.NLM_F_CAPPED|unix.NLM_F_ACK_TLVS) != 0 {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply carries CAPPED/ACK_TLVS")
		}
		if length != 2*fenceMessageBytes {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply length is not one complete error echo")
		}
		code := int32(binary.NativeEndian.Uint32(datagram[offset+16:]))
		if code >= 0 {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply is a success acknowledgement")
		}
		if unix.Errno(-code) != unix.EINVAL {
			return enqueueFenceReceipt{}, fenceNoReceipt(fmt.Sprintf("reply errno is %v, not EINVAL", unix.Errno(-code)))
		}
		if sequence != fenceGetgenSequence {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply sequence is not the GETGEN sequence")
		}
		if port != boundPort {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply port is not this socket's bound port")
		}
		embedded := datagram[offset+20 : offset+length]
		if !bytes.Equal(embedded, request.getgenBytes) {
			return enqueueFenceReceipt{}, fenceNoReceipt("embedded request echo differs from the sent GETGEN bytes")
		}
		receipt = enqueueFenceReceipt{
			sequence:  sequence,
			boundPort: port,
			errno:     unix.EINVAL,
			request:   append([]byte(nil), request.datagram...),
			reply:     append([]byte(nil), datagram[offset:offset+length]...),
		}
		seen++
		offset += (length + 3) &^ 3
		if offset != len(datagram) {
			return enqueueFenceReceipt{}, fenceNoReceipt("reply datagram has trailing messages")
		}
	}
	if seen != 1 {
		return enqueueFenceReceipt{}, fenceNoReceipt("reply does not contain exactly one error echo")
	}
	return receipt, nil
}

// fenceTransport is the send/receive surface of one fresh control-class socket
// used only for the fence. It exists so the exact encoded request and the reply
// parser can be exercised with a deterministic transport.
type fenceTransport interface {
	Close() error
	boundPort() uint32
	send([]byte) error
	recvDatagram() ([]byte, *unix.SockaddrNetlink, error)
}

var openFenceTransport = func() (fenceTransport, error) { return openNftNetlink() }

// runEnqueueFence performs the one selected operation on a fresh control-class
// socket: full-datagram send, one untruncated receive, exact receipt. A lost or
// malformed reply is NO_RECEIPT; the caller repeats the whole operation on a
// fresh socket because it is a no-mutation request.
func runEnqueueFence() (enqueueFenceReceipt, error) {
	transport, err := openFenceTransport()
	if err != nil {
		return enqueueFenceReceipt{}, err
	}
	defer transport.Close()
	request := buildEnqueueFenceRequest()
	if err = transport.send(request.datagram); err != nil {
		return enqueueFenceReceipt{}, err
	}
	datagram, peer, err := transport.recvDatagram()
	if err != nil {
		return enqueueFenceReceipt{}, err
	}
	return parseEnqueueFenceReply(datagram, peer, transport.boundPort(), request)
}

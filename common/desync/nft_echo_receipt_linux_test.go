//go:build linux

package desync

// Model receipt replay for the ordinary nftables metadata batch: the exact
// datagrams Q run545 captured on the Ubuntu 6.8 target (t_3ecf7d99,
// logs/linux-smoke-observed.txt) are replayed through the production
// *nftNetlink send/receive/batch code with a scripted datagram boundary. No
// kernel socket is opened, no netfilter object is created or read, and no
// native execution is claimed. This is a model test: it proves the demux, not
// the kernel.
//
// The captured exchange is the initial marker batch of ensureAnchorFamily on
// the control-class metadata socket bound to port 0x40000e7a:
//
//	BEGIN=2 NEWTABLE=3 NEWCHAIN=4 NEWRULE(a)=5 NEWRULE(t)=6 END=7
//	kernel ECHO copy of sequences 5/6, sender sockaddr_nl pid=0 groups=64
//	(NFNLGRP_NFTABLES, netlink_group_mask(7) == 1<<6)
//	capped ACK 0 for sequence 3, then for sequence 4, both pid=0 groups=0.
//
// The kernel queues the ECHO notification copies during commit, before the
// batch acknowledgement list, so every echo precedes its own ACK. The two rule
// ACKs were not reached by the failing run (it aborted on the echo datagram);
// they are derived here from the exact request frames the production encoder
// actually sent, in the same capped-ACK shape the capture shows for 3 and 4.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	// nftEchoCapturePort is the control-class port of the captured metadata
	// socket (0x40000e7a).
	nftEchoCapturePort = uint32(1073745530)
	// nftEchoCaptureDatagram is one datagram carrying the two NEWRULE ECHO
	// notifications of sequences 5 and 6, verbatim from the captured log.
	nftEchoCaptureDatagram = "74000000060a000c050000007a0e0040020000020e00010073625f646573796e630000000e0002005f5f736264735f76310000000c00030000000000000000020400040030000700736264733a313a613a69703a3838613461623038393266656139353262343862386234366336373163373031" +
		"7c000000060a000c060000007a0e0040020000020e00010073625f646573796e630000000e0002005f5f736264735f76310000000c00030000000000000000030400040038000700736264733a313a743a38386134616230383932666561393532623438623862343663363731633730313a31333938333431363333"
	// nftEchoCaptureTableAck and nftEchoCaptureChainAck are the verbatim capped
	// ACK 0 datagrams for sequences 3 (NEWTABLE) and 4 (NEWCHAIN).
	nftEchoCaptureTableAck = "2400000002000001030000007a0e0040000000002c000000000a05060300000000000000"
	nftEchoCaptureChainAck = "2400000002000001040000007a0e00400000000034000000030a05060400000000000000"

	// nftEchoCaptureGroup is the captured netlink group mask of
	// NFNLGRP_NFTABLES: netlink_group_mask(7) == 1<<6 == 64. It is an
	// independent literal of the captured evidence, not of the implementation.
	nftEchoCaptureGroup = uint32(64)

	nftEchoCaptureAnchorUserdata = "sbds:1:a:ip:88a4ab0892fea952b48b8b46c671c701"
	nftEchoCaptureTagUserdata    = "sbds:1:t:88a4ab0892fea952b48b8b46c671c701:1398341633"
)

// nftScriptedRecv is one scripted datagram delivery. build runs at receive time
// with the datagrams already sent, so a derived ACK embeds the exact request
// frame the production encoder produced.
type nftScriptedRecv struct {
	data  []byte
	peer  *unix.SockaddrNetlink
	err   error
	build func(sent [][]byte) ([]byte, *unix.SockaddrNetlink, error)
}

// nftScriptedDatagram is the syscall boundary of one model metadata socket. A
// step list that runs out returns EAGAIN, which the production receive path maps
// to its bounded timeout instead of blocking.
type nftScriptedDatagram struct {
	sends   [][]byte
	steps   []nftScriptedRecv
	sendErr error
}

func (s *nftScriptedDatagram) send(datagram []byte) error {
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sends = append(s.sends, append([]byte(nil), datagram...))
	return nil
}

func (s *nftScriptedDatagram) recv(buffer []byte) (int, *unix.SockaddrNetlink, error) {
	if len(s.steps) == 0 {
		return 0, nil, unix.EAGAIN
	}
	step := s.steps[0]
	s.steps = s.steps[1:]
	if step.build != nil {
		data, peer, err := step.build(s.sends)
		if err != nil {
			return 0, nil, err
		}
		step.data, step.peer = data, peer
	}
	if step.err != nil {
		return 0, nil, step.err
	}
	copy(buffer, step.data)
	return len(step.data), step.peer, nil
}

func newNftScriptedSession(port, seq uint32, scripted *nftScriptedDatagram) *nftNetlink {
	return &nftNetlink{fd: -1, port: port, seq: seq,
		buffer: make([]byte, nftMetadataBuffer), datagram: scripted}
}

func nftKernelPeer() *unix.SockaddrNetlink {
	return &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0}
}

// nftTestKernelMessage builds one kernel-addressed message: the outer
// nlmsg_pid is the receiving socket's bound port, as every kernel reply and
// ECHO copy carries it.
func nftTestKernelMessage(typ uint16, seq uint32, port uint32, payload []byte) []byte {
	message := nftTestMessage(typ, seq, payload)
	binary.NativeEndian.PutUint32(message[12:], port)
	return message
}

func nftKernelEchoPeer() *unix.SockaddrNetlink {
	return &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: nftEchoCaptureGroup}
}

func mustNftBytes(t *testing.T, hexValue string) []byte {
	t.Helper()
	data, err := decodeHexBytes(hexValue)
	if err != nil {
		t.Fatalf("captured fixture: %v", err)
	}
	return data
}

// decodeHexBytes decodes the captured lowercase hex without pulling fmt into
// the fixture literals.
func decodeHexBytes(value string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, errors.New("odd hex length")
	}
	out := make([]byte, len(value)/2)
	for index := 0; index < len(out); index++ {
		high, ok := hexNibble(value[2*index])
		if !ok {
			return nil, fmt.Errorf("bad hex digit %q", value[2*index])
		}
		low, ok := hexNibble(value[2*index+1])
		if !ok {
			return nil, fmt.Errorf("bad hex digit %q", value[2*index+1])
		}
		out[index] = high<<4 | low
	}
	return out, nil
}

func hexNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	default:
		return 0, false
	}
}

// nftInitialMarkerRequests rebuilds the exact request set of the captured
// initial marker batch: table, marker chain, anchor rule a, tag rule t.
func nftInitialMarkerRequests(t *testing.T) []nftRequest {
	t.Helper()
	anchorRule, err := nftRuleMessage(2, "sb_desync", "__sbds_v1", nil, []byte(nftEchoCaptureAnchorUserdata))
	if err != nil {
		t.Fatalf("anchor rule message: %v", err)
	}
	tagRule, err := nftRuleMessage(2, "sb_desync", "__sbds_v1", nil, []byte(nftEchoCaptureTagUserdata))
	if err != nil {
		t.Fatalf("tag rule message: %v", err)
	}
	return []nftRequest{
		nftTableMessage(2, "sb_desync", nil),
		nftRegularChainMessage(2, "sb_desync", "__sbds_v1"),
		anchorRule,
		tagRule,
	}
}

// nftFrames splits one datagram into its padded nlmsg frames.
func nftFrames(t *testing.T, datagram []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	for offset := 0; offset+16 <= len(datagram); {
		length := int(binary.NativeEndian.Uint32(datagram[offset:]))
		if length < 16 || offset+length > len(datagram) {
			t.Fatalf("malformed fixture frame at %d", offset)
		}
		aligned := (length + 3) &^ 3
		frames = append(frames, datagram[offset:offset+aligned])
		offset += aligned
	}
	return frames
}

// nftCappedAck builds the kernel's NLM_F_CAPPED ACK 0 shape for the exact
// request frame with wantSeq in the already-sent production datagram.
func nftCappedAck(sent [][]byte, wantSeq uint32, port uint32) ([]byte, *unix.SockaddrNetlink, error) {
	if len(sent) == 0 {
		return nil, nil, errors.New("model: no datagram was sent")
	}
	for offset := 0; offset+16 <= len(sent[0]); {
		length := int(binary.NativeEndian.Uint32(sent[0][offset:]))
		if length < 16 || offset+length > len(sent[0]) {
			return nil, nil, errors.New("model: malformed sent datagram")
		}
		if binary.NativeEndian.Uint32(sent[0][offset+8:]) == wantSeq {
			ack := make([]byte, 36)
			binary.NativeEndian.PutUint32(ack[0:], 36)
			binary.NativeEndian.PutUint16(ack[4:], unix.NLMSG_ERROR)
			binary.NativeEndian.PutUint16(ack[6:], unix.NLM_F_CAPPED)
			binary.NativeEndian.PutUint32(ack[8:], wantSeq)
			binary.NativeEndian.PutUint32(ack[12:], port)
			copy(ack[20:], sent[0][offset:offset+16])
			return ack, nftKernelPeer(), nil
		}
		offset += (length + 3) &^ 3
	}
	return nil, nil, fmt.Errorf("model: sent datagram has no sequence %d", wantSeq)
}

func nftScriptedAck(seq uint32, port uint32) nftScriptedRecv {
	return nftScriptedRecv{build: func(sent [][]byte) ([]byte, *unix.SockaddrNetlink, error) {
		return nftCappedAck(sent, seq, port)
	}}
}

func nftScriptedDatagramStep(t *testing.T, hexValue string, peer *unix.SockaddrNetlink) nftScriptedRecv {
	return nftScriptedRecv{data: mustNftBytes(t, hexValue), peer: peer}
}

// TestNftOrdinaryKernelEchoCompletesBatch is the permanent behavioral receipt
// for S21-DEFAULT-ECHO: the authentic captured groups64 ECHO datagram must be
// resolved to the two real rule handles while the batch still completes on the
// plain ACKs. Pre-fix this fails with "nftables metadata reply came from a
// foreign netlink peer" on the first capture.
func TestNftOrdinaryKernelEchoCompletesBatch(t *testing.T) {
	// Model test: a scripted datagram boundary, no kernel socket.
	scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
		nftScriptedDatagramStep(t, nftEchoCaptureDatagram, nftKernelEchoPeer()),
		nftScriptedDatagramStep(t, nftEchoCaptureTableAck, nftKernelPeer()),
		nftScriptedDatagramStep(t, nftEchoCaptureChainAck, nftKernelPeer()),
		nftScriptedAck(5, nftEchoCapturePort),
		nftScriptedAck(6, nftEchoCapturePort),
	}}
	session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)

	echoes, err := session.batch(nftInitialMarkerRequests(t))
	if err != nil {
		t.Fatalf("ordinary metadata batch rejected its own kernel ECHO: %v", err)
	}
	if len(echoes) != 2 {
		t.Fatalf("echoes = %d, want 2", len(echoes))
	}
	want := []struct {
		seq      uint32
		handle   uint64
		userdata string
	}{
		{seq: 5, handle: 2, userdata: nftEchoCaptureAnchorUserdata},
		{seq: 6, handle: 3, userdata: nftEchoCaptureTagUserdata},
	}
	for index, echo := range echoes {
		if echo.typ != uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE {
			t.Fatalf("echo %d type = %#x", index, echo.typ)
		}
		if echo.seq != want[index].seq {
			t.Fatalf("echo %d sequence = %d, want %d", index, echo.seq, want[index].seq)
		}
		handle, ok := nftEchoedRuleHandle(echo)
		if !ok || handle != want[index].handle {
			t.Fatalf("echo %d handle = %d,%v, want %d", index, handle, ok, want[index].handle)
		}
		_, attrs, parseErr := nftMessageData(echo)
		if parseErr != nil {
			t.Fatalf("echo %d payload: %v", index, parseErr)
		}
		if table, ok := nftAttrString(attrs, unix.NFTA_RULE_TABLE); !ok || table != "sb_desync" {
			t.Fatalf("echo %d table = %q,%v", index, table, ok)
		}
		if chain, ok := nftAttrString(attrs, unix.NFTA_RULE_CHAIN); !ok || chain != "__sbds_v1" {
			t.Fatalf("echo %d chain = %q,%v", index, chain, ok)
		}
		if userdata, ok := nftAttrBytes(attrs, unix.NFTA_RULE_USERDATA); !ok || string(userdata) != want[index].userdata {
			t.Fatalf("echo %d userdata = %q,%v", index, userdata, ok)
		}
	}
	if len(scripted.steps) != 0 {
		t.Fatalf("%d scripted datagrams were not consumed", len(scripted.steps))
	}
	if len(scripted.sends) != 1 {
		t.Fatalf("sent datagrams = %d, want 1", len(scripted.sends))
	}

	// The production encoder must have produced the captured batch shape:
	// BEGIN 2, NEWTABLE 3, NEWCHAIN 4, NEWRULE 5 (ECHO), NEWRULE 6 (ECHO), END 7.
	frames := nftFrames(t, scripted.sends[0])
	wantSeq := []uint32{2, 3, 4, 5, 6, 7}
	wantType := []uint16{
		unix.NFNL_MSG_BATCH_BEGIN,
		uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWTABLE,
		uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWCHAIN,
		uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWRULE,
		uint16(unix.NFNL_SUBSYS_NFTABLES<<8) | unix.NFT_MSG_NEWRULE,
		unix.NFNL_MSG_BATCH_END,
	}
	if len(frames) != len(wantSeq) {
		t.Fatalf("sent messages = %d, want %d", len(frames), len(wantSeq))
	}
	for index, frame := range frames {
		if got := binary.NativeEndian.Uint16(frame[4:]); got != wantType[index] {
			t.Fatalf("message %d type = %#x, want %#x", index, got, wantType[index])
		}
		if got := binary.NativeEndian.Uint32(frame[8:]); got != wantSeq[index] {
			t.Fatalf("message %d sequence = %d, want %d", index, got, wantSeq[index])
		}
		if got := binary.NativeEndian.Uint32(frame[12:]); got != 0 {
			t.Fatalf("message %d outgoing nlmsg_pid = %d, want 0", index, got)
		}
		if index == 3 || index == 4 {
			if flags := binary.NativeEndian.Uint16(frame[6:]); flags&uint16(netlink.Echo) == 0 {
				t.Fatalf("rule message %d does not request ECHO: flags=%#x", index, flags)
			}
		}
	}
	if !bytes.Contains(scripted.sends[0], []byte(nftEchoCaptureAnchorUserdata)) ||
		!bytes.Contains(scripted.sends[0], []byte(nftEchoCaptureTagUserdata)) {
		t.Fatal("the replayed batch does not carry the captured a/t marker userdata")
	}
}

// TestNftOrdinaryEchoOrderVariantsAndAckOnly covers the legal orderings of the
// same captured exchange and a batch that never requests ECHO.
func TestNftOrdinaryEchoOrderVariantsAndAckOnly(t *testing.T) {
	echoFrames := nftFrames(t, mustNftBytes(t, nftEchoCaptureDatagram))
	if len(echoFrames) != 2 {
		t.Fatalf("captured echo frames = %d, want 2", len(echoFrames))
	}

	t.Run("acknowledgements before the echo copy", func(t *testing.T) {
		// Model test: scripted datagrams only.
		scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
			nftScriptedDatagramStep(t, nftEchoCaptureTableAck, nftKernelPeer()),
			nftScriptedDatagramStep(t, nftEchoCaptureChainAck, nftKernelPeer()),
			nftScriptedDatagramStep(t, nftEchoCaptureDatagram, nftKernelEchoPeer()),
			nftScriptedAck(5, nftEchoCapturePort),
			nftScriptedAck(6, nftEchoCapturePort),
		}}
		session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
		echoes, err := session.batch(nftInitialMarkerRequests(t))
		if err != nil {
			t.Fatalf("batch: %v", err)
		}
		if len(echoes) != 2 || echoes[0].seq != 5 || echoes[1].seq != 6 {
			t.Fatalf("echoes = %+v", echoes)
		}
	})

	t.Run("separate echo datagrams interleaved with acknowledgements", func(t *testing.T) {
		// Model test: scripted datagrams only.
		scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
			{data: echoFrames[0], peer: nftKernelEchoPeer()},
			nftScriptedDatagramStep(t, nftEchoCaptureTableAck, nftKernelPeer()),
			nftScriptedAck(5, nftEchoCapturePort),
			{data: echoFrames[1], peer: nftKernelEchoPeer()},
			nftScriptedDatagramStep(t, nftEchoCaptureChainAck, nftKernelPeer()),
			nftScriptedAck(6, nftEchoCapturePort),
		}}
		session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
		echoes, err := session.batch(nftInitialMarkerRequests(t))
		if err != nil {
			t.Fatalf("batch: %v", err)
		}
		if len(echoes) != 2 || echoes[0].seq != 5 || echoes[1].seq != 6 {
			t.Fatalf("echoes = %+v", echoes)
		}
	})

	t.Run("acknowledgement-only batch", func(t *testing.T) {
		// Model test: scripted datagrams only; a table+chain batch requests no
		// ECHO, so its plain ACKs alone complete it and no echo is returned.
		scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
			nftScriptedDatagramStep(t, nftEchoCaptureTableAck, nftKernelPeer()),
			nftScriptedDatagramStep(t, nftEchoCaptureChainAck, nftKernelPeer()),
		}}
		session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
		requests := nftInitialMarkerRequests(t)[:2]
		echoes, err := session.batch(requests)
		if err != nil {
			t.Fatalf("batch: %v", err)
		}
		if len(echoes) != 0 {
			t.Fatalf("echoes = %+v, want none", echoes)
		}
	})
}

// TestNftOrdinaryEchoRejectsForeignOrMismatchedReplies pins the negative fence
// around the new ordinary-ECHO lane: only the kernel peer may answer, only a
// rule notification addressed to this port for an outstanding ECHO request is
// an echo, and a nonzero group never widens what counts as a completion.
func TestNftOrdinaryEchoRejectsForeignOrMismatchedReplies(t *testing.T) {
	echoFrames := nftFrames(t, mustNftBytes(t, nftEchoCaptureDatagram))
	echo := mustNftBytes(t, nftEchoCaptureDatagram)
	tableAck := mustNftBytes(t, nftEchoCaptureTableAck)

	mutate := func(frame []byte, change func(copy []byte)) []byte {
		out := append([]byte(nil), frame...)
		change(out)
		return out
	}
	// missingHandle is one NEWRULE notification whose payload is the production
	// rule-request payload: table/chain/expressions/userdata, no handle attr.
	ruleRequest, ruleErr := nftRuleMessage(2, "sb_desync", "__sbds_v1", nil, []byte(nftEchoCaptureAnchorUserdata))
	if ruleErr != nil {
		t.Fatalf("rule request: %v", ruleErr)
	}
	missingHandle := nftTestKernelMessage(uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE,
		5, nftEchoCapturePort, ruleRequest.data)

	cases := []struct {
		name string
		step nftScriptedRecv
		want string
	}{
		{name: "foreign sender pid", step: nftScriptedRecv{data: echo,
			peer: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 4242, Groups: 0}},
			want: "foreign netlink peer"},
		{name: "foreign sender group", step: nftScriptedRecv{data: echo,
			peer: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0x20}},
			want: "foreign netlink peer"},
		{name: "mixed sender group", step: nftScriptedRecv{data: echo,
			peer: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: nftEchoCaptureGroup | 1}},
			want: "foreign netlink peer"},
		{name: "echo group acknowledgement", step: nftScriptedRecv{data: tableAck, peer: nftKernelEchoPeer()},
			want: "not a rule notification"},
		{name: "echo group wrong message type", step: nftScriptedRecv{
			data: mutate(echoFrames[0], func(frame []byte) {
				binary.NativeEndian.PutUint16(frame[4:], uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWCHAIN)
			}),
			peer: nftKernelEchoPeer()}, want: "not a rule notification"},
		{name: "echo group foreign subsystem", step: nftScriptedRecv{
			data: mutate(echoFrames[0], func(frame []byte) { frame[5] = 9 }),
			peer: nftKernelEchoPeer()}, want: "not an nftables message"},
		{name: "echo group foreign recipient port", step: nftScriptedRecv{
			data: mutate(echoFrames[0], func(frame []byte) { binary.NativeEndian.PutUint32(frame[12:], 0x40000e99) }),
			peer: nftKernelEchoPeer()}, want: "another port"},
		{name: "echo group unknown sequence", step: nftScriptedRecv{
			data: mutate(echoFrames[0], func(frame []byte) { binary.NativeEndian.PutUint32(frame[8:], 99) }),
			peer: nftKernelEchoPeer()}, want: "unexpected sequence 99"},
		{name: "echo for a request without ECHO", step: nftScriptedRecv{
			data: mutate(echoFrames[0], func(frame []byte) { binary.NativeEndian.PutUint32(frame[8:], 3) }),
			peer: nftKernelEchoPeer()}, want: "unexpected sequence 3"},
		{name: "echo without a handle", step: nftScriptedRecv{data: missingHandle, peer: nftKernelEchoPeer()},
			want: "has no rule handle"},
		{name: "echo group malformed length", step: nftScriptedRecv{
			data: mutate(echoFrames[0], func(frame []byte) { binary.NativeEndian.PutUint32(frame[0:], 12) }),
			peer: nftKernelEchoPeer()}, want: "malformed"},
		{name: "echo group truncated datagram", step: nftScriptedRecv{data: echo[:len(echo)-3],
			peer: nftKernelEchoPeer()}, want: "malformed"},
		{name: "echo group trailing fragment", step: nftScriptedRecv{
			data: append(append([]byte(nil), echo...), make([]byte, 8)...), peer: nftKernelEchoPeer()},
			want: "malformed"},
		{name: "acknowledgement unexpected sequence", step: nftScriptedRecv{
			data: mutate(tableAck, func(frame []byte) { binary.NativeEndian.PutUint32(frame[8:], 9) }),
			peer: nftKernelPeer()}, want: "unexpected sequence 9"},
		{name: "acknowledgement foreign recipient port", step: nftScriptedRecv{
			data: mutate(tableAck, func(frame []byte) { binary.NativeEndian.PutUint32(frame[12:], 0x40000e99) }),
			peer: nftKernelPeer()}, want: "another port"},
		{name: "dump completion inside a batch", step: nftScriptedRecv{
			data: nftTestKernelMessage(unix.NLMSG_DONE, 3, nftEchoCapturePort, nil), peer: nftKernelPeer()},
			want: "dump completion"},
		{name: "notification in the plain kernel lane", step: nftScriptedRecv{data: echo, peer: nftKernelPeer()},
			want: "not an acknowledgement"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// Model test: one scripted negative datagram; no kernel socket.
			scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{test.step}}
			session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
			_, err := session.batch(nftInitialMarkerRequests(t))
			if err == nil {
				t.Fatalf("negative reply was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}

	t.Run("duplicate echo for one sequence", func(t *testing.T) {
		// Model test: scripted datagrams only.
		scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
			nftScriptedRecv{data: echo, peer: nftKernelEchoPeer()},
			nftScriptedRecv{data: echo, peer: nftKernelEchoPeer()},
		}}
		session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
		_, err := session.batch(nftInitialMarkerRequests(t))
		if err == nil || !strings.Contains(err.Error(), "unexpected sequence") {
			t.Fatalf("duplicate echo: %v", err)
		}
	})

	t.Run("acknowledgement before its echo", func(t *testing.T) {
		// Model test: scripted datagrams only. The kernel queues the ECHO copy
		// before the batch ACK list; an echo that arrives after its own ACK is
		// not a completion of this operation.
		scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
			nftScriptedAck(5, nftEchoCapturePort),
			nftScriptedRecv{data: echo, peer: nftKernelEchoPeer()},
		}}
		session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
		_, err := session.batch(nftInitialMarkerRequests(t))
		if err == nil || !strings.Contains(err.Error(), "unexpected sequence 5") {
			t.Fatalf("echo after acknowledgement: %v", err)
		}
	})

	t.Run("negative errno keeps its typed kernel error", func(t *testing.T) {
		// Model test: scripted datagrams only.
		ack := append([]byte(nil), tableAck...)
		binary.NativeEndian.PutUint32(ack[16:], negativeErrno(unix.ENOMEM))
		scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{{data: ack, peer: nftKernelPeer()}}}
		session := newNftScriptedSession(nftEchoCapturePort, 1, scripted)
		_, err := session.batch(nftInitialMarkerRequests(t))
		var kernelErr *nftKernelError
		if !errors.As(err, &kernelErr) {
			t.Fatalf("error = %v, want *nftKernelError", err)
		}
		if kernelErr.errno != unix.ENOMEM || kernelErr.sequence != 3 {
			t.Fatalf("kernel error = %+v", kernelErr)
		}
	})
}

// TestQueueAbsenceRejectsEchoGroupPeer drives the production W-query receipt
// through queryQueueAbsence: the kernel ECHO group mask is still a foreign peer
// for the sequenced -ENODEV absence query, which must stay pid0/groups0.
func TestQueueAbsenceRejectsEchoGroupPeer(t *testing.T) {
	// Model test: the fake session answers the exact raw query; no kernel
	// socket and no queue object exist.
	session := &queueAbsencePeerSession{
		fakeAnchorSession: fakeAnchorSession{namespace: newFakeNftNamespace(), port: 0x40000022},
		peer:              nftKernelEchoPeer(),
	}
	err := queryQueueAbsence(session, 16160)
	if err == nil || !strings.Contains(err.Error(), "queue absence reply came from a foreign peer") {
		t.Fatalf("echo-group peer for the W query: %v", err)
	}

	session.peer = nftKernelPeer()
	if err = queryQueueAbsence(session, 16160); err != nil {
		t.Fatalf("plain kernel peer control: %v", err)
	}
}

// queueAbsencePeerSession answers the raw no-attribute CONFIG lookup with the
// exact -ENODEV echo and a chosen sender address.
type queueAbsencePeerSession struct {
	fakeAnchorSession
	reply []byte
	peer  *unix.SockaddrNetlink
}

func (s *queueAbsencePeerSession) sendRaw(datagram []byte) error {
	reply, err := fakeQueueAbsenceReply(datagram, s.port)
	s.reply = reply
	return err
}

func (s *queueAbsencePeerSession) recvRaw() ([]byte, *unix.SockaddrNetlink, error) {
	return s.reply, s.peer, nil
}

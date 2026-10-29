//go:build linux

package desync

// Permanent model regressions for the selected-A persistent-anchor lifecycle,
// the N-A1 enqueue fence, the N-A2 release-scan and crash-recovery predicates.
// Model tests: no kernel object is created, and every case says so.
//
// The tests run the production lifecycle code over the hermetic nftables model
// and the deterministic queue kernel. They are model tests: no kernel object is
// created, and every case says so. Native-only NA1-Q1 and NA2-C6 remain NOT_RUN
// and are not substituted by these literals.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openAnchorSetup creates and closes one capture so the fixed anchors exist,
// then returns the anchor model and the IPv4 epoch.
func openAnchorSetup(t *testing.T, queue int) (*linuxCaptureSeams, string) {
	t.Helper()
	data := newFakeNFQueueConn("setup", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, queue)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("setup open: %v", err)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("setup close: %v", err)
	}
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000010}
	state, err := readAnchorFamilyState(session, FamilyIPv4)
	if err != nil {
		t.Fatalf("setup anchors: %v", err)
	}
	return seams, state.epoch
}

// addForeignRecord writes one m and optional p record of another process into
// the marker chain of the model.
func addForeignRecord(t *testing.T, seams *linuxCaptureSeams, epoch, process, capture string, phase string, port uint32, tag uint32) anchorQueuePorts {
	t.Helper()
	ports := anchorQueuePorts{
		out: 20000, in: 20001, pidnsDev: 1, pidnsIno: 2, tgid: 4242, startTicks: 99,
	}
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000011}
	manifest, err := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil,
		[]byte(anchorManifestUserdata(epoch, process, capture, ports)))
	if err != nil {
		t.Fatal(err)
	}
	requests := []nftRequest{manifest}
	if phase != "" {
		userdata, err := anchorPortUserdata(epoch, process, capture, port, phase, tag)
		if err != nil {
			t.Fatal(err)
		}
		portRule, err := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, []byte(userdata))
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, portRule)
	}
	if _, err := session.batch(requests); err != nil {
		t.Fatalf("add foreign record: %v", err)
	}
	return ports
}

// writeQueueReport appends deliberate rows that survive later model state
// changes (a dead owner's stale row, a foreign replacement).
func writeQueueReport(t *testing.T, kernel *fakeQueueKernel, rows ...string) {
	t.Helper()
	kernel.mu.Lock()
	kernel.extraReportRows = append(kernel.extraReportRows, rows...)
	kernel.publishReportLocked()
	kernel.mu.Unlock()
}

// clearQueueReport drops the deliberate rows and republishes the live state.
func clearQueueReport(t *testing.T, kernel *fakeQueueKernel) {
	t.Helper()
	kernel.mu.Lock()
	kernel.extraReportRows = nil
	kernel.publishReportLocked()
	kernel.mu.Unlock()
}

// modelCaptureRecords returns the capture records of one family.
func modelCaptureRecords(t *testing.T, seams *linuxCaptureSeams, family Family) map[string]*anchorManifestRecord {
	t.Helper()
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000012}
	state, err := readAnchorFamilyState(session, family)
	if err != nil {
		t.Fatalf("read anchor state: %v", err)
	}
	return state.captures
}

// captureTagRule returns the inject rule priority of one capture.
func captureInjectPriority(t *testing.T, seams *linuxCaptureSeams, capture *linuxCapture) uint32 {
	t.Helper()
	rules := fakeRulesWithUserdata(seams.anchors, byte(2), anchorTableName, ":"+capture.anchor.capture+":inject")
	if len(rules) != 1 {
		t.Fatalf("inject rules = %d, want 1", len(rules))
	}
	decoded, err := decodedExpressions(rules[0])
	if err != nil {
		t.Fatalf("decode inject: %v", err)
	}
	for _, expression := range decoded {
		if expression.name != "cmp" {
			continue
		}
		return binary.NativeEndian.Uint32(fakeCmpValue(expression))
	}
	t.Fatal("inject rule priority comparison missing")
	return 0
}

// TestAnchorFirstEnableCreatesFixedInfrastructure pins the F1 first-enable
// contract: one table per family, both base chains with policy accept and
// priority -150, and exactly the a/t marker rules.
func TestAnchorFirstEnableCreatesFixedInfrastructure(t *testing.T) {
	data := newFakeNFQueueConn("first", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16000)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		familyName, familyByte, _ := anchorFamilyNames(family)
		session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000013}
		state, err := readAnchorFamilyState(session, family)
		if err != nil {
			t.Fatalf("%s anchors: %v", familyName, err)
		}
		if state.epoch == "" || state.nextTag < uint64(anchorTagInitial) {
			t.Fatalf("%s anchor identity = %+v", familyName, state)
		}
		tables, err := readAnchorTables(session, familyByte)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, table := range tables {
			if table.name == anchorTableName {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("%s tables = %d, want exactly one", familyName, count)
		}
		chains, err := readAnchorChains(session, familyByte, anchorTableName)
		if err != nil {
			t.Fatal(err)
		}
		hooks := 0
		for _, chain := range chains {
			if chain.hasHook {
				hooks++
				if chain.priority != anchorBaseHookPriority {
					t.Fatalf("%s base chain %s priority = %d", familyName, chain.name, chain.priority)
				}
				if chain.policy != nftVerdictAccept {
					t.Fatalf("%s base chain %s policy = %d", familyName, chain.name, chain.policy)
				}
			}
		}
		if hooks != 2 {
			t.Fatalf("%s base hooks = %d, want 2", familyName, hooks)
		}
	}
	// A second capture reuses the same infrastructure: no second generation.
	_, second := newLinuxCaptureLease(t, 16001)
	secondCapture, err := openLinuxCapture(second)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if err := secondCapture.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000013}
		if _, err := readAnchorFamilyState(session, family); err != nil {
			t.Fatalf("anchors after close: %v", err)
		}
		if records := modelCaptureRecords(t, seams, family); len(records) != 0 {
			t.Fatalf("capture records left after close: %v", records)
		}
	}
}

// TestAnchorNeighbourTeardownKeepsPeerCapture is the F1-L model regression: two
// captures share the fixed anchors, closing one leaves the neighbour's rules,
// queues and metadata intact, and the neighbour still answers a packet.
func TestAnchorNeighbourTeardownKeepsPeerCapture(t *testing.T) {
	dataA := newFakeNFQueueConn("peer-a", 0, nil)
	seams := installLinuxCaptureSeams(t, dataA)
	_, leaseA := newLinuxCaptureLease(t, 16010)
	captureA, err := openLinuxCapture(leaseA)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	// The second capture gets its own queue transport from the seams.
	_, leaseB := newLinuxCaptureLease(t, 16011)
	captureB, err := openLinuxCapture(leaseB)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	linuxA := captureA.(*linuxCapture)
	linuxB := captureB.(*linuxCapture)
	if linuxA.queue == linuxB.queue || linuxA.outPort == linuxB.outPort {
		t.Fatalf("captures share identity: queues %d/%d ports %#x/%#x",
			linuxA.queue, linuxB.queue, linuxA.outPort, linuxB.outPort)
	}
	peerRules := fakeRulesWithUserdata(seams.anchors, byte(2), anchorTableName, ":"+linuxB.anchor.capture+":entry-o")
	if len(peerRules) != 1 {
		t.Fatalf("peer entry rules before close = %d", len(peerRules))
	}
	if err := captureA.Close(); err != nil {
		t.Fatalf("close A: %v", err)
	}
	// A's records are gone; B's remain, and the fixed markers are untouched.
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	if _, found := records[captureKey(linuxA.owner.token, linuxA.anchor.capture)]; found {
		t.Fatal("closed capture A still has metadata")
	}
	if _, found := records[captureKey(linuxB.owner.token, linuxB.anchor.capture)]; !found {
		t.Fatal("neighbour capture B lost its metadata")
	}
	if rules := fakeRulesWithUserdata(seams.anchors, byte(2), anchorTableName, ":"+linuxB.anchor.capture+":entry-o"); len(rules) != 1 {
		t.Fatal("neighbour dispatch entry was removed by the peer close")
	}
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000014}
	if _, err := readAnchorFamilyState(session, FamilyIPv4); err != nil {
		t.Fatalf("fixed anchors damaged by peer close: %v", err)
	}
	// The neighbour still answers a packet on its own queue.
	packet := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagPSH)
	if !seams.kernel.deliver(linuxB.queue, fakePacketMessage(linuxB.queue, 991, packet.Raw), 991) {
		t.Fatal("neighbour queue stopped delivering")
	}
	waitForCondition(t, "neighbour verdict", func() bool {
		return len(seams.kernel.verdictsFor(linuxB.queue, 991)) == 1
	})
	if err := captureB.Close(); err != nil {
		t.Fatalf("close B: %v", err)
	}
	if records := modelCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
		t.Fatalf("capture records after both closes: %v", records)
	}
}

// TestAnchorPartialCreationIsPreservedAndCompleted pins the initialization
// boundary: committed marker/base objects are never deleted to compensate for a
// later failure, and a missing base chain is created on the next enable.
func TestAnchorPartialCreationIsPreservedAndCompleted(t *testing.T) {
	data := newFakeNFQueueConn("partial", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	// Simulate an interrupted first enable: table, marker, a/t and the input
	// base chain exist; output does not.
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000015}
	epoch := "0123456789abcdef0123456789abcdef"
	requests := []nftRequest{
		nftTableMessage(byte(2), anchorTableName, nil),
		nftRegularChainMessage(byte(2), anchorTableName, anchorMarkerChainName),
	}
	anchorRule, _ := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, []byte(anchorMarkerUserdata("ip", epoch)))
	tagRule, _ := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, []byte(anchorTagUserdata(epoch, uint64(anchorTagInitial))))
	requests = append(requests, anchorRule, tagRule)
	if _, err := session.batch(requests); err != nil {
		t.Fatalf("partial marker: %v", err)
	}
	input := nftBaseChainMessage(byte(2), anchorTableName, anchorBaseInputName, "filter", int(unix.NF_INET_LOCAL_IN), anchorBaseHookPriority, []byte(anchorBaseUserdata(epoch, anchorBaseInputName)))
	if _, err := session.batch([]nftRequest{input}); err != nil {
		t.Fatalf("partial base: %v", err)
	}
	before, err := readAnchorFamilyStateAllowNoBase(session, FamilyIPv4)
	if err != nil {
		t.Fatalf("partial state: %v", err)
	}
	_, lease := newLinuxCaptureLease(t, 16020)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open over partial anchors: %v", err)
	}
	after, err := readAnchorFamilyState(session, FamilyIPv4)
	if err != nil {
		t.Fatalf("completed state: %v", err)
	}
	if before.epoch != after.epoch || after.epoch != epoch {
		t.Fatalf("epoch changed across completion: %q -> %q", before.epoch, after.epoch)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if state, err := readAnchorFamilyState(session, FamilyIPv4); err != nil || state.epoch != epoch {
		t.Fatalf("anchors after close: %v epoch=%q", err, state.epoch)
	}
}

// TestAnchorCollisionRefusesAdoption pins that a foreign table, a missing tag
// record or an untagged marker rule is a visible activation error, never a
// second table or a guessed tag counter.
func TestAnchorCollisionRefusesAdoption(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, seams *linuxCaptureSeams)
	}{
		{
			name: "table-without-marker",
			setup: func(t *testing.T, seams *linuxCaptureSeams) {
				session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000016}
				if _, err := session.batch([]nftRequest{nftTableMessage(byte(2), anchorTableName, nil)}); err != nil {
					t.Fatalf("foreign table: %v", err)
				}
			},
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data := newFakeNFQueueConn("collision", 0, nil)
			seams := installLinuxCaptureSeams(t, data)
			test.setup(t, seams)
			_, lease := newLinuxCaptureLease(t, 16030)
			if _, err := openLinuxCapture(lease); err == nil {
				t.Fatal("capture adopted a foreign anchor table")
			}
			session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000016}
			tables, err := readAnchorTables(session, byte(2))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, table := range tables {
				if table.name == anchorTableName {
					count++
				}
			}
			if count != 1 {
				t.Fatalf("foreign table was replaced: tables=%d", count)
			}
		})
	}
}

// TestAnchorMissingTagIsCollision proves an existing READY marker without the t
// high-water is not initialized with a guessed counter.
func TestAnchorMissingTagIsCollision(t *testing.T) {
	data := newFakeNFQueueConn("no-tag", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000017}
	epoch := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	requests := []nftRequest{
		nftTableMessage(byte(2), anchorTableName, nil),
		nftRegularChainMessage(byte(2), anchorTableName, anchorMarkerChainName),
	}
	anchorRule, _ := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, []byte(anchorMarkerUserdata("ip", epoch)))
	requests = append(requests, anchorRule)
	if _, err := session.batch(requests); err != nil {
		t.Fatal(err)
	}
	_, lease := newLinuxCaptureLease(t, 16031)
	if _, err := openLinuxCapture(lease); err == nil {
		t.Fatal("capture initialized an anchor without a tag high-water")
	}
}

// TestAnchorUntaggedMarkerRuleIsCollision proves an untagged rule in the
// marker chain is never silently ignored.
func TestAnchorUntaggedMarkerRuleIsCollision(t *testing.T) {
	data := newFakeNFQueueConn("untagged", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000018}
	epoch := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	anchorRule, _ := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, []byte(anchorMarkerUserdata("ip", epoch)))
	tagRule, _ := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, []byte(anchorTagUserdata(epoch, uint64(anchorTagInitial))))
	untagged, _ := nftRuleMessage(byte(2), anchorTableName, anchorMarkerChainName, nil, nil)
	requests := []nftRequest{
		nftTableMessage(byte(2), anchorTableName, nil),
		nftRegularChainMessage(byte(2), anchorTableName, anchorMarkerChainName),
		anchorRule, tagRule, untagged,
	}
	if _, err := session.batch(requests); err != nil {
		t.Fatal(err)
	}
	_, lease := newLinuxCaptureLease(t, 16032)
	if _, err := openLinuxCapture(lease); err == nil {
		t.Fatal("capture accepted an untagged marker rule")
	}
}

// ---------------------------------------------------------------------------
// N-A1: exact request encoding and receipt validation.
// ---------------------------------------------------------------------------

func TestEnqueueFenceRequestBytes(t *testing.T) {
	request := buildEnqueueFenceRequest()
	if len(request.datagram) != 3*fenceMessageBytes {
		t.Fatalf("request bytes = %d, want %d", len(request.datagram), 3*fenceMessageBytes)
	}
	types := []uint16{unix.NFNL_MSG_BATCH_BEGIN, nftMsgGetgen, nfnlMsgBatchEnd}
	sequences := []uint32{1, 2, 3}
	for index := 0; index < 3; index++ {
		message := request.datagram[index*fenceMessageBytes : (index+1)*fenceMessageBytes]
		if got := binary.NativeEndian.Uint32(message); got != fenceMessageBytes {
			t.Fatalf("message %d length = %d", index, got)
		}
		if got := binary.NativeEndian.Uint16(message[4:]); got != types[index] {
			t.Fatalf("message %d type = %#x, want %#x", index, got, types[index])
		}
		if got := binary.NativeEndian.Uint32(message[8:]); got != sequences[index] {
			t.Fatalf("message %d sequence = %d, want %d", index, got, sequences[index])
		}
		if got := binary.NativeEndian.Uint32(message[12:]); got != 0 {
			t.Fatalf("message %d nlmsg_pid = %d, want 0", index, got)
		}
	}
	if got := binary.NativeEndian.Uint16(request.datagram[6:]); got != unix.NLM_F_REQUEST {
		t.Fatalf("BEGIN flags = %#x", got)
	}
	if got := binary.NativeEndian.Uint16(request.datagram[fenceMessageBytes+6:]); got != unix.NLM_F_REQUEST|unix.NLM_F_ACK {
		t.Fatalf("GETGEN flags = %#x", got)
	}
	// nfgenmsg of BEGIN/END carries the nftables subsystem, GETGEN res_id=0.
	if got := binary.BigEndian.Uint16(request.datagram[18:]); got != unix.NFNL_SUBSYS_NFTABLES {
		t.Fatalf("BEGIN res_id = %#x", got)
	}
	if got := binary.BigEndian.Uint16(request.datagram[fenceMessageBytes+18:]); got != 0 {
		t.Fatalf("GETGEN res_id = %#x", got)
	}
}

// negativeErrno returns the two's-complement wire encoding of -errno.
func negativeErrno(errno unix.Errno) uint32 {
	code := int32(-int32(errno))
	return uint32(code)
}

// fenceReply builds a valid fence reply and applies mutations.
func fenceReply(t *testing.T, mutate func(reply []byte, request enqueueFenceRequest) []byte) ([]byte, *unix.SockaddrNetlink) {
	t.Helper()
	request := buildEnqueueFenceRequest()
	reply, peer, err := validFenceReply(request, 0x40000019)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		reply = mutate(reply, request)
	}
	return reply, peer
}

func TestEnqueueFenceReceiptValidation(t *testing.T) {
	baseRequest := buildEnqueueFenceRequest()
	validPeer := &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: 0}
	cases := []struct {
		name  string
		reply func(t *testing.T) ([]byte, *unix.SockaddrNetlink)
		ok    bool
	}{
		{name: "valid", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			reply, peer, _ := validFenceReply(baseRequest, 0x40000019)
			return reply, peer
		}, ok: true},
		{name: "success-ack0", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[16:], 0)
				return reply
			})
		}},
		{name: "begin-sequence-einval", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[8:], 1)
				binary.NativeEndian.PutUint32(reply[20+8:], 1)
				return reply
			})
		}},
		{name: "getgen-outside-batch", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				reply[20+4] = 0
				reply[20+5] = 1
				return reply
			})
		}},
		{name: "wrong-embedded-seq", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[20+8:], 7)
				return reply
			})
		}},
		{name: "wrong-outer-port", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[12:], 0x40000099)
				return reply
			})
		}},
		{name: "wrong-embedded-nfgenmsg", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				reply[20+16] = unix.AF_INET
				return reply
			})
		}},
		{name: "truncated", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			reply, peer, _ := validFenceReply(baseRequest, 0x40000019)
			return reply[:len(reply)-2], peer
		}},
		{name: "capped", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint16(reply[6:], unix.NLM_F_CAPPED)
				return reply
			})
		}},
		{name: "ack-tlvs", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint16(reply[6:], unix.NLM_F_ACK_TLVS)
				return reply
			})
		}},
		{name: "eperm", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[16:], negativeErrno(unix.EPERM))
				return reply
			})
		}},
		{name: "eopnotsupp", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[16:], negativeErrno(unix.EOPNOTSUPP))
				return reply
			})
		}},
		{name: "enomem", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[16:], negativeErrno(unix.ENOMEM))
				return reply
			})
		}},
		{name: "enobufs", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[16:], negativeErrno(unix.ENOBUFS))
				return reply
			})
		}},
		{name: "eintr", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			return fenceReply(t, func(reply []byte, request enqueueFenceRequest) []byte {
				binary.NativeEndian.PutUint32(reply[16:], negativeErrno(unix.EINTR))
				return reply
			})
		}},
		{name: "trailing-message", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			reply, peer, _ := validFenceReply(baseRequest, 0x40000019)
			return append(reply, reply...), peer
		}},
		{name: "foreign-peer", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			reply, _, _ := validFenceReply(baseRequest, 0x40000019)
			return reply, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 77, Groups: 0}
		}},
		// The ordinary batch lane accepts this exact kernel ECHO group mask, but
		// the selected enqueue-fence receipt stays pid0/groups0: a group-tagged
		// copy is never a fence receipt.
		{name: "echo-group-peer", reply: func(t *testing.T) ([]byte, *unix.SockaddrNetlink) {
			reply, _, _ := validFenceReply(baseRequest, 0x40000019)
			return reply, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0, Groups: nftEchoGroupMask}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			reply, peer := test.reply(t)
			receipt, err := parseEnqueueFenceReply(reply, peer, 0x40000019, baseRequest)
			if test.ok {
				if err != nil {
					t.Fatalf("valid receipt rejected: %v", err)
				}
				if receipt.errno != unix.EINVAL || receipt.sequence != 2 || receipt.boundPort != 0x40000019 {
					t.Fatalf("receipt = %+v", receipt)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid reply was accepted as the enqueue fence receipt")
			}
			if !errors.Is(err, errEnqueueFenceNoReceipt) {
				t.Fatalf("error %v is not the typed no-receipt class", err)
			}
			_ = validPeer
		})
	}
}

// TestRunEnqueueFenceWire drives the production send/parse path with the exact
// encoded datagram and a lost-then-valid schedule.
func TestRunEnqueueFenceWire(t *testing.T) {
	data := newFakeNFQueueConn("fence", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	calls := 0
	seams.setFenceReply(func(request enqueueFenceRequest, port uint32) ([]byte, *unix.SockaddrNetlink, error) {
		calls++
		if calls == 1 {
			return nil, nil, errNftMetadataTimeout
		}
		return validFenceReply(request, port)
	})
	if _, err := runEnqueueFence(); err == nil {
		t.Fatal("a lost fence reply was accepted")
	}
	receipt, err := runEnqueueFence()
	if err != nil {
		t.Fatalf("fresh fence retry: %v", err)
	}
	if receipt.sequence != fenceGetgenSequence {
		t.Fatalf("receipt sequence = %d", receipt.sequence)
	}
	last := lastFenceRequestForTest()
	expected := buildEnqueueFenceRequest()
	if string(last.datagram) != string(expected.datagram) {
		t.Fatalf("sent datagram differs from the built request:\n got %x\nwant %x", last.datagram, expected.datagram)
	}
}

// ---------------------------------------------------------------------------
// N-A1/Q3-Q4 and N-A2: lifecycle, ports, tags, witness and recovery.
// ---------------------------------------------------------------------------

// TestAnchorQueuePortClassesAndQnumZero pins the explicit port split, qnum 0 and
// the monotone tag high-water across a restart.
func TestAnchorQueuePortClassesAndQnumZero(t *testing.T) {
	data := newFakeNFQueueConn("ports", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 0)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open qnum0: %v", err)
	}
	linux := capture.(*linuxCapture)
	if linux.queue != 0 {
		t.Fatalf("queue = %d, want configured qnum 0", linux.queue)
	}
	if linux.outPort&nftQueuePortBit == 0 {
		t.Fatalf("queue port %#x is not in the queue class", linux.outPort)
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	manifest := records[captureKey(linux.owner.token, linux.anchor.capture)]
	if manifest == nil || manifest.port == nil {
		t.Fatal("capture records missing")
	}
	if manifest.record.ports.out != 0 {
		t.Fatalf("manifest outq = %d, want 0", manifest.record.ports.out)
	}
	if manifest.port.record.phase != "w" {
		t.Fatalf("port phase = %q, want w", manifest.port.record.phase)
	}
	if manifest.port.record.port != linux.outPort {
		t.Fatalf("port record = %#x, socket = %#x", manifest.port.record.port, linux.outPort)
	}
	if priority := captureInjectPriority(t, seams, linux); priority != linux.anchor.tag {
		t.Fatalf("inject priority = %#x, tag = %#x", priority, linux.anchor.tag)
	}
	firstTag := linux.anchor.tag
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// The tag high-water survives the close: the next capture gets a new tag.
	_, secondLease := newLinuxCaptureLease(t, 16040)
	second, err := openLinuxCapture(secondLease)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	secondCapture := second.(*linuxCapture)
	if secondCapture.anchor.tag <= firstTag {
		t.Fatalf("tag went backwards across restart: %#x -> %#x", firstTag, secondCapture.anchor.tag)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second: %v", err)
	}
}

// TestAnchorTagExhaustionIsPreAttachmentError proves the exhausted sentinel is a
// resource error before any capture metadata is committed.
func TestAnchorTagExhaustionIsPreAttachmentError(t *testing.T) {
	seams, _ := openAnchorSetup(t, 16050)
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000020}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		_, tableFamily, _ := anchorFamilyNames(family)
		state, err := readAnchorFamilyState(session, family)
		if err != nil {
			t.Fatal(err)
		}
		tagRule, err := nftRuleMessage(tableFamily, anchorTableName, anchorMarkerChainName, nil,
			[]byte(anchorTagUserdata(state.epoch, uint64(^uint32(0))+1)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := session.batch([]nftRequest{
			nftDeleteRuleMessage(tableFamily, anchorTableName, anchorMarkerChainName, state.tagHandle),
			tagRule,
		}); err != nil {
			t.Fatalf("%s exhaust: %v", state.family, err)
		}
	}
	_, lease := newLinuxCaptureLease(t, 16051)
	if _, err := openLinuxCapture(lease); err == nil {
		t.Fatal("capture opened with an exhausted tag high-water")
	}
	if records := modelCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
		t.Fatalf("exhausted open committed metadata: %v", records)
	}
}

// TestAnchorReleaseScanRetainsOnUnprovenWitness proves the W receipt gates the
// m/p removal and the positive capture-retired receipt.
func TestAnchorReleaseScanRetainsOnUnprovenWitness(t *testing.T) {
	data := newFakeNFQueueConn("scan", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16060)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := lease.capture.(*linuxCapture)
	// The old port is still present in a fresh report: the scan cannot prove
	// witness retirement, so the record and the charge must stay.
	writeQueueReport(t, seams.kernel, queueReportRow(linux.queue, linux.outPort, 0))
	if err := lease.Close(nil); err == nil {
		t.Fatal("close reported success without a release-scan receipt")
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	if _, found := records[captureKey(linux.owner.token, linux.anchor.capture)]; !found {
		t.Fatal("unproven witness retirement erased the capture record")
	}
	if !linux.owner.retainedState() {
		t.Fatal("unproven witness retirement did not retain the owner")
	}
	if err := lease.WaitCaptureRetired(); err == nil {
		t.Fatal("the positive capture-retired receipt was published for an unproven retirement")
	}
	// A new generation is refused while the record is retained.
	_, secondLease := newLinuxCaptureLease(t, 16061)
	if _, err := openLinuxCapture(secondLease); err == nil {
		t.Fatal("a new generation was admitted over a retained record")
	}
}

// TestAnchorReleaseScanAcceptsDifferentPort proves W-REPLACED: a genuine foreign
// row with a different port is a receipt and is never touched.
func TestAnchorReleaseScanAcceptsDifferentPort(t *testing.T) {
	data := newFakeNFQueueConn("replaced", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16062)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := capture.(*linuxCapture)
	foreignPort := linux.outPort + 1
	writeQueueReport(t, seams.kernel, queueReportRow(linux.queue, foreignPort, 3))
	if err := capture.Close(); err != nil {
		t.Fatalf("close with a genuine different-port row: %v", err)
	}
	if records := modelCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
		t.Fatalf("records after W-REPLACED: %v", records)
	}
	// The foreign row is still the only row: nothing configured or unbound it.
	content, err := os.ReadFile(namespaceQueueReportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), fmt.Sprintf("%d %d", linux.queue, foreignPort)) {
		t.Fatalf("foreign queue row changed: %q", string(content))
	}
}

// TestAnchorRecoversMetadataOnlyCapture is NA2-C1: an m without p of a dead
// process is cleaned up after whole-group death.
func TestAnchorRecoversMetadataOnlyCapture(t *testing.T) {
	seams, epoch := openAnchorSetup(t, 16070)
	process := strings.Repeat("d", 32)
	capture := strings.Repeat("e", 32)
	addForeignRecord(t, seams, epoch, process, capture, "", 0, 0)
	_, lease := newLinuxCaptureLease(t, 16071)
	opened, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open over m-only record: %v", err)
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	if _, found := records[captureKey(process, capture)]; found {
		t.Fatal("m-only record survived recovery")
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAnchorRecoversOpeningCapture is NA2-C2's model half: p(o) of a dead owner
// is retired without inventing a port receipt.
func TestAnchorRecoversOpeningCapture(t *testing.T) {
	seams, epoch := openAnchorSetup(t, 16072)
	process := strings.Repeat("f", 32)
	capture := strings.Repeat("1", 32)
	addForeignRecord(t, seams, epoch, process, capture, "o", 0x80000010, anchorTagInitial)
	_, lease := newLinuxCaptureLease(t, 16073)
	opened, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open over p(o) record: %v", err)
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	if _, found := records[captureKey(process, capture)]; found {
		t.Fatal("p(o) record survived recovery")
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAnchorRetainsWitnessedCrashUntilScan is NA2-C3/C4: a p(w) record with the
// old port still present is retained; a genuine different port completes the
// release-scan receipt.
func TestAnchorRetainsWitnessedCrashUntilScan(t *testing.T) {
	seams, epoch := openAnchorSetup(t, 16074)
	process := strings.Repeat("a", 32)
	capture := strings.Repeat("2", 32)
	port := uint32(0x80000011)
	ports := addForeignRecord(t, seams, epoch, process, capture, "w", port, anchorTagInitial)
	writeQueueReport(t, seams.kernel, queueReportRow(ports.out, port, 0))
	_, lease := newLinuxCaptureLease(t, 16075)
	if _, err := openLinuxCapture(lease); err == nil {
		t.Fatal("open admitted a new generation while the dead witness was still visible")
	}
	if _, found := modelCaptureRecords(t, seams, FamilyIPv4)[captureKey(process, capture)]; !found {
		t.Fatal("unproven p(w) record was erased")
	}
	// A genuine different-port row replaces the stale old-port row.
	clearQueueReport(t, seams.kernel)
	writeQueueReport(t, seams.kernel, queueReportRow(ports.out, port+2, 0))
	opened, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open after W-REPLACED: %v", err)
	}
	if _, found := modelCaptureRecords(t, seams, FamilyIPv4)[captureKey(process, capture)]; found {
		t.Fatal("p(w) record survived W-REPLACED recovery")
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAnchorOwnerClassification pins NA2-C7: unknown visibility, a live owner
// with a free guard and an orphan guard all refuse a new generation; a live
// owner with its guard is left untouched.
func TestAnchorOwnerClassification(t *testing.T) {
	seams, epoch := openAnchorSetup(t, 16080)
	process := strings.Repeat("b", 32)
	capture := strings.Repeat("3", 32)
	addForeignRecord(t, seams, epoch, process, capture, "o", 0x80000012, anchorTagInitial)
	session := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000021}
	before, err := readAnchorFamilyState(session, FamilyIPv4)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name      string
		verdict   anchorOwnerVerdict
		guardBusy bool
		wantOpen  bool
	}{
		{"unknown-visibility", anchorOwnerUnknown, false, false},
		{"live-with-guard", anchorOwnerLive, true, true},
		{"live-without-guard", anchorOwnerLive, false, false},
		{"dead-with-orphan-guard", anchorOwnerDead, true, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observeOwnerProcess = func(anchorRecord) (anchorOwnerObservation, error) {
				return anchorOwnerObservation{verdict: test.verdict, reason: "model schedule"}, nil
			}
			seams.guardsMu.Lock()
			delete(seams.guards, anchorGuardAddress(process))
			if test.guardBusy {
				seams.guards[anchorGuardAddress(process)] = true
			}
			seams.guardsMu.Unlock()
			_, lease := newLinuxCaptureLease(t, 16081)
			opened, err := openLinuxCapture(lease)
			if test.wantOpen {
				if err != nil {
					t.Fatalf("open refused: %v", err)
				}
				after, err := readAnchorFamilyState(session, FamilyIPv4)
				if err != nil {
					t.Fatal(err)
				}
				if _, found := after.captures[captureKey(process, capture)]; !found {
					t.Fatal("a live foreign owner's record was touched")
				}
				if err := opened.Close(); err != nil {
					t.Fatalf("close: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("open admitted a new generation for an unrecoverable owner")
			}
			after, readErr := readAnchorFamilyState(session, FamilyIPv4)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(after.captures) != len(before.captures) {
				t.Fatalf("records changed: %d -> %d", len(before.captures), len(after.captures))
			}
		})
	}
}

// TestAnchorLastGuardRetirement is NA2-C8's model half: a busy inherited guard
// retains the last record and the charge; after the guard is released a new
// incarnation recovers the record and the anchors stay fixed.
func TestAnchorLastGuardRetirement(t *testing.T) {
	data := newFakeNFQueueConn("guard", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16090)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := capture.(*linuxCapture)
	ownerToken := linux.owner.token
	seams.guardsMu.Lock()
	seams.forceGuardBusy = true
	seams.guardsMu.Unlock()
	if err := capture.Close(); err == nil {
		t.Fatal("close reported success with a busy inherited guard")
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	if _, found := records[captureKey(ownerToken, linux.anchor.capture)]; !found {
		t.Fatal("last record was erased before the guard release receipt")
	}
	// The guard is now free (the local fd was closed); a later process
	// incarnation recovers the retained record.
	seams.guardsMu.Lock()
	seams.forceGuardBusy = false
	seams.guardsMu.Unlock()
	anchorOwnerRegistry.Lock()
	delete(anchorOwnerRegistry.owners, linux.owner.key)
	anchorOwnerRegistry.Unlock()
	_, lease2 := newLinuxCaptureLease(t, 16091)
	opened, err := openLinuxCapture(lease2)
	if err != nil {
		t.Fatalf("recovery after guard release: %v", err)
	}
	if _, found := modelCaptureRecords(t, seams, FamilyIPv4)[captureKey(ownerToken, linux.anchor.capture)]; found {
		t.Fatal("retained record survived recovery after guard release")
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAnchorLostDetachAckReconciles is NA2-C5: a lost detach acknowledgement is
// reconciled by exact readback before the fence, and the close still completes.
func TestAnchorLostDetachAckReconciles(t *testing.T) {
	data := newFakeNFQueueConn("lost-ack", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16100)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := capture.(*linuxCapture)
	// The next committed batch is the detach: commit it, then report a lost
	// acknowledgement. The lifecycle must detect the committed effect by
	// readback and continue to the fence.
	seams.anchors.mu.Lock()
	seams.anchors.loseAck = 1
	seams.anchors.mu.Unlock()
	if err := capture.Close(); err != nil {
		t.Fatalf("close after a lost detach ACK: %v", err)
	}
	if records := modelCaptureRecords(t, seams, FamilyIPv4); len(records) != 0 {
		t.Fatalf("records after lost-ACK close: %v", records)
	}
	_ = linux
}

// TestAnchorNoOpConfigPrecedesUnbind pins the ordered control receipt: the own
// no-attribute CONFIG for the non-witness queue precedes its UNBIND, and outq is
// never unbound.
func TestAnchorNoOpConfigPrecedesUnbind(t *testing.T) {
	data := newFakeNFQueueConn("noop", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16110)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := capture.(*linuxCapture)
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	executed := data.executedMessages()
	noOpIndex := -1
	unbindIndex := -1
	for index, message := range executed {
		queue, command := nfqueueCommand(t, message)
		if queue != linux.inQueue {
			continue
		}
		if command == 0 && noOpIndex < 0 {
			noOpIndex = index
		}
		if command == nfqCfgCmdUnbind && unbindIndex < 0 {
			unbindIndex = index
		}
	}
	if noOpIndex < 0 || unbindIndex < 0 || noOpIndex > unbindIndex {
		t.Fatalf("CONFIG/unbind order: config=%d unbind=%d", noOpIndex, unbindIndex)
	}
	if got := countQueueCommand(t, executed, linux.queue, nfqCfgCmdUnbind); got != 0 {
		t.Fatalf("outq unbinds = %d, want 0", got)
	}
	if data.closings() != 1 {
		t.Fatalf("connection closes = %d, want 1", data.closings())
	}
	_ = seams
}

// TestAnchorRetainedChargeKeepsEndpoint pins the existing Lease discharge
// contract on an unproven retirement.
func TestAnchorRetainedChargeKeepsEndpoint(t *testing.T) {
	data := newFakeNFQueueConn("charge", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	engine, lease := newLinuxCaptureLease(t, 16120)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open: %v", err)
	}
	linux := lease.capture.(*linuxCapture)
	writeQueueReport(t, seams.kernel, queueReportRow(linux.queue, linux.outPort, 0))
	if err := lease.Close(nil); err == nil {
		t.Fatal("lease close reported success on an unproven retirement")
	}
	if engine.ActiveLeases() == 0 {
		t.Fatal("an unproven retirement discharged the lease charge")
	}
}

// TestAnchorPortCandidateSkipsReserved ensures a capture never binds a port
// already recorded by another capture in the same namespace.
func TestAnchorPortCandidateSkipsReserved(t *testing.T) {
	data := newFakeNFQueueConn("ports2", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	_, leaseA := newLinuxCaptureLease(t, 16130)
	captureA, err := openLinuxCapture(leaseA)
	if err != nil {
		t.Fatalf("open A: %v", err)
	}
	a := captureA.(*linuxCapture)
	_, leaseB := newLinuxCaptureLease(t, 16131)
	captureB, err := openLinuxCapture(leaseB)
	if err != nil {
		t.Fatalf("open B: %v", err)
	}
	b := captureB.(*linuxCapture)
	if a.outPort == b.outPort {
		t.Fatalf("two live captures bound the same netlink port %#x", a.outPort)
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	ports := make(map[uint32]bool)
	for _, record := range records {
		if record.port != nil {
			ports[record.port.record.port] = true
		}
	}
	if len(ports) != 2 {
		t.Fatalf("recorded ports = %d, want 2", len(ports))
	}
	_ = captureA.Close()
	_ = captureB.Close()
}

// TestAnchorQueueCreationHoldsForkReadToken proves the pre-witness socket
// creation runs under the single fork-read token: a simulated fork writer
// cannot acquire the write side until the token is released.
func TestAnchorQueueCreationHoldsForkReadToken(t *testing.T) {
	data := newFakeNFQueueConn("fork", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	entered := make(chan struct{})
	release := make(chan struct{})
	openQueueTransport = func(port uint32) (nfqueueTransport, error) {
		close(entered)
		<-release
		return seams.dial(port)
	}
	_, lease := newLinuxCaptureLease(t, 16150)
	opened := make(chan error, 1)
	go func() {
		_, err := openLinuxCapture(lease)
		opened <- err
	}()
	<-entered
	writerAcquired := make(chan struct{})
	go func() {
		syscall.ForkLock.Lock()
		syscall.ForkLock.Unlock()
		close(writerAcquired)
	}()
	select {
	case <-writerAcquired:
		t.Fatal("a fork writer acquired the write side while the queue socket was being created")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-opened; err != nil {
		t.Fatalf("open: %v", err)
	}
	select {
	case <-writerAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("the fork writer was not released after the transaction ended")
	}
}

// TestAnchorLostWitnessAckReconciles proves a lost p(w) acknowledgement is
// reconciled by complete readback instead of dropping the fork lock with an
// unproven socket, and the capture remains witnessed.
func TestAnchorLostWitnessAckReconciles(t *testing.T) {
	data := newFakeNFQueueConn("lost-w", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	seams.anchors.mu.Lock()
	seams.anchors.loseAckForSubstring = ":w:"
	seams.anchors.mu.Unlock()
	_, lease := newLinuxCaptureLease(t, 16151)
	opened, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open with a lost w ACK: %v", err)
	}
	linux := opened.(*linuxCapture)
	if !linux.outWitnessed {
		t.Fatal("capture is not witnessed after the lost ACK reconciliation")
	}
	if err := opened.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestQueueAbsenceReplyRejectsNonENODEV pins that EPERM is not proof of absence.
func TestQueueAbsenceReplyRejectsNonENODEV(t *testing.T) {
	session := &fakeAnchorSession{namespace: newFakeNftNamespace(), port: 0x40000022}
	request, err := nfqueueConfigMessage(16160, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Sequence = 7
	request.Header.Length = uint32(16 + len(request.Data))
	reply, err := fakeQueueAbsenceReply(marshalNetlinkMessage(request), 0x40000022)
	if err != nil {
		t.Fatal(err)
	}
	if err := parseQueueAbsenceReply(reply, 0x40000022, request); err != nil {
		t.Fatalf("valid -ENODEV reply rejected: %v", err)
	}
	eperm := append([]byte(nil), reply...)
	binary.NativeEndian.PutUint32(eperm[16:], negativeErrno(unix.EPERM))
	if err := parseQueueAbsenceReply(eperm, 0x40000022, request); err == nil {
		t.Fatal("EPERM was accepted as queue absence")
	}
	if err := parseQueueAbsenceReply(reply, 0x40000099, request); err == nil {
		t.Fatal("a foreign bound port was accepted as queue absence")
	}
	_ = session
}

// TestAnchorQueuePortEADDRINUSERetriesCandidate pins the fallback error: a
// candidate whose explicit port is already bound is skipped, not adopted, and
// the next candidate completes the open.
func TestAnchorQueuePortEADDRINUSERetriesCandidate(t *testing.T) {
	data := newFakeNFQueueConn("fallback", 0, nil)
	installLinuxCaptureSeams(t, data)
	base := openQueueTransport
	attempts := 0
	failed := uint32(0)
	openQueueTransport = func(port uint32) (nfqueueTransport, error) {
		attempts++
		if attempts == 1 {
			failed = port
			return nil, unix.EADDRINUSE
		}
		return base(port)
	}
	_, lease := newLinuxCaptureLease(t, 16155)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open after EADDRINUSE fallback: %v", err)
	}
	linux := capture.(*linuxCapture)
	if attempts != 2 {
		t.Fatalf("transport attempts = %d, want 2", attempts)
	}
	if linux.outPort == failed {
		t.Fatal("the busy candidate port was adopted")
	}
	if !linux.outWitnessed {
		t.Fatal("capture is not witnessed after the fallback")
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestAnchorOwnQueueTotalMustBeZero pins the fresh own queue_total=0 receipt:
// the no-op ACK alone does not prove that no packet of ours is still held.
func TestAnchorOwnQueueTotalMustBeZero(t *testing.T) {
	data := newFakeNFQueueConn("total", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	capture := &linuxCapture{
		queue:   16200,
		inQueue: 16201,
		outPort: data.portid,
		nl:      data,
		owner:   &anchorOwner{nsFD: 1},
	}
	if err := seams.kernel.control(data, capture.queue, nfqCfgCmdBind); err != nil {
		t.Fatal(err)
	}
	if err := seams.kernel.control(data, capture.inQueue, nfqCfgCmdBind); err != nil {
		t.Fatal(err)
	}
	if err := capture.observeOwnQueuesEmpty(); err != nil {
		t.Fatalf("empty own queues rejected: %v", err)
	}
	seams.kernel.mu.Lock()
	seams.kernel.addEntryLocked(capture.queue, 7)
	seams.kernel.mu.Unlock()
	if err := capture.observeOwnQueuesEmpty(); err == nil || !strings.Contains(err.Error(), "still holds 1") {
		t.Fatalf("a live held packet was not rejected: %v", err)
	}
	seams.kernel.verdict(data, capture.queue, 7, nfqueueVerdictAccept)
	clearQueueReport(t, seams.kernel)
	writeQueueReport(t, seams.kernel, queueReportRow(capture.queue, data.portid, 0))
	if err := capture.observeOwnQueuesEmpty(); err == nil {
		t.Fatal("a duplicate own row was accepted")
	}
}

// TestAnchorQnumReservationReleasedAfterClose pins the in-process reservation of
// an explicit qnum across a failed and a successful close.
func TestAnchorQnumReservationReleasedAfterClose(t *testing.T) {
	data := newFakeNFQueueConn("qnum", 0, nil)
	installLinuxCaptureSeams(t, data)
	_, lease := newLinuxCaptureLease(t, 16140)
	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if qnumLive(16140) {
		t.Fatal("explicit qnum reservation survived a successful close")
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("lease close: %v", err)
	}
	_ = time.Second
}

//go:build linux

package desync

// Model receipt for S22-DEFAULT-GETGEN-ACK: a standalone GETGEN that requests
// an acknowledgement owns the complete NEWGEN+ACK0 exchange before it returns,
// so the following production dump caller sees a clean receive stream.
//
// Fixtures. The two GETGEN exchanges below are verbatim kernel replies captured
// on the exact Ubuntu 6.8 target by the diagnostic-only send/receive observer of
// independent QA run549 (t_780d5908, logs/linux-smoke-observed.txt and
// netlink-trace-decoded.json):
//
//	session A (first activation): control port 0x40000f6d, GETGEN seq35,
//	                              NEWGEN seq35 generation7, ACK0 seq35.
//	session B (cleanup after the failed readback): control port 0x4000088b,
//	                              GETGEN seq1, NEWGEN seq1 generation7,
//	                              ACK0 seq1.
//
// The same-datagram and acknowledgement-first fixtures are concatenations of
// those captured messages of the same session (the datagram partition is the
// only variable); no kernel reply is invented. A later sequence number in a
// derived fixture is produced by rewriting the outer sequence field (and, for
// an ACK0, the embedded request echo's sequence field) of the captured message,
// so the acknowledgement still echoes a request with that sequence. The dump
// completion is a derived empty GETTABLE completion built for the dump's own
// sequence: the original capture ends at the stale ACK that the next dump
// consumed, so the follow-on dump response is documented as derived and the
// captured prefix stays unmodified.
//
// Model test: every case scripts the syscall datagram boundary; no kernel
// socket is opened and no netfilter object is created or read.

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
	// nftGenerationCapturePort is the captured control-class port 0x40000f6d.
	nftGenerationCapturePort = uint32(1073745773)
	// nftGenerationCaptureRequest is the verbatim GETGEN request of session A
	// (header len20, type0x0a10, flags REQUEST|ACK 0x5, seq35, pid0, IPv4).
	nftGenerationCaptureRequest = "14000000100a0500230000000000000002000000"
	// nftGenerationCaptureNewgen is the verbatim NEWGEN reply of session A.
	nftGenerationCaptureNewgen = "380000000f0a0000230000006d0f0040000000070800010000000007080002000002069714000300736d6f6b652d6f627365727665642d00"
	// nftGenerationCaptureAck is the verbatim capped ACK0 of session A.
	nftGenerationCaptureAck = "2400000002000001230000006d0f00400000000014000000100a05002300000000000000"

	// nftGenerationCleanupPort is the captured cleanup control-class port
	// 0x4000088b.
	nftGenerationCleanupPort = uint32(0x4000088b)
	// nftGenerationCleanupRequest is the verbatim GETGEN request of session B
	// (seq1 on a fresh socket).
	nftGenerationCleanupRequest = "14000000100a0500010000000000000002000000"
	// nftGenerationCleanupNewgen is the verbatim NEWGEN reply of session B.
	nftGenerationCleanupNewgen = "380000000f0a0000010000008b080040000000070800010000000007080002000002069714000300736d6f6b652d6f627365727665642d00"
	// nftGenerationCleanupAck is the verbatim capped ACK0 of session B.
	nftGenerationCleanupAck = "2400000002000001010000008b0800400000000014000000100a05000100000000000000"

	// nftGenerationCapturedID is the generation id carried by both captures.
	nftGenerationCapturedID = uint32(7)
)

// nftGenerationDumpDone answers the most recent GETTABLE dump request with the
// derived empty-result completion for that request's own sequence. It is built
// from the bytes the production encoder actually sent, so a dump that runs
// before the requested GETGEN ACK is consumed still receives this completion
// after the stale ACK has been rejected as an unexpected dump acknowledgement.
func nftGenerationDumpDone(port uint32) nftScriptedRecv {
	return nftScriptedRecv{build: func(sent [][]byte) ([]byte, *unix.SockaddrNetlink, error) {
		if len(sent) == 0 {
			return nil, nil, errors.New("model: dump request was not sent")
		}
		request := sent[len(sent)-1]
		if len(request) < 16 {
			return nil, nil, errors.New("model: dump request is truncated")
		}
		if length := int(binary.NativeEndian.Uint32(request[0:])); length != len(request) {
			return nil, nil, fmt.Errorf("model: dump request length %d, datagram %d", length, len(request))
		}
		if typ := binary.NativeEndian.Uint16(request[4:]); typ != uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_GETTABLE {
			return nil, nil, fmt.Errorf("model: last request type %#x is not a GETTABLE dump", typ)
		}
		if flags := binary.NativeEndian.Uint16(request[6:]); flags&uint16(unix.NLM_F_DUMP) == 0 {
			return nil, nil, fmt.Errorf("model: last request flags %#x do not request a dump", flags)
		}
		sequence := binary.NativeEndian.Uint32(request[8:])
		return nftTestKernelMessage(unix.NLMSG_DONE, sequence, port, nil), nftKernelPeer(), nil
	}}
}

// nftGenerationWithSequence derives a copy of one captured exchange frame whose
// outer sequence is seq. For an ACK0 the embedded request echo's sequence is
// rewritten too, so the acknowledgement remains an exact echo of a request
// with that sequence. The captured constants are never modified.
func nftGenerationWithSequence(t *testing.T, frame []byte, seq uint32) []byte {
	t.Helper()
	out := append([]byte(nil), frame...)
	if len(out) < 16 {
		t.Fatalf("derived fixture frame is truncated")
	}
	binary.NativeEndian.PutUint32(out[8:], seq)
	if binary.NativeEndian.Uint16(out[4:]) == unix.NLMSG_ERROR {
		if len(out) < 32 {
			t.Fatalf("derived acknowledgement is truncated")
		}
		binary.NativeEndian.PutUint32(out[28:], seq)
	}
	return out
}

// TestNftGenerationCompletesExchangeBeforeDump is the permanent composed
// generation -> production dump -> generation receipt. It covers the captured
// separate data/ACK datagrams, both same-datagram orderings and the
// acknowledgement-before-data ordering, and requires that no requested ACK0
// remains unread when generation returns.
func TestNftGenerationCompletesExchangeBeforeDump(t *testing.T) {
	port := nftGenerationCapturePort
	newgen := mustNftBytes(t, nftGenerationCaptureNewgen)
	ack := mustNftBytes(t, nftGenerationCaptureAck)
	request := mustNftBytes(t, nftGenerationCaptureRequest)
	dataThenAck := append(append([]byte(nil), newgen...), ack...)
	ackThenData := append(append([]byte(nil), ack...), newgen...)

	orderings := []struct {
		name  string
		first []nftScriptedRecv
	}{
		{
			name: "captured separate data then acknowledgement",
			first: []nftScriptedRecv{
				{data: newgen, peer: nftKernelPeer()},
				{data: ack, peer: nftKernelPeer()},
			},
		},
		{
			name: "same datagram data then acknowledgement",
			first: []nftScriptedRecv{
				{data: dataThenAck, peer: nftKernelPeer()},
			},
		},
		{
			name: "same datagram acknowledgement then data",
			first: []nftScriptedRecv{
				{data: ackThenData, peer: nftKernelPeer()},
			},
		},
		{
			name: "separate acknowledgement then data",
			first: []nftScriptedRecv{
				{data: ack, peer: nftKernelPeer()},
				{data: newgen, peer: nftKernelPeer()},
			},
		},
	}
	// The second generation of the composition runs with the session's third
	// sequence (35, 36 dump, 37). Its replies are derived from the captured
	// ones by rewriting only the sequence fields.
	newgen37 := nftGenerationWithSequence(t, newgen, 37)
	ack37 := nftGenerationWithSequence(t, ack, 37)

	for _, ordering := range orderings {
		t.Run(ordering.name, func(t *testing.T) {
			steps := append([]nftScriptedRecv(nil), ordering.first...)
			steps = append(steps,
				nftGenerationDumpDone(port),
				nftScriptedRecv{data: newgen37, peer: nftKernelPeer()},
				nftScriptedRecv{data: ack37, peer: nftKernelPeer()},
			)
			scripted := &nftScriptedDatagram{steps: steps}
			session := newNftScriptedSession(port, 34, scripted)

			generation, err := session.generation(unix.NFPROTO_IPV4)
			if err != nil {
				t.Fatalf("generation: %v", err)
			}
			if generation != nftGenerationCapturedID {
				t.Fatalf("generation = %d, want the captured %d", generation, nftGenerationCapturedID)
			}
			// The requested ACK is part of the completed exchange: only the
			// dump completion and the next generation's replies may remain.
			if len(scripted.steps) != 3 {
				t.Fatalf("after generation %d scripted datagrams remain, want 3 (requested ACK left unread)", len(scripted.steps))
			}
			// Drive the real production dump caller that immediately follows
			// generation in readAnchorFamilyState.
			tables, err := readAnchorTables(session, unix.NFPROTO_IPV4)
			if err != nil {
				t.Fatalf("production table dump after GETGEN: %v", err)
			}
			if len(tables) != 0 {
				t.Fatalf("table dump returned %d records, want the derived empty result", len(tables))
			}
			generation, err = session.generation(unix.NFPROTO_IPV4)
			if err != nil {
				t.Fatalf("second generation: %v", err)
			}
			if generation != nftGenerationCapturedID {
				t.Fatalf("second generation = %d, want %d", generation, nftGenerationCapturedID)
			}
			if len(scripted.steps) != 0 {
				t.Fatalf("%d scripted datagrams were not consumed", len(scripted.steps))
			}

			if len(scripted.sends) != 3 {
				t.Fatalf("sent datagrams = %d, want GETGEN, dump, GETGEN", len(scripted.sends))
			}
			if !bytes.Equal(scripted.sends[0], request) {
				t.Fatalf("first request is not the captured GETGEN frame: %x", scripted.sends[0])
			}
			dump := scripted.sends[1]
			if len(dump) < 16 {
				t.Fatalf("dump request is truncated")
			}
			if typ := binary.NativeEndian.Uint16(dump[4:]); typ != uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_GETTABLE {
				t.Fatalf("dump request type = %#x", typ)
			}
			if flags := binary.NativeEndian.Uint16(dump[6:]); flags != uint16(netlink.Request|netlink.Dump) {
				t.Fatalf("dump request flags = %#x, want REQUEST|DUMP", flags)
			}
			if seq := binary.NativeEndian.Uint32(dump[8:]); seq != 36 {
				t.Fatalf("dump request sequence = %d, want 36", seq)
			}
			next := nftGenerationWithSequence(t, request, 37)
			if !bytes.Equal(scripted.sends[2], next) {
				t.Fatalf("second GETGEN request = %x, want the captured frame with sequence 37", scripted.sends[2])
			}
		})
	}
}

// TestNftGenerationBackToBackSessions replays the captured first-session
// exchange and the captured cleanup-session exchange (a fresh socket whose
// sequence restarts at 1) through the same composed caller, back to back.
func TestNftGenerationBackToBackSessions(t *testing.T) {
	// First session: captured port, seq34 -> GETGEN35, dump36, GETGEN37.
	firstScripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
		{data: mustNftBytes(t, nftGenerationCaptureNewgen), peer: nftKernelPeer()},
		{data: mustNftBytes(t, nftGenerationCaptureAck), peer: nftKernelPeer()},
		nftGenerationDumpDone(nftGenerationCapturePort),
		{data: nftGenerationWithSequence(t, mustNftBytes(t, nftGenerationCaptureNewgen), 37), peer: nftKernelPeer()},
		{data: nftGenerationWithSequence(t, mustNftBytes(t, nftGenerationCaptureAck), 37), peer: nftKernelPeer()},
	}}
	first := newNftScriptedSession(nftGenerationCapturePort, 34, firstScripted)

	// Cleanup session: captured second port, seq0 -> GETGEN1, dump2, GETGEN3.
	cleanupNewgen := mustNftBytes(t, nftGenerationCleanupNewgen)
	cleanupAck := mustNftBytes(t, nftGenerationCleanupAck)
	secondScripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
		{data: cleanupNewgen, peer: nftKernelPeer()},
		{data: cleanupAck, peer: nftKernelPeer()},
		nftGenerationDumpDone(nftGenerationCleanupPort),
		{data: nftGenerationWithSequence(t, cleanupNewgen, 3), peer: nftKernelPeer()},
		{data: nftGenerationWithSequence(t, cleanupAck, 3), peer: nftKernelPeer()},
	}}
	second := newNftScriptedSession(nftGenerationCleanupPort, 0, secondScripted)

	for name, session := range map[string]*nftNetlink{"first activation session": first, "cleanup session": second} {
		t.Run(name, func(t *testing.T) {
			generation, err := session.generation(unix.NFPROTO_IPV4)
			if err != nil {
				t.Fatalf("generation: %v", err)
			}
			if generation != nftGenerationCapturedID {
				t.Fatalf("generation = %d, want %d", generation, nftGenerationCapturedID)
			}
			if _, err = readAnchorTables(session, unix.NFPROTO_IPV4); err != nil {
				t.Fatalf("production table dump after GETGEN: %v", err)
			}
			if generation, err = session.generation(unix.NFPROTO_IPV4); err != nil || generation != nftGenerationCapturedID {
				t.Fatalf("second generation = %d,%v", generation, err)
			}
		})
	}
	if len(firstScripted.steps) != 0 || len(secondScripted.steps) != 0 {
		t.Fatalf("unconsumed scripted datagrams: first=%d second=%d", len(firstScripted.steps), len(secondScripted.steps))
	}
	if !bytes.Equal(firstScripted.sends[0], mustNftBytes(t, nftGenerationCaptureRequest)) {
		t.Fatalf("first activation GETGEN request is not the captured frame: %x", firstScripted.sends[0])
	}
	if !bytes.Equal(secondScripted.sends[0], mustNftBytes(t, nftGenerationCleanupRequest)) {
		t.Fatalf("cleanup GETGEN request is not the captured seq1 frame: %x", secondScripted.sends[0])
	}
	if len(firstScripted.sends) != 3 || len(secondScripted.sends) != 3 {
		t.Fatalf("sent datagrams: first=%d second=%d, want 3+3", len(firstScripted.sends), len(secondScripted.sends))
	}
}

// TestNftGenerationRejectsIncompleteOrConflictingExchanges pins the negative
// receipt of the standalone GETGEN exchange: a foreign peer, a wrong recipient
// or sequence, a wrong message type, a missing or duplicated data/ACK message,
// a conflicting request echo, a kernel error and a truncated/malformed
// datagram are never a successful read.
func TestNftGenerationRejectsIncompleteOrConflictingExchanges(t *testing.T) {
	port := nftGenerationCapturePort
	newgen := mustNftBytes(t, nftGenerationCaptureNewgen)
	ack := mustNftBytes(t, nftGenerationCaptureAck)

	mutate := func(frame []byte, change func([]byte)) []byte {
		out := append([]byte(nil), frame...)
		change(out)
		return out
	}
	// The kernel's capped ACK0 carries the error code then the 16-byte request
	// header; offset 16 is the code and offset 20 starts the echoed header.
	negative := mutate(ack, func(frame []byte) {
		binary.NativeEndian.PutUint32(frame[16:], negativeErrno(unix.ENOMEM))
	})
	wrongEcho := mutate(ack, func(frame []byte) {
		frame[20+6] ^= 0x2 // embedded request flag byte: no longer the sent request
	})
	ackWrongPort := mutate(ack, func(frame []byte) {
		binary.NativeEndian.PutUint32(frame[12:], 0x40000e99)
	})
	ackWrongSeq := mutate(ack, func(frame []byte) {
		binary.NativeEndian.PutUint32(frame[8:], 36)
		binary.NativeEndian.PutUint32(frame[28:], 36)
	})
	dataWrongPort := mutate(newgen, func(frame []byte) {
		binary.NativeEndian.PutUint32(frame[12:], 0x40000e99)
	})
	dataWrongSeq := mutate(newgen, func(frame []byte) {
		binary.NativeEndian.PutUint32(frame[8:], 36)
	})
	dataWrongType := mutate(newgen, func(frame []byte) {
		binary.NativeEndian.PutUint16(frame[4:], uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWTABLE)
	})
	// An acknowledgement with only the 4-byte error code and no echoed request.
	bareAck := make([]byte, 20)
	binary.NativeEndian.PutUint32(bareAck[0:], 20)
	binary.NativeEndian.PutUint16(bareAck[4:], unix.NLMSG_ERROR)
	binary.NativeEndian.PutUint16(bareAck[6:], unix.NLM_F_CAPPED)
	binary.NativeEndian.PutUint32(bareAck[8:], 35)
	binary.NativeEndian.PutUint32(bareAck[12:], port)
	// An acknowledgement whose echoed request is neither the capped header nor
	// the complete 20-byte request. The 33-byte message is padded to the
	// netlink alignment, like any datagram.
	partialEcho := make([]byte, 36)
	copy(partialEcho, ack[:16])
	binary.NativeEndian.PutUint32(partialEcho[0:], 33)
	copy(partialEcho[20:], ack[20:33])
	// A NEWGEN data message without the generation id attribute.
	noID := nftTestKernelMessage(uint16(unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWGEN, 35, port, []byte{0, 0, 0, 0})
	done := nftTestKernelMessage(unix.NLMSG_DONE, 35, port, nil)

	cases := []struct {
		name  string
		steps []nftScriptedRecv
		want  string
		check func(t *testing.T, err error)
	}{
		{name: "foreign sender pid", want: "foreign netlink peer", steps: []nftScriptedRecv{
			{data: newgen, peer: &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 4242}}}},
		{name: "echo sender group", want: "foreign netlink peer", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelEchoPeer()}}},
		{name: "acknowledgement from echo sender group", want: "foreign netlink peer", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: ack, peer: nftKernelEchoPeer()}}},
		{name: "data addressed to another port", want: "another port", steps: []nftScriptedRecv{
			{data: dataWrongPort, peer: nftKernelPeer()}}},
		{name: "acknowledgement addressed to another port", want: "another port", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: ackWrongPort, peer: nftKernelPeer()}}},
		{name: "data with the wrong sequence", want: "sequence 36, want 35", steps: []nftScriptedRecv{
			{data: dataWrongSeq, peer: nftKernelPeer()}}},
		{name: "acknowledgement with the wrong sequence", want: "sequence 36, want 35", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: ackWrongSeq, peer: nftKernelPeer()}}},
		{name: "data with the wrong message type", want: "unexpected nftables GETGEN reply type", steps: []nftScriptedRecv{
			{data: dataWrongType, peer: nftKernelPeer()}}},
		{name: "dump completion instead of data", want: "unexpected nftables GETGEN completion", steps: []nftScriptedRecv{
			{data: done, peer: nftKernelPeer()}}},
		{name: "data without a generation id", want: "no generation id", steps: []nftScriptedRecv{
			{data: noID, peer: nftKernelPeer()}}},
		{name: "duplicate data messages", want: "duplicate nftables GETGEN reply", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: newgen, peer: nftKernelPeer()}}},
		{name: "duplicate acknowledgements", want: "duplicate nftables GETGEN acknowledgement", steps: []nftScriptedRecv{
			{data: ack, peer: nftKernelPeer()},
			{data: ack, peer: nftKernelPeer()}}},
		{name: "duplicate messages in one datagram", want: "duplicate nftables GETGEN acknowledgement", steps: []nftScriptedRecv{
			{data: append(append(append([]byte(nil), newgen...), ack...), ack...), peer: nftKernelPeer()}}},
		{name: "conflicting request echo", want: "request echo differs", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: wrongEcho, peer: nftKernelPeer()}}},
		{name: "acknowledgement without an echoed request", want: "0 echoed request bytes", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: bareAck, peer: nftKernelPeer()}}},
		{name: "acknowledgement with a partial request echo", want: "13 echoed request bytes", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: partialEcho, peer: nftKernelPeer()}}},
		{name: "negative acknowledgement", want: "rejected", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()},
			{data: negative, peer: nftKernelPeer()}},
			check: func(t *testing.T, err error) {
				t.Helper()
				var kernelErr *nftKernelError
				if !errors.As(err, &kernelErr) {
					t.Fatalf("error = %v, want *nftKernelError", err)
				}
				if kernelErr.errno != unix.ENOMEM || kernelErr.sequence != 35 {
					t.Fatalf("kernel error = %+v, want ENOMEM at sequence 35", kernelErr)
				}
			}},
		{name: "data without the requested acknowledgement", want: "not answered", steps: []nftScriptedRecv{
			{data: newgen, peer: nftKernelPeer()}}},
		{name: "acknowledgement without the requested data", want: "not answered", steps: []nftScriptedRecv{
			{data: ack, peer: nftKernelPeer()}}},
		{name: "empty datagram", want: "empty nftables GETGEN reply datagram", steps: []nftScriptedRecv{
			{data: nil, peer: nftKernelPeer()}}},
		{name: "malformed reply length", want: "malformed", steps: []nftScriptedRecv{
			{data: mutate(newgen, func(frame []byte) { binary.NativeEndian.PutUint32(frame[0:], 12) }), peer: nftKernelPeer()}}},
		{name: "truncated reply datagram", want: "malformed", steps: []nftScriptedRecv{
			{data: newgen[:len(newgen)-3], peer: nftKernelPeer()}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			scripted := &nftScriptedDatagram{steps: append([]nftScriptedRecv(nil), test.steps...)}
			session := newNftScriptedSession(port, 34, scripted)
			generation, err := session.generation(unix.NFPROTO_IPV4)
			if err == nil {
				t.Fatalf("generation = %d, negative reply was accepted", generation)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if test.check != nil {
				test.check(t, err)
			}
		})
	}
}

// TestNftGenerationAndDumpRejectEchoGroupPeer keeps the strict standalone
// callers strict: the authentic groups64 kernel marker-ECHO datagram is a
// foreign peer for both the GETGEN exchange and a dump, never a reply.
func TestNftGenerationAndDumpRejectEchoGroupPeer(t *testing.T) {
	for _, operation := range []string{"generation", "dump"} {
		t.Run(operation, func(t *testing.T) {
			scripted := &nftScriptedDatagram{steps: []nftScriptedRecv{
				nftScriptedDatagramStep(t, nftEchoCaptureDatagram, nftKernelEchoPeer()),
			}}
			session := newNftScriptedSession(nftEchoCapturePort, 4, scripted)
			var err error
			if operation == "generation" {
				_, err = session.generation(unix.NFPROTO_IPV4)
			} else {
				_, err = session.dump(unix.NFT_MSG_GETTABLE, unix.NFPROTO_IPV4, nil)
			}
			if err == nil || !strings.Contains(err.Error(), "foreign netlink peer") {
				t.Fatalf("%s accepted a groups64 peer: %v", operation, err)
			}
		})
	}
}

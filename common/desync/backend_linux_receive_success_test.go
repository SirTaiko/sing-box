//go:build linux

package desync

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// Success-only scripted TRANSPORT: the actual adapter and pinned Conn decode
// and receive. No socket/Socketpair/native capture is opened by these tests.
type receive39Script struct {
	tb      testing.TB
	wire    [][]byte
	next    int
	buffer  []byte
	active  atomic.Int32
	overlap atomic.Bool
	peer    unix.SockaddrNetlink
}

func (s *receive39Script) recvfrom(ctx context.Context, b []byte, flags int) (int, unix.Sockaddr, error) {
	if s.active.Add(1) != 1 {
		s.overlap.Store(true)
	}
	defer s.active.Add(-1)
	if ctx != context.Background() || flags != 0 || len(b) != nftMetadataBuffer || cap(b) != nftMetadataBuffer {
		s.tb.Fatal("receive transport arguments changed")
	}
	d := s.wire[s.next%len(s.wire)]
	s.next++
	clear(b) // Overwrite the entire scratch, including bytes beyond this datagram.
	copy(b, d)
	s.buffer = b
	return len(d), &s.peer, nil
}
func receive39Adapter(tb testing.TB, wire ...[]byte) (*nfqueueSocketAdapter, *receive39Script) {
	s := &receive39Script{tb: tb, wire: wire, peer: unix.SockaddrNetlink{Family: unix.AF_NETLINK}}
	return &nfqueueSocketAdapter{recvfrom: s.recvfrom}, s
}
func receive39Wire(tb testing.TB, id uint32, frames ...[]byte) []byte {
	tb.Helper()
	var out []byte
	for i, f := range frames {
		hdr := make([]byte, 7) // Real NFQA_PACKET_HDR: network-order ID, protocol, hook.
		binary.BigEndian.PutUint32(hdr, id+uint32(i))
		binary.BigEndian.PutUint16(hdr[4:], 0x0800)
		hdr[6] = 3
		attrs, e := netlink.MarshalAttributes([]netlink.Attribute{{Type: nfqPacketID, Data: hdr}, {Type: nfqPacketPayload, Data: f}})
		if e != nil {
			tb.Fatal(e)
		}
		m := netlink.Message{Header: netlink.Header{Type: netlink.HeaderType(3 << 8), Sequence: id + uint32(i), PID: 0}, Data: append([]byte{unix.AF_INET, 0, 0x2e, 0xe0}, attrs...)}
		m.Header.Length = uint32(16 + len(m.Data))
		b, e := m.MarshalBinary()
		if e != nil {
			tb.Fatal(e)
		}
		out = append(out, b...)
	}
	return out
}
func receive39Control(length int, fill byte) []byte {
	// A complete NOOP control with exact declared bytes, not a fake IP packet.
	b := nativeQueueDatagram(length, fill)
	binary.NativeEndian.PutUint16(b[4:], uint16(netlink.Noop))
	return b
}
func receive39Read(tb testing.TB, r interface {
	Receive() ([]netlink.Message, error)
}, iterRead func() []netlink.Message, i int) []netlink.Message {
	tb.Helper()
	if i%2 != 0 {
		return iterRead()
	}
	ms, e := r.Receive()
	if e != nil {
		tb.Fatal(e)
	}
	return ms
}
func receive39Iter(tb testing.TB, a *nfqueueSocketAdapter) []netlink.Message {
	var ms []netlink.Message
	for m, e := range a.ReceiveIter() {
		if e != nil {
			tb.Fatal(e)
		}
		ms = append(ms, m)
	}
	return ms
}
func receive39PinnedIter(tb testing.TB, c *netlink.Conn) []netlink.Message {
	var ms []netlink.Message
	for m, e := range c.ReceiveIter() {
		if e != nil {
			tb.Fatal(e)
		}
		ms = append(ms, m)
	}
	return ms
}
func TestSource39ReceiveDefaults(t *testing.T) {
	a := new(nfqueueSocketAdapter)
	if a.recvfrom != nil || a.conn != nil || a.configRequest != nil {
		t.Fatal("adapter defaults changed")
	}
	// Inspected zero/no-capture default, including nil public injector and empty methods.
	TestSource38BatchDefaults(t)
}
func TestSource39ReceiveRetainsMessages(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(fmt.Sprint("pinned-", pinned), func(t *testing.T) {
			controls := [][]byte{receive39Control(127, 3), receive39Control(128, 7), receive39Control(65535, 11)}
			multi := append(append([]byte(nil), controls[1]...), controls[0]...)
			wire := append(controls, multi)
			a, s := receive39Adapter(t, wire...)
			c := netlink.NewConn(a, 1)
			var got, want []netlink.Message
			for i := 0; i < 12; i++ {
				var ms []netlink.Message
				if pinned {
					ms = receive39Read(t, c, func() []netlink.Message { return receive39PinnedIter(t, c) }, i)
				} else {
					ms = receive39Read(t, a, func() []netlink.Message { return receive39Iter(t, a) }, i)
				}
				expected, e := parseNetlinkDatagram(wire[i%len(wire)])
				if e != nil {
					t.Fatal(e)
				}
				got = append(got, ms...)
				want = append(want, expected...)
				// Old messages must survive the next actual receive AND an explicit overwrite.
				for j := range s.buffer {
					s.buffer[j] = 0xa5
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("retained declared headers/Data changed after receive %d", i)
				}
			}
			if s.next != 12 || len(got) != 15 {
				t.Fatal("bounded datagram/message counts")
			}
		})
	}
}
func TestSource39ReceivePinnedSerialization(t *testing.T) {
	a, s := receive39Adapter(t, receive39Control(127, 3), receive39Control(65535, 9))
	c := netlink.NewConn(a, 1)
	var wg sync.WaitGroup
	var count atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 12; j++ {
				var ms []netlink.Message
				if j%2 == 0 {
					var e error
					ms, e = c.Receive()
					if e != nil {
						t.Error(e)
						return
					}
				} else {
					ms = receive39PinnedIter(t, c)
				}
				if len(ms) != 1 || (ms[0].Header.Length != 127 && ms[0].Header.Length != 65535) {
					t.Error("record")
				}
				count.Add(int32(len(ms)))
			}
		})
	}
	wg.Wait()
	if s.overlap.Load() || s.next != 96 || count.Load() != 96 {
		t.Fatal("mixed pinned receive serialization")
	}
	// Direct adapter calls above are serialized, never concurrent/reentrant.
}

type receive39Verdicts struct {
	nfqueueConn
	messages []netlink.Message
}

func (q *receive39Verdicts) boundPort() uint32 { return 0x80000042 }

func (q *receive39Verdicts) Send(m netlink.Message) (netlink.Message, error) {
	q.messages = append(q.messages, m)
	return m, nil
}
func receive39Capture(t *testing.T, l *Lease) (*linuxCapture, *batchSuccessModel, *receive39Verdicts) {
	c := &linuxCapture{lease: l, owner: &anchorOwner{nsFD: 900001}, anchor: captureAnchor{tag: 0x53590042}, queue: 12000, inQueue: 12001, dispatch: newCaptureDispatchGate()}
	m := batchSuccessInstall(t, c)
	q := &receive39Verdicts{}
	c.nl = q
	return c, m, q
}
func receive39CheckVerdicts(t *testing.T, q *receive39Verdicts, ids []uint32, verdict uint32) {
	t.Helper()
	if len(q.messages) != len(ids) {
		t.Fatalf("completer count %d want %d", len(q.messages), len(ids))
	}
	for i, m := range q.messages {
		as, e := netlink.UnmarshalAttributes(m.Data[4:])
		if e != nil || len(as) != 1 || len(as[0].Data) != 8 {
			t.Fatal("verdict encoding", e)
		}
		if binary.BigEndian.Uint16(m.Data[2:]) != 12000 || binary.BigEndian.Uint32(as[0].Data) != verdict || binary.BigEndian.Uint32(as[0].Data[4:]) != ids[i] {
			t.Fatal("retained ID/completer order/verdict changed")
		}
	}
}
func TestSource39ReceiveRecordsComposition(t *testing.T) {
	for _, count := range []int{1, 4} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			p := batchSuccessPacket(t, FamilyIPv4, []byte("successful immediate pass"))
			l := batchSuccessLease(t, `{"enabled":true,"rules":[{"network":["udp"],"methods":[]}]}`, p)
			q := &receive39Verdicts{}
			capture := &linuxCapture{lease: l, nl: q, queue: 12000, inQueue: 12001, dispatch: newCaptureDispatchGate()}
			var wires [][]byte
			var expectedFrames [][]byte
			var expectedIDs []uint32
			for call := 0; call < 12; call++ {
				var frames [][]byte
				for j := 0; j < count; j++ {
					frame := batchSuccessPacket(t, FamilyIPv4, []byte(fmt.Sprintf("record-%d-%d", call, j))).Raw
					frames = append(frames, frame)
					expectedFrames = append(expectedFrames, bytes.Clone(frame))
					expectedIDs = append(expectedIDs, uint32(100+call*count+j))
				}
				wires = append(wires, receive39Wire(t, uint32(100+call*count), frames...))
			}
			a, s := receive39Adapter(t, wires...)
			conn := netlink.NewConn(a, 1)
			var retained []receive39Retained
			var expectedMessages []netlink.Message
			for call := 0; call < 12; call++ {
				ms := receive39Read(t, conn, func() []netlink.Message { return receive39PinnedIter(t, conn) }, call)
				expected, err := parseNetlinkDatagram(wires[call])
				if err != nil {
					t.Fatal(err)
				}
				expectedMessages = append(expectedMessages, expected...)
				retained = receive39Consume(t, ms, retained)
				if !capture.handleBatch(ms) {
					t.Fatal("actual immediate handleBatch")
				}
				clear(s.buffer)
				for i, h := range retained {
					if !reflect.DeepEqual(h.message, expectedMessages[i]) || !bytes.Equal(h.frame, expectedFrames[i]) || !bytes.Equal(h.held.Raw, expectedFrames[i]) || binary.BigEndian.Uint32(h.id) != expectedIDs[i] {
						t.Fatal("retained Message/Data/ID/attribute frame/clone after overwrite")
					}
				}
			}
			receive39CheckVerdicts(t, q, expectedIDs, nfqueueVerdictAccept)
			if s.next != 12 || len(retained) != 12*count || l.engine.heldBytes.Load() != 0 || l.Err() != nil {
				t.Fatal("bounded success accounting")
			}
		})
	}
}

// Warmed actual-adapter scratch reuse is the resource regression. Message/Data
// allocations remain detached: 1 message slice + 1 owned record per datagram.
func TestSource39ReceiveScratchBudget(t *testing.T) {
	a, s := receive39Adapter(t, receive39Control(127, 3))
	if _, err := a.Receive(); err != nil {
		t.Fatal(err)
	}
	first := &s.buffer[0]
	allocs := testing.AllocsPerRun(20, func() {
		ms, err := a.Receive()
		if err != nil || len(ms) != 1 {
			t.Fatal("successful receive", err)
		}
		if &s.buffer[0] != first {
			t.Fatal("scratch reallocated on successful receive")
		}
	})
	if allocs > 2 {
		t.Fatalf("warmed adapter allocs %.0f > 2 detached parser allocations", allocs)
	}
	if len(s.buffer) != 65536 || cap(s.buffer) != 65536 {
		t.Fatal("scratch exceeds exact 64KiB budget")
	}
}

func TestSource39ReceiveTCPHeldComposition(t *testing.T) {
	msg := []byte("GET / HTTP/1.1\r\nHost: receive39.example\r\n\r\n")
	ps := []*Packet{buildIPv4TCP(t, msg[:12], 1000, tcpFlagACK|tcpFlagPSH), buildIPv4TCP(t, msg[12:24], 1012, tcpFlagACK|tcpFlagPSH), buildIPv4TCP(t, msg[24:], 1024, tcpFlagACK|tcpFlagPSH)}
	l := batchSuccessLease(t, `{"enabled":true,"limits":{"hold_timeout":"10s"},"rules":[{"network":["tcp"],"methods":["multisplit"],"multisplit":{"split_pos":["2","14","26"]}}]}`, ps[0])
	c, m, q := receive39Capture(t, l)
	a, s := receive39Adapter(t, receive39Wire(t, 71, ps[0].Raw), receive39Wire(t, 72, ps[1].Raw), receive39Wire(t, 73, ps[2].Raw))
	conn := netlink.NewConn(a, 1)
	var want [][]byte
	var retained []netlink.Message
	_, _, facts := protocolFacts(msg)
	for _, p := range ps {
		plan, e := PlanTCP(l.engine.config.Rules[0], p, msg, int(p.TCPSeq-1000), facts)
		if e != nil {
			t.Fatal(e)
		}
		want = append(want, plan.Packets...)
	}
	for i := range ps {
		ms := receive39Read(t, conn, func() []netlink.Message { return receive39PinnedIter(t, conn) }, i)
		retained = append(retained, ms...)
		if !c.handleBatch(ms) {
			t.Fatal("actual handleBatch")
		}
		clear(s.buffer)
		if i < 2 {
			if len(q.messages) != 0 || len(l.tcpFlow.holds) != i+1 {
				t.Fatal("TCP positive hold/completer count")
			}
			for j, h := range l.tcpFlow.holds {
				if !bytes.Equal(h.packet.Raw, ps[j].Raw) {
					t.Fatal("attribute-owned held TCP changed")
				}
			}
			// TCP owns the attribute frame. Netlink storage is independent and reusable.
			for _, x := range retained {
				clear(x.Data)
			}
		}
	}
	if !reflect.DeepEqual(m.sends, want) {
		t.Fatal("exact planned TCP bytes")
	}
	receive39CheckVerdicts(t, q, []uint32{71, 72, 73}, nfqueueVerdictDrop)
	f := l.tcpFlow
	if len(f.holds) != 0 || f.holdTimer != nil || f.holdRelease != nil || l.engine.heldBytes.Load() != 0 || l.Err() != nil || len(m.live) != 0 || m.current != 0 {
		t.Fatal("TCP success budgets/receipt")
	}
}
func TestSource39ReceiveQUICHeldComposition(t *testing.T) {
	head, tail := qa519SplitInitials(t, "receive39.example", 40, qa519DCID(0x46), 1, 1)
	ps := []*Packet{batchSuccessPacket(t, FamilyIPv4, head), batchSuccessPacket(t, FamilyIPv4, tail)}
	l := batchSuccessLease(t, `{"enabled":true,"limits":{"hold_timeout":"10s"},"rules":[{"network":["udp"],"protocol":["quic"],"methods":["fake"],"fake":{"repeats":2,"payloads":[{"protocol":"quic","hex":"0123456789abcdef"}]},"dup":{"count":1}}]}`, ps[0])
	c, m, q := receive39Capture(t, l)
	a, s := receive39Adapter(t, receive39Wire(t, 81, ps[0].Raw), receive39Wire(t, 82, ps[1].Raw))
	conn := netlink.NewConn(a, 1)
	var want [][]byte
	for i, p := range ps {
		plan, e := planUDPStages(l.engine.config.Rules[0], p, i == 0)
		if e == nil {
			e = planUDPDup(l.engine.config.Rules[0], p, p, Facts{}, plan, DefaultRand)
		}
		if e != nil {
			t.Fatal(e)
		}
		want = append(want, plan.Packets...)
	}
	for i := range ps {
		ms := receive39Read(t, conn, func() []netlink.Message { return receive39PinnedIter(t, conn) }, i)
		if !c.handleBatch(ms) {
			t.Fatal("actual handleBatch")
		}
		clear(s.buffer)
		for _, x := range ms {
			clear(x.Data)
		}
		f := l.udpFlows[flowKey(l.intent.Destination)]
		if i == 0 {
			if len(q.messages) != 0 || len(f.holds) != 1 || !bytes.Equal(f.holds[0].packet.Raw, ps[0].Raw) {
				t.Fatal("QUIC clone retention")
			}
		}
	}
	if !reflect.DeepEqual(m.sends, want) {
		t.Fatal("exact planned QUIC bytes")
	}
	receive39CheckVerdicts(t, q, []uint32{81, 82}, nfqueueVerdictAccept)
	f := l.udpFlows[flowKey(l.intent.Destination)]
	if len(f.holds) != 0 || f.holdTimer != nil || f.holdRelease != nil || l.engine.heldBytes.Load() != 0 || l.Err() != nil || len(m.live) != 0 || m.current != 0 {
		t.Fatal("QUIC success budgets/receipt")
	}
}

// MODEL costs exclude the concrete socket.Conn wrapper/kernel. Transport copies
// prebuilt datagrams. All returned message, attribute and held-clone work stays.
type receive39Retained struct {
	message netlink.Message
	id      []byte
	frame   []byte
	held    *Packet
}

func receive39Consume(tb testing.TB, ms []netlink.Message, out []receive39Retained) []receive39Retained {
	for _, m := range ms {
		as, e := netlink.UnmarshalAttributes(m.Data[4:])
		if e != nil {
			tb.Fatal(e)
		}
		id := append([]byte(nil), as[0].Data[:4]...)
		frame := as[1].Data
		p, e := ParsePacket(frame)
		if e != nil {
			tb.Fatal(e)
		}
		h, e := cloneHeldPacket(p)
		if e != nil {
			tb.Fatal(e)
		}
		out = append(out, receive39Retained{m, id, frame, h})
	}
	return out
}

var receive39Sink []receive39Retained

func BenchmarkSource39Receive(b *testing.B) {
	for _, api := range []string{"Direct", "DirectIter"} {
		for _, n := range []int{127, 128, 65535} {
			b.Run(fmt.Sprintf("%s/bytes-%d", api, n), func(b *testing.B) {
				a, _ := receive39Adapter(b, receive39Control(n, 7))
				var ms []netlink.Message
				if _, e := a.Receive(); e != nil {
					b.Fatal(e)
				} // Lazy setup excluded, equally warmed baseline.
				b.ReportAllocs()
				b.SetBytes(int64(n))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if api == "Direct" {
						var e error
						ms, e = a.Receive()
						if e != nil {
							b.Fatal(e)
						}
					} else {
						ms = receive39Iter(b, a)
					}
				}
				b.StopTimer()
				if len(ms) != 1 || int(ms[0].Header.Length) != n {
					b.Fatal("work")
				}
			})
		}
	}
	for _, api := range []string{"Pinned", "PinnedIter"} {
		for _, n := range []int{1, 4} {
			b.Run(fmt.Sprintf("%s/messages-%d", api, n), func(b *testing.B) {
				var frames [][]byte
				for i := 0; i < n; i++ {
					f := make([]byte, 1228)
					f[0] = 0x45
					f[8] = 64
					f[9] = 17
					binary.BigEndian.PutUint16(f[2:], uint16(len(f)))
					copy(f[12:], []byte{192, 0, 2, 1, 198, 51, 100, 1})
					binary.BigEndian.PutUint16(f[20:], 12345)
					binary.BigEndian.PutUint16(f[22:], 23456)
					binary.BigEndian.PutUint16(f[24:], 1208)
					for j := 28; j < len(f); j++ {
						f[j] = byte(i + j)
					}
					frames = append(frames, f)
				}
				d := receive39Wire(b, 91, frames...)
				a, _ := receive39Adapter(b, d)
				c := netlink.NewConn(a, 1)
				if _, e := c.Receive(); e != nil {
					b.Fatal(e)
				}
				ring := make([][]receive39Retained, 8)
				for i := range ring {
					ring[i] = make([]receive39Retained, 0, n)
				}
				b.ReportAllocs()
				b.SetBytes(int64(len(d)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					var ms []netlink.Message
					if api == "Pinned" {
						var e error
						ms, e = c.Receive()
						if e != nil {
							b.Fatal(e)
						}
					} else {
						ms = receive39PinnedIter(b, c)
					}
					ring[i%8] = receive39Consume(b, ms, ring[i%8][:0])
				}
				b.StopTimer()
				for _, slot := range ring {
					for i, h := range slot {
						if !bytes.Equal(h.held.Raw, frames[i]) || !bytes.Equal(h.frame, frames[i]) || binary.BigEndian.Uint32(h.id) != 91+uint32(i) {
							b.Fatal("retained work")
						}
					}
				}
				receive39Sink = ring[0]
			})
		}
	}
}

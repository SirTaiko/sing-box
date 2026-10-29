//go:build linux

package desync

// Owned quoted-ICMP filtering (capture.filter_ttl_expired_icmp) and the
// reply-direction packet limit. Every fixture is a synthetic packet: no
// network, socket or privilege is used. Model tests: no kernel object is
// created, and every case says so.

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/sagernet/nftables"
	"github.com/sagernet/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	testICMPv4TypeTimeExceeded = 11
	testICMPv6TypeTimeExceeded = 3
	testICMPv4TypeUnreachable  = 3
)

// buildQuote4 builds one IPv4 packet with the given L4 ports (the first bytes of
// the L4 header) for a TCP/UDP quote.
func buildQuote4(source netip.AddrPort, destination netip.AddrPort, protocol byte, payloadLen int) []byte {
	packet := make([]byte, 20+4+payloadLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	sourceBytes := source.Addr().As4()
	destinationBytes := destination.Addr().As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[20:], source.Port())
	binary.BigEndian.PutUint16(packet[22:], destination.Port())
	return packet
}

// buildQuote6 builds one IPv6 packet with the given L4 ports.
func buildQuote6(source netip.AddrPort, destination netip.AddrPort, protocol byte) []byte {
	packet := make([]byte, 40+4)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], 4)
	packet[6] = protocol
	packet[7] = 64
	sourceBytes := source.Addr().As16()
	destinationBytes := destination.Addr().As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[40:], source.Port())
	binary.BigEndian.PutUint16(packet[42:], destination.Port())
	return packet
}

// icmpv4Error wraps one quoted packet in an ICMPv4 error of the given type.
func icmpv4Error(source netip.Addr, destination netip.Addr, icmpType byte, quote []byte) []byte {
	packet := make([]byte, 20+8+len(quote))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 1
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	packet[20] = icmpType
	copy(packet[28:], quote)
	return packet
}

// icmpv6Error wraps one quoted packet in an ICMPv6 error of the given type.
func icmpv6Error(source netip.Addr, destination netip.Addr, icmpType byte, quote []byte) []byte {
	packet := make([]byte, 40+8+len(quote))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:], uint16(8+len(quote)))
	packet[6] = icmpv6NextHeader
	packet[7] = 64
	sourceBytes := source.As16()
	destinationBytes := destination.As16()
	copy(packet[8:24], sourceBytes[:])
	copy(packet[24:40], destinationBytes[:])
	packet[40] = icmpType
	copy(packet[48:], quote)
	return packet
}

func icmpTestLease(t *testing.T, queue int, enabled bool) (*Engine, *Lease) {
	t.Helper()
	filter := ""
	if enabled {
		filter = `"filter_ttl_expired_icmp":true,`
	}
	content := `{"enabled":true,"capture":{` + filter + `"linux":{"qnum":` + strconv.Itoa(queue) + `}},` +
		`"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443"),
	})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	t.Cleanup(func() {
		_ = engine.Close()
		releaseQnum(queue)
	})
	return engine, lease
}

// newFilteredICMPLease builds a capture lease with owned quoted-ICMP filtering.
func newFilteredICMPLease(t *testing.T, queue int) *Lease {
	t.Helper()
	content := `{"enabled":true,"capture":{"filter_ttl_expired_icmp":true,"linux":{"qnum":` +
		strconv.Itoa(queue) + `}},"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv4,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443"),
	})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	t.Cleanup(func() {
		_ = engine.Close()
		releaseQnum(queue)
	})
	return lease
}

// waitForVerdict returns the disposition of the first verdict sent for one
// packet id.
func waitForVerdict(t *testing.T, conn *fakeNFQueueConn, id uint32) uint32 {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, message := range conn.sentMessages() {
			if len(message.Data) < 4 {
				continue
			}
			attributes, err := netlink.UnmarshalAttributes(message.Data[4:])
			if err != nil {
				t.Fatalf("verdict attributes: %v", err)
			}
			for _, attribute := range attributes {
				if attribute.Type&0x3fff != 2 || len(attribute.Data) < 8 {
					continue
				}
				if binary.BigEndian.Uint32(attribute.Data[4:8]) == id {
					return binary.BigEndian.Uint32(attribute.Data[0:4])
				}
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no verdict for packet %d (sent %d messages)", id, len(conn.sentMessages()))
	return 0
}

// TestLinuxOwnedICMPQueueLifecycleAndDispatch covers the real receive path: the
// owned ICMP queue is bound only when configured, a validated owned error is
// dropped, a foreign error is passed unchanged, and teardown unbinds all three
// owned queues exactly once.
func TestLinuxOwnedICMPQueueLifecycleAndDispatch(t *testing.T) {
	data := newFakeNFQueueConn("queue", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	lease := newFilteredICMPLease(t, 15220)

	capture, err := openLinuxCapture(lease)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	linux := capture.(*linuxCapture)
	if linux.icmpQueue == 0 || linux.icmpQueue == linux.queue || linux.icmpQueue == linux.inQueue {
		t.Fatalf("owned ICMP queue = %d (out %d in %d)", linux.icmpQueue, linux.queue, linux.inQueue)
	}
	for _, queue := range []uint16{linux.queue, linux.inQueue, linux.icmpQueue} {
		if got := countQueueCommand(t, data.executedMessages(), queue, nfqCfgCmdBind); got != 1 {
			t.Fatalf("queue %d binds = %d, want 1", queue, got)
		}
	}
	icmpRules := captureRoleRules(t, seams, linux, "queue-e")
	if len(icmpRules) != 1 {
		t.Fatal("owned ICMP queue rule missing")
	}
	if queues := fakeRuleQueues(icmpRules[0]); len(queues) != 1 || queues[0] != linux.icmpQueue {
		t.Fatalf("ICMP queue rule queues = %v, want %d", queues, linux.icmpQueue)
	}
	entryRules := captureRoleRules(t, seams, linux, "entry-e")
	if len(entryRules) != 1 {
		t.Fatal("owned ICMP dispatch entry missing")
	}
	// The dispatch entry matches ICMP type 11 and carries no kernel verdict.
	if !fakeRuleMatchesByte(entryRules[0], 11) {
		t.Fatal("ICMP dispatch entry does not match the time-exceeded type")
	}

	lease.noteInjection()
	if !seams.kernel.deliver(linux.icmpQueue, fakePacketMessage(linux.icmpQueue, 7, ownedICMPv4Error()), 7) {
		t.Fatal("owned ICMP queue refused the packet")
	}
	if verdict := waitForVerdict(t, data, 7); verdict != 0 {
		t.Fatalf("owned error verdict = %d, want drop (0)", verdict)
	}
	foreign := icmpv4Error(netip.MustParseAddr("192.0.2.254"), netip.MustParseAddr("192.0.2.10"),
		testICMPv4TypeTimeExceeded,
		buildQuote4(netip.MustParseAddrPort("192.0.2.10:40000"),
			netip.MustParseAddrPort("198.51.100.99:443"), 6, 16))
	if !seams.kernel.deliver(linux.icmpQueue, fakePacketMessage(linux.icmpQueue, 8, foreign), 8) {
		t.Fatal("owned ICMP queue refused the foreign packet")
	}
	if verdict := waitForVerdict(t, data, 8); verdict != 1 {
		t.Fatalf("foreign error verdict = %d, want accept (1)", verdict)
	}

	if err = capture.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := countQueueCommand(t, data.executedMessages(), linux.queue, nfqCfgCmdUnbind); got != 0 {
		t.Fatalf("outq unbinds = %d, want 0 (witness released by its owning socket)", got)
	}
	for _, queue := range []uint16{linux.inQueue, linux.icmpQueue} {
		if got := countQueueCommand(t, data.executedMessages(), queue, nfqCfgCmdUnbind); got != 1 {
			t.Fatalf("queue %d unbinds = %d, want 1", queue, got)
		}
	}
}

// ownedICMPv4Error quotes one outbound packet of the test lease.
func ownedICMPv4Error() []byte {
	quote := buildQuote4(netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.20:443"), 6, 16)
	return icmpv4Error(netip.MustParseAddr("192.0.2.254"), netip.MustParseAddr("192.0.2.10"),
		testICMPv4TypeTimeExceeded, quote)
}

func TestOwnedICMPTimeExceededDropsOnlyOwnedOutboundQuote(t *testing.T) {
	_, lease := icmpTestLease(t, 15200, true)
	lease.noteInjection()
	if !lease.HandleICMPTimeExceeded(ownedICMPv4Error()) {
		t.Fatal("owned outbound time-exceeded was not suppressed")
	}

	// A quote of another tuple is foreign: same local port, other peer.
	foreignPeer := buildQuote4(netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.99:443"), 6, 16)
	if lease.HandleICMPTimeExceeded(icmpv4Error(netip.MustParseAddr("192.0.2.254"),
		netip.MustParseAddr("192.0.2.10"), testICMPv4TypeTimeExceeded, foreignPeer)) {
		t.Fatal("foreign peer quote was suppressed")
	}
	// Another local port is foreign.
	foreignPort := buildQuote4(netip.MustParseAddrPort("192.0.2.10:40001"),
		netip.MustParseAddrPort("198.51.100.20:443"), 6, 16)
	if lease.HandleICMPTimeExceeded(icmpv4Error(netip.MustParseAddr("192.0.2.254"),
		netip.MustParseAddr("192.0.2.10"), testICMPv4TypeTimeExceeded, foreignPort)) {
		t.Fatal("foreign local port quote was suppressed")
	}
	// The owned peer address with another destination port is foreign too.
	foreignPeerPort := buildQuote4(netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.20:8443"), 6, 16)
	if lease.HandleICMPTimeExceeded(icmpv4Error(netip.MustParseAddr("192.0.2.254"),
		netip.MustParseAddr("192.0.2.10"), testICMPv4TypeTimeExceeded, foreignPeerPort)) {
		t.Fatal("foreign peer port quote was suppressed")
	}
	// Another transport is foreign.
	foreignTransport := buildQuote4(netip.MustParseAddrPort("192.0.2.10:40000"),
		netip.MustParseAddrPort("198.51.100.20:443"), 17, 16)
	if lease.HandleICMPTimeExceeded(icmpv4Error(netip.MustParseAddr("192.0.2.254"),
		netip.MustParseAddr("192.0.2.10"), testICMPv4TypeTimeExceeded, foreignTransport)) {
		t.Fatal("foreign transport quote was suppressed")
	}
	// A reply-side quote (peer -> us) is not the packet we injected.
	replyQuote := buildQuote4(netip.MustParseAddrPort("198.51.100.20:443"),
		netip.MustParseAddrPort("192.0.2.10:40000"), 6, 16)
	if lease.HandleICMPTimeExceeded(icmpv4Error(netip.MustParseAddr("192.0.2.10"),
		netip.MustParseAddr("198.51.100.20"), testICMPv4TypeTimeExceeded, replyQuote)) {
		t.Fatal("reply-side quote was suppressed")
	}
	// Parameter problem / PMTU (type 3 code 4) is never matched.
	if lease.HandleICMPTimeExceeded(icmpv4Error(netip.MustParseAddr("192.0.2.254"),
		netip.MustParseAddr("192.0.2.10"), testICMPv4TypeUnreachable,
		buildQuote4(netip.MustParseAddrPort("192.0.2.10:40000"),
			netip.MustParseAddrPort("198.51.100.20:443"), 6, 16))) {
		t.Fatal("parameter problem/PMTU message was suppressed")
	}
}

func TestOwnedICMPTimeExceededRejectsMalformedAndTruncatedQuotes(t *testing.T) {
	_, lease := icmpTestLease(t, 15201, true)
	lease.noteInjection()
	full := ownedICMPv4Error()
	for _, length := range []int{0, 8, 19, 20, 27, 28, 39, 40, 41, len(full) - 1} {
		if length > len(full) {
			continue
		}
		if lease.HandleICMPTimeExceeded(full[:length]) {
			t.Fatalf("truncated error of %d bytes was suppressed", length)
		}
	}
	// Outer total length larger than the captured datagram: truncated capture.
	overlong := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(overlong[2:], uint16(len(overlong)+40))
	if lease.HandleICMPTimeExceeded(overlong) {
		t.Fatal("overlong total length was suppressed")
	}
	// Inner header with a bad version.
	badVersion := append([]byte(nil), full...)
	badVersion[28] = 0x65
	if lease.HandleICMPTimeExceeded(badVersion) {
		t.Fatal("bad inner version was suppressed")
	}
	// Inner non-first fragment carries no ports.
	fragment := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(fragment[28+6:], 0x0020)
	if lease.HandleICMPTimeExceeded(fragment) {
		t.Fatal("non-first fragment quote was suppressed")
	}
	// Inner header options shift the ports; the parser follows them, so the
	// tuple is still complete. A quote with too-short inner header is not.
	shortInner := append([]byte(nil), full...)
	shortInner[28] = 0x44 // inner IHL 16 < 20
	if lease.HandleICMPTimeExceeded(shortInner) {
		t.Fatal("invalid inner IHL was suppressed")
	}
}

func TestOwnedICMPTimeExceededIPv6(t *testing.T) {
	content := `{"enabled":true,"capture":{"filter_ttl_expired_icmp":true,"linux":{"qnum":15202}},` +
		`"rules":[{"network":["tcp"],"port":[443],"orig":{"ttl":9}}]}`
	config, err := Compile(enabledOption(content), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	lease, err := engine.NewAttempt(Intent{
		Family:      FamilyIPv6,
		Transport:   TransportTCP,
		Source:      netip.MustParseAddrPort("[2001:db8::10]:40000"),
		Destination: netip.MustParseAddrPort("[2001:db8::20]:443"),
	})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("[2001:db8::10]:40000"))
	t.Cleanup(func() {
		_ = engine.Close()
		releaseQnum(15202)
	})
	lease.noteInjection()

	owned := icmpv6Error(netip.MustParseAddr("2001:db8::fe"), netip.MustParseAddr("2001:db8::10"),
		testICMPv6TypeTimeExceeded,
		buildQuote6(netip.MustParseAddrPort("[2001:db8::10]:40000"),
			netip.MustParseAddrPort("[2001:db8::20]:443"), 6))
	if !lease.HandleICMPTimeExceeded(owned) {
		t.Fatal("owned IPv6 time-exceeded was not suppressed")
	}
	// ICMPv6 parameter problem (type 4) is not a time-exceeded error.
	if lease.HandleICMPTimeExceeded(icmpv6Error(netip.MustParseAddr("2001:db8::fe"),
		netip.MustParseAddr("2001:db8::10"), 4,
		buildQuote6(netip.MustParseAddrPort("[2001:db8::10]:40000"),
			netip.MustParseAddrPort("[2001:db8::20]:443"), 6))) {
		t.Fatal("IPv6 parameter problem was suppressed")
	}
	// Inner extension header (next header 0) moves the ports; rejected.
	extension := buildQuote6(netip.MustParseAddrPort("[2001:db8::10]:40000"),
		netip.MustParseAddrPort("[2001:db8::20]:443"), 0)
	if lease.HandleICMPTimeExceeded(icmpv6Error(netip.MustParseAddr("2001:db8::fe"),
		netip.MustParseAddr("2001:db8::10"), testICMPv6TypeTimeExceeded, extension)) {
		t.Fatal("quote with an inner extension header was suppressed")
	}
	// Truncated IPv6 payload length.
	truncated := owned[:60]
	if lease.HandleICMPTimeExceeded(truncated) {
		t.Fatal("truncated IPv6 error was suppressed")
	}
}

func TestOwnedICMPTimeExceededRequiresEnabledLiveGenerationAndInjection(t *testing.T) {
	// Disabled by default: an otherwise owned error passes.
	_, disabled := icmpTestLease(t, 15203, false)
	disabled.noteInjection()
	if disabled.HandleICMPTimeExceeded(ownedICMPv4Error()) {
		t.Fatal("disabled filter suppressed an error")
	}

	// Enabled but no injection yet: nothing of ours can have expired.
	_, noInjection := icmpTestLease(t, 15204, true)
	if noInjection.HandleICMPTimeExceeded(ownedICMPv4Error()) {
		t.Fatal("error suppressed before any low-hop injection")
	}

	// Enabled, injected, but the lease generation is closed.
	engine, closed := icmpTestLease(t, 15205, true)
	closed.noteInjection()
	if err := closed.Close(nil); err != nil {
		t.Fatalf("close lease: %v", err)
	}
	if closed.HandleICMPTimeExceeded(ownedICMPv4Error()) {
		t.Fatal("closed lease suppressed an error")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("close engine: %v", err)
	}
}

// TestICMPRuleOffsetsMatchTheParser pins the fixed offsets the kernel rule uses
// against the bytes the parser actually reads: an offset mistake would silently
// stop the filter from matching, so it is verified without a kernel.
func TestICMPRuleOffsetsMatchTheParser(t *testing.T) {
	owned := ownedICMPv4Error()
	quote, ok := parseTimeExceededQuote(owned, FamilyIPv4)
	if !ok {
		t.Fatal("owned IPv4 error did not parse")
	}
	if got := binary.BigEndian.Uint32(owned[40:44]); got != binary.BigEndian.Uint32(owned[28+12:28+16]) {
		t.Fatalf("IPv4 quoted source offset mismatch: %d", got)
	}
	address := netip.AddrFrom4([4]byte(owned[40:44]))
	if !sameQuoteAddr(quote.Src, address) {
		t.Fatalf("IPv4 offset 40 does not hold the quoted source %s", quote.Src)
	}

	ipv6 := icmpv6Error(netip.MustParseAddr("2001:db8::fe"), netip.MustParseAddr("2001:db8::10"),
		testICMPv6TypeTimeExceeded,
		buildQuote6(netip.MustParseAddrPort("[2001:db8::10]:40000"),
			netip.MustParseAddrPort("[2001:db8::20]:443"), 6))
	quote6, ok := parseTimeExceededQuote(ipv6, FamilyIPv6)
	if !ok {
		t.Fatal("IPv6 error did not parse")
	}
	var source6 [16]byte
	copy(source6[:], ipv6[56:72])
	if !sameQuoteAddr(quote6.Src, netip.AddrFrom16(source6)) {
		t.Fatalf("IPv6 offset 56 does not hold the quoted source %s", quote6.Src)
	}
}

// fakeNftBatchSender records the exact nftables batch bytes.
type fakeNftBatchSender struct {
	batches [][]byte
	closed  int
	err     error
}

func (f *fakeNftBatchSender) Send(batch []byte) error {
	f.batches = append(f.batches, append([]byte(nil), batch...))
	return f.err
}

func (f *fakeNftBatchSender) Close() error { f.closed++; return nil }

func installFakeBatchSender(t *testing.T) *fakeNftBatchSender {
	t.Helper()
	sender := &fakeNftBatchSender{}
	previous := newNftBatchSender
	newNftBatchSender = func() (nftBatchSender, error) { return sender, nil }
	t.Cleanup(func() { newNftBatchSender = previous })
	return sender
}

// TestCtReplyPacketsExpressionMatchesPinnedLibrary proves the local encoding is
// structurally identical to the pinned library for the keys it can express, and
// that the only difference for the packet counter is the added direction.
func TestCtReplyPacketsExpressionMatchesPinnedLibrary(t *testing.T) {
	// Kernel contract: IP_CT_DIR_ORIGINAL=0, IP_CT_DIR_REPLY=1. A wrong
	// direction here would silently count the other half of the conntrack.
	if nftCtDirectionReply != 1 || nftCtDirectionOriginal != 0 {
		t.Fatalf("direction constants = %d/%d, want 1/0", nftCtDirectionReply, nftCtDirectionOriginal)
	}
	ours, err := marshalCtExpression(expr.CtKeySRC, 1, 1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pinned, err := expr.Marshal(0, &expr.Ct{Register: 1, Key: expr.CtKeySRC, Direction: 1})
	if err != nil {
		t.Fatalf("library marshal: %v", err)
	}
	if string(ours) != string(pinned) {
		t.Fatalf("ct encoding differs from the pinned library:\n ours   %x\n pinned %x", ours, pinned)
	}
	// The direction is a 32-bit big-endian REPLY, never the original 0.
	if direction := ctDirectionAttribute(t, ours); direction != 1 {
		t.Fatalf("direction = %d, want reply (1)", direction)
	}
	pkts, err := marshalCtExpression(expr.CtKeyPKTS, 1, 1)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if direction := ctDirectionAttribute(t, pkts); direction != 1 {
		t.Fatalf("packet counter direction = %d, want reply (1)", direction)
	}
	// The pinned library cannot express the packet counter direction, so the
	// reply rule must not be the library's (direction-less) encoding.
	libraryPackets, err := expr.Marshal(0, &expr.Ct{Register: 1, Key: expr.CtKeyPKTS})
	if err != nil {
		t.Fatalf("library marshal: %v", err)
	}
	if string(libraryPackets) == string(pkts) {
		t.Fatal("reply packet counter is byte-identical to the direction-less library encoding")
	}
}

// ctDirectionAttribute decodes NFTA_CT_DIRECTION of a marshaled ct expression.
func ctDirectionAttribute(t *testing.T, expression []byte) uint32 {
	t.Helper()
	outer, err := netlink.UnmarshalAttributes(expression)
	if err != nil {
		t.Fatalf("outer attributes: %v", err)
	}
	for _, attribute := range outer {
		if attribute.Type&0x3fff != unix.NFTA_EXPR_DATA {
			continue
		}
		data, err := netlink.UnmarshalAttributes(attribute.Data)
		if err != nil {
			t.Fatalf("expression attributes: %v", err)
		}
		var direction uint32
		found := false
		for _, inner := range data {
			if inner.Type == unix.NFTA_CT_DIRECTION {
				direction, found = binary.BigEndian.Uint32(inner.Data), true
			}
		}
		if !found {
			t.Fatal("ct direction attribute missing")
		}
		return direction
	}
	t.Fatal("ct expression data missing")
	return 0
}

// TestLinuxReplyPacketLimitRuleBatch drives a positive inbound bound through the
// capture and verifies the encoded reply rule inside the capture-owned input
// chain: the transport/tuple predicates of the dispatch entry, the
// `ct reply packets <= N` counter and the owned inbound queue.
func TestLinuxReplyPacketLimitRuleBatch(t *testing.T) {
	linux, seams := openLinuxCaptureForRules(t, 15210, `,"packet_limits":{"tcp_in":3}`)
	entryRules := captureRoleRules(t, seams, linux, "entry-i")
	if len(entryRules) != 1 {
		t.Fatalf("entry-i rules = %d, want 1", len(entryRules))
	}
	queueRules := captureRoleRules(t, seams, linux, "queue-i")
	if len(queueRules) != 1 {
		t.Fatalf("queue-i rules = %d, want 1", len(queueRules))
	}
	decoded, err := decodedExpressions(queueRules[0])
	if err != nil {
		t.Fatalf("decode queue-i: %v", err)
	}
	ctIndex, queueIndex, direction := -1, -1, uint32(0)
	foundKey := uint32(0)
	for index, expression := range decoded {
		switch expression.name {
		case "ct":
			if ctIndex >= 0 {
				t.Fatal("more than one ct expression in the reply rule")
			}
			ctIndex = index
			foundKey = binary.BigEndian.Uint32(expression.data[unix.NFTA_CT_KEY])
			direction = binary.BigEndian.Uint32(expression.data[unix.NFTA_CT_DIRECTION])
		case "queue":
			queueIndex = index
			if queues := fakeRuleQueues(queueRules[0]); len(queues) != 1 || queues[0] != linux.inQueue {
				t.Fatalf("queue = %v, want owned inbound %d", queues, linux.inQueue)
			}
		}
	}
	if ctIndex < 0 {
		t.Fatal("reply packet counter expression missing")
	}
	if foundKey != uint32(expr.CtKeyPKTS) {
		t.Fatalf("ct key = %d, want packet counter", foundKey)
	}
	if direction != uint32(nftCtDirectionReply) {
		t.Fatalf("ct direction = %d, want reply (1)", direction)
	}
	if queueIndex < 0 || ctIndex > queueIndex {
		t.Fatalf("ct expression (index %d) must precede the queue (index %d)", ctIndex, queueIndex)
	}
	if limit, ok := fakeRuleHasCtPacketsBound(queueRules[0]); !ok || limit != 3 {
		t.Fatalf("reply packet bound = %d/%v, want 3/true", limit, ok)
	}
	// The dispatch entry carries the owned reverse tuple without the limit.
	if limit, ok := fakeRuleHasCtPacketsBound(entryRules[0]); ok {
		t.Fatalf("dispatch entry unexpectedly carries a packet bound of %d", limit)
	}
}

// decodedExpression is the minimal netlink view of one rule expression.
type decodedExpression struct {
	name         string
	ctKey        uint32
	ctDirection  uint32
	hasDirection bool
	queue        uint16
	comparison   []byte
}

// decodedRule is the minimal netlink view of one batch rule message.
type decodedRule struct {
	attributes  []netlink.Attribute
	table       string
	chain       string
	expressions []decodedExpression
}

func decodeRuleBatch(t *testing.T, batch []byte) []decodedRule {
	t.Helper()
	var messages []decodedRule
	types := make([]uint16, 0, 3)
	for offset := 0; offset+16 <= len(batch); {
		length := int(binary.NativeEndian.Uint32(batch[offset:]))
		if length < 16 || offset+length > len(batch) {
			t.Fatalf("malformed batch message at %d", offset)
		}
		typ := binary.NativeEndian.Uint16(batch[offset+4:])
		seq := binary.NativeEndian.Uint32(batch[offset+8:])
		types = append(types, typ)
		payload := batch[offset+16 : offset+length]
		current := decodedRule{}
		if typ == uint16((unix.NFNL_SUBSYS_NFTABLES<<8)|unix.NFT_MSG_NEWRULE) {
			if seq != nftBatchSeqRule {
				t.Fatalf("rule sequence = %d, want %d", seq, nftBatchSeqRule)
			}
			if len(payload) < 4 {
				t.Fatal("short rule message")
			}
			if payload[0] != byte(nftables.TableFamilyIPv4) {
				t.Fatalf("rule family = %d", payload[0])
			}
			attributes, err := netlink.UnmarshalAttributes(payload[4:])
			if err != nil {
				t.Fatalf("rule attributes: %v", err)
			}
			current.attributes = attributes
			for _, attribute := range attributes {
				switch attribute.Type & 0x3fff {
				case unix.NFTA_RULE_TABLE:
					current.table = string(attribute.Data)
				case unix.NFTA_RULE_CHAIN:
					current.chain = string(attribute.Data)
				case unix.NFTA_RULE_EXPRESSIONS:
					current.expressions = decodeExpressions(t, attribute.Data)
				}
			}
		}
		messages = append(messages, current)
		offset += (length + 3) &^ 3
	}
	if len(types) != 3 || types[0] != unix.NFNL_MSG_BATCH_BEGIN || types[2] != unix.NFNL_MSG_BATCH_END {
		t.Fatalf("batch envelope = %v", types)
	}
	return messages
}

func decodeExpressions(t *testing.T, data []byte) []decodedExpression {
	t.Helper()
	elements, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		t.Fatalf("expression list: %v", err)
	}
	expressions := make([]decodedExpression, 0, len(elements))
	for _, element := range elements {
		inner, err := netlink.UnmarshalAttributes(element.Data)
		if err != nil {
			t.Fatalf("expression element: %v", err)
		}
		current := decodedExpression{}
		for _, attribute := range inner {
			switch attribute.Type {
			case unix.NFTA_EXPR_NAME:
				current.name = strings.TrimRight(string(attribute.Data), "\x00")
			case unix.NLA_F_NESTED | unix.NFTA_EXPR_DATA, unix.NFTA_EXPR_DATA:
				current = decodeExpressionData(t, current, attribute.Data)
			}
		}
		expressions = append(expressions, current)
	}
	return expressions
}

func decodeExpressionData(t *testing.T, expression decodedExpression, data []byte) decodedExpression {
	t.Helper()
	attributes, err := netlink.UnmarshalAttributes(data)
	if err != nil {
		t.Fatalf("expression data: %v", err)
	}
	for _, attribute := range attributes {
		switch {
		case expression.name == "ct" && attribute.Type == unix.NFTA_CT_KEY:
			expression.ctKey = binary.BigEndian.Uint32(attribute.Data)
		case expression.name == "ct" && attribute.Type == unix.NFTA_CT_DIRECTION:
			expression.ctDirection = binary.BigEndian.Uint32(attribute.Data)
			expression.hasDirection = true
		case expression.name == "queue" && attribute.Type == unix.NFTA_QUEUE_NUM:
			expression.queue = binary.BigEndian.Uint16(attribute.Data)
		case expression.name == "cmp":
			// The packet bound comparison carries the 8-byte inclusive value.
			nested, nestedErr := netlink.UnmarshalAttributes(attribute.Data)
			if nestedErr != nil {
				continue
			}
			for _, value := range nested {
				if value.Type == unix.NFTA_DATA_VALUE && len(value.Data) == 8 {
					expression.comparison = append([]byte(nil), value.Data...)
				}
			}
		}
	}
	return expression
}

// boundedBy reports whether the decoded rule carries `<= want` on the counter.
func ruleBoundedBy(t *testing.T, expressions []decodedExpression, want uint64) bool {
	t.Helper()
	for index, expression := range expressions {
		if expression.name != "ct" || expression.ctKey != uint32(expr.CtKeyPKTS) {
			continue
		}
		for _, following := range expressions[index+1:] {
			if following.name == "cmp" && len(following.comparison) == 8 {
				return binary.BigEndian.Uint64(following.comparison) == want
			}
		}
	}
	return false
}

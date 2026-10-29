package desync

// P1 QUIC fake-unit admission regressions.
//
// Pinned nfq/desync.c (2905-3044) does not tamper with every datagram of a
// QUIC flow: while the CRYPTO ClientHello is incomplete it queues the Initials,
// and when the reassembly cycle completes it replays the queue with exactly one
// fake burst attached to the queue head (reasm_offset == 0). A datagram that
// cannot authenticate or whose framing is unsupported cancels the session and
// is sent untouched (quic_reasm_cancel -> send_orig). The captured caller used
// to fake every datagram after a rule had been selected, which produced 22
// instead of 11 fake units for a two-datagram capture and 99 instead of 55 for
// a ten-datagram retransmission flight. These tests pin the cheap, non-vacuous
// consequences of that admission rule against authentic Linux and Windows
// captures plus bounded synthetic cases.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

const (
	// p1QUICFakePayload is a distinct marker so an injected packet can be
	// attributed by exact bytes, never by length.
	p1QUICFakePayloadHex = "51413530392d66616b65" // "QA509-fake"
	p1QUICFakeRepeats    = 11
)

// p1CapturedFlight loads one authentic captured Initial flight. The files are
// the unchanged QA509 fixtures (hex of the complete captured IPv4 datagram);
// both platforms carry the same three-datagram target flight and ten-datagram
// control flight used by the independent caller reproducer.
func p1CapturedFlight(t *testing.T, name string) ([][]byte, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "qa509", name))
	if err != nil {
		t.Fatal(err)
	}
	var encoded []string
	if err = json.Unmarshal(data, &encoded); err != nil {
		t.Fatal(err)
	}
	raws := make([][]byte, 0, len(encoded))
	for index, value := range encoded {
		raw, decodeErr := hex.DecodeString(value)
		if decodeErr != nil {
			t.Fatalf("captured datagram %d: %v", index, decodeErr)
		}
		raws = append(raws, raw)
	}
	return raws, data
}

// p1QUICLease builds an owned UDP attempt over one packet rule. The first
// captured datagram supplies the owned tuple so the flow state is per capture,
// exactly like the qualified caller. A nonempty cachedHost pre-populates the
// bounded hostname cache for that exact destination, which reproduces the
// pinned ingress dp_find state when the destination host is already known; the
// cold (uncached) path is covered by the target-unprimed subtests.
func p1QUICLease(t *testing.T, ruleJSON string, first []byte, cachedHost string) *Lease {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[`+ruleJSON+`]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	if cachedHost != "" {
		config.IPCache.hostnameEnabled = true
	}
	engine, err := NewEngine(config, &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { engine.Close() })
	packet, err := ParsePacket(first)
	if err != nil {
		t.Fatal(err)
	}
	if cachedHost != "" && !engine.ipcache.learnHost(packet.Dst, "", cachedHost) {
		t.Fatalf("cached host %q was not learned", cachedHost)
	}
	source := netip.AddrPortFrom(packet.Src, packet.SrcPort)
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source: source, Destination: netip.AddrPortFrom(packet.Dst, packet.DstPort)})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lease.Close(nil) })
	return lease
}

// p1QUICDrive sends every captured datagram through the real Lease.HandlePacket
// caller and returns the exact fake-payload count per datagram together with
// the terminal-completion count per captured datagram. Under the delayed-replay
// ownership a queued original returns VerdictHold and is delivered exactly once
// through its Completer; a datagram answered immediately returns its own
// disposition and its Completer must never run. Every captured byte is
// therefore delivered exactly once either way.
func p1QUICDrive(t *testing.T, lease *Lease, raws [][]byte) []int {
	t.Helper()
	wantFake, err := hex.DecodeString(p1QUICFakePayloadHex)
	if err != nil {
		t.Fatal(err)
	}
	perDatagram := make([]int, len(raws))
	completions := make([]int, len(raws))
	held := make([]bool, len(raws))
	for index, raw := range raws {
		injected := 0
		verdict := lease.HandlePacket(raw, DirectionOutbound, func(generated []byte) error {
			packet, parseErr := ParsePacket(generated)
			if parseErr != nil {
				t.Fatalf("datagram %d fake parse: %v", index, parseErr)
			}
			if !bytes.Equal(packet.Payload, wantFake) {
				t.Fatalf("datagram %d injected payload SHA mismatch: %x", index, packet.Payload)
			}
			injected++
			return nil
		}, func(completion Verdict, reason string, modified []byte) {
			completions[index]++
			switch completion {
			case VerdictPass, VerdictModify, VerdictDrop:
			default:
				t.Errorf("datagram %d completion verdict = %d", index, completion)
			}
		})
		switch verdict {
		case VerdictHold:
			held[index] = true
		case VerdictPass:
			// The caller owns this disposition: no completer may run for it.
		default:
			t.Fatalf("datagram %d: captured original must pass or be held, verdict=%d", index, verdict)
		}
		perDatagram[index] = injected
	}
	for index := range raws {
		switch {
		case held[index] && completions[index] != 1:
			t.Fatalf("datagram %d: held original completions = %d, want exactly 1", index, completions[index])
		case !held[index] && completions[index] != 0:
			t.Fatalf("datagram %d: immediately answered original also completed %d times", index, completions[index])
		}
	}
	return perDatagram
}

func p1EqualInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// TestP1QUICFakeUnitAdmissionCapturedFlights is the authentic-capture
// regression for both operating systems. A target flight completes its
// ClientHello on the second datagram and then carries a datagram the QUIC
// session refuses: exactly one burst belongs to the completed cycle and the
// later datagram is passed untouched even though the flow rule is already
// selected. The control flight repeats the same two-fragment ClientHello five
// times: each completed cycle owns one burst, never every retransmission.
func TestP1QUICFakeUnitAdmissionCapturedFlights(t *testing.T) {
	targetRule := `{"network":["udp"],"port":[443],"domain":["www.youtube.com"],` +
		`"methods":["fake"],"fake":{"repeats":11,"payloads":[{"protocol":"quic","hex":"` + p1QUICFakePayloadHex + `"}]}}`
	controlRule := `{"network":["udp"],"port":[443],` +
		`"methods":["fake"],"fake":{"repeats":11,"payloads":[{"protocol":"quic","hex":"` + p1QUICFakePayloadHex + `"}]}}`
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform+"/target", func(t *testing.T) {
			raws, _ := p1CapturedFlight(t, "quic-"+platform+"-h2-on18.json")
			if len(raws) != 3 {
				t.Fatalf("captured target flight has %d datagrams, want 3", len(raws))
			}
			// Pinned selects a profile once per conntrack track, before the
			// CRYPTO reassembly, so a host-scoped rule is reachable on the first
			// Initial only through the cached hostname of that destination. The
			// capture is the same; only this pinned precondition is supplied.
			counts := p1QUICDrive(t, p1QUICLease(t, targetRule, raws[0], "www.youtube.com"), raws)
			want := []int{0, p1QUICFakeRepeats, 0}
			if !p1EqualInts(counts, want) {
				t.Fatalf("target fake units per datagram = %v, want %v (one burst for the completed cycle, none for the refused cached-host datagram)", counts, want)
			}
		})
		t.Run(platform+"/target-unprimed", func(t *testing.T) {
			// Cold caller state: the destination hostname is not cached yet.
			// The datagram-time selection is provisional only in the hostname
			// predicates, so the authenticated incomplete Initial is held by
			// the potentially eligible host-scoped rule and the validated
			// ClientHello then re-runs the ordered selection. The completion
			// owns exactly one burst and the refused third datagram is passed
			// untouched in both the primed and the unprimed state.
			raws, _ := p1CapturedFlight(t, "quic-"+platform+"-h2-on18.json")
			counts := p1QUICDrive(t, p1QUICLease(t, targetRule, raws[0], ""), raws)
			want := []int{0, p1QUICFakeRepeats, 0}
			if !p1EqualInts(counts, want) {
				t.Fatalf("unprimed target fake units per datagram = %v, want %v", counts, want)
			}
		})
		t.Run(platform+"/control", func(t *testing.T) {
			raws, _ := p1CapturedFlight(t, "quic-"+platform+"-c2-on18.json")
			if len(raws) != 10 {
				t.Fatalf("captured control flight has %d datagrams, want 10", len(raws))
			}
			counts := p1QUICDrive(t, p1QUICLease(t, controlRule, raws[0], ""), raws)
			want := []int{0, 11, 0, 11, 0, 11, 0, 11, 0, 11}
			if !p1EqualInts(counts, want) {
				t.Fatalf("control fake units per datagram = %v, want %v (one burst per completed retransmission cycle)", counts, want)
			}
		})
	}
}

// TestP1QUICFakeUnitAdmissionDelayedCompletion covers a ClientHello split over
// three Initials and the transport recovery path around it: only the datagram
// that completes the cycle owns the burst, an incomplete cycle owns none, and
// the captured bytes of every datagram still pass. A refused (non-authentic)
// datagram between two cycles suppresses its own burst and resets the pending
// fragments, so the next cycle has to complete from scratch.
func TestP1QUICFakeUnitAdmissionDelayedCompletion(t *testing.T) {
	rule := `{"network":["udp"],"port":[443],"methods":["fake"],` +
		`"fake":{"repeats":11,"payloads":[{"protocol":"quic","hex":"` + p1QUICFakePayloadHex + `"}]}}`
	hello := rawQUICClientHello("delayed-admission.example")
	first := len(hello) / 3
	second := 2 * len(hello) / 3
	dcid := []byte{6, 5, 4, 3, 2, 1}
	head := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:first]}, 240), dcid, 1, 1)
	middle := sealQUICInitial(t, cryptoFrames([]int{first}, [][]byte{hello[first:second]}, 240), dcid, 1, 2)
	tail := sealQUICInitial(t, cryptoFrames([]int{second}, [][]byte{hello[second:]}, 240), dcid, 1, 3)
	corrupt := append([]byte(nil), middle...)
	corrupt[len(corrupt)-20] ^= 0x01

	build := func(payload []byte) []byte { return buildIPv4UDP(t, payload, 443).Raw }
	raws := [][]byte{
		build(head), build(tail), build(middle), // completion on the third datagram
		build(head), build(tail), build(middle), // a retransmitted cycle completes again
		build(corrupt),             // refused datagram: no burst, session cancelled
		build(head), build(middle), // an incomplete retransmitted cycle: no burst
		build(tail), // completes the retransmitted cycle
	}
	counts := p1QUICDrive(t, p1QUICLease(t, rule, raws[0], ""), raws)
	want := []int{0, 0, 11, 0, 0, 11, 0, 0, 0, 11}
	if !p1EqualInts(counts, want) {
		t.Fatalf("delayed-completion fake units per datagram = %v, want %v", counts, want)
	}
}

// TestP1QUICCryptoReassemblyAdmissionStates pins the bounded reassembly state
// machine the flow admission is derived from: a pending cycle reports pending,
// its completion reports complete, a refused datagram cancels the session (a
// tail-only datagram cannot complete afterwards), a conflicting overlap is
// refused, and an oversized CRYPTO offset stays bounded.
func TestP1QUICCryptoReassemblyAdmissionStates(t *testing.T) {
	hello := rawQUICClientHello("admission-state.example")
	first := len(hello) / 3
	second := 2 * len(hello) / 3
	dcid := []byte{8, 8, 8, 8, 8, 8}
	head := sealQUICInitial(t, cryptoFrames([]int{0}, [][]byte{hello[:first]}, 240), dcid, 1, 1)
	middle := sealQUICInitial(t, cryptoFrames([]int{first}, [][]byte{hello[first:second]}, 240), dcid, 1, 2)
	tail := sealQUICInitial(t, cryptoFrames([]int{second}, [][]byte{hello[second:]}, 240), dcid, 1, 3)
	corrupt := append([]byte(nil), middle...)
	corrupt[len(corrupt)-20] ^= 0x01

	q := newQUICReassembler()
	if host, state := q.feed(head); host != "" || state != quicCryptoPending {
		t.Fatalf("head: host=%q state=%d, want pending", host, state)
	}
	if host, state := q.feed(tail); host != "" || state != quicCryptoPending {
		t.Fatalf("tail before middle: host=%q state=%d, want pending", host, state)
	}
	if host, state := q.feed(middle); host != "admission-state.example" || state != quicCryptoComplete {
		t.Fatalf("completion: host=%q state=%d, want complete", host, state)
	}
	// A refused datagram cancels the accumulated session (upstream
	// quic_reasm_cancel). The tail alone must not be able to complete it.
	if host, state := q.feed(corrupt); host != "" || state != quicCryptoRejected {
		t.Fatalf("corrupt: host=%q state=%d, want rejected", host, state)
	}
	if host, state := q.feed(tail); host != "" || state != quicCryptoPending {
		t.Fatalf("tail after cancel: host=%q state=%d, want pending", host, state)
	}
	if host, state := q.feed(head); host != "" || state != quicCryptoPending {
		t.Fatalf("head after tail: host=%q state=%d, want pending", host, state)
	}
	if host, state := q.feed(middle); host != "admission-state.example" || state != quicCryptoComplete {
		t.Fatalf("recompleted cycle: host=%q state=%d, want complete", host, state)
	}

	// Two overlapping non-contiguous fragments conflict: the merge is refused
	// instead of substituting bytes, and the session is cancelled.
	bytesA := bytes.Repeat([]byte{0x11}, 200)
	bytesB := bytes.Repeat([]byte{0x22}, 200)
	rangeA := sealQUICInitial(t, cryptoFrames([]int{100}, [][]byte{bytesA}, 0), dcid, 1, 4)
	rangeB := sealQUICInitial(t, cryptoFrames([]int{200}, [][]byte{bytesB}, 0), dcid, 1, 5)
	q2 := newQUICReassembler()
	if _, state := q2.feed(rangeA); state != quicCryptoPending {
		t.Fatalf("conflict setup: state=%d, want pending", state)
	}
	if host, state := q2.feed(rangeB); host != "" || state != quicCryptoRejected {
		t.Fatalf("conflicting overlap: host=%q state=%d, want rejected", host, state)
	}
	if host, state := q2.feed(middle); host != "" || state != quicCryptoPending {
		t.Fatalf("middle after conflict cancel: host=%q state=%d, want pending", host, state)
	}

	// CRYPTO offsets beyond the reassembly bound are refused before allocation.
	oversized := sealQUICInitial(t, []byte{6, 0x80, 0x00, 0x4e, 0x20, 0x01, 0xaa}, dcid, 1, 5)
	q3 := newQUICReassembler()
	if host, state := q3.feed(oversized); host != "" || state != quicCryptoRejected {
		t.Fatalf("oversized offset: host=%q state=%d, want rejected", host, state)
	}
}

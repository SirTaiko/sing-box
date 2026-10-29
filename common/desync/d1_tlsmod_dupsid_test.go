package desync

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// windowsClientHelloHex is the exact 186-byte ClientHello captured from the
// Windows profile-18 candidate flow in QA t_202078be (evidence/windows/
// a7-cand18.pcap, client port 55015, first record of the reassembled stream).
// It carries session_id_len = 0, which is what the Windows platform client
// sends; the Linux client's ClientHello in the same QA carries 32 bytes. The
// difference matters for tls_mod=dupsid, which upstream refuses when the
// session-id lengths differ (nfq/desync.c runtime_tls_mod).
const windowsClientHelloHex = "16030300b5010000b103036adf76f877ed26f69d38b15731843cd5bb4c17f420f88ecbbe605f046ca0139f00002ac02cc02bc030c02f009f009ec024c023c028c027c00ac009c014c013009d009c003d003c0035002f000a0100005e00000014001200000f7777772e796f75747562652e636f6d000500050100000000000a00080006001d00170018000b00020100000d001a00180804080508060401050102010403050302030202060106030023000000170000ff01000100"

func windowsClientHello(t *testing.T) []byte {
	t.Helper()
	hello, err := hex.DecodeString(windowsClientHelloHex)
	if err != nil {
		t.Fatalf("decode captured ClientHello: %v", err)
	}
	if len(hello) != 186 || hello[43] != 0 {
		t.Fatalf("captured ClientHello fixture changed: len=%d session_id_len=%d", len(hello), hello[43])
	}
	return hello
}

// TestTLSModDupSIDRefusalKeepsOtherModifiers pins the upstream
// runtime_tls_mod behaviour for a refused dupsid: the modifier is skipped and
// the other selected modifiers (rnd, sni=) still reach the emitted fake. The
// predecessor returned the raw fake payload in this case, which is exactly the
// QA D-1 wire observation on Windows (680 B default-tls.bin with the
// microsoft SNI instead of the 677 B google fake).
func TestTLSModDupSIDRefusalKeepsOtherModifiers(t *testing.T) {
	fake := buildClientHelloWithSID("www.microsoft.com", make([]byte, 32))
	original := windowsClientHello(t)
	mod := TLSMod{Randomize: true, DupSID: true, SNI: "www.google.com"}
	random := &sequenceRand{values: []uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}
	modified, applied := applyTLSMod(fake, mod, original, random)
	if !applied {
		t.Fatal("dupsid refusal reported no modification although rnd and sni were selected")
	}
	if bytes.Equal(modified, fake) {
		t.Fatal("dupsid refusal discarded the rnd and sni modifiers (raw fake returned)")
	}
	wantLength := len(fake) - (len("www.microsoft.com") - len("www.google.com"))
	if len(modified) != wantLength {
		t.Fatalf("modified fake length = %d, want %d", len(modified), wantLength)
	}
	layout, ok := parseTLSHelloLayout(modified)
	if !ok {
		t.Fatal("modified fake is not a valid ClientHello")
	}
	if got := string(modified[layout.sni : layout.sni+len("www.google.com")]); got != "www.google.com" {
		t.Fatalf("fake SNI = %q, want www.google.com", got)
	}
	if int(readUint16(modified[layout.recordLen:])) != len(modified)-5 {
		t.Fatal("record length was not updated with the shorter SNI")
	}
	if bytes.Equal(modified[11:43], fake[11:43]) {
		t.Fatal("rnd modifier did not randomize the ClientHello random")
	}
	if bytes.Equal(modified[44:76], fake[44:76]) {
		t.Fatal("rnd modifier did not randomize the fake session id")
	}
}

// TestTLSModDupSIDMatchingLengthStillCopies keeps the accepted dupsid
// behaviour for the case upstream does apply it: equal session-id lengths.
func TestTLSModDupSIDMatchingLengthStillCopies(t *testing.T) {
	fake := buildClientHelloWithSID("www.microsoft.com", make([]byte, 32))
	originalSID := bytes.Repeat([]byte{0xa5}, 32)
	original := buildClientHelloWithSID("www.youtube.com", originalSID)
	random := &sequenceRand{values: []uint32{1, 2, 3, 4}}
	modified, applied := applyTLSMod(fake, TLSMod{DupSID: true}, original, random)
	if !applied {
		t.Fatal("dupsid did not apply for matching session-id lengths")
	}
	layout, ok := parseTLSHelloLayout(modified)
	if !ok {
		t.Fatal("modified fake is not a valid ClientHello")
	}
	if !bytes.Equal(modified[layout.sessionID:layout.sessionID+32], originalSID) {
		t.Fatal("dupsid did not copy the original session id")
	}
}

// TestPlanTCPFakeTLSModEmptyOriginalSessionID exercises the production call
// path: planFirstStage must publish the modified fake (not the compiled raw
// payload) when the captured ClientHello has no session id.
func TestPlanTCPFakeTLSModEmptyOriginalSessionID(t *testing.T) {
	hello := windowsClientHello(t)
	packet := buildIPv4TCP(t, hello, 1000, tcpFlagACK|tcpFlagPSH)
	fake := buildClientHelloWithSID("www.microsoft.com", make([]byte, 32))
	rule := &Rule{
		Methods: []Method{{Kind: MethodFake}},
		Fake: &FakeSpec{Repeats: 1, Payloads: []Payload{{
			Protocol: ProtocolTLS,
			Data:     fake,
			TLSMod:   TLSMod{Randomize: true, DupSID: true, SNI: "www.google.com"},
		}}},
	}
	batch, err := PlanTCP(rule, packet, hello, 0, Facts{MessageLength: len(hello), Protocol: ProtocolTLS, Rand: &sequenceRand{values: []uint32{7, 8, 9}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Packets) != 1 {
		t.Fatalf("generated packets = %d, want 1", len(batch.Packets))
	}
	generated, err := ParsePacket(batch.Packets[0])
	if err != nil {
		t.Fatal(err)
	}
	wantLength := len(fake) - (len("www.microsoft.com") - len("www.google.com"))
	if len(generated.Payload) != wantLength {
		t.Fatalf("emitted fake length = %d, want %d", len(generated.Payload), wantLength)
	}
	layout, ok := parseTLSHelloLayout(generated.Payload)
	if !ok {
		t.Fatal("emitted fake is not a valid ClientHello")
	}
	if got := string(generated.Payload[layout.sni : layout.sni+len("www.google.com")]); got != "www.google.com" {
		t.Fatalf("emitted fake SNI = %q, want www.google.com", got)
	}
	verifyTCPChecksum(t, batch.Packets[0])
}

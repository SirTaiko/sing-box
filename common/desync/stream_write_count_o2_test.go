package desync

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// Permanent O2 regressions: net.Conn.Write must report the caller bytes it owns
// instead of 0 on every send-error path.
//
// Provenance: t_661cbe61-qa.md §5 (O2), t_79afdfd7-report.md §4 and
// t_1b39126b-report.md §7 kept the defect open for the integration owner. The
// acceptance fixture recorded there is reproduced verbatim by
// TestStreamO2SplitFragmentErrorAfterFullDelivery:
//
//	Write=0 err=boom wire="ABCDEFGH" (len=8) senderOut="ABC" connOut="DEFGH"
//
// The contract these tests pin down (see Write's doc comment):
//   - returned n counts original caller bytes only, never the OOB urgent byte
//     or any other byte the wrapper adds on the wire;
//   - bytes still buffered when the connection is still writable are owned,
//     because the hold timer, the next Write or the bounded Close flush sends
//     them;
//   - bytes still unsent after a send error are not owned, so a strict caller
//     that retries p[n:] never replays a delivered byte and never skips one;
//   - a rewritten block (HTTP tamper, TLS record splice) has no byte boundary
//     back into p, so it counts only when its whole transformed payload reached
//     the connection and contributes nothing when the send stopped inside it.
//
// Every test uses an injected connection/sender pair; no socket, no network.

var o2Boom = errors.New("o2: scripted send failure")

// o2Response scripts one native segment send: accept is how many segment bytes
// the sender claims to have handed to the socket, err the error returned with
// that count.
type o2Response struct {
	accept int
	err    error
}

type o2SendCall struct {
	data    []byte
	options sendOptions
}

// o2ScriptedSender returns one scripted response per Send and records exactly
// what it was asked to send and what it claims to have sent. An exhausted script
// accepts the whole segment without error.
type o2ScriptedSender struct {
	mu        sync.Mutex
	responses []o2Response
	calls     []o2SendCall
	emittedTo bytes.Buffer
}

func (s *o2ScriptedSender) Send(data []byte, options sendOptions) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, o2SendCall{data: append([]byte(nil), data...), options: options})
	response := o2Response{accept: len(data)}
	if len(s.responses) > 0 {
		response = s.responses[0]
		s.responses = s.responses[1:]
	}
	if response.accept < 0 {
		response.accept = 0
	}
	if response.accept > len(data) {
		response.accept = len(data)
	}
	s.emittedTo.Write(data[:response.accept])
	return response.accept, response.err
}

func (s *o2ScriptedSender) WaitNotSent(time.Duration) bool { return true }

func (s *o2ScriptedSender) sent() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.emittedTo.Bytes()...)
}

func (s *o2ScriptedSender) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

func (s *o2ScriptedSender) callData() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([][]byte, 0, len(s.calls))
	for _, call := range s.calls {
		result = append(result, call.data)
	}
	return result
}

// o2Wire is everything the peer would have received, in send order: native
// segment sends first, then the plain forwarding writes.
func o2Wire(sender *o2ScriptedSender, conn *fakeConn) []byte {
	result := sender.sent()
	return append(result, conn.collected()...)
}

// o2RequireCounts checks the three numbers a caller acts on: delivered bytes
// (what the doubles actually accepted), returned bytes (Write's n) and the
// remaining suffix (len(p)-n). On an error path nothing stays buffered, so a
// count larger than what was delivered would be a false acknowledgement.
func o2RequireCounts(t *testing.T, label string, delivered, returned, total int) {
	t.Helper()
	if returned < 0 || returned > total {
		t.Fatalf("%s: returned=%d for a %d-byte write", label, returned, total)
	}
	if returned > delivered {
		t.Fatalf("%s: false acknowledgement: returned=%d but delivered=%d (remaining=%d)",
			label, returned, delivered, total-returned)
	}
	t.Logf("%s: delivered=%d returned=%d remaining=%d", label, delivered, returned, total-returned)
}

// o2RetryOnSameConn models a strict caller that retries only the unwritten
// suffix. The wrapper is sticky-failed, so the retry must not put a second copy
// of any byte on the wire.
func o2RetryOnSameConn(t *testing.T, label string, wrapped net.Conn, payload []byte, returned int) {
	t.Helper()
	if returned >= len(payload) {
		return
	}
	retried, err := wrapped.Write(payload[returned:])
	if err == nil {
		t.Fatalf("%s: sticky wrapper accepted a retry after a send error", label)
	}
	if retried != 0 {
		t.Fatalf("%s: retry reported %d bytes after a sticky failure", label, retried)
	}
}

// O2 acceptance fixture: a split fragment error after every input byte reached
// the wire. The reported count must cover all eight bytes, and a caller that
// honours the count must not send a second copy.
func TestStreamO2SplitFragmentErrorAfterFullDelivery(t *testing.T) {
	rule := splitRule("3")
	rule.Split.SplitAnyProtocol = true
	// disorder selects the native segment sender, which is the path the
	// recorded fixture used (three bytes natively, then the rest forwarded).
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &o2ScriptedSender{responses: []o2Response{
		{accept: 3},
		{accept: 0, err: o2Boom},
	}}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()

	input := []byte("ABCDEFGH")
	returned, err := wrapped.Write(input)
	if !errors.Is(err, o2Boom) {
		t.Fatalf("Write error = %v, want the scripted send error", err)
	}
	wire := o2Wire(sender, conn)
	o2RequireCounts(t, "split fragment error after full delivery", len(wire), returned, len(input))
	if returned != len(input) {
		t.Fatalf("Write = %d, want %d (wire %q): every byte was delivered", returned, len(input), wire)
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("wire = %q, want %q exactly once", wire, input)
	}
	got := sender.callData()
	if len(got) != 2 || !bytes.Equal(got[0], []byte("ABC")) || !bytes.Equal(got[1], []byte("DEFGH")) {
		t.Fatalf("sender fragments = %q, want [ABC DEFGH]", got)
	}
	o2RetryOnSameConn(t, "split fragment error after full delivery", wrapped, input, returned)
	if after := o2Wire(sender, conn); !bytes.Equal(after, input) {
		t.Fatalf("retry changed the wire: %q, want %q", after, input)
	}
}

// O2: an unsplit native send that delivers everything and still reports an
// error must not report zero progress.
func TestStreamO2UnsplitNativeErrorAfterFullDelivery(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &o2ScriptedSender{responses: []o2Response{{accept: 9, err: o2Boom}}}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()

	input := []byte("xyzabcdef")
	returned, err := wrapped.Write(input)
	if !errors.Is(err, o2Boom) {
		t.Fatalf("Write error = %v, want the scripted send error", err)
	}
	wire := o2Wire(sender, conn)
	o2RequireCounts(t, "unsplit native error after full delivery", len(wire), returned, len(input))
	if returned != len(input) || !bytes.Equal(wire, input) {
		t.Fatalf("Write = %d, wire = %q, want %d and %q", returned, wire, len(input), input)
	}
	if count := conn.writeCount(); count != 0 {
		t.Fatalf("fully delivered bytes were written again on the plain conn: %d writes", count)
	}
}

// O2: a native send that makes no progress and reports an error must still
// forward every byte and report them, not zero.
func TestStreamO2UnsplitNativeErrorZeroProgress(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &o2ScriptedSender{responses: []o2Response{{accept: 0, err: o2Boom}}}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()

	input := []byte("xyzabcdef")
	returned, err := wrapped.Write(input)
	if !errors.Is(err, o2Boom) {
		t.Fatalf("Write error = %v, want the scripted send error", err)
	}
	wire := o2Wire(sender, conn)
	o2RequireCounts(t, "unsplit native zero progress", len(wire), returned, len(input))
	if returned != len(input) || !bytes.Equal(wire, input) {
		t.Fatalf("Write = %d, wire = %q, want %d and %q", returned, wire, len(input), input)
	}
}

// O2: an unchanged payload keeps a byte-for-byte mapping, so a partial send is
// reported exactly. The caller's retry suffix starts at the first byte that is
// really missing, and the delivered prefix appears once.
func TestStreamO2IdentityPartialDeliveryReportsExactPrefix(t *testing.T) {
	rule := splitRule("host+1")
	rule.Split.Disorder = "any"
	config := mustCompileStream(t, rule)
	sender := &o2ScriptedSender{responses: []o2Response{{accept: 3, err: o2Boom}}}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	// The forwarding write accepts two bytes and then fails.
	conn.failAfter = 2
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()

	input := []byte("xyzabcdef")
	returned, err := wrapped.Write(input)
	if err == nil {
		t.Fatal("Write succeeded although the forwarding write failed")
	}
	wire := o2Wire(sender, conn)
	o2RequireCounts(t, "identity partial delivery", len(wire), returned, len(input))
	if returned != 5 {
		t.Fatalf("Write = %d, want 5 (3 native + 2 forwarded)", returned)
	}
	if !bytes.Equal(wire, input[:returned]) {
		t.Fatalf("wire = %q, want the exact prefix %q", wire, input[:returned])
	}
	o2RetryOnSameConn(t, "identity partial delivery", wrapped, input, returned)
	if after := o2Wire(sender, conn); !bytes.Equal(after, wire) {
		t.Fatalf("retry replayed bytes: %q, want the unchanged %q", after, wire)
	}
}

// O2: a rewritten payload (HTTP tamper changes its length) has no byte boundary
// back into p. A send that stops inside it must not acknowledge a guessed
// prefix, and the connection must stay sticky so nothing is sent twice.
func TestStreamO2RewrittenBlockIsNotPartiallyAcknowledged(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods:    badoption.Listable[string]{"http_tamper"},
		HTTPTamper: &option.DirectDesyncStreamHTTPTamper{HostDot: true},
	}
	config := mustCompileStream(t, rule)
	conn := newFakeConn()
	// Stop after the inserted '.' so the delivered prefix is provably not a
	// prefix of the caller buffer.
	conn.failAfter = 45
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()

	input := []byte("GET / HTTP/1.1\r\nHost: blocked.example\r\nUser-Agent: x\r\n\r\n")
	returned, err := wrapped.Write(input)
	if err == nil {
		t.Fatal("Write succeeded although the rewritten payload stopped early")
	}
	wire := conn.collected()
	if len(wire) != 45 {
		t.Fatalf("wire prefix = %q (%d bytes), want the 45 bytes the conn accepted", wire, len(wire))
	}
	o2RequireCounts(t, "rewritten block partial send", len(wire), returned, len(input))
	if returned != 0 {
		t.Fatalf("Write = %d for a partially sent rewritten block, want 0 (no offset mapping)", returned)
	}
	if bytes.Equal(wire, input[:len(wire)]) {
		t.Fatalf("hostdot did not rewrite the request: %q", wire)
	}
	o2RetryOnSameConn(t, "rewritten block partial send", wrapped, input, returned)
	if after := conn.collected(); !bytes.Equal(after, wire) {
		t.Fatalf("retry replayed bytes: %q, want the unchanged %q", after, wire)
	}
}

// O2: buffered bytes from an earlier call are delivered first and are never
// counted again for the current caller. Only the current buffer's delivered
// suffix may be reported.
func TestStreamO2BufferedLeftoverIsNotCountedTwice(t *testing.T) {
	blocked := splitRule("2")
	blocked.Name = "blocked"
	blocked.Domain = badoption.Listable[string]{"blocked.example"}
	catchAll := splitRule("2")
	catchAll.Name = "catch-all"
	config := mustCompileStream(t, blocked, catchAll)
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{Port: 80})
	defer wrapped.Close()

	held := []byte("GET / HTTP/1.1\r\nHo")
	if returned, err := wrapped.Write(held); err != nil || returned != len(held) {
		t.Fatalf("held Write = %d,%v, want %d,nil", returned, err, len(held))
	}
	if got := conn.collected(); len(got) != 0 {
		t.Fatalf("incomplete header was released early: %q", got)
	}
	// The combined block starts with the 18 bytes owed to the first call; the
	// conn accepts 22 bytes in total, so only 4 bytes of this call are out.
	conn.failAfter = 22
	second := []byte("st: blocked.example\r\nUser-Agent: x\r\n\r\n")
	returned, err := wrapped.Write(second)
	if err == nil {
		t.Fatal("Write succeeded although the combined block stopped early")
	}
	wire := conn.collected()
	o2RequireCounts(t, "buffered leftover", len(wire), returned, len(second))
	if returned != len(wire)-len(held) {
		t.Fatalf("Write = %d, want %d: the %d buffered bytes belong to the earlier call",
			returned, len(wire)-len(held), len(held))
	}
	if !bytes.Equal(wire, append(append([]byte(nil), held...), second[:returned]...)) {
		t.Fatalf("wire = %q, want the earlier buffer plus the reported suffix", wire)
	}
	o2RetryOnSameConn(t, "buffered leftover", wrapped, second, returned)
}

// O2: after a send error the OOB urgent byte must not be counted as a caller
// byte, and the count must stay within the original buffer.
func TestStreamO2OOBByteIsNotCountedAsCallerData(t *testing.T) {
	rule := splitRule("3")
	rule.Split.SplitAnyProtocol = true
	rule.Split.OOB = "any"
	config := mustCompileStream(t, rule)
	sender := &o2ScriptedSender{responses: []o2Response{
		{accept: 3},
		{accept: 0, err: o2Boom},
	}}
	config.native = &nativeRecorder{sender: sender}
	conn := newFakeConn()
	wrapped := wrapStream(t, config, conn, MatchFacts{})
	defer wrapped.Close()

	input := []byte("ABCDEFGH")
	returned, err := wrapped.Write(input)
	if !errors.Is(err, o2Boom) {
		t.Fatalf("Write error = %v, want the scripted send error", err)
	}
	calls := sender.calls
	if len(calls) != 2 || !calls[0].options.oob {
		t.Fatalf("first fragment did not carry the OOB marker: %+v", calls)
	}
	wire := o2Wire(sender, conn)
	o2RequireCounts(t, "OOB byte accounting", len(wire), returned, len(input))
	if returned != len(input) {
		t.Fatalf("Write = %d, want %d: the OOB byte is extra wire data, not caller data", returned, len(input))
	}
	if !bytes.Equal(wire, input) {
		t.Fatalf("wire = %q, want %q (the OOB byte must not be part of the stream bytes)", wire, input)
	}
}

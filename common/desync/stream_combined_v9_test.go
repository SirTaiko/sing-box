package desync

// Submission-9 combined regression: an unproven native completion (A-S2/A-S3)
// crossing the deferred TFO attachment (firstSendSender) on the real consumer
// path (StreamConfig.WrapConn -> Write -> processBlock -> native sender
// factory -> established sender).
//
// The lane regression (stream_v9_regression_test.go) drives the same wrapper
// refusal on an eager sender. This one locks the crossing with the deferred
// attachment, where the first fragment is carried by the owned pending attempt
// and is not part of the native sender's block: the reported caller count must
// still be exactly the provable prefix, and the tail of the block must never be
// forwarded after an unproven completion - on the first write or on a later
// one.

import (
	"bytes"
	"errors"
	"testing"
)

// The deferred first fragment ("AB") is provably on the owned attempt. The
// established native sender then reports an unproven completion for "CDEF":
// the provider may already have transmitted an unknown prefix, so the wrapper
// must not forward the "unsent" tail and must not count it as caller bytes.
func TestStreamCombinedDeferredAttachmentUnprovenCompletion(t *testing.T) {
	config := combinedFirstSendRule(t)
	cause := errors.New("substituted completion query failure")
	sender := &v4ScriptedSender{short: 0, failErr: newStreamUnknownCompletionError(cause)}
	config.native = &nativeRecorder{sender: sender}
	pending := newFakePendingConn()
	wrapped := wrapStream(t, config, pending, MatchFacts{})
	defer wrapped.Close()
	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if !streamCompletionUnproven(err) {
		t.Fatalf("Write error = %v, want an unproven-completion error", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("Write error = %v, want the marker to unwrap to %v", err, cause)
	}
	if written != 2 {
		t.Fatalf("Write = %d, want 2: only the deferred first fragment is provably on the connection", written)
	}
	if got := pending.activationPayload(); !bytes.Equal(got, []byte("AB")) {
		t.Fatalf("deferred first-send payload = %q, want %q", got, "AB")
	}
	if got := sender.emitted(); len(got) != 0 {
		t.Fatalf("the native sender accepted %q, want nothing", got)
	}
	if got := pending.establishedWrites(); len(got) != 0 {
		t.Fatalf("the wrapper replayed %q after an unproven native completion", got)
	}
	if total := combinedWireStream(pending, sender.emitted()); !bytes.Equal(total, input[:2]) {
		t.Fatalf("wire stream = %q, want exactly the provable prefix %q", total, input[:2])
	}
	// The send error is sticky: a later write must not replay the block tail
	// either, and must keep the same unproven identity.
	if later, laterErr := wrapped.Write(input[2:]); later != 0 || !streamCompletionUnproven(laterErr) {
		t.Fatalf("write after the unproven completion = (%d, %v), want (0, unproven)", later, laterErr)
	}
	if got := pending.establishedWrites(); len(got) != 0 {
		t.Fatalf("a later write forwarded %q after the unproven completion", got)
	}
}

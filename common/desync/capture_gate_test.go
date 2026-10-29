package desync

// Ordered-close regressions for the capture phase boundary: records captured
// after the fence must not overtake held originals of earlier captures, and the
// fence must wait for the records that already entered the engine. These
// exercise the production gate used by the Windows receive loops; they need no
// driver and run on every platform.

import (
	"sync"
	"testing"
	"time"
)

type gateLog struct {
	mu    sync.Mutex
	order []string
}

func (l *gateLog) record(entry string) {
	l.mu.Lock()
	l.order = append(l.order, entry)
	l.mu.Unlock()
}

func (l *gateLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.order...)
}

func indexOf(order []string, entry string) int {
	for index, value := range order {
		if value == entry {
			return index
		}
	}
	return -1
}

// TestCaptureGateHeldFlushPrecedesQueuedRecord is the ARCH-02 ordering proof at
// the gate level: H1/H2 were held earlier, an active handler is still resolving
// when the fence starts, and Q3 was captured after the fence. The gate must
// (1) wait for the active handler, (2) let the lease flush H1/H2, and only then
// (3) release Q3. Without the gate, Q3 would be free to send as soon as it was
// received, i.e. before the held originals.
func TestCaptureGateHeldFlushPrecedesQueuedRecord(t *testing.T) {
	gate := newCaptureDispatchGate()
	log := &gateLog{}
	// H1 and H2 were dispatched and held before the close started.
	for _, held := range []string{"H1", "H2"} {
		if !gate.beginDispatch() {
			t.Fatal("pre-close dispatch was refused")
		}
		gate.endDispatch()
		log.record(held + "-dispatch")
	}
	// R3 is already inside the engine when the close begins.
	if !gate.beginDispatch() {
		t.Fatal("active dispatch was refused")
	}
	fenceStarted := make(chan struct{})
	flushDone := make(chan struct{})
	go func() {
		close(fenceStarted)
		gate.quiesce()
		// The lease flushes the held originals after the fence returned.
		log.record("H1")
		log.record("H2")
		gate.allowPassThrough()
		close(flushDone)
	}()
	<-fenceStarted
	// Q3 is captured after the fence; it may only pass through.
	queuedAttempted := make(chan struct{})
	queuedSent := make(chan struct{})
	go func() {
		if gate.beginDispatch() {
			t.Error("a record captured after the fence was dispatched to the engine")
		}
		close(queuedAttempted)
		gate.awaitPassThrough()
		log.record("Q3")
		close(queuedSent)
	}()
	<-queuedAttempted
	select {
	case <-flushDone:
		t.Fatal("the fence completed while an active handler was still resolving")
	case <-time.After(30 * time.Millisecond):
	}
	// The active handler resolves its own disposition (R3), then the fence can
	// proceed; Q3 stays blocked behind the held flush.
	gate.endDispatch()
	<-flushDone
	<-queuedSent
	order := log.snapshot()
	held1 := indexOf(order, "H1")
	held2 := indexOf(order, "H2")
	queued := indexOf(order, "Q3")
	if held1 < 0 || held2 < 0 || queued < 0 {
		t.Fatalf("record order missing entries: %v", order)
	}
	if !(held1 < held2 && held2 < queued) {
		t.Fatalf("queued record overtook the held flush: %v", order)
	}
}

// TestCaptureGateFenceWaitsForInFlightDisposition covers the matching send side:
// a disposition that already started before the fence must complete before the
// fence returns, otherwise it could still be in flight when the held data is
// flushed. A disposition that starts after the fence must wait for the release.
func TestCaptureGateFenceWaitsForInFlightDisposition(t *testing.T) {
	gate := newCaptureDispatchGate()
	if !gate.beginSend() {
		t.Fatal("pre-fence disposition was refused")
	}
	fenced := make(chan struct{})
	go func() {
		gate.quiesce()
		close(fenced)
	}()
	select {
	case <-fenced:
		t.Fatal("the fence returned while a pre-fence disposition was still in flight")
	case <-time.After(30 * time.Millisecond):
	}
	gate.endSend()
	select {
	case <-fenced:
	case <-time.After(time.Second):
		t.Fatal("the fence did not finish after the in-flight disposition completed")
	}
	if gate.beginSend() {
		t.Fatal("a disposition started after the fence")
	}
	sent := make(chan struct{})
	go func() {
		gate.awaitPassThrough()
		close(sent)
	}()
	select {
	case <-sent:
		t.Fatal("the post-fence disposition was not held")
	case <-time.After(20 * time.Millisecond):
	}
	gate.allowPassThrough()
	select {
	case <-sent:
	case <-time.After(time.Second):
		t.Fatal("the post-fence disposition was never released")
	}
	// The release is idempotent: Close calls it again after the lease already
	// released the queued records.
	gate.allowPassThrough()
}

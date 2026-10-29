package desync

// Model coverage for the carried D§4 producer handshake (finding F2).
//
// The demonstrated failure was an ordering one: the Windows capture stopped its
// receive path before the older held original returned, so a post-fence caller
// write reached the wire first. The repair moves the receive shutdown behind a
// real producer pause. These tests pin the two properties that make the order
// meaningful, on every host and without a Windows driver:
//
//  1. pause wait semantics: an already admitted operation delays the pause; an
//     operation that arrives while PAUSING waits without entering; resume runs
//     it afterwards;
//  2. the Lease teardown order: semantic quiesce -> held flush/pass-through ->
//     producer pause -> receive shutdown -> capture close -> positive receipt.

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitProducerCondition polls one gate predicate inside a bound. It is local so
// this model test stays platform-neutral.
func waitProducerCondition(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestEndpointProducerPauseWaitsForAdmittedWrite pins the barrier itself: a
// write already inside the gate delays PAUSED, a later write waits behind it,
// and the resume is what lets the later write run.
func TestEndpointProducerPauseWaitsForAdmittedWrite(t *testing.T) {
	gate := newEndpointProducerGate()
	end, err := gate.begin()
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}

	paused := make(chan struct{})
	go func() {
		gate.pause()
		close(paused)
	}()
	waitProducerCondition(t, "producer phase pausing", func() bool {
		phase, _ := gate.state()
		return phase == producerPausing
	})

	// A late operation must not enter: it would otherwise copy a payload into
	// the very window the pause is closing.
	lateDone := make(chan struct{})
	go func() {
		lateEnd, lateErr := gate.begin()
		if lateErr == nil {
			lateEnd()
		}
		close(lateDone)
	}()
	select {
	case <-lateDone:
		t.Fatal("a late producer entered during PAUSING")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-paused:
		t.Fatal("pause returned while an admitted producer was active")
	default:
	}

	// The admitted operation ends; PAUSED becomes true and the late producer
	// stays waiting until the resume.
	end()
	<-paused
	if phase, active := gate.state(); phase != producerPaused || active != 0 {
		t.Fatalf("gate state = (%v,%d), want paused/0", phase, active)
	}
	select {
	case <-lateDone:
		t.Fatal("the late producer ran before the capture-retired resume")
	case <-time.After(20 * time.Millisecond):
	}

	token := &endpointProducerToken{gate: gate}
	if phase, _ := gate.state(); phase != producerPaused {
		t.Fatalf("phase = %v, want paused", phase)
	}
	gate.resume(token)
	select {
	case <-lateDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the late producer never ran after the resume")
	}
	if phase, active := gate.state(); phase != producerRunning || active != 0 {
		t.Fatalf("gate state after resume = (%v,%d), want running/0", phase, active)
	}

	// end is idempotent: a deferred double end must not corrupt the counter.
	end()
	if _, remaining := gate.state(); remaining != 0 {
		t.Fatalf("active = %d after a double end", remaining)
	}
}

// TestEndpointProducerResumeIsIdempotent pins the one-shot token: two resumes
// and a resume of another gate's token change nothing.
func TestEndpointProducerResumeIsIdempotent(t *testing.T) {
	gate := newEndpointProducerGate()
	token := gate.pause()
	gate.resume(token)
	gate.resume(token)
	if phase, _ := gate.state(); phase != producerRunning {
		t.Fatalf("phase = %v, want running", phase)
	}
	other := newEndpointProducerGate()
	other.resume(token)
	if phase, _ := other.state(); phase != producerRunning {
		t.Fatalf("foreign token changed the gate phase to %v", phase)
	}
}

// producerOrderCapture records the actual teardown call order of one capture.
type producerOrderCapture struct {
	mu      sync.Mutex
	order   []string
	stopAt  time.Time
	closeAt time.Time
	err     error
}

func (c *producerOrderCapture) record(name string) {
	c.mu.Lock()
	c.order = append(c.order, name)
	c.mu.Unlock()
}

func (c *producerOrderCapture) Quiesce() error { c.record("quiesce"); return nil }

func (c *producerOrderCapture) AllowPassThrough() { c.record("allow-pass-through") }

func (c *producerOrderCapture) StopReceive() error {
	c.mu.Lock()
	c.stopAt = time.Now()
	c.mu.Unlock()
	c.record("stop-receive")
	return nil
}

func (c *producerOrderCapture) Close() error {
	c.mu.Lock()
	c.closeAt = time.Now()
	c.mu.Unlock()
	c.record("close")
	return c.err
}

func (c *producerOrderCapture) sequence() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.order...)
}

type producerOrderBackend struct{ capture Capture }

func (b *producerOrderBackend) Name() string { return "producer-order" }

func (b *producerOrderBackend) Open(*Lease) (Capture, error) { return b.capture, nil }

func newProducerOrderLease(t *testing.T, capture *producerOrderCapture) *Lease {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["udp"],"port":[443],"methods":[]}]}`), "")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	config.Limits.MaxLeases = 1
	engine, err := NewEngine(config, &producerOrderBackend{capture: capture})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatalf("attempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = lease.StartCapture(); err != nil {
		t.Fatalf("start capture: %v", err)
	}
	return lease
}

// TestLeaseTeardownPausesProducersBeforeReceiveShutdown is the ordering
// regression: with a producer admitted, teardown must not emit StopReceive or
// Close until that producer reached its terminal return.
func TestLeaseTeardownPausesProducersBeforeReceiveShutdown(t *testing.T) {
	capture := &producerOrderCapture{}
	lease := newProducerOrderLease(t, capture)
	end, err := lease.BeginEndpointWrite()
	if err != nil {
		t.Fatalf("begin endpoint write: %v", err)
	}

	closed := make(chan error, 1)
	go func() { closed <- lease.Close(nil) }()

	waitProducerCondition(t, "producer pause publication", func() bool {
		phase, active := lease.producers.state()
		return phase == producerPausing && active == 1
	})
	if got := capture.sequence(); len(got) != 2 {
		t.Fatalf("capture calls before the producer ended = %v, want quiesce+allow only", got)
	}

	end()
	select {
	case closeErr := <-closed:
		if closeErr != nil {
			t.Fatalf("lease close: %v", closeErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("lease close did not finish after the producer ended")
	}
	want := []string{"quiesce", "allow-pass-through", "stop-receive", "close"}
	got := capture.sequence()
	if len(got) != len(want) {
		t.Fatalf("capture calls = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("capture call %d = %q, want %q (all: %v)", index, got[index], want[index], got)
		}
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatalf("positive capture-retired receipt = %v, want nil", err)
	}
}

// TestCaptureRetirementReceiptKeepsErrorsVisible pins the receipt contract: a
// capture close error is a real failure, not a positive receipt.
func TestCaptureRetirementReceiptKeepsErrorsVisible(t *testing.T) {
	closeErr := errors.New("capture close failed")
	capture := &producerOrderCapture{err: closeErr}
	lease := newProducerOrderLease(t, capture)
	if err := lease.Close(nil); err == nil {
		t.Fatal("lease close reported success although the capture close failed")
	}
	if err := lease.WaitCaptureRetired(); err == nil {
		t.Fatal("capture-retired receipt was positive although the capture close failed")
	}
}

// TestRequestResultIsOnePerDatagram is a zero-ambiguity control for the
// teardown path: an application write admitted before Close still returns its
// real result, and a write admitted during the pause returns afterwards.
func TestRequestResultIsOnePerDatagram(t *testing.T) {
	capture := &producerOrderCapture{}
	lease := newProducerOrderLease(t, capture)
	var writes atomic.Int32
	write := func() error {
		end, err := lease.BeginEndpointWrite()
		if err != nil {
			return err
		}
		defer end()
		writes.Add(1)
		return nil
	}
	if err := write(); err != nil {
		t.Fatalf("write before close: %v", err)
	}
	token := lease.pauseEndpointWrites()
	var pausedWrite atomic.Int32
	done := make(chan struct{})
	go func() {
		_ = write()
		pausedWrite.Add(1)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("a write entered while the producers were paused")
	case <-time.After(20 * time.Millisecond):
	}
	lease.resumeEndpointWrites(token)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the paused write never ran after the resume")
	}
	if writes.Load() != 2 {
		t.Fatalf("real write results = %d, want 2", writes.Load())
	}
}

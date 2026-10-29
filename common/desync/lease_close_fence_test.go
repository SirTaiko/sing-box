package desync

// ARCH-02 regression: the capture dispatch fence is published before the closed
// lease becomes visible, so a record that arrives while the ordered close is
// still waiting for its own fence cannot take the closed-lease fast-pass and be
// sent before the held originals of earlier captures.

import (
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fenceOrderCapture models the production capture's ordered close: one dispatch
// gate, an early fence publication (FenceDispatch) and the ordered quiesce that
// waits for the records already inside the engine.
type fenceOrderCapture struct {
	gate *captureDispatchGate

	quiesceEntered chan struct{}
	releaseQuiesce chan struct{}
	allowed        chan struct{}

	enterOnce sync.Once
	allowOnce sync.Once
	closeOnce sync.Once

	mu    sync.Mutex
	order []string
}

func newFenceOrderCapture() *fenceOrderCapture {
	return &fenceOrderCapture{
		gate:           newCaptureDispatchGate(),
		quiesceEntered: make(chan struct{}),
		releaseQuiesce: make(chan struct{}),
		allowed:        make(chan struct{}),
	}
}

func (c *fenceOrderCapture) record(entry string) {
	c.mu.Lock()
	c.order = append(c.order, entry)
	c.mu.Unlock()
}

func (c *fenceOrderCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.order...)
}

// FenceDispatch is the early publication half of the production ordered close.
func (c *fenceOrderCapture) FenceDispatch() { c.gate.fence() }

// Quiesce pauses *before* it publishes the fence and waits for the records
// already inside the engine. That pause is exactly the interval under test: the
// lease close already published its closed flag, and the capture has not fenced
// yet. Before the repair the queued record could use that interval to overtake
// the held originals.
func (c *fenceOrderCapture) Quiesce() error {
	c.enterOnce.Do(func() {
		c.record("quiesce-enter")
		close(c.quiesceEntered)
	})
	<-c.releaseQuiesce
	c.gate.quiesce()
	c.record("quiesced")
	return nil
}

// AllowPassThrough releases records captured after the fence; the lease calls it
// only after it flushed the held originals.
func (c *fenceOrderCapture) AllowPassThrough() {
	c.allowOnce.Do(func() {
		c.record("allow")
		close(c.allowed)
	})
	c.gate.allowPassThrough()
}

func (c *fenceOrderCapture) Close() error {
	c.closeOnce.Do(func() { c.record("close") })
	return nil
}

type fenceOrderBackend struct {
	capture *fenceOrderCapture
}

func (b *fenceOrderBackend) Name() string { return "fence-order-test" }

func (b *fenceOrderBackend) Open(*Lease) (Capture, error) { return b.capture, nil }

// TestLeaseClosePublishesFenceBeforeClosedLease is the permanent regression for
// the accepted close ordering: Close publishes the capture dispatch fence before
// the closed lease becomes visible to the capture loop, so a record that arrives
// in the teardown interval is forwarded only after the held originals of earlier
// captures were flushed. It asserts the capture-record terminal order (held
// completion, pass-through release, queued record), not the TCP receiver's
// deduplicated application bytes.
func TestLeaseClosePublishesFenceBeforeClosedLease(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"hold_timeout":"10s"},`+
		`"rules":[{"network":["tcp"],"port":[443],"methods":["multisplit"],`+
		`"multisplit":{"split_pos":["host+0"]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	capture := newFenceOrderCapture()
	engine, err := NewEngine(config, &fenceOrderBackend{capture: capture})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	source := netip.MustParseAddrPort("192.0.2.10:40000")
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP,
		Source: source, Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(source)
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	if lease.capture != capture {
		t.Fatal("the capture double was not attached through StartCapture")
	}
	lease.tcpFlow.primeSemanticTrack()

	// H1 is the held original of an earlier capture. Its terminal disposition is
	// the capture record the queued record must not overtake.
	hello := buildClientHello("blocked.example")
	first := append([]byte(nil), hello[:12]...)
	packet := buildIPv4TCP(t, first, 1000, tcpFlagACK|tcpFlagPSH)
	var heldVerdicts []Verdict
	complete := func(verdict Verdict, reason string, modified []byte) {
		heldVerdicts = append(heldVerdicts, verdict)
		capture.record("H1")
	}
	if verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, nil, complete); verdict != VerdictHold {
		t.Fatalf("first segment verdict = %d, want hold", verdict)
	}

	closed := make(chan error, 1)
	go func() { closed <- lease.Close(nil) }()
	select {
	case <-capture.quiesceEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("close never reached the capture teardown")
	}

	// The lease is already closed here - that publication is what a queued
	// record used to observe - and the capture must already be fenced.
	lease.mu.Lock()
	closedPublished := lease.closed
	lease.mu.Unlock()
	if !closedPublished {
		t.Fatal("capture teardown started before the closed lease was published")
	}
	if !capture.gate.isFenced() {
		t.Fatal("closed lease was published before the capture dispatch fence")
	}
	if capture.gate.beginDispatch() {
		// Keep the gate consistent before failing so a broken test cannot leave
		// the teardown waiting forever.
		capture.gate.endDispatch()
		t.Fatal("a record captured after close publication entered the pre-fence dispatch group")
	}

	// Q3 is ready: the capture loop is about to forward it as pass-through.
	q3Sent := make(chan struct{})
	go func() {
		capture.gate.awaitPassThrough()
		capture.record("Q3")
		close(q3Sent)
	}()
	select {
	case <-q3Sent:
		t.Fatal("queued record was sent before the held original was flushed")
	case <-time.After(50 * time.Millisecond):
	}

	close(capture.releaseQuiesce)
	select {
	case closeErr := <-closed:
		if closeErr != nil {
			t.Fatalf("close: %v", closeErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("close did not finish after the capture fence returned")
	}
	select {
	case <-q3Sent:
	case <-time.After(2 * time.Second):
		t.Fatal("queued record was never released")
	}

	if len(heldVerdicts) != 1 || heldVerdicts[0] != VerdictPass {
		t.Fatalf("held completions = %+v, want exactly one pass", heldVerdicts)
	}
	order := capture.snapshot()
	heldIndex := indexOf(order, "H1")
	allowIndex := indexOf(order, "allow")
	q3Index := indexOf(order, "Q3")
	if heldIndex < 0 || allowIndex < 0 || q3Index < 0 {
		t.Fatalf("close order missing entries: %v", order)
	}
	if !(heldIndex < allowIndex && allowIndex < q3Index) {
		t.Fatalf("queued record was not ordered behind the held flush: %v", order)
	}
}

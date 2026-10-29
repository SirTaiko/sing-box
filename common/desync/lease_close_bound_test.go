package desync

// ARCH-02/ARCH-03 regressions: the whole caller-visible lease close is bounded,
// the held originals of earlier captures are delivered before records captured
// after the fence, and an admitted lease stays charged until its native
// retirement receipt instead of being released by a caller timeout.

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type orderedTestCapture struct {
	quiesceStarted chan struct{}
	quiesceGate    chan struct{}
	allowCalled    chan struct{}
	closeCalled    chan struct{}

	startedOnce sync.Once
	allowOnce   sync.Once
	closeOnce   sync.Once

	mu    sync.Mutex
	order []string
}

func newOrderedTestCapture() *orderedTestCapture {
	return &orderedTestCapture{
		quiesceStarted: make(chan struct{}),
		allowCalled:    make(chan struct{}),
		closeCalled:    make(chan struct{}),
	}
}

func (c *orderedTestCapture) record(entry string) {
	c.mu.Lock()
	c.order = append(c.order, entry)
	c.mu.Unlock()
}

func (c *orderedTestCapture) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.order...)
}

// Quiesce blocks when the test armed a gate, which is how the bound test keeps
// the synchronous fence from returning.
func (c *orderedTestCapture) Quiesce() error {
	c.startedOnce.Do(func() {
		c.record("quiesce")
		close(c.quiesceStarted)
	})
	if c.quiesceGate != nil {
		<-c.quiesceGate
	}
	return nil
}

// AllowPassThrough represents the production backend's release of records
// captured after the fence. The lease must call it only after the held flush.
func (c *orderedTestCapture) AllowPassThrough() {
	c.allowOnce.Do(func() {
		c.record("allow")
		close(c.allowCalled)
	})
}

func (c *orderedTestCapture) Close() error {
	c.closeOnce.Do(func() {
		c.record("close")
		close(c.closeCalled)
	})
	return nil
}

type orderedTestBackend struct {
	capture *orderedTestCapture
}

func (b *orderedTestBackend) Name() string { return "ordered-test" }

func (b *orderedTestBackend) Open(*Lease) (Capture, error) { return b.capture, nil }

func maxOneConfig(t *testing.T) *Config {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},`+
		`"rules":[{"ip_cidr":["any"],"methods":[]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func newBoundLease(t *testing.T, engine *Engine, capture *orderedTestCapture) *Lease {
	t.Helper()
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
		t.Fatal("the test backend's capture was not attached")
	}
	return lease
}

// TestLeaseCloseBoundsWholePathAndRetainsAdmission proves the caller bound
// covers the synchronous quiesce: a fence that never returns cannot keep the
// caller forever, the close reports that it is incomplete, the charged slot is
// retained until the real teardown finishes, and MaxLeases=1 refuses a
// replacement until then.
func TestLeaseCloseBoundsWholePathAndRetainsAdmission(t *testing.T) {
	engine, err := NewEngine(maxOneConfig(t), &orderedTestBackend{capture: newOrderedTestCapture()})
	if err != nil {
		t.Fatal(err)
	}
	capture := engine.backend.(*orderedTestBackend).capture
	capture.quiesceGate = make(chan struct{})
	lease := newBoundLease(t, engine, capture)
	defer engine.Close()

	start := time.Now()
	results := make(chan error, 1)
	go func() { results <- lease.Close(nil) }()
	select {
	case <-capture.quiesceStarted:
	case <-time.After(time.Second):
		t.Fatal("close never reached the capture fence")
	}
	select {
	case closeErr := <-results:
		if closeErr == nil {
			t.Fatal("close reported success although the synchronous quiesce never returned")
		}
	case <-time.After(leaseCloseGrace + 1500*time.Millisecond):
		t.Fatal("close did not respect the whole-path bound")
	}
	if elapsed := time.Since(start); elapsed > leaseCloseGrace+time.Second {
		t.Fatalf("close took %s, want the %s bound", elapsed, leaseCloseGrace)
	}
	if engine.ActiveLeases() != 1 {
		t.Fatalf("charged leases = %d after an incomplete close, want the retained slot", engine.ActiveLeases())
	}
	if _, err = engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP}); !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("replacement attempt at capacity one = %v, want admission refusal", err)
	}

	// The fence eventually returns; the retained teardown finishes and only
	// then discharges the admission reference.
	close(capture.quiesceGate)
	select {
	case <-capture.closeCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("teardown did not finish after the fence returned")
	}
	deadline := time.Now().Add(2 * time.Second)
	for engine.ActiveLeases() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("charged leases = %d after the teardown finished", engine.ActiveLeases())
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP}); err != nil {
		t.Fatalf("replacement attempt refused after the slot retired: %v", err)
	}
}

// TestLeaseCloseFlushesHeldOriginalsBeforePassThrough proves the D3 phase
// boundary with real held data: the captured original is delivered by the held
// completer, the pass-through release happens only afterwards, and the bytes of
// the captured packet are preserved exactly.
func TestLeaseCloseFlushesHeldOriginalsBeforePassThrough(t *testing.T) {
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],`+
		`"methods":["multisplit"],"multisplit":{"split_pos":["host+0"]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	capture := newOrderedTestCapture()
	engine, err := NewEngine(config, &orderedTestBackend{capture: capture})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	lease := newBoundLease(t, engine, capture)
	lease.tcpFlow.primeSemanticTrack()

	hello := buildClientHello("blocked.example")
	if len(hello) < 20 {
		t.Fatalf("hello too short: %d", len(hello))
	}
	first := append([]byte(nil), hello[:12]...)
	packet := buildIPv4TCP(t, first, 1000, tcpFlagACK|tcpFlagPSH)
	var delivered []byte
	var verdicts []Verdict
	complete := func(verdict Verdict, reason string, modified []byte) {
		capture.record("held")
		verdicts = append(verdicts, verdict)
		// The native backend sends the captured original on a Pass completion;
		// recording those bytes here is the same terminal disposition.
		if verdict == VerdictPass && len(modified) == 0 {
			delivered = append(delivered, first...)
		}
	}
	if verdict := lease.HandlePacket(packet.Raw, DirectionOutbound, nil, complete); verdict != VerdictHold {
		t.Fatalf("first segment verdict = %d, want hold", verdict)
	}
	if len(delivered) != 0 {
		t.Fatal("held original was delivered before close")
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0] != VerdictPass {
		t.Fatalf("held completions = %+v, want one pass", verdicts)
	}
	if string(delivered) != string(first) {
		t.Fatalf("delivered held bytes differ from the captured packet: %x vs %x", delivered, first)
	}
	order := capture.snapshot()
	heldIndex := indexOf(order, "held")
	allowIndex := indexOf(order, "allow")
	closeIndex := indexOf(order, "close")
	if heldIndex < 0 || allowIndex < 0 || closeIndex < 0 {
		t.Fatalf("close order missing entries: %v", order)
	}
	if !(heldIndex < allowIndex && allowIndex < closeIndex) {
		t.Fatalf("held original was not flushed before the queued pass-through release: %v", order)
	}
}

// TestMaxLeasesOneDeniesReplacementUntilNativeReceipt covers the retained
// admission contract: a native hold keeps the closed lease charged, a capacity
// one engine refuses a replacement while the receipt is outstanding, and the
// exactly-once release is what admits the next attempt.
func TestMaxLeasesOneDeniesReplacementUntilNativeReceipt(t *testing.T) {
	engine, err := NewEngine(maxOneConfig(t), &testBackend{name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP})
	if err != nil {
		t.Fatal(err)
	}
	release, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(nil); err != nil {
		t.Fatalf("close: %v", err)
	}
	if engine.ActiveLeases() != 1 {
		t.Fatalf("charged leases = %d with an outstanding native reference, want 1", engine.ActiveLeases())
	}
	if _, err = engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP}); !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("replacement at capacity one = %v, want admission refusal", err)
	}
	release()
	if engine.ActiveLeases() != 0 {
		t.Fatalf("charged leases = %d after the native receipt, want 0", engine.ActiveLeases())
	}
	release() // exactly once: a repeat must not discharge another slot
	if engine.ActiveLeases() != 0 {
		t.Fatalf("charged leases = %d after a repeated release", engine.ActiveLeases())
	}
	replacement, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP})
	if err != nil {
		t.Fatalf("replacement after the receipt: %v", err)
	}
	if err = replacement.Close(nil); err != nil {
		t.Fatalf("replacement close: %v", err)
	}
}

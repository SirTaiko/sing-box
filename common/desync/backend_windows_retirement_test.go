//go:build windows

package desync

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// No driver replacement: a receive-user join and retained-open receipt exercise
// the actual windowsCapture teardown and Lease producer/charge composition.
// Wire delivery is a separate native QA obligation.
func newRetirementCaptureLease(t *testing.T) (*Lease, *windowsCapture) {
	t.Helper()
	c := &windowsCapture{dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	engine, err := NewEngine(maxOneConfig(t), &producerOrderBackend{capture: c})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP})
	if err != nil {
		t.Fatal(err)
	}
	c.lease = lease
	c.releaseHold, err = lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	lease.capture = c
	t.Cleanup(func() { _ = engine.Close() })
	return lease, c
}

func TestWindowsRetainedTailOutlivesCloseGrace(t *testing.T) {
	lease, c := newRetirementCaptureLease(t)
	// This is a receive user's copied original awaiting its terminal disposition,
	// not an empty driver queue. Only this user may release its join reference.
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	c.wg.Add(1)
	var tailTerminal atomic.Bool
	go func() { <-release; tailTerminal.Store(true); c.wg.Done() }()
	start := time.Now()
	if err := lease.Close(nil); !errors.Is(err, ErrLeaseCloseIncomplete) {
		t.Fatalf("bounded Close = %v", err)
	}
	if elapsed := time.Since(start); elapsed < leaseCloseGrace || elapsed > leaseCloseGrace+time.Second {
		t.Fatalf("caller bound: %s", elapsed)
	}
	// Cross the backend's former grace even when Lease and capture timers started
	// in different scheduler turns. Elapsed grace is never a retirement receipt.
	time.Sleep(150 * time.Millisecond)
	select {
	case <-lease.closeDone:
		t.Error("teardown returned while a retained tail still awaited disposition")
	default:
	}
	select {
	case <-lease.captureRetired:
		t.Error("receipt settled before retained tail disposition")
	default:
	}
	phase, _ := lease.producers.state()
	if phase != producerPaused {
		t.Errorf("producer phase=%v before tail terminal", phase)
	}
	if lease.engine.ActiveLeases() != 1 {
		t.Error("tail lost its admission charge")
	}
	if _, err := lease.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP}); !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("replacement admitted: %v", err)
	}
	entered := make(chan bool, 1)
	go func() {
		end, err := lease.BeginEndpointWrite()
		if err != nil {
			entered <- false
			return
		}
		defer end()
		entered <- tailTerminal.Load()
	}()
	select {
	case <-entered:
		t.Fatal("later producer entered before tail terminal")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	if err := lease.WaitClosed(); err != nil {
		t.Fatalf("late WaitClosed = %v", err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatalf("late safe receipt = %v", err)
	}
	select {
	case after := <-entered:
		if !after {
			t.Error("later producer preceded tail")
		}
	case <-time.After(time.Second):
		t.Fatal("later producer not resumed")
	}
	if lease.engine.ActiveLeases() != 0 {
		t.Fatal("late retirement retained charge")
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("repeated Close = %v", err)
	}
}

func TestWindowsPartialOpenLateRetirement(t *testing.T) {
	lease, c := newRetirementCaptureLease(t)
	nativeDone := make(chan struct{})
	c.retainedReceipts = append(c.retainedReceipts, nativeDone)
	result := make(chan error, 1)
	go func() { result <- c.abortOpen() }()
	select {
	case err := <-result:
		if err == nil {
			t.Error("partial rollback returned success before native receipt")
		}
	case <-time.After(captureDrainGrace + time.Second):
		t.Error("partial activation rollback lost its caller bound")
	}
	if lease.engine.ActiveLeases() != 1 {
		t.Error("hidden inner Open lost its charge")
	}
	close(nativeDone)
	if err := lease.Close(nil); err != nil {
		t.Errorf("late close=%v", err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Errorf("late partial-open receipt=%v", err)
	}
	if lease.engine.ActiveLeases() != 0 {
		t.Error("late partial-open charge not retired")
	}
}

func TestWindowsCaptureReceiveFailureRetainsNativeHold(t *testing.T) {
	lease, c := newRetirementCaptureLease(t)
	failure := errors.New("native receive completion query failed")
	c.recordDrainError("outbound", failure)
	if err := lease.Close(nil); !errors.Is(err, failure) {
		t.Fatalf("Close=%v", err)
	}
	if err := lease.WaitCaptureRetired(); !errors.Is(err, failure) {
		t.Fatalf("receipt=%v", err)
	}
	if lease.engine.ActiveLeases() != 1 {
		t.Error("unknown receive lost native ownership")
	}
	if phase, _ := lease.producers.state(); phase != producerPaused {
		t.Errorf("producer resumed: %v", phase)
	}
}

func TestWindowsLateReceiptResumesProducerOnce(t *testing.T) {
	lease, c := newRetirementCaptureLease(t)
	retired := make(chan struct{})
	c.retainedReceipts = append(c.retainedReceipts, retired)
	var releases atomic.Int32
	release := c.releaseHold
	c.releaseHold = func() { releases.Add(1); release() }
	result := make(chan error, 1)
	go func() { result <- lease.Close(nil) }()
	waitProducerCondition(t, "producer paused", func() bool { phase, _ := lease.producers.state(); return phase == producerPaused })
	writer := make(chan error, 1)
	go func() {
		end, err := lease.BeginEndpointWrite()
		if err == nil {
			end()
		}
		writer <- err
	}()
	if err := <-result; !errors.Is(err, ErrLeaseCloseIncomplete) {
		t.Fatalf("Close=%v", err)
	}
	if lease.engine.ActiveLeases() != 1 || releases.Load() != 0 {
		t.Error("retirement charge released before receipt")
	}
	if extra, err := lease.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP}); err == nil {
		_ = extra.Close(nil)
		t.Error("MaxLeases1 did not refuse")
	}
	select {
	case <-writer:
		t.Error("writer resumed before late receipt")
	default:
	}
	close(retired)
	if err := lease.WaitClosed(); err != nil {
		t.Fatal(err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	if err := <-writer; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := lease.Close(nil); err != nil {
			t.Fatal(err)
		}
	}
	if releases.Load() != 1 || lease.engine.ActiveLeases() != 0 {
		t.Error("late retirement not exactly once")
	}
	extra, err := lease.engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP})
	if err != nil {
		t.Fatal(err)
	}
	_ = extra.Close(nil)
}

// TCP native ownership is a preservation control, not a byte-accounting claim.
// The separate inherited TCP budget witness remains failing in the task evidence;
// flow.go is outside this focused Windows/endpoint repair's write scope.
func TestWindowsTCPCancellationRetainsNativeOwnership(t *testing.T) {
	cfg, err := Compile(enabledOption(`{"enabled":true,"limits":{"max_leases":1},"rules":[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["host+0"]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	c := &windowsCapture{dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	engine, err := NewEngine(cfg, &producerOrderBackend{capture: c})
	if err != nil {
		t.Fatal(err)
	}
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP, Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("198.51.100.20:443")})
	if err != nil {
		t.Fatal(err)
	}
	c.lease = lease
	c.releaseHold, err = lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	lease.capture = c
	lease.tcpFlow.primeSemanticTrack()
	first := buildClientHello("blocked.example")[:12]
	packet := buildIPv4TCP(t, first, 1000, tcpFlagACK|tcpFlagPSH)
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	if v := lease.HandlePacket(packet.Raw, DirectionOutbound, nil, func(v Verdict, _ string, _ []byte) { calls.Add(1); close(entered); <-release; close(completed) }); v != VerdictHold {
		t.Fatalf("verdict=%v", v)
	}
	// A callback is already active, rather than merely sitting in the hold list.
	go lease.tcpFlow.flushHeld("test active callback")
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { result <- lease.Close(ctx.Err()) })
	defer stop()
	cancel()
	if err := <-result; !errors.Is(err, ErrLeaseCloseIncomplete) {
		t.Fatalf("cancellation Close=%v", err)
	}
	if engine.ActiveLeases() != 1 {
		t.Error("active callback lost native charge")
	}
	// Semantic Close has not reached producer shutdown while the callback owns
	// the original. A pre-pause real producer request must remain admissible.
	if phase, _ := lease.producers.state(); phase != producerRunning {
		t.Errorf("early producer shutdown=%v", phase)
	}
	select {
	case <-lease.captureRetired:
		t.Error("retirement before callback completion")
	default:
	}
	unblock()
	<-completed
	if err := lease.WaitClosed(); err != nil {
		t.Fatal(err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || engine.heldBytes.Load() != 0 || engine.ActiveLeases() != 0 {
		t.Error("callback/retirement not exactly once")
	}
	_ = engine.Close()
}

func TestWindowsCancellationJoinsActiveUDPHeldCallback(t *testing.T) {
	config := qa519CompileRule(t, `{"network":["udp"],"port":[443],"methods":["fake"],"fake":{"repeats":1,"payloads":[{"protocol":"quic","hex":"01020304"}]}}`, `{"max_leases":1}`)
	h := qa519NewHarness(t, config, "192.0.2.10:40000", "198.51.100.7:443")
	lease := h.lease
	c := &windowsCapture{lease: lease, dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	var err error
	c.releaseHold, err = lease.AcquireNativeHold()
	if err != nil {
		t.Fatal(err)
	}
	lease.capture = c
	head, tail := qa519SplitInitials(t, "cancel.example", 40, qa519DCID(0x79), 1, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	h.onComplete = func(_ string, v Verdict) {
		if v != VerdictPass {
			t.Errorf("disposition=%v", v)
		}
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
	}
	if v := h.send(lease, head, 443); v != VerdictHold {
		t.Fatalf("first verdict=%v", v)
	}
	replayed := make(chan Verdict, 1)
	go func() { replayed <- h.send(lease, tail, 443) }()
	<-entered
	charged := h.engine.heldBytes.Load()
	if charged <= 0 {
		t.Fatal("active UDP callback was not charged")
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	stop := context.AfterFunc(ctx, func() { result <- lease.Close(ctx.Err()) })
	defer stop()
	cancel()
	if err := <-result; !errors.Is(err, ErrLeaseCloseIncomplete) {
		t.Fatalf("cancellation Close=%v", err)
	}
	if h.engine.ActiveLeases() != 1 || h.engine.heldBytes.Load() != charged {
		t.Error("active UDP callback lost native/byte charge")
	}
	if phase, _ := lease.producers.state(); phase != producerRunning {
		t.Errorf("early producer shutdown=%v", phase)
	}
	select {
	case <-lease.captureRetired:
		t.Error("retirement before callback completion")
	default:
	}
	unblock()
	<-replayed
	if err := lease.WaitClosed(); err != nil {
		t.Fatal(err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || h.engine.heldBytes.Load() != 0 || h.engine.ActiveLeases() != 0 {
		t.Error("UDP callbacks/retirement not exactly once")
	}
	t.Logf("active UDP callback retained %d bytes throughout cancellation", charged)
}

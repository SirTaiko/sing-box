//go:build linux

package desync

// Model tests: no kernel object is created, and every case says so.

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

// drainReadGate delays the first entry into the shipped fake transport's
// Receive. It models a receive goroutine that the scheduler does not run again
// until after the configured teardown drain deadline has expired. Delivery,
// deadlines, queue control and verdicts stay entirely with the shipped model:
// the gate never fabricates a packet, a kernel failure or a late enqueue.
type drainReadGate struct {
	*fakeNFQueueConn
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (g *drainReadGate) Receive() ([]netlink.Message, error) {
	g.once.Do(func() { close(g.entered); <-g.resume })
	return g.fakeNFQueueConn.Receive()
}

// TestLinuxCaptureAnswersPrequeuedPacketAfterDelayedReader is the permanent
// regression for the delayed-reader teardown defect: a valid owned packet is
// already queued when Close removes the owned table, and the receive goroutine
// is not scheduled again until the drain deadline has expired. The packet must
// still receive exactly one terminal verdict before the queue is unbound, and
// the pending packet message must never reach the queue-control exchange.
//
// The ordinary control runs the same closure without the scheduling delay.
func TestLinuxCaptureAnswersPrequeuedPacketAfterDelayedReader(t *testing.T) {
	for _, delayed := range []bool{false, true} {
		name := "ordinary-control"
		if delayed {
			name = "reader-delayed-over-drain-window"
		}
		t.Run(name, func(t *testing.T) {
			data := newFakeNFQueueConn("drain", 10, nil)
			seams := installLinuxCaptureSeams(t, data)
			gate := &drainReadGate{fakeNFQueueConn: data, entered: make(chan struct{}), resume: make(chan struct{})}
			gate.portid = 0x51a00001
			openQueueTransport = func(port uint32) (nfqueueTransport, error) { return gate, nil }
			engine, lease := newLinuxCaptureLease(t, 15300)
			if err := lease.StartCapture(); err != nil {
				t.Fatal(err)
			}
			c := lease.capture.(*linuxCapture)
			<-gate.entered
			// The tuple, direction and payload are all owned by this capture.
			packet := buildIPv4TCP(t, []byte("owned-prequeued-payload"), 1000, tcpFlagACK|tcpFlagPSH)
			const id = 901
			if !seams.kernel.deliver(c.queue, fakePacketMessage(c.queue, id, packet.Raw), id) {
				t.Fatal("queue rejected fixture")
			}
			// The packet is on the bound socket before the table is removed.
			if len(data.incoming) != 1 {
				t.Fatal("packet was not queued")
			}
			if !delayed {
				close(gate.resume)
				waitForCondition(t, "ordinary packet verdict", func() bool {
					return len(seams.kernel.verdictsFor(c.queue, id)) == 1
				})
			}
			done := make(chan error, 1)
			go func() { done <- lease.Close(nil) }()
			if delayed {
				waitForCondition(t, "stop deadline armed", func() bool { return data.deadlineCalls.Load() > 0 })
				time.Sleep(3 * queueStopDrain)
				close(gate.resume)
			}
			err := waitWithin(t, "capture close", done)
			verdicts := len(seams.kernel.verdictsFor(c.queue, id))
			remaining := len(data.incoming)
			t.Logf("delayed=%v close_error=%v verdicts=%d unread=%d socket_closed=%d active_leases=%d",
				delayed, err, verdicts, remaining, data.closings(), engine.ActiveLeases())
			if err != nil {
				t.Fatalf("close of an owned capture must not fail: %v", err)
			}
			if verdicts != 1 {
				t.Fatalf("queued-before-close packet verdicts=%d, want exactly one", verdicts)
			}
			if remaining != 0 {
				t.Fatalf("unread packet messages=%d, want 0", remaining)
			}
			if data.closings() != 1 || engine.ActiveLeases() != 0 {
				t.Fatalf("socket_closed=%d active_leases=%d", data.closings(), engine.ActiveLeases())
			}
			if seams.extraConnections() != 0 {
				t.Fatalf("capture opened %d extra connections", seams.extraConnections())
			}
			if got := countQueueCommand(t, data.executedMessages(), c.inQueue, nfqCfgCmdUnbind); got != 1 {
				t.Fatalf("inbound queue unbind count=%d, want 1", got)
			}
			if got := countQueueCommand(t, data.executedMessages(), c.queue, nfqCfgCmdUnbind); got != 0 {
				t.Fatalf("outq unbind count=%d, want 0 (witness is released by its owning socket)", got)
			}
			vi := seams.kernel.eventIndex(func(e fakeKernelEvent) bool { return e.kind == "verdict" && e.id == id })
			ui := seams.kernel.eventIndex(func(e fakeKernelEvent) bool { return e.kind == "unbind" && e.queue == c.inQueue })
			if vi < 0 || ui < 0 || ui < vi {
				t.Fatalf("terminal verdict must precede the unbind: verdict=%d unbind=%d", vi, ui)
			}
		})
	}
}

// drainVerdictGate blocks the first verdict Send of the fake transport. It is
// an API-substitution seam: it proves that native teardown waits for a held
// callback instead of overtaking it.
type drainVerdictGate struct {
	*fakeNFQueueConn
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (g *drainVerdictGate) Send(message netlink.Message) (netlink.Message, error) {
	g.once.Do(func() { close(g.entered); <-g.resume })
	return g.fakeNFQueueConn.Send(message)
}

// TestLinuxCaptureHeldCallbackCompletesBeforeUnbind retains the independent
// held-callback regression on the corrected teardown: an incomplete held
// original keeps the native teardown from unbinding or closing the connection,
// then receives its one accept verdict before the unbind.
func TestLinuxCaptureHeldCallbackCompletesBeforeUnbind(t *testing.T) {
	data := newFakeNFQueueConn("drain-held", 12, nil)
	seams := installLinuxCaptureSeams(t, data)
	gate := &drainVerdictGate{fakeNFQueueConn: data, entered: make(chan struct{}), resume: make(chan struct{})}
	data.portid = 0x51a00002
	openQueueTransport = func(port uint32) (nfqueueTransport, error) { return gate, nil }
	// A transformation rule is required so the first packet is held as an
	// incomplete original instead of passing through immediately.
	config, err := Compile(enabledOption(`{"enabled":true,"capture":{"linux":{"qnum":15301}},"rules":[{"network":["tcp"],"port":[443],"methods":["multisplit"],"multisplit":{"split_pos":["5"]}}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
		releaseQnum(15301)
	})
	lease, err := engine.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP, Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.1:40000"))
	if err = lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	lease.tcpFlow.primeSemanticTrack()
	c := lease.capture.(*linuxCapture)
	<-data.receiving
	packet := buildIPv4TCP(t, buildClientHello("held.example")[:8], 3000, tcpFlagACK|tcpFlagPSH)
	if !seams.kernel.deliver(c.queue, fakePacketMessage(c.queue, 902, packet.Raw), 902) {
		t.Fatal("delivery rejected")
	}
	waitForCondition(t, "held original", func() bool {
		lease.tcpFlow.mu.Lock()
		defer lease.tcpFlow.mu.Unlock()
		return len(lease.tcpFlow.holds) == 1
	})
	leaseDone, engineDone := make(chan error, 1), make(chan error, 1)
	go func() { leaseDone <- lease.Close(nil) }()
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("held callback not entered")
	}
	go func() { engineDone <- engine.Close() }()
	if data.closings() != 0 || countQueueCommand(t, data.executedMessages(), c.queue, nfqCfgCmdUnbind) != 0 {
		t.Fatal("native teardown overtook held callback")
	}
	close(gate.resume)
	if err = waitWithin(t, "lease close", leaseDone); err != nil {
		t.Fatal(err)
	}
	if err = waitWithin(t, "engine close", engineDone); err != nil {
		t.Fatal(err)
	}
	v := seams.kernel.verdictsFor(c.queue, 902)
	if len(v) != 1 || v[0].verdict != nfqueueVerdictAccept {
		t.Fatalf("held terminal disposition=%v", v)
	}
	vi := seams.kernel.eventIndex(func(e fakeKernelEvent) bool { return e.kind == "verdict" && e.id == 902 })
	ui := seams.kernel.eventIndex(func(e fakeKernelEvent) bool { return e.kind == "unbind" && e.queue == c.inQueue })
	if vi < 0 || ui <= vi || engine.ActiveLeases() != 0 || data.closings() != 1 {
		t.Fatalf("invalid teardown order verdict=%d unbind=%d", vi, ui)
	}
	t.Logf("held verdict index=%d before unbind=%d; one close; active_leases=0", vi, ui)
}

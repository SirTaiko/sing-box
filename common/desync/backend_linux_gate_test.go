//go:build linux

package desync

// The Linux capture participates in the same ordered close as the Windows one:
// the lease publishes the fence before its closed flag, quiesce waits for the
// packets already inside the engine, and post-fence packets are answered
// pass-through only after the held originals were released.

import (
	"testing"
	"time"
)

// TestLinuxCaptureHooksUseTheOrderedCloseGate proves the three hooks the lease
// teardown depends on are wired to the shared dispatch gate: fencing refuses new
// dispatch, quiesce returns once nothing is in flight, and pass-through stays
// blocked until the release. It uses no queue, nftables rule or driver call.
func TestLinuxCaptureHooksUseTheOrderedCloseGate(t *testing.T) {
	capture := &linuxCapture{dispatch: newCaptureDispatchGate()}

	if !capture.dispatch.beginDispatch() {
		t.Fatal("the gate of a fresh capture refused dispatch")
	}
	quiesced := make(chan error, 1)
	go func() { quiesced <- capture.Quiesce() }()
	select {
	case err := <-quiesced:
		t.Fatalf("quiesce returned %v with one packet still inside the engine", err)
	case <-time.After(20 * time.Millisecond):
	}

	capture.FenceDispatch()
	capture.dispatch.endDispatch()
	select {
	case err := <-quiesced:
		if err != nil {
			t.Fatalf("quiesce: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("quiesce did not return after the last packet resolved")
	}
	if capture.dispatch.beginDispatch() {
		capture.dispatch.endDispatch()
		t.Fatal("a packet delivered after the fence entered the semantic engine")
	}

	// The post-fence pass-through must stay blocked until the release.
	passed := make(chan struct{})
	go func() {
		capture.dispatch.awaitPassThrough()
		close(passed)
	}()
	select {
	case <-passed:
		t.Fatal("post-fence packet passed before the lease release")
	case <-time.After(20 * time.Millisecond):
	}
	capture.AllowPassThrough()
	select {
	case <-passed:
	case <-time.After(2 * time.Second):
		t.Fatal("post-fence packet was never released")
	}
}

// TestLinuxCaptureCloseReleasesPassThrough proves a capture closed without a
// lease-ordered flush cannot leave its receive loop waiting for a release that
// never comes.
func TestLinuxCaptureCloseReleasesPassThrough(t *testing.T) {
	capture := &linuxCapture{dispatch: newCaptureDispatchGate(), done: make(chan struct{})}
	capture.FenceDispatch()
	done := make(chan struct{})
	go func() {
		capture.dispatch.awaitPassThrough()
		close(done)
	}()
	// Close performs the real teardown of an unstarted capture; it must release
	// the pass-through before it joins anything.
	if err := capture.Close(); err != nil {
		t.Fatalf("close of an unstarted capture: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close left the receive loop blocked on pass-through")
	}
}

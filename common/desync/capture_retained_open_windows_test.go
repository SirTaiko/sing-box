//go:build windows

package desync

// ARCH-03B regression: a failed inner windivert.Open can leave a native
// device/event behind. The capture must keep the original admission charge until
// that hidden owner proves retirement, instead of discharging it because the
// failed handle was never stored in the opened-handle list.

import (
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/windivert"
)

// TestCaptureKeepsChargeForUnprovenInnerOpen proves the retained receipt of a
// failed inner Open is part of the capture's retirement proof: the admission
// reference is not discharged while the receipt is open, and the autonomous
// late owner releases it exactly once after the receipt closes.
func TestCaptureKeepsChargeForUnprovenInnerOpen(t *testing.T) {
	retired := make(chan struct{})
	released := make(chan struct{}, 1)
	capture := &windowsCapture{
		done:     make(chan struct{}),
		dispatch: newCaptureDispatchGate(),
		releaseHold: func() {
			released <- struct{}{}
		},
	}
	openErr := windivert.NewRetainedOpenError(errors.Join(
		errors.New("windivert: startup ioctl: refused"),
		errors.New("windivert: close: retirement deferred")), retired)
	if recorded := capture.recordRetainedOpen(openErr); recorded == nil {
		t.Fatal("the failed open error was dropped")
	}
	if len(capture.retainedReceipts) != 1 {
		t.Fatalf("retained receipts = %d, want the hidden cleanup owner", len(capture.retainedReceipts))
	}
	if capture.handlesRetired(20 * time.Millisecond) {
		t.Fatal("retirement was certified while the hidden native resource was still alive")
	}
	select {
	case <-released:
		t.Fatal("the admission charge was discharged before the hidden receipt")
	default:
	}

	loopsDone := make(chan struct{})
	close(loopsDone)
	releaseDone := make(chan struct{})
	go func() {
		capture.releaseWhenRetired(loopsDone)
		close(releaseDone)
	}()
	select {
	case <-releaseDone:
		t.Fatal("the late retirement owner released the charge before the receipt")
	case <-time.After(20 * time.Millisecond):
	}

	close(retired)
	select {
	case <-releaseDone:
	case <-time.After(2 * time.Second):
		t.Fatal("the late retirement owner never observed the receipt")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("the admission reference was not discharged after the receipt")
	}
	if !capture.handlesRetired(time.Second) {
		t.Fatal("retirement is still unproven after the receipt closed")
	}
}

// TestCaptureReleasesChargeForProvenRollback is the control: an ordinary failed
// Open (rollback already proven) adds no receipt, so the capture's retirement
// proof is complete and the charge may be discharged at once.
func TestCaptureReleasesChargeForProvenRollback(t *testing.T) {
	released := make(chan struct{}, 1)
	capture := &windowsCapture{
		done:        make(chan struct{}),
		dispatch:    newCaptureDispatchGate(),
		releaseHold: func() { released <- struct{}{} },
	}
	if recorded := capture.recordRetainedOpen(errors.New("windivert: driver magic mismatch")); recorded == nil {
		t.Fatal("the activation error was dropped")
	}
	if len(capture.retainedReceipts) != 0 {
		t.Fatal("an ordinary activation failure added a cleanup receipt")
	}
	if !capture.handlesRetired(time.Millisecond) {
		t.Fatal("a proven rollback did not certify retirement")
	}
	capture.releaseNative()
	select {
	case <-released:
	default:
		t.Fatal("the proven rollback did not discharge the admission reference")
	}
}

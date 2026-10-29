//go:build windows

package windivert

// Windows-only completion/retirement regressions. They exercise the production
// completion classifier and the quarantine transition without needing a
// driver: the driver-facing success/cancel race is covered by the native lab
// matrix, while these pin the source-level distinction the native matrix relies
// on.

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestUnprovenCompletionClassification(t *testing.T) {
	unproven := []error{
		windows.ERROR_IO_INCOMPLETE,
		windows.ERROR_INVALID_HANDLE,
		windows.ERROR_INVALID_PARAMETER,
		windows.ERROR_NOT_FOUND,
	}
	for _, err := range unproven {
		if !unprovenCompletionStatus(err) {
			t.Fatalf("%v must leave ownership unproven", err)
		}
	}
	// A terminal operation status is the request's own completion: the lane
	// memory may be reused and the count reported with it stays authoritative.
	terminal := []error{
		windows.ERROR_OPERATION_ABORTED, // canceled request
		windows.ERROR_ACCESS_DENIED,     // driver refused the operation
		windows.ERROR_HOST_UNREACHABLE,  // driver completed with a network status
		errors.New("custom terminal status"),
	}
	for _, err := range terminal {
		if unprovenCompletionStatus(err) {
			t.Fatalf("%v must be treated as a terminal completion", err)
		}
	}
}

// TestQuarantinedLaneKeepsItsCharge covers the failed-query path of the
// production handle state machine: an unproven completion must not rename the
// lane reusable, and the lifecycle registration must stay charged so Close
// defers retirement and Done stays open.
func TestQuarantinedLaneKeepsItsCharge(t *testing.T) {
	var retired bool
	handle := &Handle{}
	handle.gate = newIOLifecycle(20*time.Millisecond, func(any) {}, func() error {
		retired = true
		return nil
	})
	lane := &ioLane{event: windows.Handle(1)}
	if err := handle.beginLane(lane); err != nil {
		t.Fatalf("registration: %v", err)
	}
	// The submission returned an unproven completion query.
	handle.finishLane(lane, false)
	if !lane.quarantined {
		t.Fatal("an unproven completion did not quarantine the lane")
	}
	if err := handle.beginLane(lane); err == nil {
		t.Fatal("a quarantined lane accepted a new operation")
	}
	err := handle.Close()
	if err == nil {
		t.Fatal("close reported success although the lane never produced a terminal receipt")
	}
	if retired {
		t.Fatal("native resources were retired under an unproven completion")
	}
	select {
	case <-handle.Done():
		t.Fatal("Done closed although the lane ownership is unproven")
	default:
	}
}

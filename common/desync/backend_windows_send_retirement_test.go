//go:build windows

package desync

import (
	"errors"
	"testing"
)

// The scripted native-boundary replay additionally drives Send's real caller
// (including n=-1 and short counts). This test pins the capture-owned receipt
// separately from diagnostics without changing any production native call.
func TestWindowsSendDiagnosticAndRetirementAreSeparate(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(map[bool]string{false: "terminal", true: "unknown"}[unknown], func(t *testing.T) {
			lease, c := newRetirementCaptureLease(t)
			failure := errors.New("send diagnostic")
			reported := failure
			if unknown {
				reported = errors.Join(failure, errCaptureSendIncomplete)
			}
			c.recordSendError(reported)
			if err := lease.Close(nil); !errors.Is(err, failure) {
				t.Fatalf("Close lost diagnostic: %v", err)
			}
			if err := lease.WaitClosed(); !errors.Is(err, failure) {
				t.Fatalf("WaitClosed lost diagnostic: %v", err)
			}
			if err := lease.Err(); !errors.Is(err, failure) {
				t.Fatalf("Err lost diagnostic: %v", err)
			}
			receipt := lease.WaitCaptureRetired()
			if unknown {
				if receipt == nil || lease.engine.ActiveLeases() != 1 {
					t.Error("unknown completion declared safe/discharged")
				}
				if phase, _ := lease.producers.state(); phase != producerPaused {
					t.Errorf("producer resumed: %v", phase)
				}
			} else {
				if receipt != nil || lease.engine.ActiveLeases() != 0 {
					t.Errorf("terminal error prevented safe retirement: %v", receipt)
				}
				end, err := lease.BeginEndpointWrite()
				if err != nil {
					t.Fatal(err)
				}
				end()
			}
		})
	}
}

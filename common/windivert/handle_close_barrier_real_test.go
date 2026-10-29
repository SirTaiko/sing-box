//go:build windows && !with_external_windivert

package windivert

// Deterministic ARCH-01 regression on the real shipped Handle and the authentic
// driver. The hook holds the exact window between lifecycle registration and
// DeviceIoControl, so Close's cancellation provably runs while the kernel has no
// request yet; without the post-submission arming handshake that cancellation is
// lost and the receive (with no traffic to rescue it) never completes.

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestRealCloseWinsDuringRegistration(t *testing.T) {
	flow := newUDPFlow(t)
	handle := openReal(t, outboundFlowFilter(t, flow), 0)

	atBarrier := make(chan struct{})
	releaseSubmission := make(chan struct{})
	var hookCalls atomic.Int32
	handleTestBeforeSubmit = func() {
		if hookCalls.Add(1) == 1 {
			close(atBarrier)
			<-releaseSubmission
		}
	}
	defer func() { handleTestBeforeSubmit = nil }()

	received := make(chan error, 1)
	go func() {
		buffer := make([]byte, MTUMax)
		_, _, err := handle.Recv(buffer)
		received <- err
	}()
	select {
	case <-atBarrier:
	case <-time.After(realWait):
		t.Fatal("the receive never registered")
	}
	// Close runs while the request is registered but not submitted: its
	// CancelIoEx cannot find anything yet and must not be the only attempt.
	closeErr := handle.Close()
	require.Error(t, closeErr, "close must report the deferred retirement")
	select {
	case <-handle.Done():
		t.Fatal("Done closed although the receive was never submitted or canceled")
	case <-time.After(100 * time.Millisecond):
	}
	// Let the lane submit. It must observe the closed gate and cancel its own
	// request, which is the only cancellation that can reach the kernel now.
	close(releaseSubmission)
	select {
	case err := <-received:
		require.Error(t, err, "the pending receive must complete as canceled, not hang")
		require.True(t, errors.Is(err, windows.ERROR_OPERATION_ABORTED),
			"receive error = %v, want ERROR_OPERATION_ABORTED", err)
	case <-time.After(realWait):
		t.Fatal("the submitted receive never produced a terminal receipt")
	}
	select {
	case <-handle.Done():
	case <-time.After(realWait):
		t.Fatal("retirement never completed after the terminal receipt")
	}
	require.NoError(t, handle.Close(), "repeated close must observe the completed retirement")
}

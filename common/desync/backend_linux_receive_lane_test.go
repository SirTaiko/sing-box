//go:build linux

package desync

// Permanent composed regressions for the real capture receive lane
// (S26-NFQUEUE-UNALIGNED-PACKET error ownership). A receive/parser failure must
// become a durable Lease diagnostic and an ownership-safe outcome instead of a
// silently retired goroutine. The ordinary stop interruption (the read deadline
// armed by stopReceive) must stay distinguishable and must not poison the
// lease. Model tests: the production linuxCapture/loop, the shipped fake
// netlink transport and the hermetic anchors are the composed objects; no
// kernel object is created.

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
)

var errModelNativeUnaligned = errors.New("netlink receive: input data is not properly aligned for netlink message")

// laneErrorTransport returns one configured receive error, then delegates to
// the shipped fake transport. The first Receive blocks until the test released
// it, so a queued owned packet can be placed before the lane fails.
type laneErrorTransport struct {
	*fakeNFQueueConn
	err     error
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	fired   atomic.Bool
}

func (f *laneErrorTransport) Receive() ([]netlink.Message, error) {
	if f.fired.Load() {
		return f.fakeNFQueueConn.Receive()
	}
	f.once.Do(func() { close(f.entered) })
	<-f.release
	f.fired.Store(true)
	return nil, f.err
}

// openReceiveLaneCapture opens one production capture over the fake transport.
// When wrap is non-nil its result replaces the first transport returned by the
// seam dialer (the wrapper embeds the same fake connection).
func openReceiveLaneCapture(t *testing.T, queue int, wrap func(*fakeNFQueueConn) nfqueueTransport) (*Engine, *Lease, *linuxCapture, *fakeNFQueueConn, *linuxCaptureSeams) {
	t.Helper()
	data := newFakeNFQueueConn("receive-lane", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	dial := openQueueTransport
	var replacement nfqueueTransport
	if wrap != nil {
		replacement = wrap(data)
	}
	openQueueTransport = func(port uint32) (nfqueueTransport, error) {
		opened, err := dial(port)
		if err != nil {
			return nil, err
		}
		if replacement != nil {
			return replacement, nil
		}
		return opened, nil
	}
	engine, lease := newLinuxCaptureLease(t, queue)
	if err := lease.StartCapture(); err != nil {
		t.Fatalf("open capture: %v", err)
	}
	return engine, lease, lease.capture.(*linuxCapture), data, seams
}

func waitLaneExit(t *testing.T, capture *linuxCapture) {
	t.Helper()
	waitForCondition(t, "receive lane exit", func() bool {
		select {
		case <-capture.done:
			return true
		default:
			return false
		}
	})
}

// TestLinuxCaptureReceiveErrorIsDurableAndDrains decides the two ownership
// halves in one composed path: the transport error is visible in Lease.Err
// before Close, the already queued owned original is still answered, and a
// proven retirement releases the charge instead of pretending the lane never
// failed.
func TestLinuxCaptureReceiveErrorIsDurableAndDrains(t *testing.T) {
	var wrapper *laneErrorTransport
	engine, lease, capture, data, seams := openReceiveLaneCapture(t, 15340, func(conn *fakeNFQueueConn) nfqueueTransport {
		wrapper = &laneErrorTransport{
			fakeNFQueueConn: conn,
			err:             errModelNativeUnaligned,
			entered:         make(chan struct{}),
			release:         make(chan struct{}),
		}
		return wrapper
	})
	select {
	case <-wrapper.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}
	// The kernel holds one owned original when the lane fails. The failing
	// Receive must not consume it.
	const id = 921
	packet := buildIPv4TCP(t, []byte("native-unaligned-receive"), 1000, tcpFlagACK|tcpFlagPSH)
	if !seams.kernel.deliver(capture.queue, fakePacketMessage(capture.queue, id, packet.Raw), id) {
		t.Fatal("kernel rejected fixture")
	}
	close(wrapper.release)
	waitLaneExit(t, capture)

	first := lease.Err()
	if first == nil || !errors.Is(first, errModelNativeUnaligned) {
		t.Fatalf("Lease.Err before close = %v, want the durable receive error", first)
	}
	if !strings.Contains(first.Error(), "receive NFQUEUE datagram") {
		t.Fatalf("Lease.Err = %v, want the receive-lane diagnostic", first)
	}
	// Repeated receipts of the same diagnostic stay stable and non-nil.
	if second := lease.Err(); second == nil || second.Error() != first.Error() {
		t.Fatalf("repeated Lease.Err = %v, want the same durable error %v", second, first)
	}
	if got := len(seams.kernel.verdictsFor(capture.queue, id)); got != 0 {
		t.Fatalf("failed lane issued %d verdicts before teardown", got)
	}

	// Teardown drains the pending owned original and proves the native
	// retirement, so the charge is released; the durable diagnostic survives.
	if err := lease.Close(nil); err != nil {
		t.Fatalf("Close with a drainable pending original: %v", err)
	}
	if err := lease.WaitClosed(); err != nil {
		t.Fatalf("WaitClosed: %v", err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatalf("WaitCaptureRetired: %v", err)
	}
	if got := len(seams.kernel.verdictsFor(capture.queue, id)); got != 1 {
		t.Fatalf("pending original verdicts=%d, want exactly one", got)
	}
	if got := seams.kernel.verdictsFor(capture.queue, id)[0].verdict; got != nfqueueVerdictAccept {
		t.Fatalf("pending original verdict=%d, want accept", got)
	}
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after a proven retirement = %d, want 0", got)
	}
	if repeated := lease.Err(); repeated == nil || repeated.Error() != first.Error() {
		t.Fatalf("Lease.Err after close = %v, want the durable receive error", repeated)
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("repeated Close = %v, want idempotent success", err)
	}
	if data.closings() != 1 {
		t.Fatalf("transport closes=%d, want exactly one", data.closings())
	}
}

// TestLinuxCaptureParseFailureRetainsCharge pins the other ownership half: a
// malformed native message consumes the userspace datagram but leaves the
// kernel original unverdicted, so the retirement must fail, keep the charge and
// publish a non-positive capture-retired receipt while the Lease diagnostic is
// already durable.
func TestLinuxCaptureParseFailureRetainsCharge(t *testing.T) {
	engine, lease, capture, data, seams := openReceiveLaneCapture(t, 15341, nil)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}
	const id = 922
	// A queue packet whose attribute area is a truncated nlattr: the queue
	// identity is valid, the attribute list is not decodable.
	malformed := netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(3 << 8)},
		Data: []byte{1, 0, byte(capture.queue >> 8), byte(capture.queue),
			0x01, 0x00, 0x08, 0x00, 0xaa, 0xbb},
	}
	if !seams.kernel.deliver(capture.queue, malformed, id) {
		t.Fatal("kernel rejected fixture")
	}
	waitLaneExit(t, capture)

	first := lease.Err()
	if first == nil || !strings.Contains(first.Error(), "malformed message batch") {
		t.Fatalf("Lease.Err before close = %v, want the durable parser error", first)
	}
	if len(seams.kernel.verdictsFor(capture.queue, id)) != 0 {
		t.Fatal("malformed packet received a verdict")
	}

	closeErr := lease.Close(nil)
	if closeErr == nil || !strings.Contains(closeErr.Error(), "still holds 1 packets") {
		t.Fatalf("Close = %v, want the retained-original rejection", closeErr)
	}
	if err := lease.WaitClosed(); err == nil || err.Error() != closeErr.Error() {
		t.Fatalf("WaitClosed = %v, want the same teardown error", err)
	}
	if err := lease.WaitCaptureRetired(); err == nil {
		t.Fatal("positive capture-retired receipt published for a failed retirement")
	}
	if repeated := lease.Close(nil); repeated == nil || repeated.Error() != closeErr.Error() {
		t.Fatalf("repeated Close = %v, want the same failure", repeated)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after a retained original = %d, want 1", got)
	}
	if err := lease.Err(); err == nil || !strings.Contains(err.Error(), "malformed message batch") {
		t.Fatalf("Lease.Err after close = %v, want the durable parser error", err)
	}
	if got := len(seams.kernel.verdictsFor(capture.queue, id)); got != 0 {
		t.Fatalf("retained original verdicts=%d, want 0", got)
	}
	// The first Engine.Close reports the retained lease; the second is engine
	// idempotence only. Neither turns the failure into a retirement.
	if err := engine.Close(); err == nil {
		t.Fatal("first Engine.Close reported success over a retained lease")
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("second Engine.Close = %v, want engine idempotence nil", err)
	}
	if got := engine.ActiveLeases(); got != 1 {
		t.Fatalf("active leases after repeated Engine.Close = %d, want the retained slot", got)
	}
}

// TestLinuxCaptureStopDeadlineIsNotAReceiveFailure is the graceful-stop control:
// the intentional read-deadline interruption armed by stopReceive must retire
// the lane without a Lease diagnostic.
func TestLinuxCaptureStopDeadlineIsNotAReceiveFailure(t *testing.T) {
	engine, lease, _, data, seams := openReceiveLaneCapture(t, 15342, nil)
	select {
	case <-data.receiving:
	case <-time.After(5 * time.Second):
		t.Fatal("capture loop never entered Receive")
	}
	if err := lease.Close(nil); err != nil {
		t.Fatalf("graceful Close: %v", err)
	}
	if err := lease.WaitClosed(); err != nil {
		t.Fatalf("WaitClosed: %v", err)
	}
	if err := lease.WaitCaptureRetired(); err != nil {
		t.Fatalf("WaitCaptureRetired: %v", err)
	}
	if err := lease.Err(); err != nil {
		t.Fatalf("Lease.Err after a graceful stop = %v, want nil", err)
	}
	if data.deadlineCalls.Load() == 0 {
		t.Fatal("stop did not arm the owning-transport read deadline")
	}
	if got := engine.ActiveLeases(); got != 0 {
		t.Fatalf("active leases after graceful close = %d, want 0", got)
	}
	if seams.extraConnections() != 0 {
		t.Fatalf("capture opened %d extra connections", seams.extraConnections())
	}
}

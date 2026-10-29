package direct

// ARCH-03A regression: a returned transport that owns a packet lease must keep
// the exclusive native endpoint together with the capture until the lease
// teardown (and therefore the capture admission boundary) is proven. A bounded
// non-success from the lease must not be followed by an unconditional socket
// close, because a still-live filter can admit the old tuple and a foreign
// socket that reuses the port would then be captured as this attempt's flow.

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
)

// endpointFenceCapture blocks the ordered capture close before it publishes any
// release, which is what makes the lease's bounded close report an incomplete
// teardown.
type endpointFenceCapture struct {
	quiesceEntered chan struct{}
	release        chan struct{}
	closed         atomic.Int32

	enterOnce   sync.Once
	releaseOnce sync.Once
}

func newEndpointFenceCapture(blocking bool) *endpointFenceCapture {
	capture := &endpointFenceCapture{quiesceEntered: make(chan struct{}), release: make(chan struct{})}
	if !blocking {
		capture.releaseNow()
	}
	return capture
}

// releaseNow unblocks the ordered close; it is idempotent so the test and its
// cleanup can both call it.
func (c *endpointFenceCapture) releaseNow() {
	c.releaseOnce.Do(func() { close(c.release) })
}

func (c *endpointFenceCapture) Quiesce() error {
	c.enterOnce.Do(func() { close(c.quiesceEntered) })
	<-c.release
	return nil
}

func (c *endpointFenceCapture) AllowPassThrough() {}

func (c *endpointFenceCapture) Close() error {
	c.closed.Add(1)
	return nil
}

type endpointFenceBackend struct {
	capture *endpointFenceCapture
}

func (b *endpointFenceBackend) Name() string { return "endpoint-fence" }

func (b *endpointFenceBackend) Open(*desync.Lease) (desync.Capture, error) { return b.capture, nil }

// newEndpointFenceLease builds one real packet-enabled lease whose capture is
// the blocking double. It crosses the real StartCapture/admission path.
func newEndpointFenceLease(t *testing.T, blocking bool) (*desync.Lease, *endpointFenceCapture) {
	t.Helper()
	config, err := desync.Compile(&option.DirectDesyncOptions{
		Rules: []option.DirectDesyncRule{{
			Name:       "packet",
			Network:    []string{"tcp"},
			Port:       []uint16{443},
			Methods:    []string{"multisplit"},
			MultiSplit: &option.DirectDesyncSplitOptions{SplitPos: []string{"1"}},
		}},
	}, "")
	if err != nil {
		t.Fatalf("desync.Compile: %v", err)
	}
	config.Limits.MaxLeases = 2
	capture := newEndpointFenceCapture(blocking)
	engine, err := desync.NewEngine(config, &endpointFenceBackend{capture: capture})
	if err != nil {
		t.Fatalf("desync.NewEngine: %v", err)
	}
	t.Cleanup(func() {
		capture.releaseNow() // unblock a teardown the test deliberately held
		_ = engine.Close()
	})
	lease, err := engine.NewAttempt(desync.Intent{
		Family:      desync.FamilyIPv4,
		Transport:   desync.TransportTCP,
		Source:      netip.MustParseAddrPort("192.0.2.10:40000"),
		Destination: netip.MustParseAddrPort("198.51.100.20:443"),
	})
	if err != nil {
		t.Fatalf("NewAttempt: %v", err)
	}
	lease.SetLocalAddress(netip.MustParseAddrPort("192.0.2.10:40000"))
	if err = lease.StartCapture(); err != nil {
		t.Fatalf("StartCapture: %v", err)
	}
	return lease, capture
}

// waitEndpointClosed polls the fixture's close counter inside a bound.
func waitEndpointClosed(t *testing.T, closed *atomic.Int32) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for closed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the retained endpoint was never retired after the proven teardown")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestEndpointCloseKeepsSocketUntilProvenFence drives the three actual returned
// transports (TCP conn, connected UDP conn, UDP listener). With a teardown that
// outlives the caller bound, Close must return the bounded non-success, must not
// have closed the native endpoint, and must retire it only after the teardown
// receipt. The non-blocking control proves the ordinary path still closes the
// endpoint inside the same call.
func TestEndpointCloseKeepsSocketUntilProvenFence(t *testing.T) {
	t.Run("tcp-conn", func(t *testing.T) {
		t.Parallel()
		lease, capture := newEndpointFenceLease(t, true)
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		endpoint := &udpLifetimeConn{Conn: client}
		wrapped := &leaseConn{Conn: endpoint, lease: lease}
		start := time.Now()
		closeErr := wrapped.Close()
		if !errors.Is(closeErr, desync.ErrLeaseCloseIncomplete) {
			t.Fatalf("close error = %v, want the bounded incomplete result", closeErr)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("close took %s, the caller bound is not preserved", elapsed)
		}
		if endpoint.closes.Load() != 0 {
			t.Fatal("TCP endpoint was released although the lease teardown was unproven")
		}
		capture.releaseNow()
		waitEndpointClosed(t, &endpoint.closes)
		if again := wrapped.Close(); !errors.Is(again, desync.ErrLeaseCloseIncomplete) {
			t.Fatalf("repeated close = %v, want the same bounded result", again)
		}
		if endpoint.closes.Load() != 1 {
			t.Fatalf("TCP endpoint closes = %d, want exactly one", endpoint.closes.Load())
		}
	})

	t.Run("connected-udp", func(t *testing.T) {
		t.Parallel()
		lease, capture := newEndpointFenceLease(t, true)
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		endpoint := &udpLifetimeConn{Conn: client}
		wrapped := &leaseUDPConn{Conn: endpoint, lease: lease}
		if closeErr := wrapped.Close(); !errors.Is(closeErr, desync.ErrLeaseCloseIncomplete) {
			t.Fatalf("close error = %v, want the bounded incomplete result", closeErr)
		}
		if endpoint.closes.Load() != 0 {
			t.Fatal("connected UDP endpoint was released although the lease teardown was unproven")
		}
		capture.releaseNow()
		waitEndpointClosed(t, &endpoint.closes)
		if endpoint.closes.Load() != 1 {
			t.Fatalf("connected UDP endpoint closes = %d, want exactly one", endpoint.closes.Load())
		}
	})

	t.Run("udp-listener", func(t *testing.T) {
		t.Parallel()
		lease, capture := newEndpointFenceLease(t, true)
		endpoint := &udpLifetimePacket{}
		wrapped := &leasePacketConn{PacketConn: endpoint, lease: lease}
		if closeErr := wrapped.Close(); !errors.Is(closeErr, desync.ErrLeaseCloseIncomplete) {
			t.Fatalf("close error = %v, want the bounded incomplete result", closeErr)
		}
		if endpoint.closes.Load() != 0 {
			t.Fatal("UDP listener was released although the lease teardown was unproven")
		}
		capture.releaseNow()
		waitEndpointClosed(t, &endpoint.closes)
		if endpoint.closes.Load() != 1 {
			t.Fatalf("UDP listener closes = %d, want exactly one", endpoint.closes.Load())
		}
	})

	t.Run("proven-close-control", func(t *testing.T) {
		t.Parallel()
		lease, _ := newEndpointFenceLease(t, false)
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		endpoint := &udpLifetimeConn{Conn: client}
		wrapped := &leaseConn{Conn: endpoint, lease: lease}
		if closeErr := wrapped.Close(); closeErr != nil {
			t.Fatalf("ordinary close = %v, want success", closeErr)
		}
		if endpoint.closes.Load() != 1 {
			t.Fatalf("ordinary close released the endpoint %d times, want one", endpoint.closes.Load())
		}
	})
}

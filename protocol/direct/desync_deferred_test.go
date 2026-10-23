package direct

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// TestWrapPendingTCPOnce verifies the accepted signature: the direct bridge is
// the only implementation and applies the compiled stream wrapper exactly once
// to the deferred logical connection, before any user write.
func TestWrapPendingTCPOnce(t *testing.T) {
	fake := &fakeStreamAttachment{}
	hook := &desyncHook{stream: fake, lifetime: context.Background()}
	intent := dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.7"), 443),
	}
	pending := &noopConn{}
	wrapped, err := hook.WrapPendingTCP(context.Background(), intent, pending)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped == nil {
		t.Fatal("pending wrapper returned nil")
	}
	prepares, wraps := fake.counts()
	if wraps != 1 {
		t.Fatalf("stream wraps = %d, want exactly 1", wraps)
	}
	if prepares != 0 {
		t.Fatalf("pending wrap must not prepare a socket: %d", prepares)
	}
}

// TestWrapPendingTCPPacketOnly verifies the packet-only case has no stream
// wrapper: capture is attached to the actual socket through the attempt lease.
func TestWrapPendingTCPPacketOnly(t *testing.T) {
	hook := &desyncHook{lifetime: context.Background()}
	pending := &noopConn{}
	wrapped, err := hook.WrapPendingTCP(context.Background(), dialer.AttemptIntent{Network: "tcp"}, pending)
	if err != nil {
		t.Fatal(err)
	}
	if wrapped != pending {
		t.Fatal("packet-only pending connection must be returned unchanged")
	}
}

// TestDeferredAttachDoesNotWrapStreamTwice is the regression for the internal
// Deferred intent bit: the actual attempt transfers packet-lease ownership but
// never applies the stream wrapper a second time. The same facts on a
// non-deferred attempt keep the ordinary single wrap.
func TestDeferredAttachDoesNotWrapStreamTwice(t *testing.T) {
	intent := dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.7"), 443),
	}
	fake := &fakeStreamAttachment{}
	hook := &desyncHook{stream: fake, lifetime: context.Background()}
	leaseValue, err := hook.NewAttempt(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	deferred := leaseValue.(*desyncLease)
	deferred.intent.Deferred = true
	if _, err = deferred.AttachConn(&noopConn{}); err != nil {
		t.Fatal(err)
	}
	if _, wraps := fake.counts(); wraps != 0 {
		t.Fatalf("deferred attach applied the stream wrapper %d times, want 0", wraps)
	}

	eagerFake := &fakeStreamAttachment{}
	eagerHook := &desyncHook{stream: eagerFake, lifetime: context.Background()}
	eagerValue, err := eagerHook.NewAttempt(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = eagerValue.AttachConn(&noopConn{}); err != nil {
		t.Fatal(err)
	}
	if _, wraps := eagerFake.counts(); wraps != 1 {
		t.Fatalf("eager attach stream wraps = %d, want exactly 1", wraps)
	}
}

// TestDeferredIntentIsInternal ensures the deferred bit never appears as a user
// option: it is only set by the dialer behind the pending facade.
func TestDeferredIntentDefaultsFalse(t *testing.T) {
	if (dialer.AttemptIntent{}).Deferred {
		t.Fatal("AttemptIntent.Deferred must default to false")
	}
}

type noopConn struct{}

func (c *noopConn) Read([]byte) (int, error)         { return 0, nil }
func (c *noopConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *noopConn) Close() error                     { return nil }
func (c *noopConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *noopConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *noopConn) SetDeadline(time.Time) error      { return nil }
func (c *noopConn) SetReadDeadline(time.Time) error  { return nil }
func (c *noopConn) SetWriteDeadline(time.Time) error { return nil }

// deferredSplitPending is the hermetic dialer-side model used by the bridge
// end-to-end test: no socket exists until the first write, that write is the
// single owned attempt carrying the transformed TFO payload, and later writes
// use the established connection.
type deferredSplitPending struct {
	mu          sync.Mutex
	established *deferredSplitEstablished
	activations int
	payload     []byte
}

func (c *deferredSplitPending) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.established == nil {
		c.established = &deferredSplitEstablished{}
		c.activations++
		c.payload = append([]byte(nil), p...)
		c.mu.Unlock()
		return len(p), nil
	}
	established := c.established
	c.mu.Unlock()
	return established.Write(p)
}

func (c *deferredSplitPending) Read([]byte) (int, error)         { return 0, nil }
func (c *deferredSplitPending) Close() error                     { return nil }
func (c *deferredSplitPending) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *deferredSplitPending) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *deferredSplitPending) SetDeadline(time.Time) error      { return nil }
func (c *deferredSplitPending) SetReadDeadline(time.Time) error  { return nil }
func (c *deferredSplitPending) SetWriteDeadline(time.Time) error { return nil }
func (c *deferredSplitPending) NativePending() bool              { return c.established == nil }
func (c *deferredSplitPending) NeedHandshake() bool              { return c.NativePending() }

func (c *deferredSplitPending) Established() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.established == nil {
		return nil
	}
	return c.established
}

func (c *deferredSplitPending) state() (int, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activations, append([]byte(nil), c.payload...)
}

type deferredSplitEstablished struct {
	mu     sync.Mutex
	writes [][]byte
}

func (c *deferredSplitEstablished) Read([]byte) (int, error) { return 0, nil }
func (c *deferredSplitEstablished) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *deferredSplitEstablished) Close() error                     { return nil }
func (c *deferredSplitEstablished) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *deferredSplitEstablished) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *deferredSplitEstablished) SetDeadline(time.Time) error      { return nil }
func (c *deferredSplitEstablished) SetReadDeadline(time.Time) error  { return nil }
func (c *deferredSplitEstablished) SetWriteDeadline(time.Time) error { return nil }

func (c *deferredSplitEstablished) collected() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	var result []byte
	for _, write := range c.writes {
		result = append(result, write...)
	}
	return result
}

// TestDeferredSplitFirstFragmentThroughBridge is the end-to-end hermetic
// control for the accepted seam: the direct bridge wraps the deferred pending
// connection with the real compiled stream configuration, the first transformed
// split fragment is the single TFO payload, later fragments use the established
// connection, and the handshake contract survives the wrapper.
func TestDeferredSplitFirstFragmentThroughBridge(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos:         badoption.Listable[string]{"2"},
			SplitAnyProtocol: true,
		},
	}
	config, err := desync.CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	if err != nil {
		t.Fatal(err)
	}
	if config == nil {
		t.Fatal("CompileStream returned no configuration")
	}
	hook := &desyncHook{stream: config, lifetime: context.Background()}
	pending := &deferredSplitPending{}
	intent := dialer.AttemptIntent{
		Network:     "tcp",
		Destination: M.SocksaddrFrom(netip.MustParseAddr("203.0.113.7"), 443),
	}
	wrapped, err := hook.WrapPendingTCP(context.Background(), intent, pending)
	if err != nil {
		t.Fatal(err)
	}
	if !N.NeedHandshakeForWrite(wrapped) {
		t.Fatal("bridge wrapper hid the pending handshake")
	}
	input := []byte("ABCDEF")
	written, err := wrapped.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("Write = %d,%v, want %d,nil", written, err, len(input))
	}
	activations, payload := pending.state()
	if activations != 1 {
		t.Fatalf("activations = %d, want exactly 1", activations)
	}
	if string(payload) != "AB" {
		t.Fatalf("TFO payload = %q, want the first split fragment %q", payload, "AB")
	}
	if got := pending.established.collected(); string(got) != "CDEF" {
		t.Fatalf("established bytes = %q, want %q", got, "CDEF")
	}
	if N.NeedHandshakeForWrite(wrapped) {
		t.Fatal("handshake still pending after the first transformed send")
	}
}

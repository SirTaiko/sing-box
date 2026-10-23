package direct

// End-to-end coverage for the QA t_a64dd1a8 G1 boundary: the real dialer
// pending facade (pendingTCPConn), the real direct.WrapPendingTCP bridge, the
// real compiled stream wrapper and the established native connection were never
// driven by one test; each side used its own fake of the other. This test uses
// the production objects only and substitutes the single platform
// first-payload attempt with a memory connection, so it never opens a socket.

import (
	"bytes"
	"context"
	"net"
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

// bridgeMemoryConn is the memory-only established connection of the substituted
// platform attempt. It records every write so the test can prove that the
// transformed first fragment was carried by the attempt and every later fragment
// went to the established connection exactly once.
type bridgeMemoryConn struct {
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

func (c *bridgeMemoryConn) Read([]byte) (int, error) { return 0, nil }
func (c *bridgeMemoryConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *bridgeMemoryConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *bridgeMemoryConn) LocalAddr() net.Addr              { return M.Socksaddr{} }
func (c *bridgeMemoryConn) RemoteAddr() net.Addr             { return M.Socksaddr{} }
func (c *bridgeMemoryConn) SetDeadline(time.Time) error      { return nil }
func (c *bridgeMemoryConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bridgeMemoryConn) SetWriteDeadline(time.Time) error { return nil }

func (c *bridgeMemoryConn) collected() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.writes, nil)
}

// recordingPendingHook observes the connection the production dialer hands to
// the bridge and then delegates to the real bridge implementation.
type recordingPendingHook struct {
	inner   dialer.PendingTCPHook
	pending net.Conn
}

func (h *recordingPendingHook) WrapPendingTCP(ctx context.Context, intent dialer.AttemptIntent, pending net.Conn) (net.Conn, error) {
	h.pending = pending
	return h.inner.WrapPendingTCP(ctx, intent, pending)
}

func TestDeferredPendingBridgeReachesNativeConnection(t *testing.T) {
	rule := option.DirectDesyncStreamRule{
		Methods: badoption.Listable[string]{"split"},
		Split: &option.DirectDesyncStreamSplit{
			SplitPos:         badoption.Listable[string]{"2"},
			SplitAnyProtocol: true,
		},
	}
	config, err := desync.CompileStream([]option.DirectDesyncStreamRule{rule}, "")
	if err != nil {
		t.Fatalf("CompileStream: %v", err)
	}
	if config == nil {
		t.Fatal("CompileStream returned no config")
	}
	hook := &desyncHook{stream: config, lifetime: context.Background()}
	pendingHook := &recordingPendingHook{inner: hook}

	dialerInstance, err := dialer.NewDefault(context.Background(), option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true},
	})
	if err != nil {
		t.Fatalf("NewDefault: %v", err)
	}
	dialerInstance.SetAttemptHook(hook)
	dialerInstance.SetPendingTCPHook(pendingHook)

	var (
		attempts    int
		submitted   []byte
		established = &bridgeMemoryConn{}
	)
	dialerInstance.SetFirstPayloadAttempt(func(_ context.Context, _ net.Dialer, _, _ string, payload []byte, _ dialer.AttemptLease) (net.Conn, int, error) {
		attempts++
		submitted = append([]byte(nil), payload...)
		return established, len(payload), nil
	})

	conn, err := dialerInstance.DialContext(context.Background(), "tcp", M.ParseSocksaddr("127.0.0.1:443"))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if pendingHook.pending == nil {
		t.Fatal("the direct bridge never received the production pending connection")
	}
	pending, ok := pendingHook.pending.(interface {
		NativePending() bool
		Established() net.Conn
	})
	if !ok {
		t.Fatal("the connection handed to the bridge is not the deferred pending facade")
	}
	if !pending.NativePending() || pending.Established() != nil {
		t.Fatal("the pending facade was not lazy at bridge time")
	}
	if !N.NeedHandshakeForWrite(conn) {
		t.Fatal("the deferred handshake contract was lost through the stream wrapper")
	}
	written, err := conn.Write([]byte("ABCDEF"))
	if err != nil {
		t.Fatalf("first write: %v", err)
	}
	if written != 6 {
		t.Fatalf("first write = %d, want 6", written)
	}
	if attempts != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", attempts)
	}
	if string(submitted) != "AB" {
		t.Fatalf("native attempt payload = %q, want the transformed first fragment %q", submitted, "AB")
	}
	if pending.NativePending() {
		t.Fatal("the pending facade did not adopt the established native connection")
	}
	if got := established.collected(); string(got) != "CDEF" {
		t.Fatalf("established connection received %q, want the remaining fragment %q", got, "CDEF")
	}
	if N.NeedHandshakeForWrite(conn) {
		t.Fatal("an established connection still reports a pending handshake")
	}
	if _, err = conn.Write([]byte("GH")); err != nil {
		t.Fatalf("later write: %v", err)
	}
	if got := established.collected(); string(got) != "CDEFGH" {
		t.Fatalf("established stream = %q, want %q", got, "CDEFGH")
	}
	if attempts != 1 {
		t.Fatalf("native attempts after the second write = %d, want exactly 1", attempts)
	}
}

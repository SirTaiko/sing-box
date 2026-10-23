//go:build windows

package dialer

// Permanent Windows regression for the public eager enabled-direct facade.
//
// The defect this pins (QA-D2): (*DefaultDialer).DialContext with an attempt
// hook installed and tcp_fast_open off reached dialConnectEx with payload=nil,
// so a context canceled before the call still returned a live connection, and
// an already expired deadline still established the TCP connection at the peer
// before reporting the error. The refusal belongs to the existing eager entry
// point, before the attempt hook, the lease and the native socket exist.
//
// A real loopback listener is part of the assertion: only a native dial can
// show that nothing reached the peer. The test is loopback-only and is meant to
// run on the Windows test guest, where the native connect path exists.

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// eagerAttemptHook records every attempt the eager facade admits and keeps the
// last lease so the test can observe prepared sockets and native holds.
type eagerAttemptHook struct {
	mu     sync.Mutex
	leases int
	last   *eagerAttemptLease
}

func (h *eagerAttemptHook) NewAttempt(context.Context, AttemptIntent) (AttemptLease, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.leases++
	h.last = &eagerAttemptLease{}
	return h.last, nil
}

// state returns the cumulative attempt count plus the lifecycle counters of the
// last lease (zero when no attempt was ever admitted).
func (h *eagerAttemptHook) state() (leases, prepared, holds, attached, closed int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.last == nil {
		return h.leases, 0, 0, 0, 0
	}
	h.last.mu.Lock()
	defer h.last.mu.Unlock()
	return h.leases, h.last.prepared, h.last.holds, h.last.attached, h.last.closed
}

// eagerAttemptLease is the ordinary admission capability of one attempt,
// including the native hold dialConnectEx requires before it creates a socket.
type eagerAttemptLease struct {
	mu       sync.Mutex
	prepared int
	holds    int
	attached int
	closed   int
}

func (l *eagerAttemptLease) bump(counter *int) {
	l.mu.Lock()
	(*counter)++
	l.mu.Unlock()
}

func (l *eagerAttemptLease) PrepareSocket(uintptr) error {
	l.bump(&l.prepared)
	return nil
}

func (l *eagerAttemptLease) RequiresExclusiveBind() bool { return false }

func (l *eagerAttemptLease) SetLocalAddress(netip.AddrPort) {}

func (l *eagerAttemptLease) StartCapture() error { return nil }

func (l *eagerAttemptLease) AttachConn(conn net.Conn) (net.Conn, error) {
	l.bump(&l.attached)
	return conn, nil
}

func (l *eagerAttemptLease) AttachPacketConn(conn net.PacketConn) net.PacketConn { return conn }

func (l *eagerAttemptLease) Close(error) error {
	l.bump(&l.closed)
	return nil
}

func (l *eagerAttemptLease) AcquireNativeHold() (func(), error) {
	l.bump(&l.holds)
	return func() { l.mu.Lock(); l.holds--; l.mu.Unlock() }, nil
}

// eagerDialResult is what one public eager dial showed to the caller, to the
// loopback peer and to the attempt hook.
type eagerDialResult struct {
	conn         net.Conn
	err          error
	peerAccepted bool
	leases       int
	prepared     int
	holds        int
	attached     int
}

// probeEagerDial performs one public eager dial against a fresh loopback
// listener. The listener is closed by the test cleanup; a successful native
// connect is observable as one accepted connection within peerAcceptWindow.
func probeEagerDial(t *testing.T, newContext func() (context.Context, context.CancelFunc)) eagerDialResult {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 1)
	go func() {
		peer, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- struct{}{}
			_ = peer.Close()
		}
	}()
	hook := &eagerAttemptHook{}
	probeDialer := &DefaultDialer{attemptHook: hook}
	destination := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), uint16(listener.Addr().(*net.TCPAddr).Port))
	ctx, cancel := newContext()
	defer cancel()
	conn, dialErr := probeDialer.DialContext(ctx, "tcp", destination)
	result := eagerDialResult{conn: conn, err: dialErr}
	select {
	case <-accepted:
		result.peerAccepted = true
	case <-time.After(500 * time.Millisecond):
	}
	result.leases, result.prepared, result.holds, result.attached, _ = hook.state()
	return result
}

// TestPublicEagerDialRefusesCompletedContext is the public-path proof for both
// completed-context cases: no connection, the context error, and no attempt,
// socket preparation, native hold or peer connection after the refusal.
func TestPublicEagerDialRefusesCompletedContext(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		newContext func() (context.Context, context.CancelFunc)
		want       error
	}{
		{
			name: "canceled",
			newContext: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			want: context.Canceled,
		},
		{
			name: "expired",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result := probeEagerDial(t, testCase.newContext)
			if result.conn != nil {
				_ = result.conn.Close()
				t.Fatal("a context completed before the call returned a live connection")
			}
			if !errors.Is(result.err, testCase.want) {
				t.Fatalf("dial error = %v, want %v", result.err, testCase.want)
			}
			if result.peerAccepted {
				t.Fatal("the loopback peer accepted a connection after a completed cancellation")
			}
			if result.leases != 0 {
				t.Fatalf("attempt hook leases = %d, want 0", result.leases)
			}
			if result.prepared != 0 {
				t.Fatalf("PrepareSocket calls = %d, want 0", result.prepared)
			}
			if result.holds != 0 {
				t.Fatalf("native holds = %d, want 0", result.holds)
			}
			if result.attached != 0 {
				t.Fatalf("AttachConn calls = %d, want 0", result.attached)
			}
		})
	}
}

// TestPublicEagerDialLiveContextControl keeps the refusal non-vacuous: the same
// public facade, hook and loopback peer must dial successfully with a live
// context, so a failure above cannot come from a broken harness.
func TestPublicEagerDialLiveContextControl(t *testing.T) {
	result := probeEagerDial(t, func() (context.Context, context.CancelFunc) {
		return context.WithCancel(context.Background())
	})
	if result.err != nil || result.conn == nil {
		t.Fatalf("live context control: conn=%v err=%v", result.conn, result.err)
	}
	_ = result.conn.Close()
	if !result.peerAccepted {
		t.Fatal("live context control: the loopback peer accepted no connection")
	}
	if result.leases != 1 {
		t.Fatalf("live context control: attempt hook leases = %d, want 1", result.leases)
	}
	if result.prepared != 1 {
		t.Fatalf("live context control: PrepareSocket calls = %d, want 1", result.prepared)
	}
	if result.attached != 1 {
		t.Fatalf("live context control: AttachConn calls = %d, want 1", result.attached)
	}
}

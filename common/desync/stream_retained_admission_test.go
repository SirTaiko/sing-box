package desync

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// retainedFakeConn is a memory-only net.Conn used to observe writes.
type retainedFakeConn struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (c *retainedFakeConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *retainedFakeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return len(p), nil
}

func (c *retainedFakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *retainedFakeConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *retainedFakeConn) LocalAddr() net.Addr                { return retainedFakeAddr("local") }
func (c *retainedFakeConn) RemoteAddr() net.Addr               { return retainedFakeAddr("remote") }
func (c *retainedFakeConn) SetDeadline(time.Time) error        { return nil }
func (c *retainedFakeConn) SetReadDeadline(time.Time) error    { return nil }
func (c *retainedFakeConn) SetWriteDeadline(time.Time) error   { return nil }

type retainedFakeAddr string

func (a retainedFakeAddr) Network() string { return "memory" }
func (a retainedFakeAddr) String() string  { return string(a) }

// retainedHolder is the admission capability fixture: it counts references and
// can refuse like a closed owner.
type retainedHolder struct {
	mu       sync.Mutex
	acquired int
	released int
	refuse   error
}

func (h *retainedHolder) AcquireNativeHold() (func(), error) {
	h.mu.Lock()
	if h.refuse != nil {
		err := h.refuse
		h.mu.Unlock()
		return nil, err
	}
	h.acquired++
	h.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			h.mu.Lock()
			h.released++
			h.mu.Unlock()
		})
	}, nil
}

func (h *retainedHolder) counts() (acquired int, released int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.acquired, h.released
}

// retainedCapConn carries an admission capability and optionally exposes a
// distinct already-owned native connection.
type retainedCapConn struct {
	net.Conn
	holder *retainedHolder
	native net.Conn
}

func (c *retainedCapConn) AcquireNativeHold() (func(), error) {
	return c.holder.AcquireNativeHold()
}

func (c *retainedCapConn) NativeStreamConn() net.Conn {
	if c.native != nil {
		return c.native
	}
	return c.Conn
}

// retainedFakeNative records the sender factory and returns a plain sender.
type retainedFakeNative struct {
	mu    sync.Mutex
	calls int
	conn  net.Conn
	err   error
}

func (n *retainedFakeNative) Prepare(uintptr, streamSocketConfig) error { return nil }

func (n *retainedFakeNative) NewSender(conn net.Conn, _ func() time.Time) (streamSender, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.calls++
	n.conn = conn
	if n.err != nil {
		return nil, n.err
	}
	return &plainSender{conn: conn}, nil
}

func (n *retainedFakeNative) state() (calls int, conn net.Conn) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.calls, n.conn
}

// retainedDeferredConn is the structural deferred facade of the stream package.
type retainedDeferredConn struct {
	net.Conn
	pending    bool
	established net.Conn
}

func (c *retainedDeferredConn) NativePending() bool  { return c.pending }
func (c *retainedDeferredConn) Established() net.Conn { return c.established }

// R15: a native factory refuses before any native effect without an admission
// owner; it never invents a default owner and never falls back.
func TestAcquireStreamNativeSourceRequiresAdmissionOwner(t *testing.T) {
	plain := &retainedFakeConn{}
	source, holder, release, err := acquireStreamNativeSource(plain)
	if err == nil {
		release()
		t.Fatalf("acquireStreamNativeSource accepted a connection without admission")
	}
	if source != nil || holder != nil || release != nil {
		t.Fatalf("failed acquisition returned usable state: source=%v holder=%v", source, holder)
	}
}

// R15: the factory consumes the already-owned native connection, and the
// reference it acquired is released exactly once.
func TestAcquireStreamNativeSourceUsesOwnedNativeConnection(t *testing.T) {
	raw := &retainedFakeConn{}
	holder := &retainedHolder{}
	conn := &retainedCapConn{Conn: &retainedFakeConn{}, holder: holder, native: raw}
	source, gotHolder, release, err := acquireStreamNativeSource(conn)
	if err != nil {
		t.Fatalf("acquireStreamNativeSource: %v", err)
	}
	if source != raw {
		t.Fatalf("source = %v, want the exposed owned native connection", source)
	}
	if gotHolder != nativeAdmissionHolder(conn) {
		t.Fatalf("holder is not the connection capability")
	}
	if acquired, _ := holder.counts(); acquired != 1 {
		t.Fatalf("acquired = %d, want 1", acquired)
	}
	release()
	release()
	if _, released := holder.counts(); released != 1 {
		t.Fatalf("released = %d, want exactly once", released)
	}
}

// R08: a refusal is classified and no reference is retained.
func TestAcquireStreamNativeSourcePropagatesRefusal(t *testing.T) {
	refusal := admissionRefused(errEngineClosed)
	holder := &retainedHolder{refuse: refusal}
	conn := &retainedCapConn{Conn: &retainedFakeConn{}, holder: holder}
	if _, _, _, err := acquireStreamNativeSource(conn); !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("acquireStreamNativeSource error = %v, want admission refusal", err)
	}
	if acquired, released := holder.counts(); acquired != 0 || released != 0 {
		t.Fatalf("refused acquisition changed state: acquired=%d released=%d", acquired, released)
	}
}

// R08/R09: a refused native send returns the known prefix without a fallback
// write on the connection.
func TestForwardUnsentAdmissionRefusalHasNoFallbackWrite(t *testing.T) {
	conn := &retainedFakeConn{}
	wrapper := &streamConn{Conn: conn}
	written, err := wrapper.forwardUnsent([]byte("abcdef"), 2, 0, admissionRefused(errLeaseClosed))
	if written != 2 {
		t.Fatalf("written = %d, want the known prefix 2", written)
	}
	if !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("error = %v, want admission refusal", err)
	}
	if conn.writeCount() != 0 {
		t.Fatalf("refusal wrote %d times to the connection, want 0 fallback writes", conn.writeCount())
	}
}

// R03/R15: when a deferred facade was activated before native sender selection,
// the factory consumes the established connection of the same attempt, not the
// pending facade.
func TestDeferredNativeSenderUsesEstablishedConnection(t *testing.T) {
	establishedRaw := &retainedFakeConn{}
	holder := &retainedHolder{}
	established := &retainedCapConn{Conn: establishedRaw, holder: holder}
	facade := &retainedDeferredConn{Conn: &retainedFakeConn{}, pending: false, established: established}
	native := &retainedFakeNative{}
	wrapper := &streamConn{Conn: facade, config: &StreamConfig{native: native}}
	sender, err := wrapper.newNativeSender()
	if err != nil {
		t.Fatalf("newNativeSender: %v", err)
	}
	if sender == nil {
		t.Fatalf("newNativeSender returned no sender")
	}
	calls, got := native.state()
	if calls != 1 || got != established {
		t.Fatalf("factory calls=%d conn=%v, want the established connection", calls, got)
	}
}

// R03/R15: a facade whose activation is still publishing has no established
// connection yet and must be refused before a native effect.
func TestDeferredNativeSenderRefusesUnpublishedFacade(t *testing.T) {
	facade := &retainedDeferredConn{Conn: &retainedFakeConn{}, pending: false, established: nil}
	native := &retainedFakeNative{}
	wrapper := &streamConn{Conn: facade, config: &StreamConfig{native: native}}
	if _, err := wrapper.newNativeSender(); err == nil {
		t.Fatalf("newNativeSender accepted an unpublished deferred facade")
	}
	if calls, _ := native.state(); calls != 0 {
		t.Fatalf("factory called %d times, want 0", calls)
	}
}

package dialer

// Permanent regressions for security t_4be63d99 TFO3-S1 / QA O1: an adopted
// connection must not be usable by a fresh Read/Write, and must not be exposed
// through the unwrap/replaceability contract, until the current call deadlines
// were published on it. Before the fix the facade published `conn` first and the
// deadlines afterwards, so a fresh operation skipped the activation wait and
// delegated to a connection that did not carry the caller deadline yet.
//
// Every fixture is memory-only: the platform first-payload attempt is
// substituted, so no socket, event handle, DNS lookup or packet I/O exists.
// The publication barrier is a deterministic channel in the adopted connection,
// not a scheduling hope, and it magnifies the ordering window instead of
// measuring exploitation frequency.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// publicationGateConn is the adopted memory connection of the pending facade.
// Its first deadline publication blocks until the test releases it, which is
// exactly the window between the facade adopting the connection and publishing
// the call deadlines on it. Later setter calls are not gated, so a setter that
// runs during the window can still settle before the barrier opens.
type publicationGateConn struct {
	entered chan struct{}
	resume  chan struct{}
	claimed atomic.Bool
	release sync.Once

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
	writes        int
	reads         int
	closes        int
	closed        bool
}

func newPublicationGateConn() *publicationGateConn {
	return &publicationGateConn{
		entered: make(chan struct{}),
		resume:  make(chan struct{}),
	}
}

// gate parks exactly one deadline publication. A setter that runs while that
// publication is parked must not block behind it (sync.Once would), it must
// settle its own newer value immediately, so the flag is claimed without a
// mutex and every other call proceeds.
func (c *publicationGateConn) gate() {
	if !c.claimed.CompareAndSwap(false, true) {
		return
	}
	close(c.entered)
	<-c.resume
}

// release opens the publication barrier exactly once.
func (c *publicationGateConn) releaseGate() {
	c.release.Do(func() {
		close(c.resume)
	})
}

func (c *publicationGateConn) SetDeadline(deadline time.Time) error {
	c.gate()
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.mu.Unlock()
	return nil
}

func (c *publicationGateConn) SetReadDeadline(deadline time.Time) error {
	c.gate()
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *publicationGateConn) SetWriteDeadline(deadline time.Time) error {
	c.gate()
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *publicationGateConn) Read([]byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, os.ErrClosed
	}
	if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	c.reads++
	// No payload exists in this fixture; io.EOF keeps a premature io.Copy
	// from spinning, so a bypass is observable as a completed copy.
	return 0, io.EOF
}

func (c *publicationGateConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, os.ErrClosed
	}
	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		return 0, os.ErrDeadlineExceeded
	}
	c.writes += len(p)
	return len(p), nil
}

func (c *publicationGateConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closes++
	c.closed = true
	return nil
}

func (c *publicationGateConn) LocalAddr() net.Addr  { return M.Socksaddr{} }
func (c *publicationGateConn) RemoteAddr() net.Addr { return M.Socksaddr{} }

func (c *publicationGateConn) snapshot() (readDeadline time.Time, writeDeadline time.Time, writes int, reads int, closes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline, c.writeDeadline, c.writes, c.reads, c.closes
}

type pendingIOResult struct {
	n   int
	err error
}

// publicationFixture drives the public DefaultDialer.DialContext deferred path
// with the substituted platform attempt; the returned connection is the public
// facade, and its pending owner is available for the unwrap assertions.
type publicationFixture struct {
	conn     *pendingHandshakeConn
	pending  *pendingTCPConn
	adopted  *publicationGateConn
	attempts *atomic.Int32
}

func newPublicationFixture(t *testing.T) *publicationFixture {
	t.Helper()
	adopted := newPublicationGateConn()
	var attempts atomic.Int32
	installPayloadFunc(t, func(_ context.Context, _ net.Dialer, _, _ string, payload []byte, _ AttemptLease) (net.Conn, int, error) {
		attempts.Add(1)
		return adopted, len(payload), nil
	})
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	public, ok := conn.(*pendingHandshakeConn)
	if !ok {
		t.Fatalf("public connection = %T, want the deferred facade", conn)
	}
	t.Cleanup(func() {
		adopted.releaseGate()
		_ = conn.Close()
	})
	return &publicationFixture{conn: public, pending: public.pending, adopted: adopted, attempts: &attempts}
}

// awaitPublicationGate waits until the adoption really reaches the deadline
// publication, so the fresh operation races the production window instead of a
// guessed delay.
func awaitPublicationGate(t *testing.T, adopted *publicationGateConn) {
	t.Helper()
	select {
	case <-adopted.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the adopted connection never received a deadline publication")
	}
}

func awaitPendingResult(t *testing.T, result <-chan pendingIOResult, timeout time.Duration) (pendingIOResult, bool) {
	t.Helper()
	select {
	case got := <-result:
		return got, true
	case <-time.After(timeout):
		return pendingIOResult{}, false
	}
}

// assertPendingHidden checks the whole unwrap/replaceability contract of the
// pending owner while the publication barrier is held.
func assertPendingHidden(t *testing.T, pending *pendingTCPConn) {
	t.Helper()
	if established := pending.Established(); established != nil {
		t.Fatalf("Established exposed the adopted connection before deadline publication: %T", established)
	}
	if upstream := pending.Upstream(); upstream != nil {
		t.Fatalf("Upstream exposed the adopted connection before deadline publication: %T", upstream)
	}
	if pending.ReaderReplaceable() || pending.WriterReplaceable() {
		t.Fatal("the pending facade reported a replaceable half before deadline publication")
	}
}

// TestPendingFreshWriteWaitsForDeadlinePublication pins the packet path: a
// fresh Write with an already expired half deadline must be refused, and it must
// not reach the adopted connection while its deadline publication is in flight.
func TestPendingFreshWriteWaitsForDeadlinePublication(t *testing.T) {
	fixture := newPublicationFixture(t)
	deadline := time.Now().Add(400 * time.Millisecond)
	if err := fixture.conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- pendingIOResult{n: n, err: err}
	}()
	awaitPublicationGate(t, fixture.adopted)
	// Let the caller deadline expire while the publication is still held.
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	fresh := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("XX"))
		fresh <- pendingIOResult{n: n, err: err}
	}()
	got, returned := awaitPendingResult(t, fresh, time.Second)
	if !returned {
		t.Fatal("an expired fresh write did not return while the deadline publication was held")
	}
	if got.n != 0 || !isDeadlineError(got.err) {
		t.Fatalf("expired fresh write = (%d, %v), want a deadline refusal", got.n, got.err)
	}
	if _, _, writes, _, _ := fixture.adopted.snapshot(); writes != 0 {
		t.Fatalf("the adopted connection accepted %d bytes before the deadline publication", writes)
	}
	assertPendingHidden(t, fixture.pending)
	fixture.adopted.releaseGate()
	result, returned := awaitPendingResult(t, owner, 2*time.Second)
	if !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	if fixture.pending.Established() == nil || fixture.pending.Upstream() == nil {
		t.Fatal("the settled connection is still hidden after deadline publication")
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPendingFreshReadWaitsForDeadlinePublication pins the read and WriteTo
// paths of the same window: neither may delegate to the adopted connection
// before its deadline publication settled.
func TestPendingFreshReadWaitsForDeadlinePublication(t *testing.T) {
	fixture := newPublicationFixture(t)
	deadline := time.Now().Add(400 * time.Millisecond)
	if err := fixture.conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	owner := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- pendingIOResult{n: n, err: err}
	}()
	awaitPublicationGate(t, fixture.adopted)
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	fresh := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Read(make([]byte, 2))
		fresh <- pendingIOResult{n: n, err: err}
	}()
	got, returned := awaitPendingResult(t, fresh, time.Second)
	if !returned {
		t.Fatal("an expired fresh read did not return while the deadline publication was held")
	}
	if got.n != 0 || !isDeadlineError(got.err) {
		t.Fatalf("expired fresh read = (%d, %v), want a deadline refusal", got.n, got.err)
	}
	if _, _, _, reads, _ := fixture.adopted.snapshot(); reads != 0 {
		t.Fatalf("the adopted connection served %d reads before the deadline publication", reads)
	}
	if written, err := fixture.pending.WriteTo(io.Discard); written != 0 || !isDeadlineError(err) {
		t.Fatalf("WriteTo during publication = (%d, %v), want a deadline refusal", written, err)
	}
	assertPendingHidden(t, fixture.pending)
	fixture.adopted.releaseGate()
	result, returned := awaitPendingResult(t, owner, 2*time.Second)
	if !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPendingLiveOperationWaitsForDeadlinePublication is the positive control:
// a live fresh write must wait for the barrier instead of completing early on a
// connection without the caller deadline, and then be admitted normally.
func TestPendingLiveOperationWaitsForDeadlinePublication(t *testing.T) {
	fixture := newPublicationFixture(t)
	if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- pendingIOResult{n: n, err: err}
	}()
	awaitPublicationGate(t, fixture.adopted)
	fresh := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("XX"))
		fresh <- pendingIOResult{n: n, err: err}
	}()
	if got, returned := awaitPendingResult(t, fresh, 150*time.Millisecond); returned {
		t.Fatalf("a fresh live write completed before the deadline publication settled: (%d, %v)", got.n, got.err)
	}
	fixture.adopted.releaseGate()
	got, returned := awaitPendingResult(t, fresh, 2*time.Second)
	if !returned || got.n != 2 || got.err != nil {
		t.Fatalf("fresh live write after publication = (%d, %v), want (2, nil)", got.n, got.err)
	}
	if _, _, writes, _, _ := fixture.adopted.snapshot(); writes != 2 {
		t.Fatalf("adopted connection accepted %d bytes, want only the fresh 2 bytes", writes)
	}
	if result, returned := awaitPendingResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPendingPublicationCloseIsBounded pins Close during publication: it must
// stay prompt and terminal, and a fresh operation must see the closed facade
// instead of the not-yet-published connection.
func TestPendingPublicationCloseIsBounded(t *testing.T) {
	fixture := newPublicationFixture(t)
	if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- pendingIOResult{n: n, err: err}
	}()
	awaitPublicationGate(t, fixture.adopted)
	start := time.Now()
	closeErr := fixture.conn.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close blocked for %v while a foreign deadline publication was in flight", elapsed)
	}
	if closeErr != nil {
		t.Fatalf("Close during publication = %v", closeErr)
	}
	fresh := make(chan pendingIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("XX"))
		fresh <- pendingIOResult{n: n, err: err}
	}()
	got, returned := awaitPendingResult(t, fresh, time.Second)
	if !returned || got.n != 0 || !errors.Is(got.err, os.ErrClosed) {
		t.Fatalf("fresh write after Close = (%d, %v), want a closed refusal", got.n, got.err)
	}
	fixture.adopted.releaseGate()
	result, returned := awaitPendingResult(t, owner, 2*time.Second)
	// The native attempt had already accepted both bytes when Close raced the
	// publication, so the authoritative count must survive. The error is either
	// the success of that completed write or the closed contract.
	if !returned || result.n != 2 || (result.err != nil && !errors.Is(result.err, os.ErrClosed)) {
		t.Fatalf("activating write = (%d, %v), want (2, nil or the closed contract)", result.n, result.err)
	}
	if _, _, _, _, closes := fixture.adopted.snapshot(); closes == 0 {
		t.Fatal("the adopted connection was never closed")
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPendingPublicationSetterBothDirections keeps the current two-half setter
// contract load-bearing across the publication barrier: a setter that settles
// during the window must win over the adoption snapshot, both when it shortens
// the write half and when it clears it.
func TestPendingPublicationSetterBothDirections(t *testing.T) {
	t.Run("shortened", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		if err := fixture.conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		owner := make(chan pendingIOResult, 1)
		go func() {
			n, err := fixture.conn.Write([]byte("AB"))
			owner <- pendingIOResult{n: n, err: err}
		}()
		awaitPublicationGate(t, fixture.adopted)
		expired := time.Now().Add(-time.Second)
		if err := fixture.conn.SetWriteDeadline(expired); err != nil {
			t.Fatalf("SetWriteDeadline during publication: %v", err)
		}
		fixture.adopted.releaseGate()
		if result, returned := awaitPendingResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
			t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
		}
		readDeadline, writeDeadline, _, _, _ := fixture.adopted.snapshot()
		if !writeDeadline.Equal(expired) {
			t.Fatalf("adopted write deadline = %v, want the completed shortened %v", writeDeadline, expired)
		}
		if readDeadline.IsZero() {
			t.Fatal("the read half was cleared by a write-half setter")
		}
		if written, err := fixture.conn.Write([]byte("XX")); written != 0 || !isDeadlineError(err) {
			t.Fatalf("write under the shortened deadline = (%d, %v), want a deadline refusal", written, err)
		}
	})
	t.Run("cleared", func(t *testing.T) {
		fixture := newPublicationFixture(t)
		if err := fixture.conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		owner := make(chan pendingIOResult, 1)
		go func() {
			n, err := fixture.conn.Write([]byte("AB"))
			owner <- pendingIOResult{n: n, err: err}
		}()
		awaitPublicationGate(t, fixture.adopted)
		if err := fixture.conn.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatalf("SetWriteDeadline during publication: %v", err)
		}
		fixture.adopted.releaseGate()
		if result, returned := awaitPendingResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
			t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
		}
		readDeadline, writeDeadline, _, _, _ := fixture.adopted.snapshot()
		if !writeDeadline.IsZero() {
			t.Fatalf("adopted write deadline = %v, want the completed clear", writeDeadline)
		}
		if readDeadline.IsZero() {
			t.Fatal("the read half was cleared by a write-half setter")
		}
		written, err := fixture.conn.Write([]byte("XX"))
		if written != 2 || err != nil {
			t.Fatalf("write after the cleared deadline = (%d, %v), want (2, nil)", written, err)
		}
	})
}

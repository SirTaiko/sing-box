package direct

// Permanent public-path regression for security t_4be63d99 TFO3-S1 / QA O1.
// The production DefaultDialer, the real direct bridge (desyncHook), a real
// Engine lease and, for the read case, the real compiled stream wrapper drive
// one deferred TFO connection whose adopted socket is a memory net.Pipe. Only
// the platform first-payload attempt is substituted: the previous tests of this
// window were one-off probes, this file keeps them non-vacuous.
//
// The publication barrier is the adopted memory connection's first deadline
// publication. It parks deterministically until the test releases it, so the
// tests assert the ordering contract itself, not a scheduling coincidence.
// No socket, DNS lookup, packet I/O or product process exists.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

// publicationDeadlineGate parks exactly one deadline publication of the adopted
// memory connection. A later setter must not block behind the parked adoption
// (sync.Once would), so the barrier is claimed by compare-and-swap and every
// other publication proceeds immediately.
type publicationDeadlineGate struct {
	net.Conn
	entered  chan struct{}
	resume   chan struct{}
	claimed  atomic.Bool
	gateRead bool
	reads    atomic.Int32
	writes   atomic.Int32
}

// Read and Write count the I/O that reaches the adopted connection, so a
// refusal that happens before the publication barrier can be proved to have
// performed no I/O at all (the counters stay at zero).
func (c *publicationDeadlineGate) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

func (c *publicationDeadlineGate) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func (c *publicationDeadlineGate) ioCounts() (reads int, writes int) {
	return int(c.reads.Load()), int(c.writes.Load())
}

func (c *publicationDeadlineGate) gate() {
	if !c.claimed.CompareAndSwap(false, true) {
		return
	}
	close(c.entered)
	<-c.resume
}

func (c *publicationDeadlineGate) SetDeadline(deadline time.Time) error {
	c.gate()
	return c.Conn.SetDeadline(deadline)
}

func (c *publicationDeadlineGate) SetReadDeadline(deadline time.Time) error {
	if c.gateRead {
		c.gate()
	}
	return c.Conn.SetReadDeadline(deadline)
}

func (c *publicationDeadlineGate) SetWriteDeadline(deadline time.Time) error {
	if !c.gateRead {
		c.gate()
	}
	return c.Conn.SetWriteDeadline(deadline)
}

type publicIOResult struct {
	n   int
	err error
}

type publicPublicationFixture struct {
	conn        net.Conn
	peer        net.Conn
	gate        *publicationDeadlineGate
	pending     net.Conn
	engine      *desync.Engine
	attempts    *atomic.Int32
	releaseOnce sync.Once
}

// release opens the publication barrier exactly once.
func (f *publicPublicationFixture) release() {
	f.releaseOnce.Do(func() {
		close(f.gate.resume)
	})
}

func newPublicPublicationFixture(t *testing.T, gateRead bool) *publicPublicationFixture {
	t.Helper()
	client, peer := net.Pipe()
	gate := &publicationDeadlineGate{
		Conn:     client,
		entered:  make(chan struct{}),
		resume:   make(chan struct{}),
		gateRead: gateRead,
	}
	engine, err := desync.NewEngine(&desync.Config{Limits: desync.LimitSet{MaxLeases: 1}}, &countingBackend{})
	if err != nil {
		_ = client.Close()
		_ = peer.Close()
		t.Fatalf("desync.NewEngine: %v", err)
	}
	hook := &desyncHook{engine: engine, lifetime: context.Background()}
	if gateRead {
		config, compileErr := desync.CompileStream([]option.DirectDesyncStreamRule{{
			Methods: []string{"split"},
			Split: &option.DirectDesyncStreamSplit{
				SplitPos:         []string{"2"},
				SplitAnyProtocol: true,
			},
		}}, "")
		if compileErr != nil {
			_ = engine.Close()
			t.Fatalf("CompileStream: %v", compileErr)
		}
		if config == nil {
			_ = engine.Close()
			t.Fatal("CompileStream returned no config")
		}
		hook.stream = config
	}
	dialerInstance, err := dialer.NewDefault(context.Background(), option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{TCPFastOpen: true},
	})
	if err != nil {
		_ = engine.Close()
		t.Fatalf("dialer.NewDefault: %v", err)
	}
	dialerInstance.SetAttemptHook(hook)
	recorder := &recordingPendingHook{inner: hook}
	dialerInstance.SetPendingTCPHook(recorder)
	var attempts atomic.Int32
	dialerInstance.SetFirstPayloadAttempt(func(_ context.Context, _ net.Dialer, _, _ string, payload []byte, _ dialer.AttemptLease) (net.Conn, int, error) {
		attempts.Add(1)
		return gate, len(payload), nil
	})
	conn, err := dialerInstance.DialContext(context.Background(), "tcp", M.ParseSocksaddr("192.0.2.1:443"))
	if err != nil {
		_ = engine.Close()
		t.Fatalf("DialContext: %v", err)
	}
	fixture := &publicPublicationFixture{
		conn:     conn,
		peer:     peer,
		gate:     gate,
		pending:  recorder.pending,
		engine:   engine,
		attempts: &attempts,
	}
	t.Cleanup(func() {
		fixture.release()
		_ = conn.Close()
		_ = peer.Close()
		_ = engine.Close()
	})
	if fixture.pending == nil {
		t.Fatal("the direct bridge never received the production pending facade")
	}
	return fixture
}

func awaitPublicationBarrier(t *testing.T, gate *publicationDeadlineGate) {
	t.Helper()
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the adopted connection never received a deadline publication")
	}
}

func awaitPublicResult(t *testing.T, result <-chan publicIOResult, timeout time.Duration) (publicIOResult, bool) {
	t.Helper()
	select {
	case got := <-result:
		return got, true
	case <-time.After(timeout):
		return publicIOResult{}, false
	}
}

func isPublicDeadlineError(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded)
}

// TestPublicPendingPublicationRefusesExpiredWrite converts security's
// packet-only probe: a fresh public write whose half deadline expired while the
// adopted connection's deadline publication was held must be refused before it
// reaches the socket.
func TestPublicPendingPublicationRefusesExpiredWrite(t *testing.T) {
	fixture := newPublicPublicationFixture(t, false)
	deadline := time.Now().Add(400 * time.Millisecond)
	if err := fixture.conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- publicIOResult{n: n, err: err}
	}()
	awaitPublicationBarrier(t, fixture.gate)
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	fresh := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("XX"))
		fresh <- publicIOResult{n: n, err: err}
	}()
	peerRead := make(chan publicIOResult, 1)
	go func() {
		n, err := io.ReadFull(fixture.peer, make([]byte, 2))
		peerRead <- publicIOResult{n: n, err: err}
	}()
	got, returned := awaitPublicResult(t, fresh, time.Second)
	if !returned {
		t.Fatal("an expired fresh public write did not return while the deadline publication was held")
	}
	if got.n != 0 || !isPublicDeadlineError(got.err) {
		t.Fatalf("expired fresh public write = (%d, %v), want a deadline refusal", got.n, got.err)
	}
	fixture.release()
	if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	_ = fixture.peer.Close()
	if result, returned := awaitPublicResult(t, peerRead, time.Second); !returned || result.n != 0 || result.err == nil {
		t.Fatalf("the refused write reached the adopted connection: (%d, %v)", result.n, result.err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPublicPendingPublicationRefusesExpiredRead converts security's
// stream probe: a concurrent public Read through the real compiled stream
// wrapper must not bypass the expired deadline while the publication of that
// deadline on the adopted socket is still held.
func TestPublicPendingPublicationRefusesExpiredRead(t *testing.T) {
	fixture := newPublicPublicationFixture(t, true)
	deadline := time.Now().Add(400 * time.Millisecond)
	if err := fixture.conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	owner := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- publicIOResult{n: n, err: err}
	}()
	awaitPublicationBarrier(t, fixture.gate)
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	peerWrite := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.peer.Write([]byte("XX"))
		peerWrite <- publicIOResult{n: n, err: err}
	}()
	fresh := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Read(make([]byte, 2))
		fresh <- publicIOResult{n: n, err: err}
	}()
	// net.Pipe delivers bytes only to a real read. A peer write that completes
	// here proves the adopted deadline-less socket was reached; the public Read
	// itself may return only after the blocked writer releases the wrapper
	// bookkeeping mutex, so the socket is observed from the peer side.
	if got, returned := awaitPublicResult(t, peerWrite, 200*time.Millisecond); returned {
		t.Fatalf("the adopted connection consumed peer bytes during the publication window: (%d, %v)", got.n, got.err)
	}
	fixture.release()
	if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	got, returned := awaitPublicResult(t, fresh, 2*time.Second)
	if !returned {
		t.Fatal("the refused concurrent stream read never returned")
	}
	if got.n != 0 || !isPublicDeadlineError(got.err) {
		t.Fatalf("concurrent stream read = (%d, %v), want a deadline refusal", got.n, got.err)
	}
	_ = fixture.peer.Close()
	if result, returned := awaitPublicResult(t, peerWrite, time.Second); !returned || result.err == nil {
		t.Fatalf("the refused read consumed peer bytes: (%d, %v)", result.n, result.err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPublicPendingPublicationLiveControl is the positive public control: a
// live fresh write must wait for the publication barrier instead of completing
// early on the still deadline-less socket, and then be admitted exactly once.
func TestPublicPendingPublicationLiveControl(t *testing.T) {
	fixture := newPublicPublicationFixture(t, false)
	if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- publicIOResult{n: n, err: err}
	}()
	awaitPublicationBarrier(t, fixture.gate)
	peerRead := make(chan publicIOResult, 1)
	go func() {
		n, err := io.ReadFull(fixture.peer, make([]byte, 2))
		peerRead <- publicIOResult{n: n, err: err}
	}()
	fresh := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("XX"))
		fresh <- publicIOResult{n: n, err: err}
	}()
	if got, returned := awaitPublicResult(t, fresh, 150*time.Millisecond); returned {
		t.Fatalf("a fresh live public write completed before the deadline publication settled: (%d, %v)", got.n, got.err)
	}
	fixture.release()
	if result, returned := awaitPublicResult(t, fresh, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("fresh live public write after publication = (%d, %v), want (2, nil)", result.n, result.err)
	}
	if result, returned := awaitPublicResult(t, peerRead, time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("adopted connection received (%d, %v) from the fresh write, want (2, nil)", result.n, result.err)
	}
	if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPublicPendingPublicationSerialExpiredControl is the serial control: once
// the publication really settled, the expired deadline is already on the socket
// and the later write is refused by the ordinary socket contract.
func TestPublicPendingPublicationSerialExpiredControl(t *testing.T) {
	fixture := newPublicPublicationFixture(t, false)
	deadline := time.Now().Add(400 * time.Millisecond)
	if err := fixture.conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- publicIOResult{n: n, err: err}
	}()
	awaitPublicationBarrier(t, fixture.gate)
	time.Sleep(time.Until(deadline) + 20*time.Millisecond)
	fixture.release()
	if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	written, err := fixture.conn.Write([]byte("XX"))
	if written != 0 || !isPublicDeadlineError(err) {
		t.Fatalf("serial write after settled publication = (%d, %v), want a deadline refusal", written, err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPublicPendingPublicationCloseBounded pins Close during the publication
// window on the public facade: it stays bounded, the fresh operation observes
// the closed facade, and the accepted count of the already-completed native
// attempt is preserved.
func TestPublicPendingPublicationCloseBounded(t *testing.T) {
	fixture := newPublicPublicationFixture(t, false)
	if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- publicIOResult{n: n, err: err}
	}()
	awaitPublicationBarrier(t, fixture.gate)
	start := time.Now()
	closeErr := fixture.conn.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close blocked for %v while a foreign deadline publication was in flight", elapsed)
	}
	if closeErr != nil {
		t.Fatalf("Close during publication = %v", closeErr)
	}
	fresh := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("XX"))
		fresh <- publicIOResult{n: n, err: err}
	}()
	if got, returned := awaitPublicResult(t, fresh, time.Second); !returned || got.n != 0 || !errors.Is(got.err, os.ErrClosed) {
		t.Fatalf("fresh write after Close = (%d, %v), want a closed refusal", got.n, got.err)
	}
	fixture.release()
	result, returned := awaitPublicResult(t, owner, 2*time.Second)
	if !returned || result.n != 2 || (result.err != nil && !errors.Is(result.err, os.ErrClosed)) {
		t.Fatalf("activating write = (%d, %v), want (2, nil or the closed contract)", result.n, result.err)
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPublicPendingPublicationHidesUnwrap pins the native exposure contract: the
// adopted socket is neither unwrappable nor replaceable through the pending
// facade until the publication settles.
func TestPublicPendingPublicationHidesUnwrap(t *testing.T) {
	fixture := newPublicPublicationFixture(t, false)
	if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	owner := make(chan publicIOResult, 1)
	go func() {
		n, err := fixture.conn.Write([]byte("AB"))
		owner <- publicIOResult{n: n, err: err}
	}()
	awaitPublicationBarrier(t, fixture.gate)
	unwrapper, ok := fixture.pending.(interface{ Upstream() any })
	if !ok {
		t.Fatalf("pending facade %T does not implement Upstream", fixture.pending)
	}
	if upstream := unwrapper.Upstream(); upstream != nil {
		t.Fatalf("Upstream exposed the adopted connection before deadline publication: %T", upstream)
	}
	established, ok := fixture.pending.(interface{ Established() net.Conn })
	if !ok {
		t.Fatalf("pending facade %T does not implement Established", fixture.pending)
	}
	if established.Established() != nil {
		t.Fatal("Established exposed the adopted connection before deadline publication")
	}
	reader, ok := fixture.pending.(interface{ ReaderReplaceable() bool })
	if !ok || reader.ReaderReplaceable() {
		t.Fatal("the pending facade reported a replaceable reader before deadline publication")
	}
	writer, ok := fixture.pending.(interface{ WriterReplaceable() bool })
	if !ok || writer.WriterReplaceable() {
		t.Fatal("the pending facade reported a replaceable writer before deadline publication")
	}
	fixture.release()
	if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
		t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
	}
	if unwrapper.Upstream() == nil || established.Established() == nil {
		t.Fatal("the settled connection is still hidden after deadline publication")
	}
	if !reader.ReaderReplaceable() || !writer.WriterReplaceable() {
		t.Fatal("the settled connection is still not replaceable after deadline publication")
	}
	if fixture.attempts.Load() != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
	}
}

// TestPublicPendingPublicationSetterBothDirections keeps the public two-half
// setter contract across the publication barrier: a setter that settles during
// the window wins over the adoption snapshot, both shortened and cleared.
func TestPublicPendingPublicationSetterBothDirections(t *testing.T) {
	t.Run("shortened", func(t *testing.T) {
		fixture := newPublicPublicationFixture(t, false)
		if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		owner := make(chan publicIOResult, 1)
		go func() {
			n, err := fixture.conn.Write([]byte("AB"))
			owner <- publicIOResult{n: n, err: err}
		}()
		awaitPublicationBarrier(t, fixture.gate)
		expired := time.Now().Add(-time.Second)
		if err := fixture.conn.SetWriteDeadline(expired); err != nil {
			t.Fatalf("SetWriteDeadline during publication: %v", err)
		}
		fixture.release()
		if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
			t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
		}
		written, err := fixture.conn.Write([]byte("XX"))
		if written != 0 || !isPublicDeadlineError(err) {
			t.Fatalf("write under the shortened deadline = (%d, %v), want a deadline refusal", written, err)
		}
		if fixture.attempts.Load() != 1 {
			t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
		}
	})
	t.Run("cleared", func(t *testing.T) {
		fixture := newPublicPublicationFixture(t, false)
		if err := fixture.conn.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		owner := make(chan publicIOResult, 1)
		go func() {
			n, err := fixture.conn.Write([]byte("AB"))
			owner <- publicIOResult{n: n, err: err}
		}()
		awaitPublicationBarrier(t, fixture.gate)
		if err := fixture.conn.SetWriteDeadline(time.Time{}); err != nil {
			t.Fatalf("SetWriteDeadline during publication: %v", err)
		}
		peerRead := make(chan publicIOResult, 1)
		go func() {
			n, err := io.ReadFull(fixture.peer, make([]byte, 2))
			peerRead <- publicIOResult{n: n, err: err}
		}()
		fixture.release()
		if result, returned := awaitPublicResult(t, owner, 2*time.Second); !returned || result.n != 2 || result.err != nil {
			t.Fatalf("activating write = (%d, %v), want (2, nil)", result.n, result.err)
		}
		written, err := fixture.conn.Write([]byte("XX"))
		if written != 2 || err != nil {
			t.Fatalf("write after the cleared deadline = (%d, %v), want (2, nil)", written, err)
		}
		if result, returned := awaitPublicResult(t, peerRead, time.Second); !returned || result.n != 2 || result.err != nil {
			t.Fatalf("adopted connection received (%d, %v) from the cleared-deadline write, want (2, nil)", result.n, result.err)
		}
		if fixture.attempts.Load() != 1 {
			t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
		}
	})
}

// publicParkedOperation is the fresh operation that is already blocked in the
// pending facade's publication wait when Close is called. It is a named
// function so the stack scan can prove where the goroutine really is instead of
// guessing from a sleep.
func publicParkedOperation(conn net.Conn, pending io.WriterTo, mode string, done chan<- publicIOResult) {
	var n int
	var err error
	switch mode {
	case "read":
		n, err = conn.Read(make([]byte, 2))
	case "write":
		n, err = conn.Write([]byte("XX"))
	case "copy":
		var count int64
		count, err = pending.WriteTo(io.Discard)
		n = int(count)
	}
	done <- publicIOResult{n: n, err: err}
}

// awaitParkedInPublication waits until the operation is really parked in
// (*pendingTCPConn).waitActivation, i.e. behind the publication barrier that a
// held foreign deadline setter keeps parked. The scan is memory-only and keeps
// the regression non-vacuous: an operation that merely observes the closed
// state on its own fast path is not accepted as evidence.
func awaitParkedInPublication(t *testing.T) {
	t.Helper()
	stop := time.Now().Add(2 * time.Second)
	for time.Now().Before(stop) {
		buffer := make([]byte, 1<<18)
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if !strings.Contains(stack, "publicParkedOperation(") {
				continue
			}
			if strings.Contains(stack, "(*pendingTCPConn).waitActivation(") {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("the fresh operation never reached the publication wait")
}

// TestPublicPendingCloseWakesParkedOperation is the permanent TFO5 regression
// for security t_81e90c7e TFO4-S1. Public Close must release an operation that
// is already parked in the pending owner's publication/activation wait, without
// waiting for the deadline publisher (a held foreign setter), without exposing
// or using the unpublished connection and without bytes reaching it. Read,
// Write and the internal WriteTo are covered separately with a cleared (zero)
// and a far-future deadline, and each mode keeps a settled-publication serial
// control so a blanket refusal of fresh operations cannot pass the test.
func TestPublicPendingCloseWakesParkedOperation(t *testing.T) {
	for _, mode := range []string{"write", "read", "copy"} {
		for _, bound := range []string{"cleared", "far-future"} {
			t.Run(mode+"/"+bound, func(t *testing.T) {
				fixture := newPublicPublicationFixture(t, false)
				if err := fixture.conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
					t.Fatalf("SetDeadline: %v", err)
				}
				owner := make(chan publicIOResult, 1)
				go func() {
					n, err := fixture.conn.Write([]byte("AB"))
					owner <- publicIOResult{n: n, err: err}
				}()
				awaitPublicationBarrier(t, fixture.gate)
				if bound == "cleared" {
					// No deadline may release the waiter: the Close wakeup has
					// to be the reason it returns.
					if err := fixture.conn.SetDeadline(time.Time{}); err != nil {
						t.Fatalf("clear deadline: %v", err)
					}
				}
				pending, ok := fixture.pending.(io.WriterTo)
				if !ok {
					t.Fatalf("pending %T does not implement the internal WriteTo", fixture.pending)
				}
				done := make(chan publicIOResult, 1)
				go publicParkedOperation(fixture.conn, pending, mode, done)
				awaitParkedInPublication(t)
				start := time.Now()
				closeErr := fixture.conn.Close()
				closeElapsed := time.Since(start)
				got, returned := awaitPublicResult(t, done, 250*time.Millisecond)
				if !returned {
					fixture.release()
					if late, ok := awaitPublicResult(t, done, time.Second); ok {
						t.Logf("waiter returned only after the publication was released: %d,%v", late.n, late.err)
					}
					t.Fatal("public Close did not wake the operation that was already parked in the publication wait")
				}
				if closeErr != nil || closeElapsed > 250*time.Millisecond {
					t.Fatalf("Close = %v after %v, want it prompt and error-free", closeErr, closeElapsed)
				}
				if got.n != 0 || !errors.Is(got.err, os.ErrClosed) {
					t.Fatalf("parked %s after Close = (%d, %v), want (0, os.ErrClosed)", mode, got.n, got.err)
				}
				if reads, writes := fixture.gate.ioCounts(); reads != 0 || writes != 0 {
					t.Fatalf("refused %s performed I/O on the unpublished connection: reads=%d writes=%d", mode, reads, writes)
				}
				if fixture.attempts.Load() != 1 {
					t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
				}
				if active := fixture.engine.ActiveLeases(); active != 0 {
					t.Fatalf("active leases after Close = %d, want 0: the close released the admission", active)
				}
				// The activation owner is still the publisher; letting it settle
				// must keep its authoritative accepted count.
				fixture.release()
				if result, ok := awaitPublicResult(t, owner, 2*time.Second); !ok || result.n != 2 {
					t.Fatalf("activation owner = (%d, %v), returned=%v; want the accepted count 2", result.n, result.err, ok)
				}
			})
		}
		t.Run(mode+"/settled-serial-control", func(t *testing.T) {
			fixture := newPublicPublicationFixture(t, false)
			if err := fixture.conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
				t.Fatalf("SetDeadline: %v", err)
			}
			owner := make(chan publicIOResult, 1)
			go func() {
				n, err := fixture.conn.Write([]byte("AB"))
				owner <- publicIOResult{n: n, err: err}
			}()
			awaitPublicationBarrier(t, fixture.gate)
			fixture.release()
			if result, ok := awaitPublicResult(t, owner, 2*time.Second); !ok || result.n != 2 || result.err != nil {
				t.Fatalf("activation owner = (%d, %v), returned=%v; want (2, nil)", result.n, result.err, ok)
			}
			// Publication settled first: the same operations are now admitted
			// and complete normally.
			switch mode {
			case "write":
				peerRead := make(chan publicIOResult, 1)
				go func() {
					n, err := io.ReadFull(fixture.peer, make([]byte, 2))
					peerRead <- publicIOResult{n: n, err: err}
				}()
				n, err := fixture.conn.Write([]byte("XX"))
				if n != 2 || err != nil {
					t.Fatalf("settled write = (%d, %v), want (2, nil)", n, err)
				}
				if result, ok := awaitPublicResult(t, peerRead, time.Second); !ok || result.n != 2 || result.err != nil {
					t.Fatalf("peer received (%d, %v), returned=%v; want (2, nil)", result.n, result.err, ok)
				}
			case "read":
				peerWrite := make(chan publicIOResult, 1)
				go func() {
					n, err := fixture.peer.Write([]byte("PQ"))
					peerWrite <- publicIOResult{n: n, err: err}
				}()
				n, err := fixture.conn.Read(make([]byte, 2))
				if n != 2 || err != nil {
					t.Fatalf("settled read = (%d, %v), want (2, nil)", n, err)
				}
				if result, ok := awaitPublicResult(t, peerWrite, time.Second); !ok || result.n != 2 || result.err != nil {
					t.Fatalf("peer write = (%d, %v), returned=%v; want (2, nil)", result.n, result.err, ok)
				}
			case "copy":
				peerWrite := make(chan struct{})
				go func() {
					_, _ = fixture.peer.Write([]byte("PQ"))
					_ = fixture.peer.Close()
					close(peerWrite)
				}()
				pending, ok := fixture.pending.(io.WriterTo)
				if !ok {
					t.Fatalf("pending %T does not implement the internal WriteTo", fixture.pending)
				}
				count, err := pending.WriteTo(io.Discard)
				if count != 2 || err != nil {
					t.Fatalf("settled WriteTo = (%d, %v), want (2, nil)", count, err)
				}
				<-peerWrite
			}
			if fixture.attempts.Load() != 1 {
				t.Fatalf("native attempts = %d, want exactly 1", fixture.attempts.Load())
			}
		})
	}
}

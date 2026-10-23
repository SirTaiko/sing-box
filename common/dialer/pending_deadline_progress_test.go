package dialer

// Permanent regressions for the TFO3 public pending deadline/progress review
// (security t_8c719ee9 B-S1, B-S2, B-S4 and QA t_a64dd1a8 F1 support). Each
// test names the defect it pins; every one is RED on the rejected submission 2
// tree or on a compiling mutant that reverts the corresponding production
// change, and GREEN on the corrected candidate. All fixtures are memory-only:
// no socket, event handle, DNS lookup or packet I/O exists.

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// attachFailHook builds one lease per attempt and fails its AttachConn after a
// fully successful native attempt. It is the descriptor-adoption error of the
// Windows helper reproduced at the shared layer, so the progress contract can
// be asserted without a native socket.
type attachFailHook struct {
	hook  *fakeAttemptHook
	error error
}

func (h *attachFailHook) NewAttempt(ctx context.Context, intent AttemptIntent) (AttemptLease, error) {
	lease, err := h.hook.NewAttempt(ctx, intent)
	if err != nil {
		return nil, err
	}
	return &attachFailLease{fakeAttemptLease: lease.(*fakeAttemptLease), failure: h.error}, nil
}

type attachFailLease struct {
	*fakeAttemptLease
	failure error
}

func (l *attachFailLease) AttachConn(net.Conn) (net.Conn, error) { return nil, l.failure }

// installPayloadFunc substitutes the platform first-payload attempt for one
// test.
func installPayloadFunc(t *testing.T, attempt func(ctx context.Context, base net.Dialer, network, address string, payload []byte, lease AttemptLease) (net.Conn, int, error)) {
	t.Helper()
	previous := dialAttemptPayloadHook
	dialAttemptPayloadHook = attempt
	t.Cleanup(func() { dialAttemptPayloadHook = previous })
}

// A native attempt that accepted a positive prefix and then failed must report
// that prefix through the public Write. Reporting zero would tell the caller
// that nothing left the process and invite a byte-duplicating replay.
func TestDeferredProgressSurvivesAttemptError(t *testing.T) {
	failure := errors.New("native attempt accepted a prefix and failed")
	attempts := 0
	installPayloadFunc(t, func(context.Context, net.Dialer, string, string, []byte, AttemptLease) (net.Conn, int, error) {
		attempts++
		return nil, 2, failure
	})
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	written, err := conn.Write([]byte("FIRST"))
	if written != 2 || !errors.Is(err, failure) {
		t.Fatalf("public first write = (%d, %v), want (2, the attempt failure)", written, err)
	}
	if _, later := conn.Write([]byte("SECOND")); later == nil {
		t.Fatal("write after a failed activation succeeded: a second socket may have been created")
	}
	if attempts != 1 {
		t.Fatalf("native attempts = %d, want exactly 1", attempts)
	}
}

// The lease attachment happens after the native attempt already succeeded, so
// its failure must keep the accepted count and must still close the lease.
func TestDeferredProgressSurvivesLeaseAttachError(t *testing.T) {
	installPayloadFunc(t, func(_ context.Context, _ net.Dialer, _, _ string, payload []byte, _ AttemptLease) (net.Conn, int, error) {
		return &fakeConn{}, len(payload), nil
	})
	hook := &fakeAttemptHook{}
	failure := errors.New("substituted descriptor adoption failure")
	dialer := newTestDeferredDialer(t, &attachFailHook{hook: hook, error: failure}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	written, err := conn.Write([]byte("FIRST"))
	if written != 5 || !errors.Is(err, failure) {
		t.Fatalf("public write = (%d, %v), want (5, the attachment failure)", written, err)
	}
	hook.mu.Lock()
	closes := hook.closes
	hook.mu.Unlock()
	if closes != 1 {
		t.Fatalf("lease closes = %d, want exactly 1 for a failed attempt", closes)
	}
}

// The facade maps the activation cancellation to its own deadline reason. That
// mapping must not discard a count the platform attempt already reported.
func TestDeferredProgressSurvivesCancellationReason(t *testing.T) {
	installPayloadFunc(t, func(ctx context.Context, _ net.Dialer, _, _ string, _ []byte, _ AttemptLease) (net.Conn, int, error) {
		<-ctx.Done()
		return nil, 3, ctx.Err()
	})
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	written, err := conn.Write([]byte("FIRST"))
	if written != 3 || !isDeadlineError(err) {
		t.Fatalf("public write = (%d, %v), want (3, a deadline error)", written, err)
	}
}

// The retained native operation must own its payload storage. The caller is
// allowed to reuse its Write buffer as soon as Write returned, so the bytes the
// platform attempt submitted must be an independent allocation.
func TestDeferredPayloadIsOperationOwned(t *testing.T) {
	var (
		submitted   []byte
		aliasesCall bool
	)
	caller := []byte("FIRST")
	installPayloadFunc(t, func(_ context.Context, _ net.Dialer, _, _ string, payload []byte, _ AttemptLease) (net.Conn, int, error) {
		submitted = payload
		aliasesCall = &payload[0] == &caller[0]
		return nil, 0, errors.New("no native I/O in this fixture")
	})
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err = conn.Write(caller); err == nil {
		t.Fatal("fixture expected the substituted attempt failure")
	}
	// The caller legitimately reuses its buffer after Write returned.
	copy(caller, []byte("OTHER"))
	if aliasesCall {
		t.Fatal("the caller's backing store reached the native submission unchanged")
	}
	if got := string(submitted); got != "FIRST" {
		t.Fatalf("submitted native bytes = %q after caller buffer reuse, want %q", got, "FIRST")
	}
}

// installGatedPayload replaces the platform first-payload attempt with one that
// reports entry and then waits for the test to release it. The activation
// context is honored as well, so a deadline failure is still observable.
func installGatedPayload(t *testing.T, entered chan struct{}, release chan struct{}, attempts *atomic.Int32) {
	t.Helper()
	installPayloadFunc(t, func(ctx context.Context, _ net.Dialer, _, _ string, payload []byte, _ AttemptLease) (net.Conn, int, error) {
		attempts.Add(1)
		close(entered)
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-release:
			return &fakeConn{}, len(payload), nil
		}
	})
}

// awaitPendingWaiter waits until a goroutine really blocks in the production
// waitActivation, so the deadline update races a waiter that is already
// waiting instead of one that has not started.
func awaitPendingWaiter(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		buffer := make([]byte, 1<<18)
		length := runtime.Stack(buffer, true)
		if strings.Contains(string(buffer[:length]), "(*pendingTCPConn).waitActivation(") {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("waiter did not reach the production waitActivation")
}

// A deadline set while another operation is already waiting for the same
// single activation must wake that waiter and re-evaluate the current value.
// Before the fix a waiter slept on its original (absent or far) bound and
// ignored the shortened deadline entirely.
func TestPendingWaiterReevaluatesUpdatedDeadline(t *testing.T) {
	for _, ownerRead := range []bool{false, true} {
		for _, initialBound := range []bool{false, true} {
			name := "write-owner/read-waiter"
			if ownerRead {
				name = "read-owner/write-waiter"
			}
			if initialBound {
				name += "/far-bound"
			} else {
				name += "/no-bound"
			}
			t.Run(name, func(t *testing.T) {
				entered := make(chan struct{})
				release := make(chan struct{})
				var attempts atomic.Int32
				installGatedPayload(t, entered, release, &attempts)
				dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
				conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
				defer conn.Close()
				owner := make(chan error, 1)
				go func() {
					var err error
					if ownerRead {
						_, err = conn.Read(make([]byte, 1))
					} else {
						_, err = conn.Write([]byte("FIRST"))
					}
					owner <- err
				}()
				select {
				case <-entered:
				case <-time.After(time.Second):
					close(release)
					t.Fatal("activation did not start")
				}
				set := conn.SetReadDeadline
				if ownerRead {
					set = conn.SetWriteDeadline
				}
				if initialBound {
					if err := set(time.Now().Add(time.Minute)); err != nil {
						t.Fatal(err)
					}
				}
				waiter := make(chan error, 1)
				go func() {
					var err error
					if ownerRead {
						_, err = conn.Write([]byte("SECOND"))
					} else {
						_, err = conn.Read(make([]byte, 1))
					}
					waiter <- err
				}()
				awaitPendingWaiter(t)
				if err := set(time.Now().Add(20 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				honored := false
				var waiterErr error
				select {
				case waiterErr = <-waiter:
					honored = isDeadlineError(waiterErr)
				case <-time.After(200 * time.Millisecond):
				}
				close(release)
				select {
				case <-owner:
				case <-time.After(2 * time.Second):
				}
				if !honored {
					select {
					case <-waiter:
					case <-time.After(time.Second):
						t.Fatal("fixture waiter failed cleanup")
					}
					t.Errorf("shortened 20ms deadline did not wake the existing waiter within 200ms: %v", waiterErr)
				}
				if attempts.Load() != 1 {
					t.Errorf("native attempts = %d, want exactly 1", attempts.Load())
				}
			})
		}
	}
}

// net.Conn defines SetDeadline as equivalent to both half setters. An earlier
// combined deadline is therefore not an independent cap: a later half setter
// must supersede it for that half, including extending or clearing it.
func TestPendingHalfDeadlineSupersedesCombined(t *testing.T) {
	for _, operation := range []string{"read", "write", "empty-write"} {
		for _, clear := range []bool{false, true} {
			name := operation + "/extend"
			if clear {
				name = operation + "/clear"
			}
			t.Run(name, func(t *testing.T) {
				record := &payloadRecord{}
				withFakePayload(t, record)
				dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
				conn := newPendingTCPConn(context.Background(), dialer, net.Dialer{}, "tcp4", "192.0.2.1:443", AttemptIntent{})
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
				next := time.Now().Add(time.Minute)
				if clear {
					next = time.Time{}
				}
				var err error
				switch operation {
				case "read":
					if err = conn.SetReadDeadline(next); err == nil {
						_, err = conn.Read(make([]byte, 1))
					}
				case "write":
					if err = conn.SetWriteDeadline(next); err == nil {
						_, err = conn.Write([]byte("FIRST"))
					}
				case "empty-write":
					if err = conn.SetWriteDeadline(next); err == nil {
						_, err = conn.Write(nil)
					}
				}
				if err != nil {
					t.Fatalf("operation = %v after a half setter superseded the combined deadline", err)
				}
				if record.prepared != 1 {
					t.Fatalf("native attempts = %d, want exactly 1", record.prepared)
				}
			})
		}
	}
}

// gatedDeadlineConn blocks the first combined deadline publication, which is the
// exact window in which a completed newer half setter used to be overwritten by
// the adoption snapshot. Later calls are not gated, so the fixture cannot
// deadlock and the ordering property itself is what is measured.
type gatedDeadlineConn struct {
	*fakeConn
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once

	mu       sync.Mutex
	deadline time.Time
	accepted int
}

func newGatedDeadlineConn() *gatedDeadlineConn {
	return &gatedDeadlineConn{
		fakeConn: &fakeConn{},
		entered:  make(chan struct{}),
		resume:   make(chan struct{}),
	}
}

func (c *gatedDeadlineConn) SetDeadline(deadline time.Time) error {
	c.once.Do(func() {
		close(c.entered)
		<-c.resume
	})
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *gatedDeadlineConn) SetReadDeadline(time.Time) error { return nil }

func (c *gatedDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return nil
}

func (c *gatedDeadlineConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.deadline.IsZero() && !time.Now().Before(c.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	c.accepted += len(p)
	return len(p), nil
}

func (c *gatedDeadlineConn) counters() (time.Time, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, c.accepted
}

// A deadline setter that completes while the adopted connection is being
// published must survive the publication. The snapshot the publication applies
// may not overwrite the newer value, and later I/O must observe the newer one.
func TestPendingPublicationKeepsCompletedDeadline(t *testing.T) {
	adopted := newGatedDeadlineConn()
	installPayloadFunc(t, func(_ context.Context, _ net.Dialer, _, _ string, payload []byte, _ AttemptLease) (net.Conn, int, error) {
		return adopted, len(payload), nil
	})
	dialer := newTestDeferredDialer(t, &fakeAttemptHook{}, &fakePendingHook{})
	conn, err := dialer.DialContext(context.Background(), "tcp", testAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write([]byte("FIRST"))
		writeDone <- writeErr
	}()
	select {
	case <-adopted.entered:
	case <-time.After(time.Second):
		t.Fatal("adoption did not publish the combined deadline")
	}
	expired := time.Now().Add(-time.Second)
	setterDone := make(chan error, 1)
	go func() { setterDone <- conn.SetWriteDeadline(expired) }()
	// The gate is opened from an independent goroutine: the ordering property
	// is asserted below, never the fixture's ability to interleave forever.
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(adopted.resume)
	}()
	select {
	case err = <-setterDone:
		if err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SetWriteDeadline blocked on the adoption publication")
	}
	select {
	case err = <-writeDone:
		if err != nil {
			t.Fatalf("first write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first write did not finish")
	}
	last, accepted := adopted.counters()
	if !last.Equal(expired) {
		t.Fatalf("adopted connection deadline = %v, want the completed newer %v", last, expired)
	}
	if accepted != 0 {
		t.Fatalf("bytes accepted before the deadline update = %d, want 0", accepted)
	}
	if written, writeErr := conn.Write([]byte("NEXT")); !isDeadlineError(writeErr) {
		t.Fatalf("later write = (%d, %v), want the retained expired deadline error", written, writeErr)
	}
}

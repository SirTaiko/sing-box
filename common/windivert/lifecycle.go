package windivert

import (
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// ioLifecycle is the close-versus-registration gate of one native handle.
//
// It is deliberately portable and free of driver calls so its invariants are
// regression-tested on any host: an operation registers before the kernel can
// see it, closing refuses every later registration, cancels what is registered,
// and retires native resources only after the terminal receipts - or, when the
// kernel does not produce one inside the bounded grace, reports a non-success
// close and retires later while Done stays open. That deferral is transient: a
// late retirement which then proves successful supersedes it, so a later Close
// observes the completed retirement rather than the stale deferral.
type ioLifecycle struct {
	grace  time.Duration
	cancel func(key any)
	retire func() error

	mu      sync.Mutex
	cond    *sync.Cond
	closed  bool
	pending map[any]*ioOperation
	// err is the close result every Close returns. deferred marks it as the
	// bounded-grace result that only describes the outstanding state: it is
	// superseded by nil once the late retirement is proven successful, and
	// replaced by the durable failure when that retirement attempt fails.
	err      error
	deferred bool

	done       chan struct{}
	doneOnce   sync.Once
	retireOnce sync.Once
	retireErr  error
	closeOnce  sync.Once
}

// ioOperation is one registered native operation. armed reports that the
// kernel has been given the request: only then can a cancellation find it.
// The registration exists before submission precisely so that Close can refuse
// later work and drain what is already owned; the armed transition is what
// makes cancellation and submission linearizable in either order.
type ioOperation struct {
	armed bool
}

// newIOLifecycle builds a gate. cancel requests cancellation of one registered
// operation (it is called once per still-pending key when closing wins), retire
// releases the native resources and must run exactly once, after the drain.
func newIOLifecycle(grace time.Duration, cancel func(key any), retire func() error) *ioLifecycle {
	lifecycle := &ioLifecycle{
		grace:   grace,
		cancel:  cancel,
		retire:  retire,
		pending: make(map[any]*ioOperation),
		done:    make(chan struct{}),
	}
	lifecycle.cond = sync.NewCond(&lifecycle.mu)
	return lifecycle
}

// begin registers one native operation. After Close won the gate every begin is
// refused, including one queued behind another operation on the same lane.
func (l *ioLifecycle) begin(key any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return E.New("windivert: handle is closed")
	}
	l.pending[key] = &ioOperation{}
	return nil
}

// arm publishes that the kernel has received this operation's request. It must
// be called after the submission returned "pending" and before waiting for the
// terminal receipt. The returned closed flag tells the caller that closing won
// the gate; because the request is now visible to the kernel, the caller must
// issue its own cancellation for this exact OVERLAPPED. A Close-time
// CancelIoEx that ran before this submission could not have found the request,
// so this second, post-submission cancellation is what makes the protocol
// coherent in both interleavings:
//
//   - close before submission: this call observes closed and cancels the
//     request it just submitted;
//   - close after submission: the close-time cancellation already finds the
//     request, and this call either observes closed and repeats the harmless
//     cancellation or observes open and does nothing.
//
// A successful completion that raced either cancellation keeps its count; the
// lane's own wait still observes the terminal status.
func (l *ioLifecycle) arm(key any) (closed bool) {
	l.mu.Lock()
	if operation, loaded := l.pending[key]; loaded {
		operation.armed = true
	}
	closed = l.closed
	l.mu.Unlock()
	return closed
}

// end deregisters one operation after its terminal receipt.
func (l *ioLifecycle) end(key any) {
	l.mu.Lock()
	delete(l.pending, key)
	if l.closed && len(l.pending) == 0 {
		l.cond.Broadcast()
	}
	l.mu.Unlock()
}

// isClosed reports whether closing already won the gate.
func (l *ioLifecycle) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// Done is closed only after every registered operation reached a terminal
// receipt and retire finished.
func (l *ioLifecycle) Done() <-chan struct{} {
	return l.done
}

// Close refuses new registrations, cancels the registered operations and retires
// only after their terminal receipts. It is idempotent and safe to call
// concurrently: callers arriving while retirement is deferred observe the same
// non-success result, and callers arriving after the late retirement was proven
// observe the completed retirement instead of that transient deferral.
func (l *ioLifecycle) Close() error {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		keys := make([]any, 0, len(l.pending))
		for key := range l.pending {
			keys = append(keys, key)
		}
		pending := len(keys)
		l.mu.Unlock()
		for _, key := range keys {
			if l.cancel != nil {
				// A cancel request is not a completion; the lane's own wait
				// observes the terminal status and count.
				l.cancel(key)
			}
		}
		if pending == 0 {
			l.retireAndFinish()
			return
		}
		drained := make(chan struct{})
		go func() {
			l.mu.Lock()
			for len(l.pending) > 0 {
				l.cond.Wait()
			}
			l.mu.Unlock()
			close(drained)
		}()
		timer := time.NewTimer(l.grace)
		defer timer.Stop()
		select {
		case <-drained:
			l.retireAndFinish()
		case <-timer.C:
			// No terminal receipt inside the bounded grace. The operations are
			// canceled and their owners are still alive, so retirement is
			// deferred instead of freeing native memory under the kernel. This
			// result is recorded as deferred, not settled: it is only true while
			// the receipts are outstanding, so a later Close must not keep
			// reporting it once retirement has been proven.
			l.setDeferredErr(E.New("windivert: close: native operations still pending after ",
				l.grace, "; retirement deferred"))
			go func() {
				<-drained
				if retireErr := l.retireNative(); retireErr != nil {
					// The late retirement itself failed: Done must stay open
					// because the device/events are not proven released, and the
					// deferral becomes a durable failure.
					l.setLateRetireErr(retireErr)
					return
				}
				// The condition the deferral described no longer exists:
				// retirement is proven, so its result is success.
				l.clearDeferredErr()
				l.finish()
			}()
		}
	})
	return l.closeErr()
}

// retireAndFinish retires the native resources only when every registered
// operation produced a terminal receipt, and closes Done only when retirement
// itself succeeded. A failed CloseHandle attempt is not proof that the device
// or events were released, so it is reported and Done stays open instead of
// certifying a retirement that did not happen.
func (l *ioLifecycle) retireAndFinish() {
	err := l.retireNative()
	l.setErr(err)
	if err == nil {
		l.finish()
	}
}

func (l *ioLifecycle) closeErr() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

func (l *ioLifecycle) setErr(err error) {
	l.mu.Lock()
	l.err = err
	l.mu.Unlock()
}

// setDeferredErr records the bounded-grace outcome. It is deliberately marked
// as deferred: the error answers "retirement is not proven yet", so it must not
// outlive the proof that later settles the retirement.
func (l *ioLifecycle) setDeferredErr(err error) {
	l.mu.Lock()
	l.err = err
	l.deferred = true
	l.mu.Unlock()
}

// setLateRetireErr settles the deferred path as a durable failure: the late
// retirement attempt failed, so its error is added to the deferral and Done
// stays open.
func (l *ioLifecycle) setLateRetireErr(retireErr error) {
	l.mu.Lock()
	l.err = E.Errors(l.err, retireErr)
	l.deferred = false
	l.mu.Unlock()
}

// clearDeferredErr supersedes the transient deferral once the late retirement
// was proven successful. Only the deferred result is cleared: a settled failure
// is never dropped here.
func (l *ioLifecycle) clearDeferredErr() {
	l.mu.Lock()
	if l.deferred {
		l.err = nil
		l.deferred = false
	}
	l.mu.Unlock()
}

func (l *ioLifecycle) retireNative() error {
	l.retireOnce.Do(func() {
		if l.retire != nil {
			l.retireErr = l.retire()
		}
	})
	// retireOnce.Do gives every later caller the same completed attempt; the
	// stored error is what makes a failed retirement visible to repeated
	// Close calls instead of being reported as a clean second attempt.
	return l.retireErr
}

func (l *ioLifecycle) finish() {
	l.doneOnce.Do(func() { close(l.done) })
}

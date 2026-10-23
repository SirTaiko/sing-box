package dialer

import (
	"context"
	"errors"
	"time"
)

const (
	// connectPollSlice is the granularity of the caller completion wait: the
	// attempt context and the caller deadline are re-checked at least this
	// often, so there is still exactly one bounded wait and no second timer.
	connectPollSlice = 50 * time.Millisecond
	// connectCancelGrace bounds how long the caller waits for terminal
	// completion after CancelIoEx. Cancellation is only a request: when the
	// completion has not arrived inside this grace the per-attempt owner
	// retains the operation instead of freeing native memory the kernel may
	// still reference.
	connectCancelGrace = 100 * time.Millisecond
	// connectRetainPause delays a retention retry after a failing wait. A
	// failing wait never proves completion, so the owner keeps the operation
	// and retries instead of freeing resources that may still be in use.
	connectRetainPause = 100 * time.Millisecond
)

// outstandingConnect is the terminal-completion owner of one asynchronous
// native connect operation (Windows ConnectEx).
//
// It is owned by the per-attempt code that issued the operation. While the
// caller can still absorb the latency, that same owner waits inline and frees
// the resources exactly once after terminal completion. When the caller's
// budget ends first, the owner cancels the request, gives the kernel a bounded
// grace to report completion, and otherwise retains the operation: the
// OVERLAPPED, its event, the socket handle and the initial payload stay alive
// until the kernel reports terminal completion, and only then are they freed.
//
// Retention is bounded by the existing attempt admission: a retained operation
// is a subset of the admitted native attempts, and there is exactly one
// retention goroutine per retained operation. There is no global queue, no
// shared reaper daemon and no public knob.
type outstandingConnect struct {
	// wait reports terminal completion of the event, or false on timeout.
	// timeout < 0 waits without a caller budget.
	wait func(timeout time.Duration) (signaled bool, err error)
	// result harvests the authoritative transferred count of the completed
	// operation and clears its overlapped state.
	result func() (transferred uint32, err error)
	// cancel requests cancellation without waiting for it.
	cancel func() error
	// release frees the non-socket resources of the operation (event and
	// overlapped ownership). It runs exactly once, after completion.
	release func()
	// retireSocket frees the module-owned socket handle of the operation and
	// reports whether the native release is proven. It is only used by the
	// retention path, where the caller no longer owns the socket and the
	// platform's documented close-error contract applies: a would-block
	// outcome leaves the descriptor valid and is retried through the same
	// socket API by this owner, an ambiguous outcome returns an
	// unresolved-retirement error, and nothing is closed twice. A failed
	// release keeps the operation's admission charge: it is not retried
	// blindly and it never discharges the native hold.
	retireSocket func() (proven bool, err error)
	// buffer keeps the initial payload submitted to the kernel reachable for
	// the entire operation, including after the caller returned.
	buffer []byte
	// lease is the attempt's existing admission owner. A retained operation
	// keeps it charged until the kernel reports terminal completion: the
	// per-attempt caller must not close it while the operation is still owned
	// (see retainedAttemptError). It is nil for operations without an
	// admission owner.
	lease AttemptLease
	// nativeHold discharges the admission reference acquired before the
	// native connect existed. The operation owns it from retention until its
	// terminal retirement; a nil hold means the operation was not issued by
	// the retaining helper.
	nativeHold func()

	released bool
	retained bool
}

// connectCompletion is one observation of the outstanding operation. It
// separates a failed wait (completion is still unknown) from a terminal
// completion that ended in an error (completion is proven, the operation
// failed).
type connectCompletion struct {
	complete    bool
	transferred uint32
	resultErr   error
	waitErr     error
}

// awaitConnectCompletion waits for terminal completion until the earliest of
// the caller deadline and attempt context cancellation. It returns the
// authoritative byte count of a completed operation, or a terminal error.
//
// A caller budget that ends first never frees the operation: it is cancelled,
// observed for a bounded grace, and otherwise retained.
func (c *outstandingConnect) awaitConnectCompletion(ctx context.Context, deadline time.Time) (uint32, error) {
	for {
		remaining := connectPollSlice
		if !deadline.IsZero() {
			left := time.Until(deadline)
			if left <= 0 {
				return c.abandon(context.DeadlineExceeded)
			}
			if left < remaining {
				remaining = left
			}
		}
		observation := c.poll(remaining)
		if observation.waitErr != nil {
			// A failing wait is not a completion: keep the operation owned.
			return c.retainFailed(observation.waitErr)
		}
		if observation.complete {
			return observation.transferred, observation.resultErr
		}
		select {
		case <-ctx.Done():
			reason := ctx.Err()
			if reason == nil {
				reason = context.Canceled
			}
			return c.abandon(reason)
		default:
		}
	}
}

// poll waits one bounded slice for terminal completion and harvests the result
// when it arrives.
func (c *outstandingConnect) poll(timeout time.Duration) connectCompletion {
	signaled, err := c.wait(timeout)
	if err != nil {
		return connectCompletion{waitErr: err}
	}
	if !signaled {
		return connectCompletion{}
	}
	transferred, resultErr := c.result()
	if resultErr != nil {
		// A failed operation has no authoritative accepted-byte count. The
		// count contract is enforced here, at the owner every platform shares,
		// so a provider that leaves its out value undefined can never report
		// initial-payload progress for a connection that does not exist. A
		// successfully completed operation keeps its authoritative count.
		transferred = 0
	}
	c.releaseResources()
	return connectCompletion{complete: true, transferred: transferred, resultErr: resultErr}
}

// abandon requests cancellation and observes the operation for the bounded
// grace. It returns the reason after either inline completion or retention, so
// the caller's latency never exceeds that grace.
func (c *outstandingConnect) abandon(reason error) (uint32, error) {
	_ = c.cancel()
	graceEnd := time.Now().Add(connectCancelGrace)
	for {
		remaining := time.Until(graceEnd)
		if remaining <= 0 {
			break
		}
		observation := c.poll(remaining)
		if observation.waitErr != nil {
			break
		}
		if observation.complete {
			// The completion raced the cancellation. The operation is terminal
			// and its event/overlapped ownership was freed inline; the caller
			// still owns the socket and closes it through the attempt's own
			// cleanup.
			return observation.transferred, reason
		}
	}
	c.retain(reason)
	return 0, reason
}

// retainFailed retains an operation whose wait failed: an unobservable
// completion is still a live operation.
func (c *outstandingConnect) retainFailed(waitErr error) (uint32, error) {
	_ = c.cancel()
	c.retain(waitErr)
	return 0, waitErr
}

// retain hands the outstanding operation to its own completion waiter. The
// caller returns immediately; the waiter frees the event, overlapped and socket
// only after the kernel reported terminal completion, and only then discharges
// the operation's native reference. The attempt's capture teardown is initiated
// immediately, independently of that receipt: a capture that cannot be torn
// down quickly must not be coupled to an unprovable native completion.
func (c *outstandingConnect) retain(reason error) {
	if c.released || c.retained {
		return
	}
	c.retained = true
	lease := c.lease
	hold := c.nativeHold
	c.nativeHold = nil
	var closeDone chan struct{}
	if lease != nil {
		closeDone = make(chan struct{})
		go func() {
			// Exactly one owner invokes AttemptLease.Close on this path (the
			// caller path is excluded by the retained marker). It runs before
			// the terminal receipt is known, so capture teardown is prompt.
			_ = lease.Close(reason)
			close(closeDone)
		}()
	}
	go func() {
		for {
			observation := c.poll(-1)
			if observation.waitErr != nil {
				time.Sleep(connectRetainPause)
				continue
			}
			if observation.complete {
				// Terminal completion, including a failed operation: only now
				// is the kernel done with the socket and with the submitted
				// payload. The native I/O receipt is not a socket release, so the
				// release runs separately under its own documented error
				// contract: a would-block descriptor is retried by this same
				// owner, and an unproven release performs no further native side
				// effect.
				proven, retireErr := c.retireSocket()
				if retireErr != nil {
					// The caller returned before this point, so the attempt's
					// lease is the only surviving error path: the close error is
					// reported there instead of being dropped.
					c.reportRetirementFailure(retireErr)
				}
				if !proven {
					// The descriptor may still be valid and is never closed again:
					// the operation keeps its native admission charge as an
					// unresolved tombstone of this attempt.
					return
				}
				if closeDone != nil {
					<-closeDone
				}
				if hold != nil {
					hold()
				}
				return
			}
			// An unbounded wait must not time out; a substituted or faulty
			// wait that does is retried without busy-spinning.
			time.Sleep(connectRetainPause)
		}
	}()
}

// nativeFailureReporter is the optional diagnostic capability of an attempt
// lease. A retained operation outlives its caller, so a socket retirement that
// cannot be proven at terminal completion has no caller error to join: the
// attempt's lease is the existing per-attempt diagnostic owner that stays
// charged (it already owns the native hold and the capture teardown). The
// dialer reports the failure there instead of dropping it, and never widens
// admission accounting or creates a second owner for the descriptor. A lease
// that does not implement the capability keeps its charge and simply has no
// diagnostic sink: the error can then only be observed through the retained
// tombstone itself.
type nativeFailureReporter interface {
	ReportNativeFailure(err error)
}

// reportRetirementFailure publishes one terminal socket-retirement failure on
// the attempt lease's existing diagnostic path. It performs no native side
// effect, holds no lock of its own and cannot delay the caller: the caller of a
// retained operation already returned.
func (c *outstandingConnect) reportRetirementFailure(err error) {
	if err == nil {
		return
	}
	if reporter, ok := c.lease.(nativeFailureReporter); ok {
		reporter.ReportNativeFailure(err)
	}
}

// releaseResources frees the event/overlapped ownership exactly once.
func (c *outstandingConnect) releaseResources() {
	if c.released {
		return
	}
	c.released = true
	c.release()
}

// connectTransferred resolves the authoritative number of initial payload
// bytes accepted by one native connect attempt and clamps it to the submitted
// payload.
//
// A synchronous ConnectEx success reports the count through its initiation out
// parameter. An asynchronous operation reports it only at terminal completion,
// so the completion count is authoritative there and the initiation value must
// never be reused: doing so replays the uncertain prefix on the same socket.
func connectTransferred(asynchronous bool, initiation uint32, completion uint32, payload int) int {
	count := initiation
	if asynchronous {
		count = completion
	}
	if uint64(count) > uint64(payload) {
		return payload
	}
	return int(count)
}

// retainedAttemptError marks an attempt whose native operation outlived the
// caller budget and is now owned by its retained completion owner. The
// per-attempt caller path must not close the attempt lease of such an attempt:
// the lease is the existing admission charge of the operation and is discharged
// by the completion owner only after the kernel reports terminal completion.
// The wrapped error is otherwise returned unchanged, so the caller still sees
// its deadline/cancellation contract.
type retainedAttemptError struct {
	err error
}

func (e *retainedAttemptError) Error() string { return e.err.Error() }

func (e *retainedAttemptError) Unwrap() error { return e.err }

// retainedOperation reports whether err belongs to an attempt whose native
// operation is retained until terminal native completion.
func retainedOperation(err error) bool {
	var retained *retainedAttemptError
	return errors.As(err, &retained)
}

package windivert

import "errors"

// RetainedOpenError is an Open failure whose native resources could not be
// proven retired inside the bounded close grace. Joining the cleanup error into
// the Open error keeps the diagnosis, but the diagnosis is not an ownership
// receipt: the device and its lane events may still be alive, so the caller must
// keep whatever admission charge protected this activation until the kernel
// proves retirement. This type carries exactly that receipt through the existing
// Open error boundary, so the existing per-attempt charge owner can stay charged
// instead of being discharged on a failed activation.
//
// A proven rollback is not reported this way: Open returns the plain joined
// error and the caller's charge can be discharged immediately.
type RetainedOpenError struct {
	err  error
	done <-chan struct{}
}

func (e *RetainedOpenError) Error() string { return e.err.Error() }

// Unwrap exposes the original activation and cleanup errors. Callers that only
// classify failures keep working unchanged.
func (e *RetainedOpenError) Unwrap() error { return e.err }

// Retired is the retirement receipt: it is closed only after the retained
// device and lane events were actually released. A failed late release keeps it
// open, exactly like Handle.Done.
func (e *RetainedOpenError) Retired() <-chan struct{} { return e.done }

// RetainedRetirement returns the retirement receipt of a failed Open whose
// cleanup is still outstanding, and reports false for every ordinary activation
// error (argument validation, filter encoding, a rollback that proved
// retirement). It never widens ownership: the receipt is the Handle's own Done
// channel, so there is exactly one retirement owner.
func RetainedRetirement(err error) (<-chan struct{}, bool) {
	var retained *RetainedOpenError
	if errors.As(err, &retained) && retained.done != nil {
		return retained.done, true
	}
	return nil, false
}

// NewRetainedOpenError builds the carrier Open returns for a failed activation
// whose native resources are still being retired. retired must be the retirement
// receipt of exactly one native owner (for Open it is Handle.Done); it is never
// copied, wrapped or polled, only awaited.
func NewRetainedOpenError(err error, retired <-chan struct{}) error {
	return &RetainedOpenError{err: err, done: retired}
}

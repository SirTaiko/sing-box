package desync

// Endpoint producer gate.
//
// The selected-A Windows contract (carried D§4) needs a real barrier between
// the caller's socket operations and the capture's receive shutdown. The
// semantic dispatch gate cannot supply it: a caller write is a syscall that
// never passes through captureDispatchGate, and raw native sends bypass the
// driver's send lane entirely. This gate is therefore the per-Lease owner of
// "may an application socket production start now?".
//
// It is deliberately tiny and platform-neutral:
//
//   - a producing operation enters under the gate lock and records its
//     terminal end (the end function is idempotent and follows the actual
//     socket operation's return, never a wrapper's return);
//   - pause publishes PAUSING under the same lock before it waits, so an
//     operation that arrives later waits without copying its payload and the
//     wait converges;
//   - resume is only called after the positive capture-retired receipt; a
//     writer that waited out the pause then performs the real socket
//     operation unchanged (same socket, same bytes, no fabricated result);
//   - the gate is a leaf: no caller holds an Engine/Lease/flow lock while it
//     waits, and no receive/Completer path ever enters it.
//
// The zero value is not usable; NewEndpointProducerGate owns the condition
// variable.

import (
	"errors"
	"sync"
)

// producerPhase is the admission state of one Lease's endpoint production.
type producerPhase uint8

const (
	// producerRunning admits operations immediately.
	producerRunning producerPhase = iota
	// producerPausing is published before the pause waits. New operations
	// queue behind the pause instead of extending it.
	producerPausing
	// producerPaused means every covered operation ended; the capture may now
	// stop its receive path.
	producerPaused
	// producerClosed refuses new operations permanently.
	producerClosed
)

// errEndpointProducerClosed reports a gate that was shut down without a
// resume. It is not returned merely because the semantic Lease closed.
var errEndpointProducerClosed = errors.New("desync: endpoint producer gate is closed")

// endpointProducerGate is the per-Lease socket-production admission gate.
type endpointProducerGate struct {
	mu     sync.Mutex
	cond   *sync.Cond
	phase  producerPhase
	active int
	// paused counts completed pause publications; resume consumes one.
	pauses int
	// failure refuses new production without joining operations already admitted.
	// It is sticky and orthogonal to shutdown pause/endpoint close.
	failure error
}

func newEndpointProducerGate() *endpointProducerGate {
	gate := &endpointProducerGate{cond: sync.NewCond(&sync.Mutex{})}
	// The condition variable owns the same mutex as the gate, so a single
	// lock protects the phase and the counters.
	gate.cond = sync.NewCond(&gate.mu)
	return gate
}

// begin enters one producing operation. It returns once the operation may
// perform its real socket call, and the caller must invoke end on the actual
// terminal return of that call (including an error). begin blocks while a
// pause is pending; it does not fail because the semantic lease closed.
func (g *endpointProducerGate) begin() (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for {
		if g.failure != nil {
			return nil, g.failure
		}
		switch g.phase {
		case producerClosed:
			return nil, errEndpointProducerClosed
		case producerRunning:
			g.active++
			var once sync.Once
			return func() {
				once.Do(func() {
					g.mu.Lock()
					if g.active > 0 {
						g.active--
					}
					g.cond.Broadcast()
					g.mu.Unlock()
				})
			}, nil
		case producerPausing, producerPaused:
			g.cond.Wait()
		}
	}
}

// pause publishes PAUSING and waits until every already admitted operation
// ended. The returned token is idempotent at resume. A second pause while the
// first is still waiting is served by the first publication.
func (g *endpointProducerGate) pause() *endpointProducerToken {
	g.mu.Lock()
	if g.phase == producerRunning {
		g.phase = producerPausing
	}
	for g.active > 0 {
		g.cond.Wait()
	}
	if g.phase != producerClosed {
		g.phase = producerPaused
		g.pauses++
	}
	g.mu.Unlock()
	return &endpointProducerToken{gate: g}
}

// resume releases a paused gate. Only the positive capture-retired receipt may
// call it: waiting writers then perform their real operation on the endpoint
// that is still owned and open.
func (g *endpointProducerGate) resume(token *endpointProducerToken) {
	if token == nil || token.gate != g {
		return
	}
	token.once.Do(func() {
		g.mu.Lock()
		if g.phase == producerPaused {
			if g.pauses > 0 {
				g.pauses--
			}
			if g.pauses == 0 {
				g.phase = producerRunning
			}
		}
		g.cond.Broadcast()
		g.mu.Unlock()
	})
}

// close permanently refuses new operations. It is used only by a failed
// activation rollback, never by an ordinary capture retirement (which resumes
// the gate for a still-owned endpoint).
func (g *endpointProducerGate) close() {
	g.mu.Lock()
	g.phase = producerClosed
	g.cond.Broadcast()
	g.mu.Unlock()
}

// fail is a nonwaiting leaf operation. Only Windows capture failures invoke it;
// ordinary Linux retirement and normal pause/resume are unchanged.
func (g *endpointProducerGate) fail(err error) {
	if err == nil {
		return
	}
	g.mu.Lock()
	if g.failure == nil {
		g.failure = err
	}
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *endpointProducerGate) err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failure
}

// closeAndWait is endpoint release, not semantic Lease.Close. The positive
// capture receipt has already arrived. Refuse later operations and join every
// operation admitted before this publication before the owner closes its socket.
func (g *endpointProducerGate) closeAndWait() {
	g.mu.Lock()
	g.phase = producerClosed
	g.cond.Broadcast()
	for g.active != 0 {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

// state reports the current phase and active count for tests and diagnostics.
func (g *endpointProducerGate) state() (producerPhase, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.phase, g.active
}

// endpointProducerToken is the one-shot resume capability of a pause.
type endpointProducerToken struct {
	gate *endpointProducerGate
	once sync.Once
}

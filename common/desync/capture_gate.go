package desync

import "sync"

// captureDispatchGate is the ordered close gate shared by every receive loop of
// one capture. It has three phases:
//
//  1. open: records may be dispatched to the semantic engine and their
//     disposition may be sent;
//  2. fenced: no new dispatch starts, but records already inside the engine and
//     dispositions already in flight are allowed to resolve - the close path
//     waits for exactly those;
//  3. pass-through: records captured during phase 2 are forwarded unchanged,
//     but only after the lease released the held originals of earlier captures,
//     so a queued record can never overtake a held one.
//
// The phase transition and the "may I still send" check share one mutex, so a
// disposition either belongs to the pre-fence group (and Quiesce waits for it)
// or waits for the pass-through release. It is deliberately independent of the
// lease and of the driver: the ordering it enforces is the D3 phase boundary
// itself, so it is regression-tested on every host.
type captureDispatchGate struct {
	mu       sync.Mutex
	cond     *sync.Cond
	fenced   bool
	dispatch int
	sending  int
	released bool
	pass     chan struct{}
}

func newCaptureDispatchGate() *captureDispatchGate {
	gate := &captureDispatchGate{pass: make(chan struct{})}
	gate.cond = sync.NewCond(&gate.mu)
	return gate
}

// beginDispatch starts the semantic handling of one captured record. It reports
// false after the fence won: that record is pass-through only.
func (g *captureDispatchGate) beginDispatch() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fenced {
		return false
	}
	g.dispatch++
	return true
}

// endDispatch finishes the semantic handling of one record. The disposition is
// still owned by the caller and must be started with beginSend.
func (g *captureDispatchGate) endDispatch() {
	g.mu.Lock()
	g.dispatch--
	if g.dispatch == 0 && g.sending == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

// beginSend claims the disposition slot of one record. It reports false after
// the fence won: the caller must wait on awaitPassThrough and only then send,
// so the record cannot overtake an older held original. A true result is a
// pre-fence disposition that quiesce waits for before releasing held data.
func (g *captureDispatchGate) beginSend() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fenced {
		return false
	}
	g.sending++
	return true
}

func (g *captureDispatchGate) endSend() {
	g.mu.Lock()
	g.sending--
	if g.dispatch == 0 && g.sending == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}

// isFenced reports whether the close phase already started.
func (g *captureDispatchGate) isFenced() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.fenced
}

// fence publishes the close fence without waiting for the records already
// inside the engine. It is the publication half of quiesce: after it returns no
// new record can enter the semantic engine, while records that already started
// keep their pre-fence disposition. The lease calls it before it publishes its
// own closed flag, so "the lease is closed" and "the capture is fenced" become
// one linearization point instead of an interval in which a queued record could
// take the closed-lease fast-pass and be sent before the held originals are
// flushed. It never blocks and never calls back into the lease, so it may be
// taken under the lease lock (the gate is a leaf lock: no path holds it while
// acquiring the lease lock).
func (g *captureDispatchGate) fence() {
	g.mu.Lock()
	g.fenced = true
	g.mu.Unlock()
}

// awaitPassThrough blocks a record captured after the fence until the lease
// released the held originals of earlier captures. It is safe after release.
func (g *captureDispatchGate) awaitPassThrough() {
	<-g.pass
}

// allowPassThrough releases queued post-fence records. It is idempotent: the
// lease calls it after flushing held data, and a direct capture close calls it
// when no lease-ordered flush exists.
func (g *captureDispatchGate) allowPassThrough() {
	g.mu.Lock()
	if !g.released {
		g.released = true
		close(g.pass)
	}
	g.mu.Unlock()
}

// quiesce fences the gate and waits until every record that already started
// dispatching or sending resolved. After it returns no record can be sent
// except through awaitPassThrough, so the caller can flush the held set knowing
// it is complete.
func (g *captureDispatchGate) quiesce() {
	g.fence()
	g.mu.Lock()
	for g.dispatch > 0 || g.sending > 0 {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

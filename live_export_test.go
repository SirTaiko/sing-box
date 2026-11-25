package box

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"github.com/sagernet/sing-box/adapter"
)

func (s *Box) RoutingPolicyDrainedForTest() <-chan struct{} {
	return s.live.active.Load().drained
}

func TestRetiredAssetClosesOutsideItsLastFlow(t *testing.T) {
	runtime := &liveRuntime{stop: make(chan struct{})}
	policy := &routingPolicy{live: runtime, assets: make(map[any]*policyAsset)}
	scope := adapter.NewScope(context.Background(), nil)
	started, proceed := make(chan struct{}), make(chan struct{})
	defer func() { close(proceed); runtime.cleanup.Wait() }()
	scope.Add(func() error { close(started); <-proceed; return nil })
	policy.own("transport", scope)
	asset := policy.assets["transport"]
	asset.flows.Add(1)
	policy.release()
	select {
	case <-started:
		t.Fatal("retired a resource still in use")
	default:
	}
	released := make(chan struct{})
	go func() { asset.dropFlow(); close(released) }()
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("scope cleanup blocked its own flow callback")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("retired resource did not start closing")
	}
}

// The returned probe contains only weak pointers, including to the cold-start objects.
func (s *Box) PolicyObjectsForTest() func() [5]bool {
	p := s.live.active.Load()
	r, d, o, e, tr := weak.Make(p.router), weak.Make(p.dns), weak.Make(p.out), weak.Make(p.end), weak.Make(p.transports)
	return func() [5]bool {
		return [5]bool{r.Value() != nil, d.Value() != nil, o.Value() != nil, e.Value() != nil, tr.Value() != nil}
	}
}

// Observe retirement without holding the outbound or its routing generation.
func (s *Box) OutboundScopeDoneForTest(tag string) <-chan struct{} {
	p := s.live.active.Load()
	ob, _ := p.out.Outbound(tag)
	return p.assets[ob].scope.Context().Done()
}

func (s *Box) DNSScopeDoneForTest(tag string) <-chan struct{} {
	p := s.live.active.Load()
	transport, _ := p.transports.Transport(tag)
	return p.assets[transport].scope.Context().Done()
}

// Exercise the normal flow handoff without requiring an external corporate gateway.
func (s *Box) HoldEndpointFlowForTest(tag string) (func(), <-chan struct{}) {
	p := s.live.active.Load()
	ep, _ := p.end.Get(tag)
	closeFlow, handoff := p.leaseForFlow(nil)
	handoff([]adapter.Outbound{ep})
	return func() { closeFlow(nil) }, p.assets[ep].scope.Context().Done()
}

func TestAbortCancelsOnlyCandidateDNSReaders(t *testing.T) {
	h := &liveRuntime{stop: make(chan struct{})}
	active := &routingPolicy{live: h, drained: make(chan struct{})}
	active.refs.Store(1)
	h.active.Store(active)
	h.view = newPolicyView(h)
	staged := &routingPolicy{live: h, drained: make(chan struct{})}
	staged.refs.Store(1)
	staged.preparing, staged.cancelPreparation = context.WithCancel(context.Background())
	staged.construction = newPolicyView(h)
	staged.construction.staged.Store(staged)
	_, stableQuery, finishStable := h.view.acquireQuery(context.Background())
	defer finishStable()
	_, pendingQuery, finishPending := staged.construction.acquireQuery(context.Background())
	go func() { <-pendingQuery.Done(); finishPending() }()
	aborted := make(chan error, 1)
	cause := errors.New("invalid candidate")
	go func() { aborted <- staged.abort(cause) }()
	select {
	case err := <-aborted:
		if !errors.Is(err, cause) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		finishPending()
		staged.cancelPreparation()
		t.Fatal("rollback blocked on candidate DNS")
	}
	if stableQuery.Err() != nil || h.active.Load() != active {
		t.Fatal("rollback cancelled an active query or published the candidate")
	}
}

func TestConcurrentFlowHandoffAndCloseBalanceBothReferences(t *testing.T) {
	for i := 0; i < 1000; i++ {
		var policy, assets atomic.Int32
		lease := flowLease{release: func() { policy.Add(1) }}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); lease.replace(func() { assets.Add(1) }) }()
		go func() { defer wg.Done(); lease.replace(nil) }()
		wg.Wait()
		if policy.Load() != 1 || assets.Load() != 1 {
			t.Fatal("unbalanced release", policy.Load(), assets.Load())
		}
	}
}

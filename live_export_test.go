package box

import (
	"context"
	"testing"
	"time"

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

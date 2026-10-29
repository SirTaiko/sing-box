package desync

import (
	"errors"
	"testing"
	"time"
)

func TestEndpointProducerFailureDoesNotJoinOrResume(t *testing.T) {
	g := newEndpointProducerGate()
	end, err := g.begin()
	if err != nil {
		t.Fatal(err)
	}
	paused := make(chan *endpointProducerToken, 1)
	go func() { paused <- g.pause() }()
	waitProducerCondition(t, "pause", func() bool { p, _ := g.state(); return p == producerPausing })
	waiting := make(chan error, 1)
	go func() { _, e := g.begin(); waiting <- e }()
	failure := errors.New("capacity")
	// A permanently failed producer must not join the active operation. The
	// ordinary pause still must join it; a failure is not producerClosed.
	g.fail(failure)
	select {
	case e := <-waiting:
		if !errors.Is(e, failure) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("failure did not wake waiting admission")
	}
	select {
	case <-paused:
		t.Fatal("failure skipped active join")
	default:
	}
	end()
	end()
	token := <-paused
	g.resume(token)
	g.resume(token)
	if _, e := g.begin(); !errors.Is(e, failure) {
		t.Fatalf("resume erased failure: %v", e)
	}
	if _, n := g.state(); n != 0 {
		t.Fatal("failed admission incremented active")
	}
}

package desync

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A failed capture Close is not permission for a cached endpoint producer to
// enter the native socket. Exercise the real Lease composition, not just the
// leaf gate's resume method.
func TestLeaseNegativeRetirementKeepsProducerPaused(t *testing.T) {
	failure := errors.New("capture retirement unproven")
	capture := &producerOrderCapture{err: failure}
	lease := newProducerOrderLease(t, capture)
	if err := lease.Close(nil); !errors.Is(err, failure) {
		t.Fatalf("Close = %v", err)
	}
	if err := lease.WaitCaptureRetired(); !errors.Is(err, failure) {
		t.Fatalf("receipt = %v", err)
	}
	phase, active := lease.producers.state()
	if phase != producerPaused || active != 0 {
		t.Fatalf("negative receipt released producer gate: phase=%v active=%d", phase, active)
	}
	entered := make(chan error, 1)
	go func() {
		end, err := lease.BeginEndpointWrite()
		if err == nil {
			end()
		}
		entered <- err
	}()
	select {
	case err := <-entered:
		t.Fatalf("producer admitted without safe receipt: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	// Fixture-only disposal; production must retain the pending caller.
	lease.producers.close()
	<-entered
	if got := lease.engine.ActiveLeases(); got != 1 {
		t.Fatalf("charge = %d", got)
	}
}

func TestLeaseNegativeRetirementRetainsCaptureOwner(t *testing.T) {
	capture := &producerOrderCapture{err: errors.New("native memory still owned")}
	lease := newProducerOrderLease(t, capture)
	if err := lease.Close(nil); err == nil {
		t.Fatal("negative receipt lost")
	}
	lease.mu.Lock()
	retained := lease.capture
	lease.mu.Unlock()
	if retained != capture {
		t.Fatal("charged Lease lost its native capture/buffer owner")
	}
}

type openingRetirementBackend struct {
	entered, release chan struct{}
	capture          *openingRetirementCapture
	openErr          error
}
type openingRetirementCapture struct {
	release func()
	closes  atomic.Int32
	once    sync.Once
}

func (c *openingRetirementCapture) Close() error {
	c.once.Do(func() { c.closes.Add(1); c.release() })
	return nil
}
func (b *openingRetirementBackend) Name() string { return "opening-retirement" }
func (b *openingRetirementBackend) Open(l *Lease) (Capture, error) {
	release, err := l.AcquireNativeHold()
	if err != nil {
		return nil, err
	}
	b.capture.release = release
	close(b.entered)
	<-b.release
	return b.capture, b.openErr
}

func TestLeaseCloseJoinsOpeningCapture(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "retained-failure"}[failed], func(t *testing.T) {
			b := &openingRetirementBackend{entered: make(chan struct{}), release: make(chan struct{}), capture: &openingRetirementCapture{}}
			if failed {
				b.openErr = errors.New("partial activation retained")
			}
			e, err := NewEngine(maxOneConfig(t), b)
			if err != nil {
				t.Fatal(err)
			}
			l, err := e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportUDP})
			if err != nil {
				t.Fatal(err)
			}
			opened := make(chan error, 1)
			go func() { opened <- l.StartCapture() }()
			<-b.entered
			closed := make(chan error, 1)
			go func() { closed <- l.Close(nil) }()
			waitProducerCondition(t, "closed flag", func() bool { return l.closedFlag.Load() })
			select {
			case <-l.captureRetired:
				t.Error("capture-safe receipt published while Open still owned native effects")
			case <-time.After(20 * time.Millisecond):
			}
			if e.ActiveLeases() != 1 {
				t.Error("opening native charge lost")
			}
			close(b.release)
			if err := <-opened; !errors.Is(err, errLeaseClosed) {
				t.Errorf("opening after Close = %v", err)
			}
			if err := <-closed; err != nil {
				t.Errorf("joined Close = %v", err)
			}
			if err := l.WaitCaptureRetired(); err != nil {
				t.Errorf("safe receipt=%v", err)
			}
			if got := b.capture.closes.Load(); got != 1 {
				t.Errorf("partial capture closes=%d", got)
			}
			if got := e.ActiveLeases(); got != 0 {
				t.Errorf("retired charge=%d", got)
			}
			_ = e.Close()
		})
	}
}

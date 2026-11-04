//go:build linux

package desync

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type guardFailureSession struct {
	*fakeAnchorSession
	kind       string
	gate       func()
	unreadable *atomic.Bool
}

func (s *guardFailureSession) batch(requests []nftRequest) ([]nftReply, error) {
	matched := false
	for _, r := range requests {
		if (strings.HasPrefix(s.kind, "m-") && strings.Contains(string(r.data), ":m:")) ||
			(strings.HasPrefix(s.kind, "w-") && strings.Contains(string(r.data), ":w:")) {
			matched = true
		}
	}
	if !matched {
		return s.fakeAnchorSession.batch(requests)
	}
	if s.kind == "m-rejected" {
		s.gate()
		return nil, unix.EPERM
	}
	r, err := s.fakeAnchorSession.batch(requests)
	if err != nil {
		return r, err
	}
	s.unreadable.Store(true)
	s.gate()
	if strings.Contains(s.kind, "ack") {
		return nil, errNftMetadataTimeout
	}
	return r, nil
}
func (s *guardFailureSession) generation(f byte) (uint32, error) {
	if s.unreadable.Load() {
		return 0, unix.EPERM
	}
	return s.fakeAnchorSession.generation(f)
}

// A real ForkLock writer inspects modeled ownership at its FIRST acquisition.
// TryRLock rejection proves the writer queued, rather than relying on a sleep.
func guardWriterQueued(t *testing.T, result <-chan int) (int, bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		select {
		case n := <-result:
			return n, true
		default:
		}
		if !syscall.ForkLock.TryRLock() {
			return 0, false
		}
		syscall.ForkLock.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("MODEL: actual fork writer did not queue")
		}
		runtime.Gosched()
	}
}
func guardCount(s *linuxCaptureSeams) int {
	s.guardsMu.Lock()
	defer s.guardsMu.Unlock()
	return len(s.guards)
}

type guardResidue struct {
	tables map[byte]map[string]*fakeNftTable
	gen    uint32
	ports  []uint32
	guards int
	owners map[string]int
	closes int
}

func guardResidueSnapshot(s *linuxCaptureSeams, data *fakeNFQueueConn) guardResidue {
	s.anchors.mu.Lock()
	tables := s.anchors.clone().tables
	gen := s.anchors.gen
	s.anchors.mu.Unlock()
	r := guardResidue{tables: tables, gen: gen, ports: s.boundPortList(), guards: guardCount(s), owners: make(map[string]int), closes: data.closings()}
	anchorOwnerRegistry.Lock()
	for _, o := range anchorOwnerRegistry.owners {
		o.mu.Lock()
		r.owners[o.token] = o.refs
		o.mu.Unlock()
	}
	anchorOwnerRegistry.Unlock()
	return r
}

func testAnchorGuardFailures(t *testing.T) {
	for _, kind := range []string{"tx-error", "session-error", "guard-error", "pre-m-collision", "m-rejected", "m-ack-unknown", "m-readback-unknown", "bind-error", "w-encode-error", "w-ack-unknown", "w-readback-unknown"} {
		t.Run(kind, func(t *testing.T) {
			data := newFakeNFQueueConn("provisional", 0, nil)
			seams := installLinuxCaptureSeams(t, data)
			engine, lease := newLinuxCaptureLease(t, 16510)
			entered, release := make(chan struct{}), make(chan struct{})
			var gated, unblock sync.Once
			gate := func() { gated.Do(func() { close(entered); <-release }) }
			defer unblock.Do(func() { close(release) })
			var unreadable atomic.Bool
			baseSession := openAnchorSession
			openAnchorSession = func() (anchorSession, error) {
				if kind == "session-error" {
					gate()
					return nil, unix.EPERM
				}
				return &guardFailureSession{fakeAnchorSession: &fakeAnchorSession{namespace: seams.anchors, port: 0x40000032}, kind: kind, gate: gate, unreadable: &unreadable}, nil
			}
			if kind == "tx-error" {
				bindAnchorTransactionSocket = func(string) (int, error) { gate(); return -1, unix.EPERM }
			}
			if kind == "guard-error" {
				bindAnchorGuardSocket = func(string) (*anchorGuard, error) { gate(); return nil, unix.EPERM }
			}
			if kind == "pre-m-collision" {
				s := &fakeAnchorSession{namespace: seams.anchors, port: 0x40000032}
				if _, err := s.batch([]nftRequest{nftTableMessage(2, anchorTableName, nil)}); err != nil {
					t.Fatal(err)
				}
				bindAnchorGuardSocket = func(name string) (*anchorGuard, error) { g, err := seams.bindGuard(name); gate(); return g, err }
			}
			if kind == "bind-error" {
				data.setExecuteHook(func(int, netlink.Message) error { gate(); return unix.EPERM })
			}
			encode := anchorPortUserdataRecord
			if kind == "w-encode-error" {
				anchorPortUserdataRecord = func(f byte, e, p, c string, port uint32, phase string, tag uint32) (nftRequest, error) {
					if phase == "w" {
						gate()
						return nftRequest{}, unix.EPERM
					}
					return encode(f, e, p, c, port, phase, tag)
				}
				t.Cleanup(func() { anchorPortUserdataRecord = encode })
			}
			opened := make(chan error, 1)
			go func() { opened <- lease.StartCapture() }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("MODEL failure boundary not reached")
			}
			writer := make(chan int, 1)
			go func() {
				syscall.ForkLock.Lock()
				n := guardCount(seams)
				if data.closings() == 0 && len(seams.boundPortList()) > 0 {
					n += 100
				}
				writer <- n
				syscall.ForkLock.Unlock()
			}()
			n, early := guardWriterQueued(t, writer)
			if early {
				t.Error("MODEL: fork writer escaped while provisional guard/failure operation was active")
			}
			unblock.Do(func() { close(release) })
			if err := waitWithin(t, "failed first open", opened); err == nil {
				t.Fatal("MODEL: failed open succeeded")
			}
			if !early {
				select {
				case n = <-writer:
				case <-time.After(3 * time.Second):
					t.Fatal("MODEL: recursive token/deadlock")
				}
			}
			if n != 0 {
				t.Errorf("MODEL: fork writer saw unpublished guard/queue after token release: %d", n)
			}
			if guardCount(seams) != 0 {
				t.Error("MODEL: failed first open kept provisional guard")
			}
			unknown := strings.HasSuffix(kind, "unknown")
			if unknown {
				lease.mu.Lock()
				c, ok := lease.capture.(*linuxCapture)
				lease.mu.Unlock()
				if !ok {
					t.Error("MODEL: uncertain metadata lost same capture/admission owner")
					return
				}
				key := captureKey(c.owner.token, c.anchor.capture)
				before := modelCaptureRecords(t, seams, FamilyIPv4)[key]
				if before == nil || before.port == nil {
					t.Fatal("MODEL: uncertain committed identity lost")
				}
				phase := "o"
				if strings.HasPrefix(kind, "w-") {
					phase = "w"
				}
				if before.port.record.phase != phase {
					t.Fatalf("MODEL: irreversible witness changed to %s", before.port.record.phase)
				}
				baseline := guardResidueSnapshot(seams, data)
				for i := 0; i < 2; i++ {
					if err := lease.Close(nil); err == nil {
						t.Error("MODEL: uncertainty published successful close")
					}
					if err := lease.WaitCaptureRetired(); err == nil {
						t.Error("MODEL: uncertainty published positive retirement")
					}
					if engine.ActiveLeases() != 1 || !c.owner.retainedState() {
						t.Error("MODEL: uncertainty lost charge/owner")
					}
					_, next := newLinuxCaptureLease(t, 16512+i*2)
					if err := next.StartCapture(); err == nil {
						t.Error("MODEL: new generation over uncertainty")
					}
					if err := next.Close(nil); err != nil {
						t.Error(err)
					}
					if !reflect.DeepEqual(baseline, guardResidueSnapshot(seams, data)) {
						t.Error("MODEL: negative retry changed exact residue")
					}
				}
			} else {
				if err := lease.Close(nil); err != nil {
					t.Error(err)
				}
				if engine.ActiveLeases() != 0 {
					t.Error("MODEL: effect-free failure leaked admission charge")
				}
				anchorOwnerRegistry.Lock()
				n := len(anchorOwnerRegistry.owners)
				anchorOwnerRegistry.Unlock()
				if n != 0 {
					t.Error("MODEL: effect-free failure became permanent orphan")
				}
			}
			openAnchorSession = baseSession
		})
	}
}

func testAnchorPublishedGuardSurvives(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	_, healthy := newLinuxCaptureLease(t, 16540)
	if err := healthy.StartCapture(); err != nil {
		t.Fatal(err)
	}
	c := healthy.capture.(*linuxCapture)
	guard := c.owner.guard
	oldOpen := openQueueTransport
	openQueueTransport = func(uint32) (nfqueueTransport, error) { return nil, unix.EPERM }
	_, failed := newLinuxCaptureLease(t, 16542)
	if err := failed.StartCapture(); err == nil {
		t.Fatal("failure not injected")
	}
	if err := failed.Close(nil); err != nil {
		t.Fatal(err)
	}
	if c.owner.guard != guard || guardCount(seams) != 1 || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 1 {
		t.Fatal("MODEL: later failure damaged published peer guard/record")
	}
	openQueueTransport = oldOpen
	if err := healthy.Close(nil); err != nil {
		t.Fatal(err)
	}
	if guardCount(seams) != 0 {
		t.Fatal("MODEL: final published guard leaked")
	}
}

// The waiter owns a reference before final retirement, but no durable record.
// It must be excluded under the same tx, not keep the guard alive without m+p.
func testAnchorLastCloseWaitingOpen(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	_, healthy := newLinuxCaptureLease(t, 16550)
	if err := healthy.StartCapture(); err != nil {
		t.Fatal(err)
	}
	c := healthy.capture.(*linuxCapture)
	waiter, err := anchorOwnerAcquire()
	if err != nil {
		t.Fatal(err)
	}
	if waiter != c.owner {
		t.Fatal("MODEL: different owner for same namespace")
	}
	_, lease := newLinuxCaptureLease(t, 16552)
	next := &linuxCapture{owner: waiter, lease: lease, refHeld: true, done: make(chan struct{}), dispatch: newCaptureDispatchGate()}
	entered, release := make(chan struct{}), make(chan struct{})
	base := bindAnchorTransactionSocket
	var waiting atomic.Bool
	bindAnchorTransactionSocket = func(name string) (int, error) {
		if waiting.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return base(name)
	}
	done := make(chan error, 1)
	go func() { done <- next.open(lease.Endpoint()) }()
	<-entered
	if err := healthy.Close(nil); err != nil {
		close(release)
		<-done
		t.Fatal(err)
	}
	if guardCount(seams) != 0 {
		t.Error("MODEL: waiting opener stranded published guard after last record removal")
	}
	close(release)
	err = waitWithin(t, "waiting opener after last close", done)
	if err == nil {
		_ = next.Close()
		t.Error("MODEL: already-retiring owner admitted waiting opener")
	} else {
		next.rollbackOpen()
		next.releaseOwnerRef()
	}
	if guardCount(seams) != 0 || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 0 {
		t.Error("MODEL: last-close/waiting-open residue")
	}
}

func testAnchorConcurrentFirstFailure(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	first, err := anchorOwnerAcquire()
	if err != nil {
		t.Fatal(err)
	}
	second, err := anchorOwnerAcquire()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("MODEL: same namespace split owner")
	}
	_, a := newLinuxCaptureLease(t, 16560)
	_, b := newLinuxCaptureLease(t, 16562)
	ca := &linuxCapture{owner: first, lease: a, refHeld: true, done: make(chan struct{}), dispatch: newCaptureDispatchGate()}
	cb := &linuxCapture{owner: second, lease: b, refHeld: true, done: make(chan struct{}), dispatch: newCaptureDispatchGate()}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	base := openQueueTransport
	openQueueTransport = func(port uint32) (nfqueueTransport, error) {
		failed := false
		once.Do(func() { failed = true; close(entered); <-release })
		if failed {
			return nil, unix.EPERM
		}
		return base(port)
	}
	da, db := make(chan error, 1), make(chan error, 1)
	go func() { err := ca.open(a.Endpoint()); ca.rollbackOpen(); ca.releaseOwnerRef(); da <- err }()
	<-entered
	go func() { db <- cb.open(b.Endpoint()) }()
	close(release)
	if err := waitWithin(t, "first failure", da); !errors.Is(err, unix.EPERM) {
		t.Fatal(err)
	}
	if err := waitWithin(t, "second first open", db); err != nil {
		t.Fatal(err)
	}
	if cb.owner != first || guardCount(seams) != 1 || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 1 {
		t.Fatal("MODEL: first failure lost same-P successful waiter")
	}
	if err := cb.Close(); err != nil {
		t.Fatal(err)
	}
}

func testAnchorGuardPublication(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	_, lease := newLinuxCaptureLease(t, 16570)
	bindAnchorGuardSocket = func(name string) (*anchorGuard, error) {
		if syscall.ForkLock.TryLock() {
			syscall.ForkLock.Unlock()
			t.Error("MODEL: successful guard born outside token")
		}
		return seams.bindGuard(name)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	openQueueTransport = func(port uint32) (nfqueueTransport, error) { close(entered); <-release; return seams.dial(port) }
	done := make(chan error, 1)
	go func() { done <- lease.StartCapture() }()
	<-entered
	writer := make(chan int, 1)
	go func() {
		syscall.ForkLock.Lock()
		records := modelCaptureRecords(t, seams, FamilyIPv4)
		n := guardCount(seams)
		for _, m := range records {
			if m.port == nil || m.port.record.phase != "w" {
				n += 100
			}
		}
		if len(records) != 1 {
			n += 100
		}
		writer <- n
		syscall.ForkLock.Unlock()
	}()
	n, early := guardWriterQueued(t, writer)
	if early {
		t.Error("MODEL: publication writer escaped pre-w interval")
	}
	close(release)
	if err := waitWithin(t, "publication", done); err != nil {
		t.Fatal(err)
	}
	if !early {
		n = <-writer
	}
	if n != 1 {
		t.Fatalf("MODEL: guard was not published with durable w: %d", n)
	}
	if err := lease.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func testAnchorConcurrentUnknown(t *testing.T) {
	data := newFakeNFQueueConn("unknown-first", 0, nil)
	seams := installLinuxCaptureSeams(t, data)
	first, err := anchorOwnerAcquire()
	if err != nil {
		t.Fatal(err)
	}
	second, err := anchorOwnerAcquire()
	if err != nil {
		t.Fatal(err)
	}
	_, a := newLinuxCaptureLease(t, 16580)
	_, b := newLinuxCaptureLease(t, 16582)
	ca := &linuxCapture{owner: first, lease: a, refHeld: true, done: make(chan struct{}), dispatch: newCaptureDispatchGate()}
	cb := &linuxCapture{owner: second, lease: b, refHeld: true, done: make(chan struct{}), dispatch: newCaptureDispatchGate()}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var unreadable atomic.Bool
	openAnchorSession = func() (anchorSession, error) {
		return &guardFailureSession{fakeAnchorSession: &fakeAnchorSession{namespace: seams.anchors, port: 0x40000032}, kind: "m-ack-unknown", unreadable: &unreadable, gate: func() { once.Do(func() { close(entered); <-release }) }}, nil
	}
	da, db := make(chan error, 1), make(chan error, 1)
	go func() { err := ca.open(a.Endpoint()); ca.rollbackOpen(); da <- err }()
	<-entered
	go func() { err := cb.open(b.Endpoint()); cb.rollbackOpen(); cb.releaseOwnerRef(); db <- err }()
	close(release)
	if err := waitWithin(t, "unknown first", da); err == nil {
		t.Fatal("missing first failure")
	}
	if err := waitWithin(t, "waiting first recheck", db); err == nil || !strings.Contains(err.Error(), "retained or retiring") {
		t.Errorf("MODEL: waiting opener failed to recheck retained owner: %v", err)
	}
	if first != second || !first.retainedState() || guardCount(seams) != 0 || len(seams.boundPortList()) != 0 {
		t.Fatal("MODEL: unknown first-open identity/resources escaped")
	}
	records := modelCaptureRecords(t, seams, FamilyIPv4)
	if len(records) != 1 || records[captureKey(first.token, ca.anchor.capture)] == nil {
		t.Fatal("MODEL: unknown first-open lost exact metadata")
	}
	baseline := guardResidueSnapshot(seams, data)
	for i := 0; i < 2; i++ {
		if err := ca.Close(); err == nil {
			t.Error("MODEL: uncertain first-open Close succeeded")
		}
		if !reflect.DeepEqual(baseline, guardResidueSnapshot(seams, data)) {
			t.Error("MODEL: uncertain close changed exact residue")
		}
	}
}

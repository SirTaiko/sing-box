//go:build linux

package desync

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Model only the namespace transaction socket, keeping the actual ForkLock
// and caller transaction/retry/close order. No kernel socket or setns is used.
func installForkModelTransport(t *testing.T) {
	t.Helper()
	forkInitModel(t, func() error { return nil })
	bind, closeFD := bindAnchorTransactionSocket, closeAnchorTransactionSocket
	var transaction sync.Mutex
	bindAnchorTransactionSocket = func(name string) (int, error) {
		if name != anchorTransactionAddress {
			t.Errorf("unexpected transaction name %q", name)
		}
		if !transaction.TryLock() {
			return -1, unix.EADDRINUSE
		}
		return 1000001, nil
	}
	closeAnchorTransactionSocket = func(fd int) error {
		if fd != 1000001 {
			t.Errorf("unexpected model transaction fd %d", fd)
		}
		transaction.Unlock()
		return nil
	}
	t.Cleanup(func() { bindAnchorTransactionSocket, closeAnchorTransactionSocket = bind, closeFD })
}

// These are MODEL transports and initializer outcomes, not a native pidfd or
// fork test. Never reset the real standard-library once or open a native socket.
func TestAnchorForkInitDefaults(t *testing.T) {
	seams := installLinuxCaptureSeams(t, nil)
	engine, lease := newForkDefaultLease(t)
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	_ = lease
	if guardCount(seams) != 0 || len(seams.boundPortList()) != 0 {
		t.Fatal("MODEL: zero capture acquired resources")
	}
	engine, lease = newForkDefaultLease(t)
	if err := lease.StartCapture(); err != nil {
		t.Fatal(err)
	}
	c := lease.capture.(*linuxCapture)
	if c.icmpQueue != 0 || c.overrideQnum != 0 {
		t.Fatal("MODEL: default has optional ICMP/explicit qnum")
	}
	packet := buildIPv4TCP(t, nil, 1000, tcpFlagACK|tcpFlagPSH)
	if !seams.kernel.deliver(c.queue, fakePacketMessage(c.queue, 991, packet.Raw), 991) {
		t.Fatal("MODEL: default packet not delivered")
	}
	waitForCondition(t, "default verdict", func() bool { return len(seams.kernel.verdictsFor(c.queue, 991)) == 1 })
	for i := 0; i < 2; i++ {
		if err := lease.Close(nil); err != nil {
			t.Fatal(err)
		}
		if err := lease.WaitCaptureRetired(); err != nil {
			t.Fatal(err)
		}
		if err := engine.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if engine.ActiveLeases() != 0 || guardCount(seams) != 0 || len(modelCaptureRecords(t, seams, FamilyIPv4)) != 0 {
		t.Fatal("MODEL: default repeated Close left ownership")
	}
}

func newForkDefaultLease(t *testing.T) (*Engine, *Lease) {
	t.Helper()
	config, err := Compile(enabledOption(`{"enabled":true,"rules":[{"network":["tcp"],"port":[443],"methods":[]}]}`), "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(config, linuxBackend{})
	if err != nil {
		t.Fatal(err)
	}
	l, err := e.NewAttempt(Intent{Family: FamilyIPv4, Transport: TransportTCP, Source: netip.MustParseAddrPort("192.0.2.1:40000"), Destination: netip.MustParseAddrPort("198.51.100.7:443")})
	if err != nil {
		t.Fatal(err)
	}
	l.SetLocalAddress(netip.MustParseAddrPort("192.0.2.1:40000"))
	t.Cleanup(func() { _ = e.Close() })
	return e, l
}

func forkInitModel(t *testing.T, initialize func() error) {
	t.Helper()
	previous := linuxForkSafetyOnce
	linuxForkSafetyOnce = sync.OnceValue(initialize)
	t.Cleanup(func() { linuxForkSafetyOnce = previous })
}

func TestAnchorForkInitOrdering(t *testing.T) {
	t.Run("shared-external-once-two-namespaces", func(t *testing.T) {
		installLinuxCaptureSeams(t, nil)
		paths := []string{filepath.Join(t.TempDir(), "namespace-a"), filepath.Join(t.TempDir(), "namespace-b")}
		for _, p := range paths {
			if err := os.WriteFile(p, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		var mu sync.Mutex
		byThread := make(map[int]string)
		var effects, probeCalls, adapterCalls atomic.Int32
		getThreadNetns = func() (netns.NsHandle, error) {
			effects.Add(1)
			mu.Lock()
			p := byThread[unix.Gettid()]
			mu.Unlock()
			fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			return netns.NsHandle(fd), err
		}
		entered, release := make(chan struct{}), make(chan struct{})
		shared := sync.OnceValue(func() error { probeCalls.Add(1); close(entered); <-release; return nil })
		external := make(chan error, 1)
		go func() { external <- shared() }()
		<-entered
		forkInitModel(t, func() error { adapterCalls.Add(1); return shared() })
		type result struct {
			group int
			owner *anchorOwner
			err   error
		}
		done := make(chan result, 4)
		started := make(chan struct{}, 4)
		for i := 0; i < 4; i++ {
			go func(group int) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				mu.Lock()
				byThread[unix.Gettid()] = paths[group]
				mu.Unlock()
				started <- struct{}{}
				o, err := anchorOwnerAcquire()
				done <- result{group, o, err}
			}(i % 2)
		}
		for i := 0; i < 4; i++ {
			<-started
		}
		deadline := time.Now().Add(time.Second)
		for adapterCalls.Load() == 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
		if effects.Load() != 0 {
			t.Error("MODEL: namespace descriptors escaped shared external initialization")
		}
		if !syscall.ForkLock.TryLock() {
			t.Error("MODEL: shared once holds fork token")
		} else {
			syscall.ForkLock.Unlock()
		}
		close(release)
		if err := <-external; err != nil {
			t.Fatal(err)
		}
		owners := make(map[int]*anchorOwner)
		var held []*anchorOwner
		for i := 0; i < 4; i++ {
			r := <-done
			if r.err != nil {
				t.Fatal(r.err)
			}
			if old := owners[r.group]; old != nil && old != r.owner {
				t.Error("MODEL: same namespace split owner")
			}
			owners[r.group] = r.owner
			held = append(held, r.owner)
		}
		if owners[0] == owners[1] || probeCalls.Load() != 1 || adapterCalls.Load() != 1 {
			t.Error("MODEL: barrier was per-owner/netns or did not join external once")
		}
		for _, o := range held {
			o.releaseRef()
		}
	})
	t.Run("backend-and-lease", func(t *testing.T) {
		installLinuxCaptureSeams(t, nil)
		_, first := newLinuxCaptureLease(t, 16500)
		_, second := newLinuxCaptureLease(t, 16502)
		entered, release := make(chan struct{}), make(chan struct{})
		var calls, effects atomic.Int32
		forkInitModel(t, func() error { calls.Add(1); close(entered); <-release; return nil })
		get := getThreadNetns
		getThreadNetns = func() (netns.NsHandle, error) { effects.Add(1); return get() }
		done := make(chan error, 2)
		go func() {
			c, err := (linuxBackend{}).Open(first)
			if c != nil {
				err = errors.Join(err, c.Close())
			}
			done <- err
		}()
		go func() { done <- second.StartCapture() }()
		select {
		case <-entered:
		case <-time.After(100 * time.Millisecond):
			t.Error("MODEL: first backend acquisition bypassed shared initializer")
		}
		if effects.Load() != 0 {
			t.Error("MODEL: descriptor effects before first-use barrier")
		}
		if !syscall.ForkLock.TryLock() {
			t.Error("MODEL: initializer holds ForkLock")
		} else {
			syscall.ForkLock.Unlock()
		}
		close(release)
		for i := 0; i < 2; i++ {
			if err := waitWithin(t, "first acquisition", done); err != nil {
				t.Error(err)
			}
		}
		if calls.Load() != 1 {
			t.Errorf("MODEL: initializer calls=%d, want1", calls.Load())
		}
		if effects.Load() == 0 {
			t.Error("MODEL: no progress after initialization")
		}
	})
	t.Run("standalone-token", func(t *testing.T) {
		entered, release := make(chan struct{}), make(chan struct{})
		forkInitModel(t, func() error { close(entered); <-release; return nil })
		done := make(chan error, 1)
		var effects atomic.Int32
		go func() { done <- withForkReadToken(func() error { effects.Add(1); return nil }) }()
		select {
		case <-entered:
		case <-time.After(100 * time.Millisecond):
			t.Error("MODEL: token bypassed initializer")
		}
		if effects.Load() != 0 {
			t.Error("MODEL: token operation before barrier")
		}
		if !syscall.ForkLock.TryLock() {
			t.Error("MODEL: initializer under token")
		} else {
			syscall.ForkLock.Unlock()
		}
		close(release)
		if err := waitWithin(t, "token", done); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("raw-before-lock-and-namespace", func(t *testing.T) {
		c, p := injectionFixture(t, FamilyIPv4)
		m := installInjectionModel(t, c, p)
		entered, release := make(chan struct{}), make(chan struct{})
		forkInitModel(t, func() error { close(entered); <-release; return nil })
		done := make(chan error, 1)
		go func() { done <- c.inject(p) }()
		select {
		case <-entered:
		case <-time.After(100 * time.Millisecond):
			t.Error("MODEL: raw entry bypassed initializer")
		}
		m.mu.Lock()
		n := len(m.events)
		m.mu.Unlock()
		if n != 0 {
			t.Error("MODEL: raw namespace/descriptor before barrier")
		}
		if !c.rawMu.TryLock() {
			t.Error("MODEL: rawMu held during initialization")
		} else {
			c.rawMu.Unlock()
		}
		close(release)
		if err := waitWithin(t, "raw injection", done); err != nil {
			t.Fatal(err)
		}
		m.assertEvents(injectionSuccessEvents(FamilyIPv4))
	})
}

func TestAnchorForkInitErrorPaths(t *testing.T) {
	// Each capability failure has completed the pinned stdlib once. FindProcess
	// falls back to a PID Process and Release succeeds; it is NOT a public error.
	for _, outcome := range []string{"pre-clone-error", "clone-error", "post-clone-wait-error", "capability-success"} {
		t.Run(outcome, func(t *testing.T) {
			var calls, releases, effects int
			var capabilityErr error
			if outcome != "capability-success" {
				capabilityErr = errors.New("MODEL " + outcome)
			}
			shared := sync.OnceValue(func() error { calls++; return capabilityErr })
			forkInitModel(t, func() error {
				// Model the source-proven public FindProcess fallback, not a
				// reset/retry of Go's private capability probe or native success.
				_ = shared()
				releases++
				return nil
			})
			for i := 0; i < 2; i++ {
				if err := withForkReadToken(func() error { effects++; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(shared(), capabilityErr) || !errors.Is(shared(), capabilityErr) || calls != 1 || releases != 1 || effects != 2 {
				t.Fatalf("MODEL: terminal capability outcome retried/bypassed: calls=%d releases=%d effects=%d", calls, releases, effects)
			}
		})
	}
	t.Run("fake-public-api-error", func(t *testing.T) {
		installLinuxCaptureSeams(t, nil)
		want := errors.New("MODEL unexpected public API error; not Unix capability-false")
		var calls, effects int
		forkInitModel(t, func() error { calls++; return want })
		getThreadNetns = func() (netns.NsHandle, error) { effects++; return -1, want }
		for i := 0; i < 2; i++ {
			if _, err := anchorOwnerAcquire(); !errors.Is(err, want) {
				t.Errorf("owner error=%v", err)
			}
			if err := withForkReadToken(func() error { effects++; return nil }); !errors.Is(err, want) {
				t.Errorf("token error=%v", err)
			}
		}
		if calls != 1 || effects != 0 {
			t.Fatalf("MODEL: error bypass: calls=%d effects=%d", calls, effects)
		}
	})
	t.Run("raw-public-error", func(t *testing.T) {
		c, p := injectionFixture(t, FamilyIPv4)
		m := installInjectionModel(t, c, p)
		want := errors.New("MODEL public adapter failure")
		var calls int
		forkInitModel(t, func() error { calls++; return want })
		for i := 0; i < 2; i++ {
			if err := c.inject(p); !errors.Is(err, want) {
				t.Errorf("raw error=%v", err)
			}
		}
		m.mu.Lock()
		effects := len(m.events)
		m.mu.Unlock()
		if calls != 1 || effects != 0 {
			t.Fatalf("MODEL: raw error bypass calls=%d effects=%d", calls, effects)
		}
	})
	t.Run("panic-rethrows", func(t *testing.T) {
		var calls, effects int
		forkInitModel(t, func() error { calls++; panic("MODEL initializer panic") })
		for i := 0; i < 2; i++ {
			func() {
				defer func() {
					if recover() != "MODEL initializer panic" {
						t.Error("MODEL: panic was bypassed")
					}
				}()
				_ = withForkReadToken(func() error { effects++; return nil })
			}()
		}
		if calls != 1 || effects != 0 {
			t.Fatalf("MODEL: panic state calls=%d effects=%d", calls, effects)
		}
	})
}

func TestAnchorUnpublishedGuardLifetime(t *testing.T) {
	t.Run("successful-publication", testAnchorGuardPublication)
	t.Run("failure-close-before-writer", testAnchorGuardFailures)
	t.Run("published-peer", testAnchorPublishedGuardSurvives)
	t.Run("last-close-waiting-opener", testAnchorLastCloseWaitingOpen)
	t.Run("concurrent-first-failure", testAnchorConcurrentFirstFailure)
	t.Run("concurrent-unknown-recheck", testAnchorConcurrentUnknown)
	t.Run("acquire-only", func(t *testing.T) {
		seams := installLinuxCaptureSeams(t, nil)
		owner, err := anchorOwnerAcquire()
		if err != nil {
			t.Fatal(err)
		}
		seams.guardsMu.Lock()
		n := len(seams.guards)
		seams.guardsMu.Unlock()
		if n != 0 {
			t.Error("MODEL: unpublished guard born outside first namespace transaction")
		}
		owner.releaseRef()
	})
}

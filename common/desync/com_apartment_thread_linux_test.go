//go:build linux

package desync

import (
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestRunOnNativeThreadKeepsOneOSThread pins the thread affinity of the COM
// query wrapper: the OS thread observed before and after a blocking point must
// be the same, because a COM apartment is owned by that thread. The unpinned
// control is logged (not asserted) so the fixture stays deterministic; the
// pinned invariant is the regression.
func TestRunOnNativeThreadKeepsOneOSThread(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)

	stop := make(chan struct{})
	var occupiers sync.WaitGroup
	for index := 0; index < 3; index++ {
		occupiers.Add(1)
		go func() {
			defer occupiers.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			for {
				select {
				case <-stop:
					return
				default:
					runtime.Gosched()
				}
			}
		}()
	}

	var controlBefore, controlAfter int
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		controlBefore = syscall.Gettid()
		time.Sleep(2 * time.Millisecond)
		runtime.Gosched()
		controlAfter = syscall.Gettid()
	}()
	<-controlDone
	t.Logf("unpinned control thread ids: before=%d after=%d", controlBefore, controlAfter)

	var before, after int
	runOnNativeThread(func() {
		before = syscall.Gettid()
		time.Sleep(2 * time.Millisecond)
		runtime.Gosched()
		after = syscall.Gettid()
	})
	close(stop)
	occupiers.Wait()
	if before != after {
		t.Fatalf("pinned sequence migrated between OS threads: before=%d after=%d", before, after)
	}
}

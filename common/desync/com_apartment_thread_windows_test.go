//go:build windows

package desync

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestRunOnNativeThreadKeepsOneOSThread pins the thread affinity of the COM
// query wrapper on the platform whose apartment state is thread-local: the
// thread id observed before and after a blocking point must be identical. The
// unpinned control is logged, not asserted, so the fixture itself is stable.
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

	var controlBefore, controlAfter uint32
	controlDone := make(chan struct{})
	go func() {
		defer close(controlDone)
		controlBefore = windows.GetCurrentThreadId()
		time.Sleep(2 * time.Millisecond)
		runtime.Gosched()
		controlAfter = windows.GetCurrentThreadId()
	}()
	<-controlDone
	t.Logf("unpinned control thread ids: before=%d after=%d", controlBefore, controlAfter)

	var before, after uint32
	runOnNativeThread(func() {
		before = windows.GetCurrentThreadId()
		time.Sleep(2 * time.Millisecond)
		runtime.Gosched()
		after = windows.GetCurrentThreadId()
	})
	close(stop)
	occupiers.Wait()
	if before != after {
		t.Fatalf("pinned sequence migrated between OS threads: before=%d after=%d", before, after)
	}
}

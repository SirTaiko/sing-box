package desync

import (
	"fmt"
	"runtime"
)

// COM apartment lifetime is per native OS thread, not per goroutine. A Go
// goroutine can resume on a different OS thread at any blocking point, so a
// query that initializes COM, calls interface methods, releases the objects
// and uninitializes must hold the thread for the whole sequence. This is the
// Go-documented use of runtime.LockOSThread for OS services that depend on
// thread-local state (src/runtime/proc.go LockOSThread).
//
// The helper is portable so the pinning contract is exercised by the ordinary
// package tests; production only uses it from the Windows COM query.
func runOnNativeThread(fn func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fn()
}

// HRESULT values of one CoInitializeEx call.
const (
	comSOK            = 0x00000000
	comSFalse         = 0x00000001
	comRPCChangedMode = 0x80010106
)

// comApartmentEnter interprets the HRESULT of exactly one CoInitializeEx call
// and returns the release function for the initialization reference that this
// call acquired.
//
// S_OK (fresh apartment) and S_FALSE (thread already initialized, one more
// reference) both acquire a reference that this invocation must balance with
// one CoUninitialize on the same thread. RPC_E_CHANGED_MODE means the thread
// already lives in another apartment: the call failed, acquired no reference,
// and the apartment is owned by whoever initialized it, so this invocation
// must not decrement it. Any other failure acquired nothing either.
func comApartmentEnter(result uint32, uninitialize func()) (func(), error) {
	switch result {
	case comSOK, comSFalse:
		return uninitialize, nil
	case comRPCChangedMode:
		return nil, nil
	default:
		return nil, fmt.Errorf("desync: CoInitializeEx failed: %#x", result)
	}
}

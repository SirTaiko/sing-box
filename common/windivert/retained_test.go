package windivert

// Portable regression for the retained-cleanup receipt that a failed Open can
// carry. The receipt is the only thing that keeps a caller's admission charge
// alive after Open returned no handle, so its identity and its error chain must
// survive classification unchanged.

import (
	"errors"
	"testing"
)

func TestRetainedOpenErrorCarriesRetirementReceipt(t *testing.T) {
	activation := errors.New("windivert: startup ioctl: refused")
	cleanup := errors.New("windivert: close: retirement deferred")
	retired := make(chan struct{})
	carried := &RetainedOpenError{err: errors.Join(activation, cleanup), done: retired}

	if !errors.Is(carried, activation) || !errors.Is(carried, cleanup) {
		t.Fatal("the activation/cleanup errors are not visible through the receipt")
	}
	receipt, retained := RetainedRetirement(carried)
	if !retained {
		t.Fatal("an unproven cleanup was not reported as a retained receipt")
	}
	if receipt != (<-chan struct{})(retired) {
		t.Fatal("the reported receipt is not the original retirement owner")
	}
	select {
	case <-receipt:
		t.Fatal("the receipt was already closed for an unfinished retirement")
	default:
	}
	close(retired)
	select {
	case <-receipt:
	default:
		t.Fatal("the receipt did not follow the native retirement owner")
	}
}

func TestRetainedRetirementIgnoresOrdinaryOpenErrors(t *testing.T) {
	ordinary := errors.New("windivert: driver magic mismatch")
	if _, retained := RetainedRetirement(ordinary); retained {
		t.Fatal("an ordinary activation error was reported as a retained cleanup owner")
	}
	if _, retained := RetainedRetirement(nil); retained {
		t.Fatal("nil error reported a retained cleanup owner")
	}
	// A proven rollback is reported as the plain joined error, so it has no
	// receipt and the caller may discharge its charge immediately.
	proven := &RetainedOpenError{err: ordinary, done: nil}
	if _, retained := RetainedRetirement(proven); retained {
		t.Fatal("a carrier without a retirement owner was treated as retained")
	}
}

func TestNewRetainedOpenErrorIsDetectable(t *testing.T) {
	cause := errors.New("windivert: initialize ioctl: refused")
	retired := make(chan struct{})
	carried := NewRetainedOpenError(cause, retired)
	receipt, retained := RetainedRetirement(carried)
	if !retained || receipt != (<-chan struct{})(retired) {
		t.Fatal("the constructed receipt is not detectable")
	}
	if !errors.Is(carried, cause) {
		t.Fatal("the constructed carrier hides its cause")
	}
}

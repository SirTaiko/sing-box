package dialer

// Permanent regression for the accepted-byte contract of a failed native
// connect: a definitively failed operation reports no initial-payload progress,
// while a completed operation keeps its authoritative count.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConnectFailureReportsNoAcceptedBytes(t *testing.T) {
	payload := []byte("0123456789")
	fake := newFakeConnectCompletion()
	// The provider leaves the whole initial payload in its out parameter even
	// though the operation failed (observed natively with WSAECONNREFUSED).
	fake.resultErr = errors.New("desync: ConnectEx result: connection refused")
	fake.complete(uint32(len(payload)))
	owner := fake.owner(payload)
	transferred, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(time.Second))
	if err == nil {
		t.Fatal("a failed completion reported no error")
	}
	if transferred != 0 {
		t.Fatalf("failed completion reported %d accepted bytes, want 0: a connection that does not exist cannot have delivered the initial payload", transferred)
	}
}

// Mutation control: the same owner still preserves the authoritative count of a
// successful completion, so the failure rule never zeroes legitimate progress.
func TestConnectSuccessPreservesAuthoritativeCount(t *testing.T) {
	payload := []byte("0123456789")
	fake := newFakeConnectCompletion()
	fake.complete(7)
	owner := fake.owner(payload)
	transferred, err := owner.awaitConnectCompletion(context.Background(), time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("successful completion returned an error: %v", err)
	}
	if transferred != 7 {
		t.Fatalf("successful completion reported %d accepted bytes, want the authoritative 7", transferred)
	}
}

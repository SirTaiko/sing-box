package dialer

// Permanent regression for the public eager enabled-direct facade: a context
// that is already canceled or expired when (*DefaultDialer).DialContext is
// called must be refused before the attempt hook, the per-attempt lease and the
// native socket exist.
//
// The assertion is deliberately made on the public method, not on a helper: a
// synchronous native connect never consults the context, so only the entry
// point can enforce this contract. The test is hermetic on every platform —
// the refused call returns before any platform dial, so no socket, no name
// resolution and no peer are involved.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestDialContextRefusesCompletedContextBeforeAttempt(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		newContext func() (context.Context, context.CancelFunc)
		want       error
	}{
		{
			name: "canceled",
			newContext: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			want: context.Canceled,
		},
		{
			name: "expired",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: context.DeadlineExceeded,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			hook := &countHook{}
			dialer := &DefaultDialer{attemptHook: hook}
			ctx, cancel := testCase.newContext()
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", M.SocksaddrFrom(netip.MustParseAddr("127.0.0.1"), 1))
			if conn != nil {
				_ = conn.Close()
				t.Fatal("a context completed before the call returned a live connection")
			}
			if !errors.Is(err, testCase.want) {
				t.Fatalf("dial error = %v, want %v", err, testCase.want)
			}
			if leases := hook.leases.Load(); leases != 0 {
				t.Fatalf("attempt hook leases = %d, want 0", leases)
			}
			if prepared := hook.prepared.Load(); prepared != 0 {
				t.Fatalf("PrepareSocket calls = %d, want 0", prepared)
			}
			if closed := hook.closed.Load(); closed != 0 {
				t.Fatalf("lease Close calls = %d, want 0 (no lease may be created)", closed)
			}
			if attached := hook.connAttached.Load(); attached != 0 {
				t.Fatalf("AttachConn calls = %d, want 0", attached)
			}
		})
	}
}

package local

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
)

type testLocalTransport struct {
	adapter.DNSTransport
	reply func(context.Context, *mDNS.Msg) (*mDNS.Msg, error)
	calls int
}

func (t *testLocalTransport) ExchangeAsync(ctx context.Context, query *mDNS.Msg, cb func(*mDNS.Msg, error)) {
	t.calls++
	response, err := t.reply(ctx, query)
	cb(response, err)
}

func (t *testLocalTransport) Reset() {}

func TestLocalServerTransportFallback(t *testing.T) {
	query := new(mDNS.Msg).SetQuestion("dns.msftncsi.com.", mDNS.TypeA)
	ok := func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) { return new(mDNS.Msg).SetReply(q), ctx.Err() }
	dead := func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) { return nil, context.DeadlineExceeded }
	udp, tcp := &testLocalTransport{reply: dead}, &testLocalTransport{reply: ok}
	server := localNameServer{primary: udp, alternate: tcp}
	exchange := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		server.exchange(ctx, query, func(response *mDNS.Msg, err error) {
			if err != nil || response == nil {
				t.Fatalf("exchange failed: %v", err)
			}
		})
	}
	exchange()
	exchange()
	if udp.calls != 1 || tcp.calls != 2 {
		t.Fatalf("successful fallback was not reused: udp=%d tcp=%d", udp.calls, tcp.calls)
	}
	tcp.reply, udp.reply = dead, ok
	exchange()
	exchange()
	if udp.calls != 3 || tcp.calls != 3 {
		t.Fatalf("did not recover when TCP stopped working: udp=%d tcp=%d", udp.calls, tcp.calls)
	}
	udp.reply, tcp.reply = dead, ok
	exchange()
	server.reset()
	udp.reply = func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		return new(mDNS.Msg).SetRcode(q, mDNS.RcodeNameError), nil
	}
	exchange()
	if udp.calls != 5 || tcp.calls != 4 {
		t.Fatalf("reset or NXDOMAIN handling failed: udp=%d tcp=%d", udp.calls, tcp.calls)
	}
}

func TestLocalServerTimeoutAndCancellation(t *testing.T) {
	query := new(mDNS.Msg).SetQuestion("example.com.", mDNS.TypeA)
	var firstDeadline time.Time
	udp := &testLocalTransport{reply: func(ctx context.Context, _ *mDNS.Msg) (*mDNS.Msg, error) {
		firstDeadline, _ = ctx.Deadline()
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	tcp := &testLocalTransport{reply: func(ctx context.Context, q *mDNS.Msg) (*mDNS.Msg, error) {
		deadline, _ := ctx.Deadline()
		if !deadline.After(firstDeadline) {
			t.Fatal("no time budget reserved for fallback")
		}
		return new(mDNS.Msg).SetReply(q), ctx.Err()
	}}
	server := localNameServer{primary: udp, alternate: tcp}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	server.exchange(ctx, query, func(response *mDNS.Msg, err error) {
		if err != nil || response == nil {
			t.Fatalf("timed-out UDP did not fall back: %v", err)
		}
	})
	server.reset()
	cancel()
	server.exchange(ctx, query, func(response *mDNS.Msg, err error) {
		if !errors.Is(err, context.Canceled) || tcp.calls != 1 {
			t.Fatalf("cancelled request reached fallback: %v, TCP calls=%d", err, tcp.calls)
		}
	})
}

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/common/desync/tools"
)

// These regressions pin the production boundary between the operator resolver
// adapter and the real mdig consumer. The platform lookup is replaced with typed
// synthetic *net.DNSError values through the adapter seam; no socket, DNS
// transport, command root or product binary is involved.
const (
	resolverRegressionName    = "adapter-synthetic.invalid"
	resolverRegressionAddress = "192.0.2.7"
	resolverRegressionError   = "synthetic resolver failure"
)

// resolverRegressionFailure builds the typed error the platform resolver returns
// for temporary and timeout failures, or for an ordinary permanent failure.
func resolverRegressionFailure(isTemporary bool, isTimeout bool) *net.DNSError {
	return &net.DNSError{
		Err:         resolverRegressionError,
		Name:        resolverRegressionName,
		Server:      "192.0.2.53",
		IsTemporary: isTemporary,
		IsTimeout:   isTimeout,
	}
}

// adapterScript is a scripted platform lookup. The first failures calls return
// failure, later calls return one fixed address, so the real operatorResolver
// classification and the real tools.MDig retry loop run unchanged.
type adapterScript struct {
	calls    atomic.Int32
	failures int32
	failure  error
	networks []string
	names    []string
}

func (s *adapterScript) lookup(_ context.Context, network string, name string) ([]netip.Addr, error) {
	s.networks = append(s.networks, network)
	s.names = append(s.names, name)
	call := s.calls.Add(1)
	if s.failure != nil && call <= s.failures {
		return nil, s.failure
	}
	return []netip.Addr{netip.MustParseAddr(resolverRegressionAddress)}, nil
}

func (s *adapterScript) adapter() operatorResolver {
	return operatorResolver{lookupNetIP: s.lookup}
}

func runAdapterMDig(t *testing.T, adapter operatorResolver, attempts int, verbose bool) (string, string, tools.MDigStats, error) {
	t.Helper()
	var out strings.Builder
	var diagnostics strings.Builder
	stats, err := tools.MDig(
		context.Background(),
		strings.NewReader(resolverRegressionName+"\n"),
		&out,
		&diagnostics,
		adapter,
		nil,
		tools.MDigOptions{
			Family:         tools.FamilyIPv4,
			EAgainAttempts: attempts,
			Verbose:        verbose,
		},
	)
	return out.String(), diagnostics.String(), stats, err
}

func TestToolsDesyncResolverAdapterTemporaryRecovery(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		failure *net.DNSError
	}{
		{name: "temporary", failure: resolverRegressionFailure(true, false)},
		{name: "timeout", failure: resolverRegressionFailure(false, true)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			script := &adapterScript{failure: testCase.failure, failures: 2}
			stdout, diagnostics, stats, err := runAdapterMDig(t, script.adapter(), 3, false)
			if err != nil {
				t.Fatalf("mdig returned an unexpected error: %v", err)
			}
			if calls := script.calls.Load(); calls != 3 {
				t.Fatalf("expected the real consumer to retry to 3 lookups, got %d", calls)
			}
			if stdout != resolverRegressionAddress+"\n" {
				t.Fatalf("expected exactly the recovered address, got %q", stdout)
			}
			if stats.Success != 1 || stats.Error != 0 || stats.Retries != 2 || stats.Addresses != 1 {
				t.Fatalf("unexpected statistics %+v", stats)
			}
			if diagnostics != "" {
				t.Fatalf("no diagnostics expected without --verbose, got %q", diagnostics)
			}
			for index, network := range script.networks {
				if network != "ip4" || script.names[index] != resolverRegressionName {
					t.Fatalf("unexpected lookup arguments %q %q", network, script.names[index])
				}
			}
		})
	}
}

func TestToolsDesyncResolverAdapterTemporaryExhaustion(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		failure *net.DNSError
	}{
		{name: "temporary", failure: resolverRegressionFailure(true, false)},
		{name: "timeout", failure: resolverRegressionFailure(false, true)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			script := &adapterScript{failure: testCase.failure, failures: 100}
			stdout, diagnostics, stats, err := runAdapterMDig(t, script.adapter(), 3, true)
			if err != nil {
				t.Fatalf("a per-name resolution failure must not fail the batch: %v", err)
			}
			if calls := script.calls.Load(); calls != 3 {
				t.Fatalf("expected exactly the configured 3 attempts, got %d", calls)
			}
			if stdout != "" {
				t.Fatalf("exhaustion must not emit an address, got %q", stdout)
			}
			if stats.Success != 0 || stats.Error != 1 || stats.Retries != 3 {
				t.Fatalf("unexpected statistics %+v", stats)
			}
			if !strings.Contains(diagnostics, resolverRegressionError) {
				t.Fatalf("original resolver diagnostic was lost: %q", diagnostics)
			}
			if !strings.Contains(diagnostics, tools.ErrTemporary.Error()) {
				t.Fatalf("temporary classification is missing from the diagnostic: %q", diagnostics)
			}
		})
	}
}

func TestToolsDesyncResolverAdapterPermanentNotRetried(t *testing.T) {
	permanent := resolverRegressionFailure(false, false)
	permanent.IsNotFound = true
	script := &adapterScript{failure: permanent, failures: 100}
	stdout, _, stats, err := runAdapterMDig(t, script.adapter(), 10, true)
	if err != nil {
		t.Fatalf("a per-name resolution failure must not fail the batch: %v", err)
	}
	if calls := script.calls.Load(); calls != 1 {
		t.Fatalf("permanent failures must not be retried, got %d lookups", calls)
	}
	if stdout != "" || stats.Success != 0 || stats.Error != 1 || stats.Retries != 0 {
		t.Fatalf("unexpected permanent-failure result %q %+v", stdout, stats)
	}
	mapped, err := script.adapter().Lookup(context.Background(), resolverRegressionName, tools.FamilyIPv4)
	if mapped != nil || err == nil {
		t.Fatalf("unexpected lookup result %v %v", mapped, err)
	}
	if errors.Is(err, tools.ErrTemporary) || err != error(permanent) {
		t.Fatalf("a permanent failure must stay permanent and unchanged: %v", err)
	}
}

func TestToolsDesyncResolverAdapterImmediateSuccess(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		family tools.Family
		expect string
	}{
		{name: "ipv4", family: tools.FamilyIPv4, expect: "ip4"},
		{name: "ipv6", family: tools.FamilyIPv6, expect: "ip6"},
		{name: "both", family: tools.FamilyIPv4 | tools.FamilyIPv6, expect: "ip"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			script := &adapterScript{}
			var out strings.Builder
			stats, err := tools.MDig(
				context.Background(),
				strings.NewReader(resolverRegressionName+"\n"),
				&out,
				&strings.Builder{},
				script.adapter(),
				nil,
				tools.MDigOptions{Family: testCase.family, EAgainAttempts: 3},
			)
			if err != nil {
				t.Fatalf("mdig returned an unexpected error: %v", err)
			}
			if calls := script.calls.Load(); calls != 1 {
				t.Fatalf("a successful lookup must run exactly once, got %d", calls)
			}
			if len(script.networks) != 1 || script.networks[0] != testCase.expect {
				t.Fatalf("expected network %q, got %v", testCase.expect, script.networks)
			}
			if out.String() != resolverRegressionAddress+"\n" {
				t.Fatalf("unexpected output %q", out.String())
			}
			if stats.Success != 1 || stats.Error != 0 || stats.Retries != 0 || stats.Addresses != 1 {
				t.Fatalf("unexpected statistics %+v", stats)
			}
		})
	}
}

func TestToolsDesyncResolverAdapterErrorIdentity(t *testing.T) {
	temporary := resolverRegressionFailure(true, false)
	timeout := resolverRegressionFailure(false, true)
	for _, testCase := range []struct {
		name     string
		original *net.DNSError
	}{
		{name: "temporary", original: temporary},
		{name: "timeout", original: timeout},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			adapter := operatorResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, testCase.original
			}}
			_, err := adapter.Lookup(context.Background(), resolverRegressionName, tools.FamilyIPv4)
			if err == nil {
				t.Fatal("expected a resolver error")
			}
			if !errors.Is(err, tools.ErrTemporary) {
				t.Fatalf("the temporary sentinel is not in the adapter error chain: %v", err)
			}
			if !errors.Is(err, testCase.original) {
				t.Fatalf("the original resolver error is not in the adapter error chain: %v", err)
			}
			var typed *net.DNSError
			if !errors.As(err, &typed) || typed != testCase.original {
				t.Fatalf("the typed DNS error identity was lost: %v", err)
			}
			if !strings.Contains(err.Error(), resolverRegressionError) || !strings.Contains(err.Error(), tools.ErrTemporary.Error()) {
				t.Fatalf("the adapter error lost a diagnostic component: %v", err)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("a temporary DNS error must not be confused with cancellation: %v", err)
			}
		})
	}

	t.Run("permanent", func(t *testing.T) {
		permanent := resolverRegressionFailure(false, false)
		adapter := operatorResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, permanent
		}}
		_, err := adapter.Lookup(context.Background(), resolverRegressionName, tools.FamilyIPv4)
		if err == nil {
			t.Fatal("expected a resolver error")
		}
		if errors.Is(err, tools.ErrTemporary) {
			t.Fatalf("a permanent failure must not be classified as temporary: %v", err)
		}
		if err != error(permanent) {
			t.Fatalf("a permanent failure must be returned unchanged, got %v", err)
		}
	})

	t.Run("non_dns", func(t *testing.T) {
		plain := errors.New("synthetic transport failure")
		adapter := operatorResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, plain
		}}
		_, err := adapter.Lookup(context.Background(), resolverRegressionName, tools.FamilyIPv4)
		if err != plain {
			t.Fatalf("a non-DNS failure must be returned unchanged, got %v", err)
		}
	})

	t.Run("wrapped_dns", func(t *testing.T) {
		adapter := operatorResolver{lookupNetIP: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, fmt.Errorf("resolver wrapper: %w", temporary)
		}}
		_, err := adapter.Lookup(context.Background(), resolverRegressionName, tools.FamilyIPv4)
		if !errors.Is(err, tools.ErrTemporary) || !errors.Is(err, temporary) {
			t.Fatalf("a wrapped temporary DNS error must keep both identities: %v", err)
		}
	})
}

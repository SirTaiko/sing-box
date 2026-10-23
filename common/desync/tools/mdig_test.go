package tools

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type funcResolver func(ctx context.Context, name string, family Family) ([]netip.Addr, error)

func (f funcResolver) Lookup(ctx context.Context, name string, family Family) ([]netip.Addr, error) {
	return f(ctx, name, family)
}

// fakeClock records sleeps and advances a virtual clock instead of blocking.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(1700000000, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.sleeps = append(c.sleeps, duration)
	c.now = c.now.Add(duration)
	c.mu.Unlock()
	return nil
}

func (c *fakeClock) recorded() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.sleeps...)
}

func fixedResolver(addresses ...string) funcResolver {
	parsed := make([]netip.Addr, 0, len(addresses))
	for _, text := range addresses {
		parsed = append(parsed, netip.MustParseAddr(text))
	}
	return func(context.Context, string, Family) ([]netip.Addr, error) {
		return parsed, nil
	}
}

func runMDig(t *testing.T, options MDigOptions, input string, resolver MDigResolver) (stdout string, diagnostics string, stats MDigStats, sleepCount int, err error) {
	t.Helper()
	var out strings.Builder
	var diag strings.Builder
	clock := newFakeClock()
	if options.Family == 0 {
		options.Family = FamilyIPv4
	}
	stats, err = MDig(context.Background(), strings.NewReader(input), &out, &diag, resolver, clock, options)
	return out.String(), diag.String(), stats, len(clock.recorded()), err
}

func TestMDigLiteralPassthrough(t *testing.T) {
	t.Parallel()
	calls := new(int32)
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		atomic.AddInt32(calls, 1)
		return nil, errors.New("must not be called")
	})
	input := "1.2.3.4\n1.2.3.4/24\n1.2.3.4/32\n2001:0DB8::1\n2001:db8::1/64\n2001:db8::1/129\n"
	stdout, _, stats, sleepCount, err := runMDig(t, MDigOptions{Family: FamilyIPv4 | FamilyIPv6}, input, resolver)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "1.2.3.4\n1.2.3.4/24\n1.2.3.4\n2001:0DB8::1\n2001:db8::1/64\n"
	if stdout != expected {
		t.Fatalf("output mismatch\n got: %q\nwant: %q", stdout, expected)
	}
	if atomic.LoadInt32(calls) != 0 {
		t.Fatal("literals must not reach the resolver")
	}
	if stats.Domains != 6 || stats.Success != 5 || stats.Error != 1 || stats.LiteralAddresses != 5 {
		t.Fatalf("unexpected stats %+v", stats)
	}
	if sleepCount != 0 {
		t.Fatalf("unexpected sleeps %d", sleepCount)
	}
}

func TestMDigFamilyFilter(t *testing.T) {
	t.Parallel()
	stdout, _, stats, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4}, "2001:db8::1\n1.2.3.4\n", fixedResolver())
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "1.2.3.4\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	if stats.Success != 1 || stats.Error != 1 {
		t.Fatalf("unexpected stats %+v", stats)
	}
}

func TestMDigResolveMock(t *testing.T) {
	t.Parallel()
	var usedFamily Family
	var usedName string
	resolver := funcResolver(func(_ context.Context, name string, family Family) ([]netip.Addr, error) {
		usedFamily = family
		usedName = name
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946")}, nil
	})
	stdout, diagnostics, stats, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4 | FamilyIPv6}, "example.com\n", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "93.184.216.34\n2606:2800:220:1:248:1893:25c8:1946\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	if usedName != "example.com" || usedFamily != FamilyIPv4|FamilyIPv6 {
		t.Fatalf("unexpected resolver call %q %v", usedName, usedFamily)
	}
	if stats.Addresses != 2 || stats.Success != 1 {
		t.Fatalf("unexpected stats %+v", stats)
	}
	if diagnostics != "" {
		t.Fatalf("host names must not be logged by default: %q", diagnostics)
	}
}

func TestMDigRetriesTemporaryFailure(t *testing.T) {
	t.Parallel()
	var calls int32
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			return nil, ErrTemporary
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	})
	stdout, _, stats, sleepCount, err := runMDig(t, MDigOptions{Family: FamilyIPv4, EAgainAttempts: 10, EAgainDelay: 500 * time.Millisecond}, "example.com\n", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
	if sleepCount != 2 {
		t.Fatalf("expected 2 delays between attempts, got %d", sleepCount)
	}
	if stdout != "1.1.1.1\n" || stats.Retries != 2 || stats.Success != 1 {
		t.Fatalf("unexpected result %q %+v", stdout, stats)
	}
}

func TestMDigRetriesExhausted(t *testing.T) {
	t.Parallel()
	var calls int32
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		atomic.AddInt32(&calls, 1)
		return nil, ErrTemporary
	})
	stdout, _, stats, sleepCount, err := runMDig(t, MDigOptions{Family: FamilyIPv4, EAgainAttempts: 3, EAgainDelay: 250 * time.Millisecond}, "example.com\n", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
	if sleepCount != 2 {
		t.Fatalf("expected 2 delays, got %d: a trailing delay is not reproduced", sleepCount)
	}
	if stdout != "" || stats.Error != 1 || stats.Success != 0 {
		t.Fatalf("unexpected result %q %+v", stdout, stats)
	}
}

func TestMDigPermanentFailureIsNotRetried(t *testing.T) {
	t.Parallel()
	var calls int32
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("EAI_NONAME")
	})
	_, _, stats, sleepCount, err := runMDig(t, MDigOptions{Family: FamilyIPv4}, "example.com\n", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&calls) != 1 || sleepCount != 0 {
		t.Fatalf("permanent failures must not be retried: calls=%d sleeps=%d", calls, sleepCount)
	}
	if stats.Error != 1 {
		t.Fatalf("unexpected stats %+v", stats)
	}
}

func TestMDigEmptyResultIsFailure(t *testing.T) {
	t.Parallel()
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		return nil, nil
	})
	stdout, _, stats, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4}, "example.com\n", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" || stats.Error != 1 {
		t.Fatalf("unexpected result %q %+v", stdout, stats)
	}
}

func TestMDigInvalidDomain(t *testing.T) {
	t.Parallel()
	var calls int32
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		atomic.AddInt32(&calls, 1)
		return nil, nil
	})
	input := "exa mple.com\nexample.com/24\n\x01bad.example\n.example.com\n"
	stdout, diagnostics, stats, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4, Verbose: true}, input, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "" || atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("invalid domains must not be resolved: %q calls=%d", stdout, calls)
	}
	if stats.InvalidDomains != 4 || stats.Error != 4 {
		t.Fatalf("unexpected stats %+v", stats)
	}
	if strings.Contains(diagnostics, "resolving") {
		t.Fatalf("invalid domains must not be resolved: %q", diagnostics)
	}
	if strings.Count(diagnostics, "invalid domain :") != 4 {
		t.Fatalf("expected four invalid-domain diagnostics, got %q", diagnostics)
	}
	if !strings.Contains(diagnostics, "[0] invalid domain : ?bad.example") {
		t.Fatalf("expected a beautified invalid domain diagnostic, got %q", diagnostics)
	}
}

func TestMDigStatsLines(t *testing.T) {
	t.Parallel()
	// 4 input lines: two literals, one empty line, one invalid domain.
	input := "1.2.3.4\n\nbad name\n1.2.3.5\n"
	stdout, diagnostics, stats, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4, StatsEvery: 2}, input, fixedResolver())
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "1.2.3.4\n1.2.3.5\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	const first = "mdig stats : 00:00:00 : domains=2 success=1 error=1\n"
	final := "mdig stats : 00:00:00 : domains=4 success=2 error=2\n"
	expected := first + final + final
	// The source prints once when the counter hits the interval and once at
	// the end (mdig.c:175,323), hence the duplicated final line.
	if diagnostics != expected {
		t.Fatalf("statistics mismatch\n got: %q\nwant: %q", diagnostics, expected)
	}
	if stats.Domains != 4 || stats.Success != 2 || stats.Error != 2 || stats.EmptyLines != 1 || stats.InvalidDomains != 1 {
		t.Fatalf("unexpected stats %+v", stats)
	}
}

func TestMDigStatisticsDisabledByDefault(t *testing.T) {
	t.Parallel()
	_, diagnostics, _, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4}, "1.2.3.4\n", fixedResolver())
	if err != nil {
		t.Fatal(err)
	}
	if diagnostics != "" {
		t.Fatalf("unexpected diagnostics %q", diagnostics)
	}
}

func TestMDigExplicitLogs(t *testing.T) {
	t.Parallel()
	resolver := funcResolver(func(_ context.Context, name string, _ Family) ([]netip.Addr, error) {
		if name == "fail.example" {
			return nil, errors.New("EAI_NONAME")
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	})
	var resolved strings.Builder
	var failed strings.Builder
	stdout, _, _, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4, LogResolved: &resolved, LogFailed: &failed}, "ok.example\nfail.example\n\n", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if stdout != "10.0.0.1\n" {
		t.Fatalf("unexpected output %q", stdout)
	}
	if resolved.String() != "ok.example\n" {
		t.Fatalf("unexpected resolved log %q", resolved.String())
	}
	if failed.String() != "fail.example\n" {
		t.Fatalf("unexpected failed log %q", failed.String())
	}
}

func TestMDigConcurrencyAndBoundedWorkers(t *testing.T) {
	t.Parallel()
	const workers = 8
	const names = 24
	var inFlight int32
	var maxInFlight int32
	gate := make(chan struct{})
	var once sync.Once
	resolver := funcResolver(func(ctx context.Context, name string, _ Family) ([]netip.Addr, error) {
		current := atomic.AddInt32(&inFlight, 1)
		for {
			previous := atomic.LoadInt32(&maxInFlight)
			if current <= previous || atomic.CompareAndSwapInt32(&maxInFlight, previous, current) {
				break
			}
		}
		if current == workers {
			once.Do(func() { close(gate) })
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		atomic.AddInt32(&inFlight, -1)
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	})
	var input strings.Builder
	for index := 0; index < names; index++ {
		input.WriteString("host")
		input.WriteString(strings.Repeat("a", index%5))
		input.WriteString(".example\n")
	}
	stdout, _, stats, _, err := runMDig(t, MDigOptions{Family: FamilyIPv4, Threads: workers}, input.String(), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Domains != names || stats.Success != names {
		t.Fatalf("unexpected stats %+v", stats)
	}
	if lines := strings.Count(stdout, "10.0.0.1\n"); lines != names {
		t.Fatalf("expected %d output lines, got %d", names, lines)
	}
	if got := atomic.LoadInt32(&maxInFlight); got < 2 || got > workers {
		t.Fatalf("concurrency outside the worker bound: %d", got)
	}
}

func TestMDigCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	var once sync.Once
	resolver := funcResolver(func(ctx context.Context, _ string, _ Family) ([]netip.Addr, error) {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	var diag strings.Builder
	done := make(chan error, 1)
	go func() {
		_, err := MDig(ctx, strings.NewReader("one.example\ntwo.example\n"), &out, &diag, resolver, newFakeClock(), MDigOptions{Family: FamilyIPv4, Threads: 2})
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("MDig did not stop on cancellation")
	}
}

func TestMDigOptionValidation(t *testing.T) {
	t.Parallel()
	base := MDigOptions{Family: FamilyIPv4}
	cases := []struct {
		name    string
		options MDigOptions
	}{
		{"missing family", MDigOptions{}},
		{"threads too high", MDigOptions{Family: FamilyIPv4, Threads: 101}},
		{"threads negative", MDigOptions{Family: FamilyIPv4, Threads: -1}},
		{"attempts too high", MDigOptions{Family: FamilyIPv4, EAgainAttempts: 1001}},
		{"delay negative", MDigOptions{Family: FamilyIPv4, EAgainDelay: -time.Second}},
		{"delay too high", MDigOptions{Family: FamilyIPv4, EAgainDelay: 101 * time.Second}},
		{"stats negative", MDigOptions{Family: FamilyIPv4, StatsEvery: -1}},
		{"line limit too small", MDigOptions{Family: FamilyIPv4, MaxLineLength: 8}},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var out strings.Builder
			_, err := MDig(context.Background(), strings.NewReader("1.2.3.4\n"), &out, io.Discard, fixedResolver(), newFakeClock(), test.options)
			if err == nil {
				t.Fatalf("expected a validation error for %+v", test.options)
			}
		})
	}
	var out strings.Builder
	_, err := MDig(context.Background(), strings.NewReader("1.2.3.4\n"), &out, io.Discard, nil, newFakeClock(), base)
	if err == nil {
		t.Fatal("expected a resolver requirement error")
	}
}

func TestMDigAddressLimit(t *testing.T) {
	t.Parallel()
	resolver := funcResolver(func(context.Context, string, Family) ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("10.0.0.2"),
			netip.MustParseAddr("10.0.0.3"),
		}, nil
	})
	var out strings.Builder
	_, err := MDig(context.Background(), strings.NewReader("example.com\n"), &out, io.Discard, resolver, newFakeClock(), MDigOptions{Family: FamilyIPv4, MaxAddressesPerName: 2})
	if err == nil || !strings.Contains(err.Error(), "address limit") && !strings.Contains(err.Error(), "more than") {
		t.Fatalf("expected an address limit error, got %v", err)
	}
}

func TestMDigOverlongLine(t *testing.T) {
	t.Parallel()
	var out strings.Builder
	_, err := MDig(context.Background(), strings.NewReader(strings.Repeat("a", 128)+"\n"), &out, io.Discard, fixedResolver(), newFakeClock(), MDigOptions{Family: FamilyIPv4, MaxLineLength: 32})
	if err == nil {
		t.Fatal("expected a line length error")
	}
}

func TestMDigShortWrite(t *testing.T) {
	t.Parallel()
	_, err := MDig(context.Background(), strings.NewReader("1.2.3.4\n"), shortWriter{}, io.Discard, fixedResolver(), newFakeClock(), MDigOptions{Family: FamilyIPv4})
	if err == nil {
		t.Fatal("expected a short write error")
	}
}

func TestValidMDigDomain(t *testing.T) {
	t.Parallel()
	valid := []string{"example.com", "a", "-lead.example", "under_score.example", "UPPER.example", "example..com"}
	for _, name := range valid {
		if !validMDigDomain(name) {
			t.Fatalf("%q should be accepted by dom_valid", name)
		}
	}
	invalid := []string{"", ".example.com", "exa mple.com", "example.com:443", "пример.рф", "example.com/24", "a\x7f.example"}
	for _, name := range invalid {
		if validMDigDomain(name) {
			t.Fatalf("%q should be rejected by dom_valid", name)
		}
	}
}

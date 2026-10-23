package direct

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// retainedReportNetwork and retainedReportDNS are inert dependency services for
// the production constructor: the probe never resolves, dials or captures, so
// no OS capability is required and no service call is synthesized.
type retainedReportNetwork struct{ adapter.NetworkManager }

func (retainedReportNetwork) InterfaceFinder() control.InterfaceFinder { return nil }
func (retainedReportNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (retainedReportNetwork) AutoDetectInterface() bool                { return false }
func (retainedReportNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }

type retainedReportDNS struct{ adapter.DNSTransportManager }

func (retainedReportDNS) Transports() []adapter.DNSTransport { return nil }
func (retainedReportDNS) Default() adapter.DNSTransport      { return nil }

// retainedReportWriter is the real configured logger's destination. It also
// reads the attempt lease and the engine while a message is being written, so a
// report that held an Engine/Lease lock across the logging call would deadlock
// and be reported as a bounded failure instead of hanging the test process.
type retainedReportWriter struct {
	mu    sync.Mutex
	text  string
	probe func()
}

func (w *retainedReportWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	w.text += string(p)
	probe := w.probe
	w.mu.Unlock()
	if probe != nil {
		probe()
	}
	return len(p), nil
}

func (w *retainedReportWriter) content() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.text
}

// TestRetainedNativeFailureReachesOperatorLogger is the SEC346-S2 regression.
// A retained native operation fails after its caller returned, so the caller's
// error channel no longer exists. The failure must still reach the operator
// exactly once through the direct outbound's existing production logger; before
// the fix it stopped in the private engine lease and neither the real logger
// nor the four existing diagnostic readers exposed it.
//
// The test uses the actual public constructor, a real started logging factory
// with a memory sink (positive control included), the real installed attempt
// hook, the real Engine lease and its admission charge. The only substituted
// input is the native retirement error itself, which is unavailable on this
// platform.
func TestRetainedNativeFailureReachesOperatorLogger(t *testing.T) {
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), retainedReportNetwork{})
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, retainedReportDNS{})
	sink := &retainedReportWriter{}
	factory, err := log.New(log.Options{
		Context:       ctx,
		DefaultWriter: sink,
		Options:       option.LogOptions{Level: "trace", DisableColor: true},
	})
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	if err = factory.Start(); err != nil {
		t.Fatalf("logging factory Start: %v", err)
	}
	defer factory.Close()
	logger := factory.NewLogger("retained-report")
	logger.ErrorContext(ctx, "RETENTION_REPORT_LOGGER_CONTROL")
	if !strings.Contains(sink.content(), "RETENTION_REPORT_LOGGER_CONTROL") {
		t.Fatal("real configured logger positive control failed: the sink is not active")
	}

	made, err := NewOutbound(ctx, nil, logger, "retained-report", option.DirectOutboundOptions{
		Desync: &option.DirectDesyncOptions{
			StreamRules: []option.DirectDesyncStreamRule{testStreamRule(443)},
		},
	})
	if err != nil {
		t.Fatalf("NewOutbound: %v", err)
	}
	outbound := made.(*Outbound)
	engine := outbound.desync
	if engine == nil {
		t.Fatal("stream-only desync configuration produced no state engine")
	}
	defer engine.Close()
	outbound.desyncStarted.Store(true)

	defaultDialer, ok := common.Cast[*dialer.DefaultDialer](outbound.dialer)
	if !ok {
		t.Fatal("production constructor did not install a DefaultDialer")
	}
	attempt, err := defaultDialer.AttemptHook().NewAttempt(ctx, dialer.AttemptIntent{
		Network:     N.NetworkTCP,
		Destination: M.ParseSocksaddr("198.51.100.20:443"),
	})
	if err != nil {
		t.Fatalf("attempt hook NewAttempt: %v", err)
	}
	lease, ok := attempt.(*desyncLease)
	if !ok {
		t.Fatalf("attempt lease is %T, want the production desyncLease", attempt)
	}
	reporter, ok := attempt.(interface{ ReportNativeFailure(error) })
	if !ok {
		t.Fatal("production attempt lease does not implement the retained-failure capability")
	}
	// The native hold is the charge a retained operation keeps. Acquiring it
	// here reproduces the retained owner that outlives its caller.
	hold, err := lease.AcquireNativeHold()
	if err != nil {
		t.Fatalf("AcquireNativeHold: %v", err)
	}
	// The caller returns and closes its own lease; the operation is retained.
	callerErr := errors.New("caller returned before the terminal receipt")
	if err = lease.Close(callerErr); err != nil {
		t.Fatalf("attempt lease Close: %v", err)
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases after the caller returned = %d, want the retained charge", active)
	}

	closeCause := errors.New("RETENTION_LATE_CLOSE_CAUSE")
	joinedCause := errors.New("RETENTION_JOINED_DIAGNOSTIC")
	late := E.Errors(E.Cause(closeCause, "desync: retire original socket"), joinedCause)

	// A report implementation that kept the lease or engine lock across the
	// logger call would deadlock in the sink probe below.
	sink.probe = func() {
		_ = lease.lease.Err()
		_ = engine.ActiveLeases()
	}
	reported := make(chan struct{})
	go func() {
		reporter.ReportNativeFailure(late)
		close(reported)
	}()
	select {
	case <-reported:
	case <-time.After(5 * time.Second):
		t.Fatal("retained failure report did not return within 5s: Engine/Lease lock held across the report")
	}
	sink.probe = nil

	text := sink.content()
	const reportPrefix = "desync: retained native socket retirement failed"
	if !strings.Contains(text, reportPrefix) {
		t.Fatalf("real production logger = %q, want the retained retirement report", text)
	}
	if !strings.Contains(text, "desync: retire original socket") || !strings.Contains(text, closeCause.Error()) {
		t.Fatalf("real production logger = %q, want the original close cause preserved", text)
	}
	if !strings.Contains(text, joinedCause.Error()) {
		t.Fatalf("real production logger = %q, want the joined cause preserved", text)
	}
	if count := strings.Count(text, closeCause.Error()); count != 1 {
		t.Fatalf("late cause reported %d time(s), want exactly once: %q", count, text)
	}
	if count := strings.Count(text, reportPrefix); count != 1 {
		t.Fatalf("retirement report emitted %d time(s), want exactly once: %q", count, text)
	}
	// The private per-attempt record is not the operator boundary, but the
	// existing join must still be intact: the lease remains the diagnostic
	// owner of the attempt.
	if !errors.Is(lease.lease.Err(), closeCause) {
		t.Fatalf("attempt lease diagnostic = %v, want the late cause joined", lease.lease.Err())
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases after the late report = %d, want the retained charge unchanged", active)
	}

	// A proven retirement discharges the charge exactly once and the freed slot
	// admits a replacement attempt.
	hold()
	deadline := time.Now().Add(2 * time.Second)
	for engine.ActiveLeases() != 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if active := engine.ActiveLeases(); active != 0 {
		t.Fatalf("active leases after the proven retirement = %d, want 0", active)
	}
	replacement, err := defaultDialer.AttemptHook().NewAttempt(ctx, dialer.AttemptIntent{
		Network:     N.NetworkTCP,
		Destination: M.ParseSocksaddr("198.51.100.21:443"),
	})
	if err != nil {
		t.Fatalf("replacement attempt after the proven retirement: %v", err)
	}
	defer replacement.Close(nil)
}

// TestRetainedNativeFailureWithoutLoggerKeepsPrivateRecord pins the bounded
// degradation: an attempt lease built without a configured logger still joins
// the failure into its existing engine diagnostic and does not panic, so a test
// or embedding caller that supplies no logger keeps the charge semantics.
func TestRetainedNativeFailureWithoutLoggerKeepsPrivateRecord(t *testing.T) {
	engine := newLimitedStateEngine(t)
	defer engine.Close()
	engineLease, err := engine.NewAttempt(desync.Intent{Transport: desync.TransportTCP})
	if err != nil {
		t.Fatalf("engine NewAttempt: %v", err)
	}
	bridge := &desyncLease{lease: engineLease}
	cause := errors.New("RETENTION_WITHOUT_LOGGER_CAUSE")
	bridge.ReportNativeFailure(E.Cause(cause, "desync: retire original socket"))
	if !errors.Is(engineLease.Err(), cause) {
		t.Fatalf("private lease diagnostic = %v, want the cause preserved without a logger", engineLease.Err())
	}
	if active := engine.ActiveLeases(); active != 1 {
		t.Fatalf("active leases = %d, want the untouched single charge", active)
	}
}

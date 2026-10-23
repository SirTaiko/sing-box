package direct

// Lifecycle and transport semantics of the optional diagnostics interface.

import (
	"context"
	"errors"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/desync"
	"github.com/sagernet/sing-box/option"
)

func desyncErrorCode(t *testing.T, err error) string {
	t.Helper()
	var diagnosticError adapter.DesyncDiagnosticError
	if !errors.As(err, &diagnosticError) {
		t.Fatalf("expected a typed desync diagnostic error, got %v", err)
	}
	return diagnosticError.Code
}

func TestDesyncDiagnosticsDisabledOutbound(t *testing.T) {
	outbound := &Outbound{}
	snapshot, err := outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != adapter.DesyncStateDisabled || snapshot.Kind != "status" || snapshot.Format != adapter.DesyncDiagnosticsFormat {
		t.Fatalf("unexpected disabled status %+v", snapshot)
	}
	if snapshot.Status == nil || snapshot.Status.PacketEnabled || snapshot.Status.StreamEnabled || snapshot.Status.ListRevision != 0 {
		t.Fatalf("disabled status must not touch an engine: %+v", snapshot.Status)
	}
	if snapshot.Total == nil || *snapshot.Total != 1 {
		t.Fatal("status total must be one")
	}
	if _, err = outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{Kind: adapter.DesyncDiagnosticConntrack}); desyncErrorCode(t, err) != "disabled" {
		t.Fatalf("unexpected disabled conntrack error %v", err)
	}
	if _, err = outbound.ReloadDesyncLists(context.Background()); desyncErrorCode(t, err) != "disabled" {
		t.Fatalf("unexpected disabled reload error %v", err)
	}
	// Invalid requests are rejected at the interface boundary as well.
	if _, err = outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{Kind: adapter.DesyncDiagnosticStatus, AllNetworks: true}); desyncErrorCode(t, err) != "invalid_request" {
		t.Fatalf("unexpected invalid request error %v", err)
	}
}

func TestDesyncDiagnosticsLifecycleStates(t *testing.T) {
	engine, err := desync.NewStateEngine(&option.DirectDesyncOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	outbound := &Outbound{desync: engine}
	snapshot, err := outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != adapter.DesyncStateNotStarted {
		t.Fatalf("state before lifecycle start: %s", snapshot.State)
	}
	if _, err = outbound.ReloadDesyncLists(context.Background()); desyncErrorCode(t, err) != "not_started" {
		t.Fatalf("reload before start: %v", err)
	}
	outbound.desyncStarted.Store(true)
	snapshot, err = outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != adapter.DesyncStateRunning || snapshot.Status == nil {
		t.Fatalf("running status: %+v", snapshot)
	}
	if snapshot.Status.PacketEnabled {
		t.Fatal("a stream-only state engine must not claim a packet backend")
	}
	if snapshot.Status.ListRevision != 1 {
		t.Fatalf("initial list revision %d", snapshot.Status.ListRevision)
	}
	rows, err := outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{Kind: adapter.DesyncDiagnosticConntrack})
	if err != nil {
		t.Fatal(err)
	}
	if rows.Conntrack == nil || len(rows.Conntrack.Rows) != 0 || rows.Total == nil || *rows.Total != 0 {
		t.Fatalf("empty conntrack section: %+v", rows)
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err = outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != adapter.DesyncStateClosed {
		t.Fatalf("closed state: %s", snapshot.State)
	}
	if _, err = outbound.ReloadDesyncLists(context.Background()); desyncErrorCode(t, err) != "closed" {
		t.Fatalf("reload after close: %v", err)
	}
	if _, err = outbound.DesyncDiagnostics(context.Background(), adapter.DesyncDiagnosticsRequest{Kind: adapter.DesyncDiagnosticWindowsNetwork}); desyncErrorCode(t, err) != "closed" {
		t.Fatalf("native query after close: %v", err)
	}
}

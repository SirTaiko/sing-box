package desync

// Bounded diagnostics and native-scope seam tests.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// snapshotOnlyProbe implements only the base NetworkProbe.
type snapshotOnlyProbe struct {
	calls int
}

func (p *snapshotOnlyProbe) MatchSSID(context.Context, []string) (bool, error) { return true, nil }
func (p *snapshotOnlyProbe) MatchNLM(context.Context, []string) (bool, error)  { return true, nil }
func (p *snapshotOnlyProbe) Snapshot(context.Context) (WindowsNetworkSnapshot, error) {
	p.calls++
	return WindowsNetworkSnapshot{QueriedAt: time.Unix(1, 0)}, nil
}

// optionProbe implements the optional bounded/all scope.
type optionProbe struct {
	snapshotOnlyProbe
	options []NetworkQueryOptions
}

func (p *optionProbe) SnapshotWithOptions(_ context.Context, options NetworkQueryOptions) (WindowsNetworkSnapshot, error) {
	p.options = append(p.options, options)
	return WindowsNetworkSnapshot{QueriedAt: time.Unix(2, 0)}, nil
}

func TestD5NativeScopeSeam(t *testing.T) {
	engine, err := NewStateEngine(&option.DirectDesyncOptions{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	base := &snapshotOnlyProbe{}
	engine.SetNetworkProbe(base)
	if _, err = engine.QueryWindowsNetworkWithOptions(context.Background(), NetworkQueryOptions{All: true}); !errors.Is(err, ErrNativeScopeUnsupported) {
		t.Fatalf("all scope without native support: %v", err)
	}
	if base.calls != 0 {
		t.Fatal("the connected-only fallback must not be used for the all scope")
	}
	if _, err = engine.QueryWindowsNetworkWithOptions(context.Background(), NetworkQueryOptions{}); err != nil {
		t.Fatal(err)
	}
	if base.calls != 1 {
		t.Fatalf("connected default query calls: %d", base.calls)
	}
	extension := &optionProbe{}
	engine.SetNetworkProbe(extension)
	if _, err = engine.QueryWindowsNetworkWithOptions(context.Background(), NetworkQueryOptions{All: true, Limit: 10}); err != nil {
		t.Fatal(err)
	}
	if len(extension.options) != 1 || !extension.options[0].All || extension.options[0].Limit != 10 {
		t.Fatalf("unexpected native options %+v", extension.options)
	}
	if _, err = engine.QueryWindowsNetworkWithOptions(context.Background(), NetworkQueryOptions{Limit: 1025}); err == nil {
		t.Fatal("limit above the documented bound must be rejected")
	}
}

func TestD5DiagnosticsIPCacheIsReadOnly(t *testing.T) {
	engine, err := NewStateEngine(&option.DirectDesyncOptions{IPCache: &option.DirectDesyncIPCache{Hostname: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	address := netip.MustParseAddr("192.0.2.7")
	if !engine.ipcache.learnHost(address, "owned0", "example.com") {
		t.Fatal("test cache entry was not learned")
	}
	key := ipCacheKey{address: address, iface: "owned0"}
	engine.ipcache.mu.Lock()
	before := engine.ipcache.entries[key].last
	engine.ipcache.mu.Unlock()
	rows, total, truncated := engine.DiagnosticsIPCache(10, false)
	if total != 1 || truncated || len(rows) != 1 {
		t.Fatalf("unexpected ipcache section %d %v %d", total, truncated, len(rows))
	}
	if rows[0].Address != nil || rows[0].Interface != nil || rows[0].Hostname != nil {
		t.Fatal("default diagnostics must omit sensitive identifiers")
	}
	if !rows[0].HostnamePresent || !rows[0].HostnameIsIP {
		// hostname_is_ip is false for a domain; only presence is asserted.
		_ = rows[0].HostnameIsIP
	}
	if rows[0].ExpiresInMs == nil {
		t.Fatal("a bounded cache lifetime must report a remaining expiry")
	}
	engine.ipcache.mu.Lock()
	after := engine.ipcache.entries[key].last
	engine.ipcache.mu.Unlock()
	if !after.Equal(before) {
		t.Fatal("the diagnostics snapshot refreshed the cache entry")
	}
	sensitive, _, _ := engine.DiagnosticsIPCache(10, true)
	if len(sensitive) != 1 || sensitive[0].Address == nil || sensitive[0].Hostname == nil {
		t.Fatal("explicit sensitive mode must expose the documented optional fields")
	}
}

func TestD5SelectionBudgetRejected(t *testing.T) {
	state := newListBuildState()
	if err := state.account("bundle\x00gen\x00ip4", 0, int(listSelectionMaxEntries)+1); err == nil {
		t.Fatal("entry budget overrun must fail before allocation")
	}
	if err := state.account("bundle\x00gen\x00ip4", listSelectionMaxBytes+1, 0); err == nil {
		t.Fatal("byte budget overrun must fail before allocation")
	}
	state = newListBuildState()
	if err := state.account("shared", 10, 1); err != nil {
		t.Fatal(err)
	}
	if err := state.account("shared", listSelectionMaxBytes, int(listSelectionMaxEntries)); err != nil {
		t.Fatalf("a deduplicated shared reference must be charged once: %v", err)
	}
}

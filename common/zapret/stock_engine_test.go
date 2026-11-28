//go:build linux || windows

package zapret

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const observerLua = `function mvpn_observe(ctx, packet)
  if not mvpn_observed then
    mvpn_observed = true
    DLOG_CONDUP("MVPN_TEST_OBSERVED")
  end
  return VERDICT_PASS
end
`

type stockLogger struct {
	mu       sync.Mutex
	lines    int
	errors   int
	observed bool
	luaDebug bool
}

func (l *stockLogger) Info(...any) {}
func (l *stockLogger) Debug(args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines++
	for _, arg := range args {
		if s, ok := arg.(string); ok {
			l.observed = l.observed || s == "LUA: MVPN_TEST_OBSERVED"
			l.luaDebug = l.luaDebug || s == "LUA INIT DONE"
		}
	}
}
func (l *stockLogger) Error(...any) { l.mu.Lock(); l.errors++; l.mu.Unlock() }

func stockProfile(t *testing.T, executable, script, target string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "observe.lua"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	recipe, _ := json.Marshal([]string{"--lua-init=@observe.lua", "--filter-tcp=80", "--lua-desync=" + target})
	if err := os.WriteFile(filepath.Join(dir, "strategy.json"), recipe, 0600); err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(profileDocument{Engine: EngineName, Executable: executable, StrategyFile: "strategy.json"})
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, doc, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStockEngineReadinessAndDiagnostics(t *testing.T) {
	exe := os.Getenv("MVPN_TEST_ZAPRET_ENGINE")
	if exe == "" {
		t.Skip("requires the stock engine and a dedicated test interface")
	}
	iface, err := net.InterfaceByName(os.Getenv("MVPN_TEST_ZAPRET_INTERFACE"))
	if err != nil {
		t.Fatal(err)
	}
	target := os.Getenv("MVPN_TEST_ZAPRET_RECEIVER")
	ip := net.ParseIP(target)
	if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
		t.Fatal("set an IPv4 private lab receiver")
	}
	for _, tc := range []struct{ name, debug, script, fn, expected string }{
		{"quiet", "", observerLua, "mvpn_observe", ""},
		{"diagnostic", "1", observerLua, "mvpn_observe", ""},
		{"invalid-lua", "", "error('fixture initialization failed')", "mvpn_observe", "fixture initialization failed"},
		{"invalid-syntax", "", "function )", "mvpn_observe", "observe.lua"},
		{"missing-function", "", observerLua, "mvpn_missing", "mvpn_missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MVPN_ZAPRET_DEBUG", tc.debug)
			logger := new(stockLogger)
			m, err := NewManager(Options{Tag: "mvpn-test", ProfilePath: stockProfile(t, exe, tc.script, tc.fn), BindInterface: iface.Name, Logger: logger, StartupTimeout: 6 * time.Second, StopTimeout: 4 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			start := time.Now()
			err = m.Start(context.Background(), iface.Index)
			if tc.expected != "" {
				if err == nil || m.State() != StateFailed || !strings.Contains(err.Error(), tc.expected) {
					t.Fatalf("wrong failed startup: %v", err)
				}
				logger.mu.Lock()
				n := logger.errors
				logger.mu.Unlock()
				if n == 0 {
					t.Fatal("child failure did not reach error logger")
				}
				return
			}
			if err != nil || m.State() != StateReady {
				t.Fatalf("idle startup failed: %v", err)
			}
			started := time.Since(start)
			// No owned connection was opened before the manager reported readiness.
			dialer := net.Dialer{Control: m.Control, Timeout: 4 * time.Second}
			transport := &http.Transport{DialContext: dialer.DialContext, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/pilot-32MiB.bin", target), nil)
			req.Header.Set("Range", "bytes=0-65535")
			client := http.Client{Transport: transport, Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			n, err := io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if err != nil || n != 65536 || resp.StatusCode != http.StatusPartialContent {
				t.Fatalf("incomplete lab transfer: %d %d %v", resp.StatusCode, n, err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				logger.mu.Lock()
				seen, verbose, lines := logger.observed, logger.luaDebug, logger.lines
				logger.mu.Unlock()
				if seen {
					if verbose != (tc.debug == "1") {
						t.Fatal("stock debug mode differs from request")
					}
					t.Logf("ready without traffic in %s, observed %d bytes, %d child/manager debug lines", started, n, lines)
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("stock Lua did not see an owned test packet")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

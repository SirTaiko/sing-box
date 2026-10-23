package clashapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
)

type fakeDesyncOutbound struct {
	adapter.Outbound
	tag           string
	snapshot      adapter.DesyncDiagnosticsSnapshot
	snapshotError error
	reloadResult  adapter.DesyncReloadResult
	reloadError   error
	lastRequest   adapter.DesyncDiagnosticsRequest
	reloads       int
}

func (f *fakeDesyncOutbound) Tag() string { return f.tag }

func (f *fakeDesyncOutbound) DesyncDiagnostics(_ context.Context, request adapter.DesyncDiagnosticsRequest) (adapter.DesyncDiagnosticsSnapshot, error) {
	f.lastRequest = request
	return f.snapshot, f.snapshotError
}

func (f *fakeDesyncOutbound) ReloadDesyncLists(_ context.Context) (adapter.DesyncReloadResult, error) {
	f.reloads++
	return f.reloadResult, f.reloadError
}

type fakePlainOutbound struct {
	adapter.Outbound
	tag string
}

func (f *fakePlainOutbound) Tag() string { return f.tag }

type fakeOutboundManager struct {
	outbounds map[string]adapter.Outbound
}

func (m *fakeOutboundManager) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (m *fakeOutboundManager) Outbounds() []adapter.Outbound {
	values := make([]adapter.Outbound, 0, len(m.outbounds))
	for _, outbound := range m.outbounds {
		values = append(values, outbound)
	}
	return values
}
func (m *fakeOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, found := m.outbounds[tag]
	return outbound, found
}
func (m *fakeOutboundManager) Default() adapter.Outbound { return nil }
func (m *fakeOutboundManager) Create(context.Context, adapter.Router, log.ContextLogger, string, string, any) error {
	return nil
}

func sensitivePointer(value string) *string { return &value }

func newSnapshot() adapter.DesyncDiagnosticsSnapshot {
	total := uint64(1)
	return adapter.DesyncDiagnosticsSnapshot{
		Format:     adapter.DesyncDiagnosticsFormat,
		Outbound:   "zapret",
		State:      adapter.DesyncStateRunning,
		Kind:       "conntrack",
		Redacted:   false,
		CapturedAt: "2026-10-22T12:00:00Z",
		Total:      &total,
		Returned:   1,
		Conntrack: &adapter.DesyncConntrackPayload{
			Enabled: true,
			Rows: []adapter.DesyncConntrackRow{{
				Family:      4,
				Transport:   "tcp",
				State:       "established",
				Source:      sensitivePointer("192.0.2.10:1234"),
				Destination: sensitivePointer("198.51.100.20:443"),
			}},
		},
	}
}

func testManager(outbound *fakeDesyncOutbound) *fakeOutboundManager {
	return &fakeOutboundManager{outbounds: map[string]adapter.Outbound{
		"zapret": outbound,
		"plain":  &fakePlainOutbound{tag: "plain"},
	}}
}

func serve(t *testing.T, manager adapter.OutboundManager, method string, target string, body string, header http.Header, remote string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == "" {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader([]byte(body))
	}
	request := httptest.NewRequest(method, target, reader)
	if remote == "" {
		remote = "127.0.0.1:45678"
	}
	request.RemoteAddr = remote
	for key, values := range header {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	recorder := httptest.NewRecorder()
	desyncRouter(manager).ServeHTTP(recorder, request)
	return recorder
}

func decodeJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("invalid JSON response: %v (%s)", err, recorder.Body.String())
	}
	return document
}

func TestDesyncDiagnosticsRoutes(t *testing.T) {
	outbound := &fakeDesyncOutbound{tag: "zapret", snapshot: newSnapshot()}
	manager := testManager(outbound)
	recorder := serve(t, manager, http.MethodGet, "/desync/diagnostics?outbound=zapret&kind=conntrack&limit=8", "", nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	if outbound.lastRequest.Limit != 8 || outbound.lastRequest.Kind != adapter.DesyncDiagnosticConntrack {
		t.Fatalf("request not forwarded: %+v", outbound.lastRequest)
	}
	document := decodeJSON(t, recorder)
	if document["format"] != adapter.DesyncDiagnosticsFormat || document["redacted"] != true {
		t.Fatalf("unexpected default snapshot: %v", document)
	}
	conntrack := document["conntrack"].(map[string]any)
	row := conntrack["rows"].([]any)[0].(map[string]any)
	if _, present := row["source"]; present {
		t.Fatal("default redaction must omit endpoint identities")
	}
	// Direct mounting without the /desync prefix works and sensitive mode keeps
	// the documented optional fields.
	recorder = serve(t, manager, http.MethodGet, "/diagnostics?outbound=zapret&kind=conntrack&include_sensitive=true", "", nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected direct mount status %d", recorder.Code)
	}
	document = decodeJSON(t, recorder)
	row = document["conntrack"].(map[string]any)["rows"].([]any)[0].(map[string]any)
	if row["source"] != "192.0.2.10:1234" || document["redacted"] != false {
		t.Fatalf("sensitive mode must keep optional fields: %v", document)
	}
	// The default kind is status and the default limit is 128.
	statusOutbound := &fakeDesyncOutbound{tag: "zapret", snapshot: adapter.DesyncDiagnosticsSnapshot{State: adapter.DesyncStateDisabled}}
	serve(t, testManager(statusOutbound), http.MethodGet, "/desync/diagnostics?outbound=zapret", "", nil, "")
	if statusOutbound.lastRequest.Kind != adapter.DesyncDiagnosticStatus || statusOutbound.lastRequest.Limit != adapter.DesyncDefaultDiagnosticsLimit {
		t.Fatalf("unexpected defaults: %+v", statusOutbound.lastRequest)
	}
	if t.Run("reload", func(t *testing.T) {
		outbound.reloadResult = adapter.DesyncReloadResult{State: adapter.DesyncStateRunning, ListRevision: 2, Changed: true}
		recorder := serve(t, manager, http.MethodPost, "/desync/reload", `{"outbound":"zapret"}`, http.Header{"Content-Type": {"application/json"}}, "")
		if recorder.Code != http.StatusOK {
			t.Fatalf("reload status %d: %s", recorder.Code, recorder.Body.String())
		}
		result := decodeJSON(t, recorder)
		if result["format"] != adapter.DesyncReloadFormat || result["outbound"] != "zapret" || result["changed"] != true {
			t.Fatalf("unexpected reload result: %v", result)
		}
	}); !t.Failed() {
		_ = outbound.reloads
	}
}

func TestDesyncDiagnosticsErrorMapping(t *testing.T) {
	outbound := &fakeDesyncOutbound{tag: "zapret", snapshot: newSnapshot()}
	manager := testManager(outbound)
	cases := []struct {
		name   string
		target string
		body   string
		header http.Header
		remote string
		status int
		code   string
	}{
		{"unknown tag", "/desync/diagnostics?outbound=nope", "", nil, "", http.StatusNotFound, "outbound_not_found"},
		{"unsupported outbound", "/desync/diagnostics?outbound=plain", "", nil, "", http.StatusConflict, "diagnostics_unsupported"},
		{"missing tag", "/desync/diagnostics", "", nil, "", http.StatusBadRequest, "invalid_query"},
		{"unknown parameter", "/desync/diagnostics?outbound=zapret&path=/etc/passwd", "", nil, "", http.StatusBadRequest, "invalid_query"},
		{"duplicate parameter", "/desync/diagnostics?outbound=zapret&outbound=zapret", "", nil, "", http.StatusBadRequest, "invalid_query"},
		{"unknown kind", "/desync/diagnostics?outbound=zapret&kind=packets", "", nil, "", http.StatusBadRequest, "invalid_query"},
		{"limit out of range", "/desync/diagnostics?outbound=zapret&limit=2048", "", nil, "", http.StatusBadRequest, "invalid_query"},
		{"all networks on status", "/desync/diagnostics?outbound=zapret&all_networks=true", "", nil, "", http.StatusBadRequest, "invalid_query"},
		{"query token", "/desync/diagnostics?outbound=zapret&token=secret", "", nil, "", http.StatusForbidden, "query_token_forbidden"},
		{"origin", "/desync/diagnostics?outbound=zapret", "", http.Header{"Origin": {"https://evil.example"}}, "", http.StatusForbidden, "origin_forbidden"},
		{"upgrade", "/desync/diagnostics?outbound=zapret", "", http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}}, "", http.StatusForbidden, "upgrade_forbidden"},
		{"non loopback", "/desync/diagnostics?outbound=zapret", "", nil, "203.0.113.5:1234", http.StatusForbidden, "not_loopback"},
	}
	for _, testCase := range cases {
		recorder := serve(t, manager, http.MethodGet, testCase.target, testCase.body, testCase.header, testCase.remote)
		if recorder.Code != testCase.status {
			t.Fatalf("%s: status %d, want %d (%s)", testCase.name, recorder.Code, testCase.status, recorder.Body.String())
		}
		document := decodeJSON(t, recorder)
		if document["format"] != adapter.DesyncErrorFormat || document["code"] != testCase.code {
			t.Fatalf("%s: unexpected error document %v", testCase.name, document)
		}
	}
	// Method handling.
	recorder := serve(t, manager, http.MethodPost, "/desync/diagnostics?outbound=zapret", "", nil, "")
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("diagnostics must reject POST: %d", recorder.Code)
	}
	recorder = serve(t, manager, http.MethodGet, "/desync/reload", "", nil, "")
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("reload must reject GET: %d", recorder.Code)
	}
}

func TestDesyncReloadBodyValidation(t *testing.T) {
	outbound := &fakeDesyncOutbound{tag: "zapret", snapshot: newSnapshot()}
	manager := testManager(outbound)
	jsonHeader := http.Header{"Content-Type": {"application/json"}}
	rejects := []struct {
		name   string
		body   string
		header http.Header
		status int
	}{
		{"missing content type", `{"outbound":"zapret"}`, nil, http.StatusBadRequest},
		{"wrong content type", `{"outbound":"zapret"}`, http.Header{"Content-Type": {"text/plain"}}, http.StatusBadRequest},
		{"unknown field", `{"outbound":"zapret","path":"/tmp/x"}`, jsonHeader, http.StatusBadRequest},
		{"duplicate field", `{"outbound":"zapret","outbound":"plain"}`, jsonHeader, http.StatusBadRequest},
		{"trailing document", `{"outbound":"zapret"} {}`, jsonHeader, http.StatusBadRequest},
		{"empty tag", `{"outbound":""}`, jsonHeader, http.StatusBadRequest},
		{"malformed", `{`, jsonHeader, http.StatusBadRequest},
	}
	for _, testCase := range rejects {
		recorder := serve(t, manager, http.MethodPost, "/desync/reload", testCase.body, testCase.header, "")
		if recorder.Code != testCase.status {
			t.Fatalf("%s: status %d, want %d (%s)", testCase.name, recorder.Code, testCase.status, recorder.Body.String())
		}
	}
	oversized := `{"outbound":"` + strings.Repeat("a", desyncBodyMaxBytes) + `"}`
	recorder := serve(t, manager, http.MethodPost, "/desync/reload", oversized, jsonHeader, "")
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized reload body: %d", recorder.Code)
	}
	if outbound.reloads != 0 {
		t.Fatal("rejected bodies must not reach the outbound")
	}
}

func TestDesyncDiagnosticsTypedFailure(t *testing.T) {
	for _, testCase := range []struct {
		code   string
		status int
	}{
		{"closed", http.StatusConflict},
		{"not_started", http.StatusConflict},
		{"disabled", http.StatusConflict},
		{"busy", http.StatusConflict},
		{"unsupported", http.StatusUnprocessableEntity},
		{"native_query_failed", http.StatusServiceUnavailable},
	} {
		outbound := &fakeDesyncOutbound{tag: "zapret", snapshotError: adapter.DesyncDiagnosticError{Code: testCase.code, RetainedLastGood: true}}
		recorder := serve(t, testManager(outbound), http.MethodGet, "/desync/diagnostics?outbound=zapret", "", nil, "")
		if recorder.Code != testCase.status {
			t.Fatalf("%s: status %d, want %d", testCase.code, recorder.Code, testCase.status)
		}
		document := decodeJSON(t, recorder)
		if document["code"] != testCase.code || document["retained_last_good"] != true {
			t.Fatalf("%s: unexpected document %v", testCase.code, document)
		}
	}
}

func TestDesyncDiagnosticsBoundedResponse(t *testing.T) {
	rows := make([]adapter.DesyncConntrackRow, 0, 64)
	host := strings.Repeat("h", 40000)
	for index := 0; index < 64; index++ {
		rows = append(rows, adapter.DesyncConntrackRow{
			Family: 4, Transport: "tcp", State: "established",
			Source: sensitivePointer(host + ":1234"), Destination: sensitivePointer(host + ":443"),
		})
	}
	total := uint64(len(rows))
	outbound := &fakeDesyncOutbound{tag: "zapret", snapshot: adapter.DesyncDiagnosticsSnapshot{
		State: adapter.DesyncStateRunning, Kind: "conntrack", CapturedAt: "2026-10-22T12:00:00Z",
		Total: &total, Returned: total,
		Conntrack: &adapter.DesyncConntrackPayload{Enabled: true, Rows: rows},
	}}
	recorder := serve(t, testManager(outbound), http.MethodGet, "/desync/diagnostics?outbound=zapret&kind=conntrack&limit=64&include_sensitive=true", "", nil, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d", recorder.Code)
	}
	if recorder.Body.Len() > desyncResponseMaxBytes {
		t.Fatalf("response exceeds the bound: %d", recorder.Body.Len())
	}
	document := decodeJSON(t, recorder)
	if document["truncated"] != true {
		t.Fatalf("bounded response must be marked truncated: %v", document["truncated"])
	}
}

func TestDesyncRouterEligibility(t *testing.T) {
	if err := desyncRouterEligible("", "127.0.0.1:9090"); err == nil {
		t.Fatal("empty secret must make the routes ineligible")
	}
	for _, address := range []string{"0.0.0.0:9090", ":9090", "example.com:9090", "127.0.0.1:0", "127.0.0.1"} {
		if err := desyncRouterEligible("secret", address); err == nil {
			t.Fatalf("%s must be ineligible", address)
		}
	}
	for _, address := range []string{"127.0.0.1:9090", "127.8.9.10:1", "[::1]:9090"} {
		if err := desyncRouterEligible("secret", address); err != nil {
			t.Fatalf("%s must be eligible: %v", address, err)
		}
	}
}

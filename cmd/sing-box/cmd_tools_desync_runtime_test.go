package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

type fakeRuntimeTransport struct {
	requests []*http.Request
	bodies   [][]byte
	respond  func(*http.Request) (*http.Response, error)
}

func (f *fakeRuntimeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, request)
	return f.respond(request)
}

func testRuntimeClient(transport http.RoundTripper, secret string) desyncRuntimeClient {
	return desyncRuntimeClient{
		transport: transport,
		getenv: func(key string) string {
			if key == desyncRuntimeSecretEnv {
				return secret
			}
			return ""
		},
	}
}

func jsonResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
		Request:    request,
	}
}

func TestValidateDesyncServer(t *testing.T) {
	valid := []string{"http://127.0.0.1:9090", "http://127.8.9.10:1", "http://[::1]:9090", "http://127.0.0.1:9090/"}
	for _, value := range valid {
		if _, err := validateDesyncServer(value); err != nil {
			t.Fatalf("%s must be accepted: %v", value, err)
		}
	}
	invalid := []string{
		"", "https://127.0.0.1:9090", "http://localhost:9090", "http://0.0.0.0:9090",
		"http://192.168.1.1:9090", "http://127.0.0.1:0", "http://127.0.0.1",
		"http://127.0.0.1:9090/api", "http://user:pass@127.0.0.1:9090",
		"http://127.0.0.1:9090/?token=x", "http://127.0.0.1:9090/#fragment",
	}
	for _, value := range invalid {
		if _, err := validateDesyncServer(value); err == nil {
			t.Fatalf("%s must be rejected", value)
		}
	}
}

func TestDesyncRuntimeClientTransport(t *testing.T) {
	transport := &fakeRuntimeTransport{respond: func(request *http.Request) (*http.Response, error) {
		return jsonResponse(request, http.StatusOK, `{"format":"desync.reload/v1","outbound":"zapret"}`), nil
	}}
	client := testRuntimeClient(transport, "top-secret")
	payload, err := client.do(context.Background(), mustServerURL(t, "http://127.0.0.1:9090"), "/desync/reload", http.MethodPost, "top-secret", []byte(`{"outbound":"zapret"}`), "application/json")
	if err != nil {
		t.Fatalf("reload request: %v", err)
	}
	if !strings.Contains(string(payload), adapter.DesyncReloadFormat) {
		t.Fatal("typed reload result missing")
	}
	if len(transport.requests) != 1 {
		t.Fatal("exactly one request is expected")
	}
	request := transport.requests[0]
	if request.Method != http.MethodPost || request.URL.Path != "/desync/reload" {
		t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
	}
	if request.Header.Get("Authorization") != "Bearer top-secret" {
		t.Fatal("bearer header missing")
	}
	if strings.Contains(request.URL.RawQuery, "top-secret") || strings.Contains(request.URL.RawQuery, "token") {
		t.Fatal("credential must not appear in the URL")
	}
	// A typed error response is reduced to its stable code.
	errorTransport := &fakeRuntimeTransport{respond: func(request *http.Request) (*http.Response, error) {
		return jsonResponse(request, http.StatusConflict, `{"format":"desync.error/v1","code":"closed","retained_last_good":false}`), nil
	}}
	_, err = testRuntimeClient(errorTransport, "top-secret").doURL(context.Background(), "http://127.0.0.1:9090/desync/reload", http.MethodPost, "top-secret", []byte(`{}`), "application/json")
	if err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("typed error code missing: %v", err)
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatal("credential leaked into an error message")
	}
	// Missing environment credential fails before any request.
	if _, err = readDesyncSecret(testRuntimeClient(transport, "")); err == nil {
		t.Fatal("missing environment secret must fail")
	}
	if _, err = testRuntimeClient(transport, "abc").doURL(context.Background(), "http://127.0.0.1:9090/desync/reload", http.MethodPost, "abc", nil, "application/json"); err != nil {
		t.Fatalf("empty body request: %v", err)
	}
}

func mustServerURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := validateDesyncServer(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestDesyncDiagnosticsCommand(t *testing.T) {
	transport := &fakeRuntimeTransport{respond: func(request *http.Request) (*http.Response, error) {
		body := `{"format":"desync.diagnostics/v1","outbound":"zapret","state":"running","kind":"conntrack","redacted":true,"captured_at":"2026-10-22T12:00:00Z","total":0,"returned":0,"truncated":false,"conntrack":{"enabled":true,"rows":[]}}`
		return jsonResponse(request, http.StatusOK, body), nil
	}}
	command := newToolsDesyncDiagnosticsCommand(testRuntimeClient(transport, "top-secret"))
	buffer := new(bytes.Buffer)
	command.SetOut(buffer)
	command.SetArgs([]string{"--server", "http://127.0.0.1:9090", "--outbound", "zapret", "--kind", "conntrack", "--limit", "64"})
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("diagnostics command: %v", err)
	}
	if !strings.Contains(buffer.String(), adapter.DesyncDiagnosticsFormat) {
		t.Fatalf("typed snapshot missing: %s", buffer.String())
	}
	if len(transport.requests) != 1 {
		t.Fatal("expected one request")
	}
	request := transport.requests[0]
	query := request.URL.Query()
	if request.Method != http.MethodGet || query.Get("outbound") != "zapret" || query.Get("kind") != "conntrack" || query.Get("limit") != "64" {
		t.Fatalf("unexpected query: %s", request.URL.RawQuery)
	}
	if query.Get("token") != "" || strings.Contains(request.URL.RawQuery, "top-secret") {
		t.Fatal("credential must not appear in the query")
	}
	// Invalid flags fail before any request.
	failing := newToolsDesyncDiagnosticsCommand(testRuntimeClient(transport, "top-secret"))
	failing.SetOut(new(bytes.Buffer))
	failing.SetArgs([]string{"--server", "http://127.0.0.1:9090", "--outbound", "zapret", "--all-networks"})
	if err := failing.ExecuteContext(context.Background()); err == nil {
		t.Fatal("--all-networks outside windows-network must fail")
	}
	if len(transport.requests) != 1 {
		t.Fatal("invalid flags must not reach the controller")
	}
}

func TestDesyncOutputFileIsStagedAndAliasSafe(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "snapshot.json")
	payload := []byte(`{"format":"desync.diagnostics/v1"}`)
	command := newToolsDesyncReloadCommand(testRuntimeClient(&fakeRuntimeTransport{}, "s"))
	command.SetOut(new(bytes.Buffer))
	if err := writeDesyncCommandOutput(command, path, payload); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("output mode must be 0600: %o", info.Mode().Perm())
	}
	read, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(read, payload) {
		t.Fatal("output content mismatch")
	}
	linkDirectory := filepath.Join(t.TempDir(), "link.json")
	if err = os.Symlink(path, linkDirectory); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err = writeDesyncCommandOutput(command, linkDirectory, payload); err == nil {
		t.Fatal("a symlinked output file must be refused")
	}
}

func TestDesyncRuntimeCommandsNeverUseAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client := operatorDesyncRuntimeClient()
	transport, ok := client.transport.(*http.Transport)
	if !ok {
		t.Fatal("production transport type changed")
	}
	if transport.Proxy != nil {
		t.Fatal("the runtime client must not use an ambient proxy")
	}
	if !transport.DisableCompression {
		t.Fatal("automatic decompression must stay disabled")
	}
	command := newToolsDesyncReloadCommand(client)
	command.SetOut(new(bytes.Buffer))
	command.SetArgs([]string{"--server", "http://127.0.0.1:9090", "--outbound", "zapret"})
	t.Setenv(desyncRuntimeSecretEnv, "")
	if err := command.ExecuteContext(context.Background()); err == nil {
		t.Fatal("a missing environment secret must fail before dialing")
	}
}

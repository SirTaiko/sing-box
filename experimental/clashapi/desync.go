package clashapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/go-chi/chi/v5"
)

// Desync diagnostics HTTP surface.
//
// desyncRouter is the exact integration contract of the D5 helper lane: the core
// owner mounts it inside the existing authenticated controller group, only when
// the existing controller secret is nonempty and ExternalController is a numeric
// loopback address with an explicit port. The router itself adds the
// feature-local protections that must hold irrespective of the shared
// authentication middleware: no query token, no WebSocket upgrade, no browser
// origin, no URL credentials and a loopback RemoteAddr check.
//
// No listener, background retry, cache or secret store is created here.

const (
	desyncDiagnosticsPath  = "/diagnostics"
	desyncReloadPath       = "/reload"
	desyncMountPath        = "/desync"
	desyncQueryMaxBytes    = 4096
	desyncBodyMaxBytes     = 4096
	desyncResponseMaxBytes = 1 << 20
	desyncMaxTagBytes      = 256
)

// desyncRouter builds the /desync subtree. Both direct mounting at /desync and a
// root handler registration are supported, so the core owner can wire it inside
// the existing group without another path decision.
func desyncRouter(outbound adapter.OutboundManager) http.Handler {
	router := chi.NewRouter()
	router.Use(desyncFeatureMiddleware)
	register := func(pattern string) {
		router.Get(pattern, desyncDiagnosticsHandler(outbound))
	}
	register(desyncDiagnosticsPath)
	register(desyncMountPath + desyncDiagnosticsPath)
	router.Post(desyncMountPath+desyncReloadPath, desyncReloadHandler(outbound))
	router.Post(desyncReloadPath, desyncReloadHandler(outbound))
	router.Get("/", desyncNotFound)
	return router
}

// DesyncRouter is the exported alias of desyncRouter for out-of-package
// integration tests. The core owner uses desyncRouter from inside this package.
func DesyncRouter(outbound adapter.OutboundManager) http.Handler {
	return desyncRouter(outbound)
}

// desyncRouterEligible documents and checks the existing-controller gate: the
// router may be mounted only for a nonempty secret and a numeric loopback
// listener with an explicit nonzero port. It never starts a controller.
func desyncRouterEligible(secret string, listenAddress string) error {
	if secret == "" {
		return E.New("desync routes require a nonempty controller secret")
	}
	host, portText, err := net.SplitHostPort(listenAddress)
	if err != nil {
		return E.Cause(err, "desync routes require a numeric loopback controller address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return E.New("desync routes require an explicit nonzero controller port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return E.New("desync routes require a numeric loopback controller address")
	}
	return nil
}

func desyncNotFound(writer http.ResponseWriter, _ *http.Request) {
	writer.WriteHeader(http.StatusNotFound)
}

// desyncFeatureMiddleware enforces the feature-local transport rules before any
// Engine or native work happens.
func desyncFeatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		if request.URL.User != nil {
			writeDesyncError(writer, http.StatusForbidden, "credentials_in_url", false)
			return
		}
		for _, key := range []string{"token", "access_token", "auth"} {
			if _, present := request.URL.Query()[key]; present {
				writeDesyncError(writer, http.StatusForbidden, "query_token_forbidden", false)
				return
			}
		}
		if request.Header.Get("Upgrade") != "" || request.Header.Get("Connection") != "" &&
			strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") {
			writeDesyncError(writer, http.StatusForbidden, "upgrade_forbidden", false)
			return
		}
		if request.Header.Get("Origin") != "" {
			writeDesyncError(writer, http.StatusForbidden, "origin_forbidden", false)
			return
		}
		if !desyncRemoteIsLoopback(request.RemoteAddr) {
			writeDesyncError(writer, http.StatusForbidden, "not_loopback", false)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func desyncRemoteIsLoopback(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return address.IsLoopback()
}

func desyncDiagnosticsHandler(outbound adapter.OutboundManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			writeDesyncError(writer, http.StatusMethodNotAllowed, "method_not_allowed", false)
			return
		}
		if request.ContentLength > 0 || len(request.URL.RawQuery) > desyncQueryMaxBytes {
			writeDesyncError(writer, http.StatusRequestEntityTooLarge, "request_too_large", false)
			return
		}
		tag, diagnosticsRequest, err := parseDesyncDiagnosticsQuery(request)
		if err != nil {
			writeDesyncError(writer, http.StatusBadRequest, "invalid_query", false)
			return
		}
		target, found := outbound.Outbound(tag)
		if !found {
			writeDesyncError(writer, http.StatusNotFound, "outbound_not_found", false)
			return
		}
		diagnostics, supported := target.(adapter.OutboundDesyncDiagnostics)
		if !supported {
			writeDesyncError(writer, http.StatusConflict, "diagnostics_unsupported", false)
			return
		}
		snapshot, err := diagnostics.DesyncDiagnostics(request.Context(), diagnosticsRequest)
		if err != nil {
			writeDesyncDiagnosticFailure(writer, err)
			return
		}
		snapshot.Outbound = tag
		if snapshot.Format == "" {
			snapshot.Format = adapter.DesyncDiagnosticsFormat
		}
		if snapshot.Kind == "" {
			snapshot.Kind = diagnosticsRequest.Kind.String()
		}
		if !diagnosticsRequest.IncludeSensitive {
			snapshot = adapter.RedactDesyncDiagnosticsSnapshot(snapshot)
		}
		encoded, err := encodeDesyncSnapshot(snapshot)
		if err != nil {
			writeDesyncError(writer, http.StatusServiceUnavailable, "snapshot_encode_failed", false)
			return
		}
		writeDesyncJSON(writer, http.StatusOK, encoded)
	}
}

func desyncReloadHandler(outbound adapter.OutboundManager) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.Header().Set("Allow", http.MethodPost)
			writeDesyncError(writer, http.StatusMethodNotAllowed, "method_not_allowed", false)
			return
		}
		tag, err := parseDesyncReloadBody(request)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, errDesyncBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			writeDesyncError(writer, status, "invalid_body", false)
			return
		}
		target, found := outbound.Outbound(tag)
		if !found {
			writeDesyncError(writer, http.StatusNotFound, "outbound_not_found", false)
			return
		}
		diagnostics, supported := target.(adapter.OutboundDesyncDiagnostics)
		if !supported {
			writeDesyncError(writer, http.StatusConflict, "diagnostics_unsupported", false)
			return
		}
		result, err := diagnostics.ReloadDesyncLists(request.Context())
		if err != nil {
			writeDesyncDiagnosticFailure(writer, err)
			return
		}
		result.Outbound = tag
		if result.Format == "" {
			result.Format = adapter.DesyncReloadFormat
		}
		if result.BundleGenerations == nil {
			result.BundleGenerations = []adapter.DesyncBundleGeneration{}
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > desyncResponseMaxBytes {
			writeDesyncError(writer, http.StatusServiceUnavailable, "result_encode_failed", false)
			return
		}
		writeDesyncJSON(writer, http.StatusOK, encoded)
	}
}

func parseDesyncDiagnosticsQuery(request *http.Request) (string, adapter.DesyncDiagnosticsRequest, error) {
	var diagnosticsRequest adapter.DesyncDiagnosticsRequest
	query := request.URL.Query()
	allowed := map[string]struct{}{
		"outbound": {}, "kind": {}, "limit": {}, "include_sensitive": {}, "all_networks": {},
	}
	for key, values := range query {
		if _, ok := allowed[key]; !ok {
			return "", diagnosticsRequest, E.New("unknown query parameter ", key)
		}
		if len(values) != 1 {
			return "", diagnosticsRequest, E.New("duplicate query parameter ", key)
		}
	}
	tagValues, present := query["outbound"]
	if !present || len(tagValues) != 1 || tagValues[0] == "" || len(tagValues[0]) > desyncMaxTagBytes {
		return "", diagnosticsRequest, E.New("outbound tag is required")
	}
	kind, err := adapter.ParseDesyncDiagnosticKind(query.Get("kind"))
	if err != nil {
		return "", diagnosticsRequest, err
	}
	diagnosticsRequest.Kind = kind
	if raw := query.Get("limit"); raw != "" {
		parsed, parseErr := strconv.ParseUint(raw, 10, 16)
		if parseErr != nil {
			return "", diagnosticsRequest, E.New("invalid limit")
		}
		diagnosticsRequest.Limit = uint16(parsed)
	}
	if raw, present := query["include_sensitive"]; present {
		parsed, parseErr := strconv.ParseBool(raw[0])
		if parseErr != nil {
			return "", diagnosticsRequest, E.New("invalid include_sensitive")
		}
		diagnosticsRequest.IncludeSensitive = parsed
	}
	if raw, present := query["all_networks"]; present {
		parsed, parseErr := strconv.ParseBool(raw[0])
		if parseErr != nil {
			return "", diagnosticsRequest, E.New("invalid all_networks")
		}
		diagnosticsRequest.AllNetworks = parsed
	}
	diagnosticsRequest, err = diagnosticsRequest.Validate()
	if err != nil {
		return "", diagnosticsRequest, err
	}
	return tagValues[0], diagnosticsRequest, nil
}

var errDesyncBodyTooLarge = errors.New("desync request body too large")

type desyncReloadBody struct {
	Outbound string `json:"outbound"`
}

func parseDesyncReloadBody(request *http.Request) (string, error) {
	contentType := request.Header.Get("Content-Type")
	if contentType != "application/json" && contentType != "application/json; charset=utf-8" {
		return "", E.New("content type must be application/json")
	}
	if request.ContentLength > desyncBodyMaxBytes {
		return "", errDesyncBodyTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, desyncBodyMaxBytes+1))
	if err != nil {
		return "", E.Cause(err, "read request body")
	}
	if len(body) > desyncBodyMaxBytes {
		return "", errDesyncBodyTooLarge
	}
	if err = rejectDuplicateJSONKeys(body); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var parsed desyncReloadBody
	if err = decoder.Decode(&parsed); err != nil {
		return "", E.Cause(err, "decode request body")
	}
	var trailing any
	if err = decoder.Decode(&trailing); err != io.EOF {
		return "", E.New("request body must contain exactly one object")
	}
	if parsed.Outbound == "" || len(parsed.Outbound) > desyncMaxTagBytes {
		return "", E.New("outbound tag is required")
	}
	return parsed.Outbound, nil
}

func writeDesyncDiagnosticFailure(writer http.ResponseWriter, err error) {
	var diagnosticError adapter.DesyncDiagnosticError
	if !errors.As(err, &diagnosticError) {
		writeDesyncError(writer, http.StatusServiceUnavailable, "diagnostics_failed", false)
		return
	}
	status := http.StatusServiceUnavailable
	switch diagnosticError.Code {
	case "disabled", "not_started", "closed", "busy":
		status = http.StatusConflict
	case "platform_inapplicable", "unsupported":
		status = http.StatusUnprocessableEntity
	}
	writeDesyncError(writer, status, diagnosticError.Code, diagnosticError.RetainedLastGood)
}

func writeDesyncError(writer http.ResponseWriter, status int, code string, retainedLastGood bool) {
	document := struct {
		Format           string `json:"format"`
		Code             string `json:"code"`
		RetainedLastGood bool   `json:"retained_last_good"`
	}{Format: adapter.DesyncErrorFormat, Code: code, RetainedLastGood: retainedLastGood}
	encoded, err := json.Marshal(document)
	if err != nil {
		encoded = []byte(`{"format":"desync.error/v1","code":"internal","retained_last_good":false}`)
	}
	writeDesyncJSON(writer, status, encoded)
}

func writeDesyncJSON(writer http.ResponseWriter, status int, encoded []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

// encodeDesyncSnapshot encodes a snapshot into a bounded buffer, trimming rows
// with explicit metadata instead of emitting partial JSON.
func encodeDesyncSnapshot(snapshot adapter.DesyncDiagnosticsSnapshot) ([]byte, error) {
	for attempt := 0; attempt < 64; attempt++ {
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return nil, err
		}
		if len(encoded) <= desyncResponseMaxBytes {
			return encoded, nil
		}
		if !trimDesyncSnapshot(&snapshot) {
			return nil, E.New("desync snapshot exceeds the response bound")
		}
	}
	return nil, E.New("desync snapshot cannot be bounded")
}

func trimDesyncSnapshot(snapshot *adapter.DesyncDiagnosticsSnapshot) bool {
	progress := false
	trimRows := func(length int) int {
		if length <= 0 {
			return 0
		}
		progress = true
		return length / 2
	}
	if snapshot.Conntrack != nil {
		snapshot.Conntrack.Rows = snapshot.Conntrack.Rows[:trimRows(len(snapshot.Conntrack.Rows))]
	}
	if snapshot.FailurePool != nil {
		snapshot.FailurePool.Rows = snapshot.FailurePool.Rows[:trimRows(len(snapshot.FailurePool.Rows))]
	}
	if snapshot.IPCache != nil {
		snapshot.IPCache.Rows = snapshot.IPCache.Rows[:trimRows(len(snapshot.IPCache.Rows))]
	}
	if snapshot.WindowsNetwork != nil {
		snapshot.WindowsNetwork.Wireless = snapshot.WindowsNetwork.Wireless[:trimRows(len(snapshot.WindowsNetwork.Wireless))]
		snapshot.WindowsNetwork.Networks = snapshot.WindowsNetwork.Networks[:trimRows(len(snapshot.WindowsNetwork.Networks))]
		snapshot.WindowsNetwork.Adapters = snapshot.WindowsNetwork.Adapters[:trimRows(len(snapshot.WindowsNetwork.Adapters))]
	}
	if snapshot.CaptureFilters != nil {
		snapshot.CaptureFilters.Rows = snapshot.CaptureFilters.Rows[:trimRows(len(snapshot.CaptureFilters.Rows))]
	}
	snapshot.Truncated = true
	snapshot.Returned = countDesyncRows(*snapshot)
	return progress
}

func countDesyncRows(snapshot adapter.DesyncDiagnosticsSnapshot) uint64 {
	switch {
	case snapshot.Conntrack != nil:
		return uint64(len(snapshot.Conntrack.Rows))
	case snapshot.FailurePool != nil:
		return uint64(len(snapshot.FailurePool.Rows))
	case snapshot.IPCache != nil:
		return uint64(len(snapshot.IPCache.Rows))
	case snapshot.WindowsNetwork != nil:
		return uint64(len(snapshot.WindowsNetwork.Wireless) + len(snapshot.WindowsNetwork.Networks) + len(snapshot.WindowsNetwork.Adapters))
	case snapshot.CaptureFilters != nil:
		return uint64(len(snapshot.CaptureFilters.Rows))
	default:
		return snapshot.Returned
	}
}

// rejectDuplicateJSONKeys rejects a repeated object key at any nesting level so a
// reload body cannot carry two different outbound tags.
func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		object    bool
		keys      map[string]struct{}
		expectKey bool
	}
	var stack []*frame
	complete := func() {
		if len(stack) == 0 {
			return
		}
		if parent := stack[len(stack)-1]; parent.object {
			parent.expectKey = true
		}
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if len(stack) != 0 {
				return E.New("truncated JSON document")
			}
			return nil
		}
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if isDelimiter {
			switch delimiter {
			case '{':
				complete()
				stack = append(stack, &frame{object: true, keys: make(map[string]struct{}), expectKey: true})
			case '[':
				complete()
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) == 0 {
					return E.New("malformed JSON document")
				}
				current := stack[len(stack)-1]
				if delimiter == '}' && !current.object || delimiter == ']' && current.object {
					return E.New("mismatched JSON delimiter")
				}
				stack = stack[:len(stack)-1]
				complete()
			}
			continue
		}
		if len(stack) == 0 {
			continue
		}
		current := stack[len(stack)-1]
		if !current.object {
			continue
		}
		if current.expectKey {
			key, ok := token.(string)
			if !ok {
				return E.New("malformed JSON object key")
			}
			if _, duplicate := current.keys[key]; duplicate {
				return E.New("duplicate JSON key ", key)
			}
			current.keys[key] = struct{}{}
			current.expectKey = false
			continue
		}
		current.expectKey = true
	}
}

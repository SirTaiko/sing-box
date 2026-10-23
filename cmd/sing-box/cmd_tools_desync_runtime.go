package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

// Explicit runtime inspection commands.
//
// Both commands talk only to an explicit numeric loopback HTTP controller. The
// credential comes exclusively from the existing BOX_API_SECRET environment
// source, is read once and is never accepted as a flag, a URL query or a log
// line. The client ignores proxy environment variables, refuses redirects and
// never retries: a POST reload is not idempotent at the transport level.

const (
	desyncRuntimeTimeout      = 30 * time.Second
	desyncRuntimeResponseMax  = 1 << 20
	desyncRuntimeSecretEnv    = "BOX_API_SECRET"
	desyncRuntimeMaxServerLen = 512
)

func init() {
	commandToolsDesync.AddCommand(
		newToolsDesyncReloadCommand(operatorDesyncRuntimeClient()),
		newToolsDesyncDiagnosticsCommand(operatorDesyncRuntimeClient()),
	)
}

// desyncRuntimeClient is the injectable CLI transport seam. Tests inject a
// RoundTripper and an environment getter; no test resolves a host or opens a
// socket.
type desyncRuntimeClient struct {
	transport http.RoundTripper
	getenv    func(string) string
	now       func() time.Time
}

func operatorDesyncRuntimeClient() desyncRuntimeClient {
	return desyncRuntimeClient{
		transport: &http.Transport{
			Proxy:                  nil,
			DisableCompression:     true,
			ForceAttemptHTTP2:      true,
			MaxResponseHeaderBytes: 64 << 10,
			TLSClientConfig:        nil,
			DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		},
		getenv: os.Getenv,
		now:    time.Now,
	}
}

func newToolsDesyncReloadCommand(client desyncRuntimeClient) *cobra.Command {
	var (
		flagServer   string
		flagOutbound string
	)
	command := &cobra.Command{
		Use:          "reload",
		Short:        "Reload the list snapshot of one direct desync outbound",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			endpoint, err := validateDesyncServer(flagServer)
			if err != nil {
				return err
			}
			secret, err := readDesyncSecret(client)
			if err != nil {
				return err
			}
			body, err := json.Marshal(struct {
				Outbound string `json:"outbound"`
			}{Outbound: flagOutbound})
			if err != nil {
				return E.Cause(err, "reload: encode request")
			}
			response, err := client.do(command.Context(), endpoint, "/desync/reload", http.MethodPost, secret, body, "application/json")
			if err != nil {
				return err
			}
			if err = writeDesyncCommandOutput(command, "", response); err != nil {
				return err
			}
			return nil
		},
	}
	command.Flags().StringVar(&flagServer, "server", "", "explicit http://<numeric-loopback>:<port> controller")
	command.Flags().StringVar(&flagOutbound, "outbound", "", "exact direct outbound tag")
	return command
}

func newToolsDesyncDiagnosticsCommand(client desyncRuntimeClient) *cobra.Command {
	var (
		flagServer      string
		flagOutbound    string
		flagKind        string
		flagLimit       int
		flagSensitive   bool
		flagAllNetworks bool
		flagOutput      string
	)
	command := &cobra.Command{
		Use:          "diagnostics",
		Short:        "Read one bounded runtime inspection section of a direct outbound",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			endpoint, err := validateDesyncServer(flagServer)
			if err != nil {
				return err
			}
			kind, err := adapter.ParseDesyncDiagnosticKind(flagKind)
			if err != nil {
				return err
			}
			request := adapter.DesyncDiagnosticsRequest{
				Kind:             kind,
				IncludeSensitive: flagSensitive,
				AllNetworks:      flagAllNetworks,
			}
			if flagLimit != 0 {
				if flagLimit < 1 || flagLimit > int(adapter.DesyncMaxDiagnosticsLimit) {
					return E.New("diagnostics: --limit must be within 1..1024")
				}
				request.Limit = uint16(flagLimit)
			}
			request, err = request.Validate()
			if err != nil {
				return E.Cause(err, "diagnostics")
			}
			secret, err := readDesyncSecret(client)
			if err != nil {
				return err
			}
			query := make(url.Values)
			query.Set("outbound", flagOutbound)
			query.Set("kind", request.Kind.String())
			query.Set("limit", strconv.Itoa(int(request.Limit)))
			if request.IncludeSensitive {
				query.Set("include_sensitive", "true")
			}
			if request.AllNetworks {
				query.Set("all_networks", "true")
			}
			target := endpoint.String() + "/desync/diagnostics?" + query.Encode()
			response, err := client.doURL(command.Context(), target, http.MethodGet, secret, nil, "")
			if err != nil {
				return err
			}
			return writeDesyncCommandOutput(command, flagOutput, response)
		},
	}
	command.Flags().StringVar(&flagServer, "server", "", "explicit http://<numeric-loopback>:<port> controller")
	command.Flags().StringVar(&flagOutbound, "outbound", "", "exact direct outbound tag")
	command.Flags().StringVar(&flagKind, "kind", "status", "status, conntrack, failure-pool, ipcache, windows-network or capture-filter")
	command.Flags().IntVar(&flagLimit, "limit", 0, "row limit, default 128, accepted 1..1024")
	command.Flags().BoolVar(&flagSensitive, "include-sensitive", false, "include the documented optional identity fields")
	command.Flags().BoolVar(&flagAllNetworks, "all-networks", false, "windows-network only: include disconnected networks")
	command.Flags().StringVar(&flagOutput, "output", "-", "explicit output file or - for stdout")
	return command
}

// validateDesyncServer accepts exactly http://<numeric-loopback>:<port> with no
// path beyond an optional root, no user info, query or fragment.
func validateDesyncServer(value string) (*url.URL, error) {
	if value == "" {
		return nil, E.New("--server is required")
	}
	if len(value) > desyncRuntimeMaxServerLen {
		return nil, E.New("--server is too long")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, E.Cause(err, "--server is not a valid URL")
	}
	if parsed.Scheme != "http" {
		return nil, E.New("--server must use plain http on a numeric loopback address")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, E.New("--server must not carry credentials, a query or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, E.New("--server must not carry a path")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		return nil, E.New("--server must carry an explicit port")
	}
	if parsedPort, parseErr := strconv.ParseUint(port, 10, 16); parseErr != nil || parsedPort == 0 {
		return nil, E.New("--server must carry an explicit nonzero port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return nil, E.New("--server host must be a numeric loopback address")
	}
	return parsed, nil
}

func readDesyncSecret(client desyncRuntimeClient) (string, error) {
	getenv := client.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	secret := getenv(desyncRuntimeSecretEnv)
	if secret == "" {
		return "", E.New("desync runtime: the ", desyncRuntimeSecretEnv, " environment variable must carry the controller secret")
	}
	return secret, nil
}

func (client desyncRuntimeClient) do(ctx context.Context, endpoint *url.URL, path string, method string, secret string, body []byte, contentType string) ([]byte, error) {
	return client.doURL(ctx, endpoint.String()+path, method, secret, body, contentType)
}

func (client desyncRuntimeClient) doURL(ctx context.Context, target string, method string, secret string, body []byte, contentType string) ([]byte, error) {
	if client.transport == nil {
		return nil, E.New("desync runtime client requires an explicit transport")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, desyncRuntimeTimeout)
	defer cancel()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, E.Cause(err, "build controller request")
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	request.Header.Set("Accept", "application/json")
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	httpClient := &http.Client{
		Transport: client.transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return E.New("controller redirects are not allowed")
		},
		Timeout: desyncRuntimeTimeout,
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, E.Cause(err, "controller request failed")
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, desyncRuntimeResponseMax+1))
	if err != nil {
		return nil, E.Cause(err, "read controller response")
	}
	if len(payload) > desyncRuntimeResponseMax {
		return nil, E.New("controller response exceeds 1 MiB")
	}
	if response.StatusCode != http.StatusOK {
		code := desyncErrorCode(payload)
		if code == "" {
			return nil, E.New("controller returned HTTP ", response.StatusCode)
		}
		return nil, E.New("controller returned HTTP ", response.StatusCode, " (", code, ")")
	}
	return payload, nil
}

// desyncErrorCode reads only the stable error code of a typed error document.
// The raw body is never printed or persisted.
func desyncErrorCode(payload []byte) string {
	if len(payload) > 4096 {
		payload = payload[:4096]
	}
	var document struct {
		Format string `json:"format"`
		Code   string `json:"code"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		return ""
	}
	if document.Format != adapter.DesyncErrorFormat {
		return ""
	}
	if len(document.Code) > 64 {
		return ""
	}
	return document.Code
}

// writeDesyncCommandOutput writes the typed response to stdout or to an explicit
// staged, atomic, alias-safe user-only file.
func writeDesyncCommandOutput(command *cobra.Command, path string, payload []byte) error {
	if path == "" || path == "-" {
		_, err := command.OutOrStdout().Write(payload)
		return err
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return E.New("refusing to replace a non-regular output file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return E.Cause(err, "inspect output")
	}
	temporary, err := os.CreateTemp(directory, ".desync-output-*.tmp")
	if err != nil {
		return E.Cause(err, "create staged output")
	}
	temporaryPath := temporary.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = temporary.Close()
			_ = os.Remove(temporaryPath)
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		return E.Cause(err, "set output mode")
	}
	if _, err = temporary.Write(payload); err != nil {
		return E.Cause(err, "write output")
	}
	if err = temporary.Sync(); err != nil {
		return E.Cause(err, "sync output")
	}
	if err = temporary.Close(); err != nil {
		return E.Cause(err, "close output")
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return E.Cause(err, "publish output")
	}
	cleanup = false
	return nil
}

var _ = strings.TrimSpace

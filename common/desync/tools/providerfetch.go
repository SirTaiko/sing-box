package tools

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

// Provider acquisition over the network.
//
// Every request is explicit operator action: fixed HTTPS URLs, certificate and
// host name verification with the system roots, a minimum of TLS 1.2, no proxy,
// no cookie jar, no ambient credentials and no insecure option. The real
// transport is only constructed by the production command wiring; unit tests
// inject ProviderHTTPClient and fail when a real dial is attempted.

// providerFetched is one acquired and decoded input.
type providerFetched struct {
	Source     ProviderSource
	Provenance ListBundleSource
	Data       []byte
}

type providerAttemptError struct {
	err       error
	temporary bool
}

func (e *providerAttemptError) Error() string { return e.err.Error() }
func (e *providerAttemptError) Unwrap() error { return e.err }

// acquireProviderSource fetches exactly one fixed source URL and returns its
// decoded text. Retries cover transient transport errors and HTTP 408/429/5xx
// only, inside the source attempt budget and the invocation deadline.
func acquireProviderSource(ctx context.Context, recipe ProviderRecipe, source ProviderSource, deps ProviderDependencies, deadline time.Time, clock MDigClock, maxDecoded int64) (providerFetched, error) {
	var fetched providerFetched
	if deps.HTTP == nil {
		return fetched, E.New("provider acquisition requires an explicit HTTP client")
	}
	if clock == nil {
		clock = systemClock{}
	}
	parsed, err := url.Parse(source.URL)
	if err != nil {
		return fetched, E.Cause(err, "invalid fixed provider URL")
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return fetched, E.New("fixed provider URL must be a plain https URL")
	}
	attempts := source.Attempts
	if attempts <= 0 {
		attempts = providerDefaultAttempts
	}
	var lastError error
	for attempt := 0; attempt < attempts; attempt++ {
		if err = ctx.Err(); err != nil {
			return fetched, err
		}
		if time.Now().After(deadline) && !clock.Now().Before(deadline) {
			return fetched, E.New("list refresh deadline exceeded")
		}
		attemptCtx := ctx
		var cancel context.CancelFunc = func() {}
		if source.AttemptTimeout > 0 {
			attemptCtx, cancel = context.WithTimeout(ctx, source.AttemptTimeout)
		}
		fetched, lastError = fetchProviderAttempt(attemptCtx, recipe, source, deps, deadline, maxDecoded)
		cancel()
		if lastError == nil {
			return fetched, nil
		}
		var attemptErr *providerAttemptError
		if !errors.As(lastError, &attemptErr) || !attemptErr.temporary {
			return fetched, lastError
		}
		if attempt+1 >= attempts {
			break
		}
		delay := time.Duration(1<<uint(attempt)) * time.Second
		if delay > 8*time.Second {
			delay = 8 * time.Second
		}
		if err = clock.Sleep(ctx, delay); err != nil {
			return fetched, err
		}
	}
	if lastError == nil {
		lastError = E.New("provider acquisition failed")
	}
	return fetched, E.Cause(lastError, "provider source ", source.URL, " failed after ", attempts, " attempts")
}

func fetchProviderAttempt(ctx context.Context, recipe ProviderRecipe, source ProviderSource, deps ProviderDependencies, deadline time.Time, maxDecoded int64) (providerFetched, error) {
	var fetched providerFetched
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return fetched, &providerAttemptError{err: E.Cause(err, "build provider request")}
	}
	if source.AcceptEncoding {
		request.Header.Set("Accept-Encoding", "gzip")
	}
	request.Header.Set("User-Agent", "sing-box-desync-tools")
	response, err := deps.HTTP.Do(request)
	if err != nil {
		temporary := isTemporaryTransportError(err)
		return fetched, &providerAttemptError{err: E.Cause(err, "request provider URL"), temporary: temporary}
	}
	defer response.Body.Close()
	if response.Request != nil && response.Request.URL != nil {
		if err = validateFinalProviderURL(recipe, source, response.Request.URL); err != nil {
			return fetched, err
		}
	}
	temporaryStatus := response.StatusCode == http.StatusRequestTimeout ||
		response.StatusCode == http.StatusTooManyRequests ||
		response.StatusCode >= 500
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fetched, &providerAttemptError{
			err:       E.New("provider URL returned HTTP ", response.StatusCode),
			temporary: temporaryStatus,
		}
	}
	if err = validateProviderHeaders(response.Header); err != nil {
		return fetched, err
	}
	encoding := strings.ToLower(strings.TrimSpace(response.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity", "gzip":
	default:
		return fetched, E.New("unsupported provider content encoding ", encoding)
	}
	limit := source.MaximumBytes
	if limit <= 0 || limit > providerSourceMaxBytes {
		limit = providerSourceMaxBytes
	}
	if response.ContentLength > limit {
		return fetched, E.New("provider body exceeds the configured size limit")
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		temporary := isTemporaryTransportError(err)
		return fetched, &providerAttemptError{err: E.Cause(err, "read provider body"), temporary: temporary}
	}
	if int64(len(wire)) > limit {
		return fetched, E.New("provider body exceeds the configured size limit")
	}
	if int64(len(wire)) < source.MinimumBytes {
		return fetched, E.New("provider body is below the source minimum of ", source.MinimumBytes, " bytes")
	}
	compression := CompressionNone
	decoded := wire
	if gzipMagic(wire) {
		compression = CompressionGzip
		decoded, err = decodeGzipOnce(wire, maxDecoded)
		if err != nil {
			return fetched, E.Cause(err, "decode provider body")
		}
	} else if source.RequireGzip || encoding == "gzip" {
		return fetched, E.New("provider body is not the required gzip stream")
	}
	if int64(len(decoded)) > maxDecoded {
		return fetched, E.New("decoded provider body exceeds the hard limit")
	}
	provenance := ListBundleSource{
		ID:               providerSourceID(recipe, source, 0),
		URL:              source.URL,
		SHA256:           sha256Hex(wire),
		Size:             int64(len(wire)),
		Compression:      compression,
		DecompressedSize: int64(len(decoded)),
	}
	finalURL := request.URL
	if response.Request != nil && response.Request.URL != nil {
		finalURL = response.Request.URL
	}
	provenance.FinalURL = ProviderFinalURL(finalURL)
	fullFinal := finalURL.String()
	provenance.FinalURLSHA256 = sha256Hex([]byte(fullFinal))
	provenance.ETag = boundedMetadata(response.Header.Get("ETag"))
	provenance.LastModified = boundedMetadata(response.Header.Get("Last-Modified"))
	provenance.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	fetched = providerFetched{Source: source, Provenance: provenance, Data: decoded}
	return fetched, nil
}

func boundedMetadata(value string) string {
	if len(value) > providerMetaMaxBytes {
		return value[:providerMetaMaxBytes]
	}
	return value
}

// validateProviderHeaders bounds the response metadata and rejects a body that
// would be silently decoded by something other than gzip.
func validateProviderHeaders(header http.Header) error {
	total := 0
	for key, values := range header {
		total += len(key)
		for _, value := range values {
			total += len(value)
		}
	}
	if total > providerHeadersMaxBytes {
		return E.New("provider response headers exceed ", providerHeadersMaxBytes, " bytes")
	}
	return nil
}

// validateFinalProviderURL enforces the fixed-host and redirect policy on the
// final response URL. An injected client cannot bypass it by following a
// redirect itself.
func validateFinalProviderURL(recipe ProviderRecipe, source ProviderSource, final *url.URL) error {
	if final == nil {
		return E.New("provider response has no final URL")
	}
	if len(final.String()) > providerURLMaxBytes {
		return E.New("provider final URL exceeds ", providerURLMaxBytes, " bytes")
	}
	if final.Scheme != "https" {
		return E.New("provider redirect downgraded the scheme")
	}
	if final.User != nil || final.Fragment != "" {
		return E.New("provider final URL carries user info or a fragment")
	}
	original, err := url.Parse(source.URL)
	if err != nil {
		return E.Cause(err, "invalid fixed provider URL")
	}
	host := strings.ToLower(final.Hostname())
	allowed := map[string]struct{}{strings.ToLower(original.Hostname()): {}}
	if source.AllowRedirects {
		for _, candidate := range source.RedirectHosts {
			allowed[strings.ToLower(candidate)] = struct{}{}
		}
	}
	if _, ok := allowed[host]; !ok {
		return E.New("provider redirect host is not allowed")
	}
	if host == strings.ToLower(original.Hostname()) {
		if final.Port() != original.Port() {
			return E.New("provider redirect changed the port")
		}
	} else if final.Port() != "" && final.Port() != "443" {
		return E.New("provider redirect changed the port")
	}
	return nil
}

func isTemporaryTransportError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netError net.Error
	if errors.As(err, &netError) {
		if netError.Timeout() {
			return true
		}
	}
	// A TLS verification, redirect policy or protocol failure is permanent.
	message := err.Error()
	for _, permanent := range []string{
		"certificate", "tls:", "x509:", "redirect", "unsupported protocol scheme", "no such host",
	} {
		if strings.Contains(message, permanent) {
			return false
		}
	}
	return true
}

// providerPublicDestination reports whether a resolved acquisition destination
// may be dialed. Loopback, private, link-local, CGNAT, multicast, unspecified,
// benchmarking and reserved ranges are rejected, so a hostile DNS answer cannot
// turn acquisition into a local probe.
func providerPublicDestination(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range providerRejectedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

var providerRejectedPrefixes = func() []netip.Prefix {
	values := []string{
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "::/128", "64:ff9b:1::/48", "2001:db8::/32",
		"2002::/16", "ff00::/8",
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}()

// NewProviderHTTPClient builds the real acquisition client of one recipe. It is
// only constructed by the production command wiring.
func NewProviderHTTPClient(recipe ProviderRecipe) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: providerHeadersMaxBytes,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// The zero value keeps certificate and host name verification with
			// the system roots. No insecure equivalent of curl -k exists here.
		},
		DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, E.Cause(err, "invalid dial address")
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, E.Cause(err, "resolve acquisition host")
			}
			var lastError error
			for _, candidate := range addresses {
				if !providerPublicDestination(candidate) {
					continue
				}
				connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastError = dialErr
			}
			if lastError != nil {
				return nil, E.Cause(lastError, "connect acquisition host")
			}
			return nil, E.New("acquisition host has no public destination")
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= providerMaxRedirects {
				return E.New("provider redirect limit exceeded")
			}
			source, ok := providerSourceForURL(recipe, via[0].URL.String())
			if !ok {
				return E.New("provider redirect from an unknown source")
			}
			return validateFinalProviderURL(recipe, source, request.URL)
		},
	}
}

func providerSourceForURL(recipe ProviderRecipe, raw string) (ProviderSource, bool) {
	for _, source := range recipe.Sources {
		if source.URL == raw {
			return source, true
		}
	}
	return ProviderSource{}, false
}

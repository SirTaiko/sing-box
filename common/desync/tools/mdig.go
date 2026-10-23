package tools

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	E "github.com/sagernet/sing/common/exceptions"
)

const (
	// mdig defaults from mdig/mdig.c: RESOLVER_EAGAIN_ATTEMPTS,
	// RESOLVER_EAGAIN_DELAY and main().
	mdigDefaultThreads        = 1
	mdigMaxThreads            = 100
	mdigDefaultEAgainAttempts = 10
	mdigMaxEAgainAttempts     = 1000
	mdigDefaultEAgainDelay    = 500 * time.Millisecond
	mdigMaxEAgainDelay        = 100 * time.Second
	mdigDefaultMaxLine        = 1024
	mdigDefaultMaxAddresses   = 1024
)

// ErrTemporary marks a resolver failure that may succeed after a delay.
//
// It is the Go equivalent of EAI_AGAIN, the only getaddrinfo result the pinned
// mdig retries. A real resolver adapter must classify its errors into
// ErrTemporary or a permanent error; tests inject a mock resolver instead of
// touching the network.
var ErrTemporary = errors.New("temporary resolver failure")

// MDigResolver is the injectable batch resolver seam. family is a bit set so a
// "both" run can ask for A and AAAA in one call.
type MDigResolver interface {
	Lookup(ctx context.Context, name string, family Family) ([]netip.Addr, error)
}

// MDigClock is the injectable clock seam. Sleep must return the context error
// when it is cancelled during the wait.
type MDigClock interface {
	Now() time.Time
	Sleep(ctx context.Context, duration time.Duration) error
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

func (systemClock) Sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// MDigOptions configures one batch resolution run.
//
// A zero value reproduces the pinned defaults: IPv4, one worker, ten EAGAIN
// attempts with a 500 ms delay and no statistics.
type MDigOptions struct {
	Family Family
	// Threads is the worker count, 1..100.
	Threads int
	// EAgainAttempts is the total number of lookup attempts for a temporary
	// failure, 1..1000.
	EAgainAttempts int
	// EAgainDelay is the wait between two attempts.
	EAgainDelay time.Duration
	Verbose     bool
	// StatsEvery prints a statistics line to the diagnostics stream every N
	// input lines and once at the end. Zero disables statistics.
	StatsEvery int
	// LogResolved and LogFailed are explicit operator sinks. Host names are
	// never logged anywhere else.
	LogResolved io.Writer
	LogFailed   io.Writer
	// MaxLineLength bounds one input line; over-long input is an error.
	MaxLineLength int
	// MaxAddressesPerName bounds the addresses accepted from one lookup so a
	// hostile resolver cannot exhaust memory. Exceeding it is an error.
	MaxAddressesPerName int
}

// MDigStats is the accounting of one run.
type MDigStats struct {
	Domains          int
	Success          int
	Error            int
	Addresses        int
	Retries          int
	EmptyLines       int
	InvalidDomains   int
	LiteralAddresses int
}

type mdigParams struct {
	family      Family
	threads     int
	attempts    int
	delay       time.Duration
	verbose     bool
	statsEvery  int
	maxLine     int
	maxAddrs    int
	logResolved io.Writer
	logFailed   io.Writer
}

func (o MDigOptions) resolve() (mdigParams, error) {
	var p mdigParams
	switch o.Family {
	case FamilyIPv4, FamilyIPv6, FamilyIPv4 | FamilyIPv6:
		p.family = o.Family
	case 0:
		return p, E.New("mdig: --family is required (4, 6 or both)")
	default:
		return p, E.New("mdig: invalid --family")
	}
	p.threads = o.Threads
	if p.threads == 0 {
		p.threads = mdigDefaultThreads
	}
	if p.threads < 1 || p.threads > mdigMaxThreads {
		return p, E.New("mdig: --threads must be within 1-", mdigMaxThreads)
	}
	p.attempts = o.EAgainAttempts
	if p.attempts == 0 {
		p.attempts = mdigDefaultEAgainAttempts
	}
	if p.attempts < 1 || p.attempts > mdigMaxEAgainAttempts {
		return p, E.New("mdig: --eagain must be within 1-", mdigMaxEAgainAttempts)
	}
	p.delay = o.EAgainDelay
	if p.delay < 0 || p.delay > mdigMaxEAgainDelay {
		return p, E.New("mdig: --eagain-delay must be within 0-", mdigMaxEAgainDelay)
	}
	p.verbose = o.Verbose
	p.statsEvery = o.StatsEvery
	if p.statsEvery < 0 {
		return p, E.New("mdig: --stats must not be negative")
	}
	p.maxLine = o.MaxLineLength
	if p.maxLine == 0 {
		p.maxLine = mdigDefaultMaxLine
	}
	if p.maxLine < 16 {
		return p, E.New("mdig: invalid line length limit")
	}
	p.maxAddrs = o.MaxAddressesPerName
	if p.maxAddrs == 0 {
		p.maxAddrs = mdigDefaultMaxAddresses
	}
	if p.maxAddrs < 1 {
		return p, E.New("mdig: invalid address limit")
	}
	p.logResolved = o.LogResolved
	p.logFailed = o.LogFailed
	return p, nil
}

// MDig resolves a newline separated name list with the typed behavior of
// mdig/mdig.c: literal addresses and ip/bits are passed through for the
// selected families, other lines are validated as host names and resolved with
// EAGAIN retries, diagnostics go to the diagnostics stream and host names are
// logged only to explicitly configured sinks.
//
// The run is bounded by the worker count, the line length and the per-name
// address limit, and it stops on context cancellation.
func MDig(ctx context.Context, in io.Reader, out io.Writer, diagnostics io.Writer, resolver MDigResolver, clock MDigClock, options MDigOptions) (MDigStats, error) {
	var stats MDigStats
	params, err := options.resolve()
	if err != nil {
		return stats, err
	}
	if in == nil || out == nil {
		return stats, E.New("mdig: input and output streams are required")
	}
	if resolver == nil {
		return stats, E.New("mdig: a resolver is required")
	}
	if clock == nil {
		clock = systemClock{}
	}
	if diagnostics == nil {
		diagnostics = io.Discard
	}
	if ctx == nil {
		ctx = context.Background()
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := &mdigRun{
		params:      params,
		resolver:    resolver,
		clock:       clock,
		out:         out,
		diagnostics: diagnostics,
		start:       clock.Now(),
		cancel:      cancel,
	}
	lines := make(chan string, params.threads*2)
	var readerError error
	var readerErrMu sync.Mutex
	var readerWait sync.WaitGroup
	readerWait.Add(1)
	go func() {
		defer readerWait.Done()
		defer close(lines)
		scanner := newLineScanner(in, params.maxLine)
		for scanner.Scan() {
			select {
			case <-workerCtx.Done():
				return
			case lines <- scanner.Text():
			}
		}
		if err := scanner.Err(); err != nil {
			readerErrMu.Lock()
			readerError = E.Cause(err, "mdig: read input (line limit ", params.maxLine, ")")
			readerErrMu.Unlock()
			cancel()
		}
	}()
	var workerWait sync.WaitGroup
	for workerID := 0; workerID < params.threads; workerID++ {
		workerWait.Add(1)
		go func(workerID int) {
			defer workerWait.Done()
			run.worker(workerCtx, workerID, lines)
		}(workerID)
	}
	workerWait.Wait()
	readerWait.Wait()
	stats = run.snapshot()
	if readerError != nil {
		return stats, readerError
	}
	if run.err != nil {
		return stats, run.err
	}
	if err = ctx.Err(); err != nil {
		return stats, err
	}
	if params.statsEvery > 0 {
		run.printStats(run.stats.Domains, run.stats.Success)
	}
	return stats, nil
}

type mdigRun struct {
	params      mdigParams
	resolver    MDigResolver
	clock       MDigClock
	out         io.Writer
	diagnostics io.Writer
	start       time.Time
	cancel      context.CancelFunc

	outMu     sync.Mutex
	logMu     sync.Mutex
	statsMu   sync.Mutex
	diagMu    sync.Mutex
	errOnce   sync.Once
	err       error
	stats     MDigStats
}

func (r *mdigRun) fail(err error) {
	r.errOnce.Do(func() {
		r.err = err
		if r.cancel != nil {
			r.cancel()
		}
	})
}

func (r *mdigRun) snapshot() MDigStats {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.stats
}

func (r *mdigRun) worker(ctx context.Context, workerID int, lines <-chan string) {
	r.logf(workerID, "started")
	defer r.logf(workerID, "ended")
	for line := range lines {
		if ctx.Err() != nil {
			return
		}
		r.processLine(ctx, workerID, line)
	}
}

// processLine mirrors the per-line body of t_resolver (mdig.c:191-282).
func (r *mdigRun) processLine(ctx context.Context, workerID int, rawLine string) {
	line := rtrim(rawLine)
	success := false
	r.addDomain()
	if line != "" {
		ipPart := line
		hasMask := false
		maskPart := ""
		if index := strings.IndexByte(line, '/'); index >= 0 {
			ipPart = line[:index]
			maskPart = line[index+1:]
			hasMask = true
		}
		if family := literalFamily(ipPart); family != 0 {
			if family.Has(r.params.family) {
				if !hasMask {
					r.addLiteral()
					success = r.writeAddresses(workerID, []string{ipPart})
				} else if mask, ok := parsePrefixNumber(maskPart); ok {
					limit := uint32(32)
					if family == FamilyIPv6 {
						limit = 128
					}
					if mask <= limit {
						r.addLiteral()
						text := ipPart
						if mask < limit {
							text = ipPart + "/" + strconv.FormatUint(uint64(mask), 10)
						}
						success = r.writeAddresses(workerID, []string{text})
					} else {
						r.logf(workerID, "bad ip/subnet %s", line)
					}
				} else {
					r.logf(workerID, "bad ip/subnet %s", line)
				}
			} else {
				r.logf(workerID, "wrong address family %s", ipPart)
			}
		} else if validMDigDomain(line) {
			r.logf(workerID, "resolving %s", line)
			success = r.resolve(ctx, workerID, line)
		} else {
			r.logf(workerID, "invalid domain : %s", beautifyInvalidDomain(line))
			r.addInvalidDomain()
		}
	} else {
		r.addEmpty()
	}
	r.recordResult(success)
	if line != "" {
		// mdig.c:276 logs inside the non-empty branch only.
		r.writeLog(success, line)
	}
}

func (r *mdigRun) resolve(ctx context.Context, workerID int, name string) bool {
	for attempt := 0; attempt < r.params.attempts; attempt++ {
		addresses, err := r.resolver.Lookup(ctx, name, r.params.family)
		if err != nil {
			r.logf(workerID, "failed to resolve %s : %v", name, err)
			if errors.Is(err, ErrTemporary) {
				r.addRetry()
				if attempt == r.params.attempts-1 {
					return false
				}
				if sleepErr := r.clock.Sleep(ctx, r.params.delay); sleepErr != nil {
					r.fail(sleepErr)
					return false
				}
				continue
			}
			return false
		}
		if len(addresses) == 0 {
			r.logf(workerID, "failed to resolve %s : no addresses", name)
			return false
		}
		if len(addresses) > r.params.maxAddrs {
			r.fail(E.New("mdig: resolver returned more than ", r.params.maxAddrs, " addresses for one name"))
			return false
		}
		texts := make([]string, 0, len(addresses))
		for _, address := range addresses {
			texts = append(texts, address.String())
		}
		return r.writeAddresses(workerID, texts)
	}
	return false
}

func (r *mdigRun) writeAddresses(workerID int, texts []string) bool {
	var builder strings.Builder
	for _, text := range texts {
		builder.WriteString(text)
		builder.WriteByte('\n')
	}
	r.outMu.Lock()
	written, err := io.WriteString(r.out, builder.String())
	r.outMu.Unlock()
	if err != nil {
		r.fail(E.Cause(err, "mdig: write output"))
		return false
	}
	if written != builder.Len() {
		r.fail(io.ErrShortWrite)
		return false
	}
	r.statsMu.Lock()
	r.stats.Addresses += len(texts)
	r.statsMu.Unlock()
	return true
}

func (r *mdigRun) writeLog(success bool, line string) {
	sink := r.params.logFailed
	if success {
		sink = r.params.logResolved
	}
	if sink == nil {
		return
	}
	r.logMu.Lock()
	written, err := io.WriteString(sink, line+"\n")
	r.logMu.Unlock()
	if err != nil {
		r.fail(E.Cause(err, "mdig: write domain log"))
		return
	}
	if written != len(line)+1 {
		r.fail(io.ErrShortWrite)
	}
}

func (r *mdigRun) addDomain() {
	r.statsMu.Lock()
	r.stats.Domains++
	r.statsMu.Unlock()
}

func (r *mdigRun) addRetry() {
	r.statsMu.Lock()
	r.stats.Retries++
	r.statsMu.Unlock()
}

func (r *mdigRun) addLiteral() {
	r.statsMu.Lock()
	r.stats.LiteralAddresses++
	r.statsMu.Unlock()
}

func (r *mdigRun) addEmpty() {
	r.statsMu.Lock()
	r.stats.EmptyLines++
	r.statsMu.Unlock()
}

func (r *mdigRun) addInvalidDomain() {
	r.statsMu.Lock()
	r.stats.InvalidDomains++
	r.statsMu.Unlock()
}

func (r *mdigRun) recordResult(success bool) {
	r.statsMu.Lock()
	if success {
		r.stats.Success++
	} else {
		r.stats.Error++
	}
	domains := r.stats.Domains
	successes := r.stats.Success
	shouldPrint := r.params.statsEvery > 0 && domains%r.params.statsEvery == 0
	r.statsMu.Unlock()
	if shouldPrint {
		r.printStats(domains, successes)
	}
}

func (r *mdigRun) printStats(domains int, success int) {
	line := formatMDigStats(r.clock.Now().Sub(r.start), domains, success)
	r.diagMu.Lock()
	_, _ = io.WriteString(r.diagnostics, line)
	r.diagMu.Unlock()
}

func formatMDigStats(elapsed time.Duration, domains int, success int) string {
	seconds := int64(elapsed / time.Second)
	if seconds < 0 {
		seconds = 0
	}
	return fmt.Sprintf("mdig stats : %02d:%02d:%02d : domains=%d success=%d error=%d\n",
		(seconds/3600)%100, (seconds/60)%60, seconds%60, domains, success, domains-success)
}

func (r *mdigRun) logf(workerID int, format string, args ...any) {
	if !r.params.verbose {
		return
	}
	line := fmt.Sprintf(format, args...)
	r.diagMu.Lock()
	_, _ = fmt.Fprintf(r.diagnostics, "[%d] %s\n", workerID, line)
	r.diagMu.Unlock()
}

// literalFamily returns FamilyIPv4/FamilyIPv6 for a literal address and 0
// otherwise. Zone-scoped IPv6 literals are rejected like inet_pton does.
func literalFamily(text string) Family {
	address, err := netip.ParseAddr(text)
	if err != nil || address.Zone() != "" {
		return 0
	}
	if address.Is4() {
		return FamilyIPv4
	}
	return FamilyIPv6
}

// validMDigDomain is dom_valid() from mdig.c:79-86.
func validMDigDomain(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if character < 0x20 || character&0x80 != 0 {
			return false
		}
		if character != '.' && character != '-' && character != '_' &&
			(character < '0' || character > '9') &&
			(character < 'a' || character > 'z') &&
			(character < 'A' || character > 'Z') {
			return false
		}
	}
	return true
}

// beautifyInvalidDomain is invalid_domain_beautify() from mdig.c:88-93: control
// bytes become '?' and the diagnostic is cut at 64 bytes.
func beautifyInvalidDomain(name string) string {
	limit := len(name)
	if limit > 64 {
		limit = 64
	}
	result := make([]byte, limit)
	for index := 0; index < limit; index++ {
		character := name[index]
		if character < 0x20 || character >= 0x80 {
			result[index] = '?'
		} else {
			result[index] = character
		}
	}
	return string(result)
}

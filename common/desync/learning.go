package desync

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// This file implements the bounded, opt-in packet hostlist-auto learning that
// nfqws exposes as --hostlist-auto/--hostlist-auto-fail-threshold/
// --hostlist-auto-fail-time/--hostlist-auto-retrans-threshold. One learner is
// owned by the existing Engine (per direct outbound), next to the conntrack
// table and the IP cache. There is no process-global store, no sidecar, no
// background updater and no logging/persistence unless the operator configured
// an explicit path.

const (
	defaultLearningMaxHosts   = 4096
	maxLearningMaxHosts       = 1 << 20
	defaultLearningFailCount  = 3
	defaultLearningRetrans    = 3
	defaultLearningFailWindow = 60 * time.Second
	minLearningFailWindow     = 1 * time.Second
	maxLearningFailWindow     = 255 * time.Second // upstream uint8 fail time
	maxLearningSnapshotBytes  = 1 << 20
	maxLearningHostLength     = 253
	maxLearningDebugBytes     = 8 << 20
	maxLearningDebugLine      = 512
	gzipMagic0                = 0x1f
	gzipMagic1                = 0x8b
)

// learningConfig is the compiled per-outbound learning configuration.
type learningConfig struct {
	path     string
	debugLog string
	maxHosts int
	enabled  bool
}

func defaultLearningConfig() learningConfig {
	return learningConfig{maxHosts: defaultLearningMaxHosts}
}

// ruleLearning is the compiled per-rule auto-hostlist applicability. Threshold
// defaults and ranges are the pinned nfqws ones.
type ruleLearning struct {
	failThreshold    int
	failWindow       time.Duration
	retransThreshold int
}

func defaultRuleLearning() *ruleLearning {
	return &ruleLearning{
		failThreshold:    defaultLearningFailCount,
		failWindow:       defaultLearningFailWindow,
		retransThreshold: defaultLearningRetrans,
	}
}

type learningFailCounter struct {
	count  int
	expire time.Time
}

// learningPathClaims is the in-process duplicate-writer registry for explicit
// snapshot paths. It is keyed by the canonical path, so two outbounds (or two
// engines) cannot publish to the same file concurrently. The registry is only
// bookkeeping, not a shared learning store.
var learningPathClaims = struct {
	sync.Mutex
	paths map[string]int
}{paths: make(map[string]int)}

func canonicalLearningPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	absolute = filepath.Clean(absolute)
	// Resolve a symlinked parent directory so two aliases cannot claim the
	// same file. The leaf itself is never followed: a symlink leaf is
	// rejected at load/publish time.
	if parent, err := filepath.EvalSymlinks(filepath.Dir(absolute)); err == nil {
		absolute = filepath.Join(parent, filepath.Base(absolute))
	}
	return absolute
}

func claimLearningPath(path string) (string, error) {
	canonical := canonicalLearningPath(path)
	learningPathClaims.Lock()
	defer learningPathClaims.Unlock()
	if learningPathClaims.paths[canonical] > 0 {
		return "", fmt.Errorf("desync: learning path %q already has an active writer", path)
	}
	learningPathClaims.paths[canonical]++
	return canonical, nil
}

func releaseLearningPath(canonical string) {
	if canonical == "" {
		return
	}
	learningPathClaims.Lock()
	if learningPathClaims.paths[canonical] <= 1 {
		delete(learningPathClaims.paths, canonical)
	} else {
		learningPathClaims.paths[canonical]--
	}
	learningPathClaims.Unlock()
}

type learner struct {
	mu     sync.Mutex
	config learningConfig
	now    func() time.Time

	hosts map[string]struct{}
	fails map[string]*learningFailCounter

	path         string // canonical claimed path, empty when not persisting
	debug        *os.File
	debugBytes   int64
	lastPurgeSec int64
	lastErr      error
	closed       bool
	// sig is the last observed snapshot identity (size, modification time and
	// mode). Upstream watches the auto hostlist and appends learned hosts to
	// it; this engine cannot share the upstream append protocol, so it performs
	// the feasible part: detect a real file change without a background
	// watcher and reload transactionally, keeping the last-good set on error.
	sig    learningFileSig
	sigSet bool
}

// learningFileSig is a bounded-change detector for the explicit snapshot path.
type learningFileSig struct {
	size    int64
	modTime int64
	mode    os.FileMode
}

func learningSnapshotSignature(path string) (learningFileSig, bool) {
	info, err := os.Lstat(path)
	if err != nil {
		return learningFileSig{}, false
	}
	return learningFileSig{size: info.Size(), modTime: info.ModTime().UnixNano(), mode: info.Mode()}, true
}

// newLearner builds the per-engine learning owner. It claims an explicit
// snapshot path, loads its last snapshot and opens the opt-in debug log. Any
// construction error releases the claim and leaves existing files untouched
// (the snapshot is never truncated here).
func newLearner(config learningConfig, now func() time.Time) (*learner, error) {
	if !config.enabled {
		return nil, nil
	}
	if now == nil {
		now = time.Now
	}
	instance := &learner{config: config, now: now,
		hosts: make(map[string]struct{}), fails: make(map[string]*learningFailCounter)}
	if config.path != "" {
		canonical, err := claimLearningPath(config.path)
		if err != nil {
			return nil, err
		}
		instance.path = canonical
		hosts, err := loadLearningSnapshot(canonical, config.maxHosts)
		if err != nil {
			releaseLearningPath(canonical)
			return nil, err
		}
		instance.hosts = hosts
		// Remember the identity of the snapshot just loaded so the first
		// ReloadLists does not treat an unchanged file as a foreign change and
		// replace an in-memory learned set.
		if signature, ok := learningSnapshotSignature(canonical); ok {
			instance.sig, instance.sigSet = signature, true
		}
	}
	if config.debugLog != "" {
		file, err := openLearningDebugLog(config.debugLog)
		if err != nil {
			releaseLearningPath(instance.path)
			return nil, err
		}
		instance.debug = file
	}
	return instance, nil
}

// loadLearningSnapshot reads a plain (never gzip, upstream rejects gzipped
// auto hostlists) hostname-per-line snapshot. Symlinks and non-regular files
// are refused, and both the byte size and the entry count are bounded.
func loadLearningSnapshot(path string, maxHosts int) (map[string]struct{}, error) {
	hosts := make(map[string]struct{})
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return hosts, nil
		}
		return nil, fmt.Errorf("desync: stat learning snapshot: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("desync: learning snapshot %q is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("desync: learning snapshot %q is not a regular file", path)
	}
	if info.Size() > maxLearningSnapshotBytes {
		return nil, fmt.Errorf("desync: learning snapshot %q exceeds %d bytes", path, maxLearningSnapshotBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("desync: read learning snapshot: %w", err)
	}
	if len(data) >= 2 && data[0] == gzipMagic0 && data[1] == gzipMagic1 {
		// Upstream exits with "gzipped auto hostlists are not supported".
		return nil, fmt.Errorf("desync: gzipped learning snapshots are not supported")
	}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		host, err := normalizeLearnedHost(string(line))
		if err != nil {
			return nil, fmt.Errorf("desync: learning snapshot %q: %w", path, err)
		}
		if _, exists := hosts[host]; exists {
			continue
		}
		if len(hosts) >= maxHosts {
			return nil, fmt.Errorf("desync: learning snapshot %q exceeds %d hosts", path, maxHosts)
		}
		hosts[host] = struct{}{}
	}
	return hosts, nil
}

// normalizeLearnedHost keeps only validated hostname facts. It lowercases and
// strips the trailing dot exactly like the domain matcher; IP literals are
// accepted because upstream tracks hostname_is_ip facts in the same pool.
func normalizeLearnedHost(host string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(host), ".")))
	if value == "" {
		return "", errors.New("empty hostname")
	}
	if len(value) > maxLearningHostLength {
		return "", fmt.Errorf("hostname %q is too long", value)
	}
	literal := strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	if _, err := netip.ParseAddr(literal); err == nil {
		return value, nil
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return "", fmt.Errorf("invalid hostname %q", value)
		}
	}
	return value, nil
}

func openLearningDebugLog(path string) (*os.File, error) {
	file, err := openPrivateAppend(path)
	if err != nil {
		return nil, fmt.Errorf("desync: open learning debug log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("desync: stat learning debug log: %w", err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("desync: learning debug log %q is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, fmt.Errorf("desync: learning debug log %q is not owner-private (mode %04o)", path, info.Mode().Perm())
	}
	return file, nil
}

// learned reports whether the host or one of its parent domains was learned.
// Matching follows the existing domain-list suffix semantics without scanning
// the whole set: a hostname has a small bounded number of suffixes.
func (l *learner) learned(host string) bool {
	if l == nil {
		return false
	}
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if value == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if _, ok := l.hosts[value]; ok {
			return true
		}
		index := strings.IndexByte(value, '.')
		if index < 0 || index+1 >= len(value) {
			return false
		}
		value = value[index+1:]
	}
}

// learnedHosts returns a sorted copy for diagnostics/tests.
func (l *learner) learnedHosts() []string {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	hosts := make([]string, 0, len(l.hosts))
	for host := range l.hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func (l *learner) lastError() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

// recordFailure ports auto_hostlist_failed: one failure for the host, a fresh
// fail-window record on first failure, and at the threshold the host joins the
// snapshot (after the upstream duplicate recheck).
func (l *learner) recordFailure(rule *Rule, host string) bool {
	if rule == nil {
		return false
	}
	return l.recordFailureWith(rule.Learning, rule.Name, rule.DomainsExclude.matches, host)
}

// recordFailureWith is the shared implementation for packet and stream rules.
// The caller supplies the compiled applicability, the rule name for the debug
// log and the exclusion predicate; the store is always this learner.
func (l *learner) recordFailureWith(learning *ruleLearning, ruleName string, excluded func(string) bool, host string) bool {
	if l == nil || learning == nil {
		return false
	}
	value, err := normalizeLearnedHost(host)
	if err != nil {
		l.setLastError(err)
		return false
	}
	if excluded != nil && excluded(value) {
		// User exclusions never become learned hosts (upstream bCheckExcluded).
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	if _, ok := l.hosts[value]; ok {
		delete(l.fails, value)
		return false
	}
	l.purgeFailsLocked(now)
	counter := l.fails[value]
	if counter == nil || !now.Before(counter.expire) {
		counter = &learningFailCounter{expire: now.Add(learning.failWindow)}
		l.fails[value] = counter
	}
	counter.count++
	l.debugLocked("host=%s rule=%s event=fail count=%d/%d", value, ruleName, counter.count, learning.failThreshold)
	if counter.count < learning.failThreshold {
		return false
	}
	delete(l.fails, value)
	if len(l.hosts) >= l.config.maxHosts {
		l.setLastErrorLocked(fmt.Errorf("desync: learning host bound (%d) reached", l.config.maxHosts))
		return false
	}
	l.hosts[value] = struct{}{}
	l.debugLocked("host=%s rule=%s event=learnt path=%s", value, ruleName, l.path)
	if publishErr := l.publishLocked(); publishErr != nil {
		l.setLastErrorLocked(publishErr)
	}
	return true
}

// recordSuccess ports auto_hostlist_reset_fail_counter.
func (l *learner) recordSuccess(host string) {
	if l == nil {
		return
	}
	value, err := normalizeLearnedHost(host)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.fails[value]; ok {
		delete(l.fails, value)
		l.debugLocked("host=%s event=reset", value)
	}
}

func (l *learner) setLastError(err error) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.lastErr = err
	l.mu.Unlock()
}

func (l *learner) setLastErrorLocked(err error) { l.lastErr = err }

// purgeFailsLocked ports HostFailPoolPurgeRateLimited: expired fail windows
// are dropped at most once per clock second.
func (l *learner) purgeFailsLocked(now time.Time) {
	second := now.Unix()
	if l.lastPurgeSec == second {
		return
	}
	l.lastPurgeSec = second
	for host, counter := range l.fails {
		if !now.Before(counter.expire) {
			delete(l.fails, host)
		}
	}
}

// publishLocked writes a deterministic, bounded snapshot atomically. The file
// is created owner-private (0600) through an exclusive temporary file in the
// same directory and renamed over the target; an existing symlink or
// non-regular target is refused instead of truncated.
func (l *learner) publishLocked() error {
	if l.path == "" {
		return nil
	}
	hosts := make([]string, 0, len(l.hosts))
	for host := range l.hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var content bytes.Buffer
	for _, host := range hosts {
		content.WriteString(host)
		content.WriteByte('\n')
	}
	if content.Len() > maxLearningSnapshotBytes {
		return fmt.Errorf("desync: learning snapshot exceeds %d bytes", maxLearningSnapshotBytes)
	}
	if info, err := os.Lstat(l.path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("desync: learning snapshot %q is not a regular file", l.path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("desync: stat learning snapshot: %w", err)
	}
	directory := filepath.Dir(l.path)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(l.path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("desync: create learning snapshot: %w", err)
	}
	temporaryName := temporary.Name()
	if err = temporary.Chmod(0o600); err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("desync: chmod learning snapshot: %w", err)
	}
	if _, err = temporary.Write(content.Bytes()); err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("desync: write learning snapshot: %w", err)
	}
	if err = temporary.Sync(); err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("desync: sync learning snapshot: %w", err)
	}
	if err = temporary.Close(); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("desync: close learning snapshot: %w", err)
	}
	if err = os.Rename(temporaryName, l.path); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("desync: publish learning snapshot: %w", err)
	}
	// Our own write is not a foreign change: remember the fresh identity so a
	// subsequent reload does not re-read it.
	if signature, ok := learningSnapshotSignature(l.path); ok {
		l.sig, l.sigSet = signature, true
	}
	return nil
}

// reload re-reads the explicit snapshot only when its size, modification time
// or mode changed since the last successful read/publish, keeping the
// last-good set on any read/format error (the accepted transactional
// adaptation of the upstream append+modtime watch).
func (l *learner) reload() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	path := l.path
	maxHosts := l.config.maxHosts
	previous, previousSet := l.sig, l.sigSet
	l.mu.Unlock()
	if path == "" {
		return nil
	}
	if current, ok := learningSnapshotSignature(path); ok && previousSet && current == previous {
		return nil
	}
	hosts, err := loadLearningSnapshot(path, maxHosts)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.lastErr = err
		return err
	}
	l.hosts = hosts
	if signature, ok := learningSnapshotSignature(path); ok {
		l.sig, l.sigSet = signature, true
	} else {
		l.sig, l.sigSet = learningFileSig{}, false
	}
	l.lastErr = nil
	return nil
}

func (l *learner) debugLocked(format string, args ...any) {
	if l.debug == nil || l.debugBytes >= maxLearningDebugBytes {
		return
	}
	line := fmt.Sprintf(format, args...)
	line = strings.ReplaceAll(line, "\n", " ")
	if len(line) > maxLearningDebugLine {
		line = line[:maxLearningDebugLine]
	}
	written, err := l.debug.WriteString(time.Now().UTC().Format(time.RFC3339) + " " + line + "\n")
	if err != nil {
		l.setLastErrorLocked(err)
		return
	}
	l.debugBytes += int64(written)
}

func (l *learner) close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	debug := l.debug
	l.debug = nil
	path := l.path
	l.path = ""
	l.mu.Unlock()
	if debug != nil {
		debug.Close()
	}
	releaseLearningPath(path)
}

// isHTTPReply ports upstream IsHttpReply (HTTP/1.x status line).
func isHTTPReply(data []byte) bool {
	return len(data) > 14 && bytes.HasPrefix(data, []byte("HTTP/1.")) &&
		(data[7] == '0' || data[7] == '1') && data[8] == ' ' &&
		data[9] >= '0' && data[9] <= '9' && data[10] >= '0' && data[10] <= '9' &&
		data[11] >= '0' && data[11] <= '9'
}

func httpReplyCode(data []byte) int {
	return int(data[9]-'0')*100 + int(data[10]-'0')*10 + int(data[11]-'0')
}

// httpReplyHeaderValue ports HttpExtractHeader for one complete reply buffer.
func httpReplyHeaderValue(data []byte, name string) (string, bool) {
	lines := bytes.Split(data, []byte("\n"))
	prefix := []byte(strings.ToLower(name) + ":")
	for _, raw := range lines[1:] {
		line := bytes.TrimSuffix(raw, []byte("\r"))
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			break
		}
		if len(line) >= len(prefix) && bytes.EqualFold(line[:len(prefix)], prefix) {
			value := strings.TrimSpace(string(line[len(prefix):]))
			if value != "" {
				return value, true
			}
			return "", false
		}
	}
	return "", false
}

// httpReplyLooksLikeDPIRedirect ports HttpReplyLooksLikeDPIRedirect: only a
// 302/307 redirect to a different second-level domain is a DPI failure.
func httpReplyLooksLikeDPIRedirect(data []byte, host string) bool {
	if host == "" {
		return false
	}
	code := httpReplyCode(data)
	if code != 302 && code != 307 {
		return false
	}
	location, ok := httpReplyHeaderValue(data, "Location")
	if !ok {
		return false
	}
	var target string
	switch {
	case strings.HasPrefix(location, "http://"):
		target = location[len("http://"):]
	case strings.HasPrefix(location, "https://"):
		target = location[len("https://"):]
	default:
		return false
	}
	if index := strings.IndexAny(target, "/?#"); index >= 0 {
		target = target[:index]
	}
	if at := strings.LastIndexByte(target, '@'); at >= 0 {
		target = target[at+1:]
	}
	if colon := strings.LastIndexByte(target, ':'); colon >= 0 && strings.Count(target, ":") == 1 {
		target = target[:colon]
	}
	localSLD, localOK := secondLevelDomain(host)
	redirectSLD, redirectOK := secondLevelDomain(target)
	return localOK && redirectOK && !strings.EqualFold(localSLD, redirectSLD)
}

func secondLevelDomain(host string) (string, bool) {
	value := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return "", false
	}
	return strings.Join(labels[len(labels)-2:], "."), true
}

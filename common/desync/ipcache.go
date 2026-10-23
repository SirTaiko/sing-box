package desync

// Bounded per-outbound IP -> hostname and hop-count cache.
//
// Ported from the pinned upstream `ip_cache` (nfq/pools.c, zapret v72.9
// c849e55e) with the accepted architecture's per-outbound isolation: the cache
// belongs to one engine (one direct outbound) and never leaks between
// outbounds or config snapshots. Upstream keys the cache by address (and
// interface); the interface component is not part of the native-attempt
// envelope here, so the key is the exact destination address.
//
// Hostnames are learned only from validated L7 facts (decrypted and
// authenticated QUIC Initial, parsed TLS ClientHello, parsed HTTP request).
// The cache never guesses a hostname from a port or an unauthenticated
// plaintext scan. A cache hit applies to the exact destination address; it is
// not a wildcard or subnet rule.

import (
	"net/netip"
	"sync"
	"time"
)

const (
	defaultIPCacheEntries = 4096
	// upstream IPCACHE_LIFETIME default (nfq/params.h).
	defaultIPCacheLifetime = 7200 * time.Second
	// ipCachePurgeInterval mirrors upstream's rate-limited purge.
	ipCachePurgeInterval = 10 * time.Second
)

type ipCacheConfig struct {
	hostnameEnabled bool
	lifetime        time.Duration
	maxEntries      int
	// noExpiry is set when the lifetime option was explicitly zero, which
	// upstream documents as "no expiration".
	noExpiry bool
}

func defaultIPCacheConfig() ipCacheConfig {
	return ipCacheConfig{lifetime: defaultIPCacheLifetime, maxEntries: defaultIPCacheEntries}
}

// ipCacheKey is the upstream ip4if/ip6if key: the exact address plus the
// native-attempt interface name. Attempts on different interfaces never share
// one entry.
type ipCacheKey struct {
	address netip.Addr
	iface   string
}

type ipCacheEntry struct {
	hostname    string
	hostnameSet bool
	// hostnameIsIP mirrors the upstream hostname_is_ip marker: the cached
	// "hostname" is an IP literal, so hostlist matching is exact and never
	// expands subdomains.
	hostnameIsIP bool
	hops         uint8
	hopsSet      bool
	last         time.Time
}

type ipCache struct {
	mu        sync.Mutex
	entries   map[ipCacheKey]*ipCacheEntry
	config    ipCacheConfig
	now       func() time.Time
	lastPurge time.Time
}

func newIPCache(config ipCacheConfig, now func() time.Time) *ipCache {
	if now == nil {
		now = time.Now
	}
	if config.maxEntries <= 0 {
		config.maxEntries = defaultIPCacheEntries
	}
	if config.lifetime <= 0 && !config.noExpiry {
		config.lifetime = defaultIPCacheLifetime
	}
	return &ipCache{entries: make(map[ipCacheKey]*ipCacheEntry), config: config,
		now: now, lastPurge: now()}
}

// lookupHost returns the cached hostname and its hostname_is_ip marker for the
// exact destination address on the given native-attempt interface.
func (c *ipCache) lookupHost(address netip.Addr, iface string) (string, bool, bool) {
	if c == nil || !c.config.hostnameEnabled || !address.IsValid() {
		return "", false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	entry, found := c.entries[ipCacheKey{address: address, iface: iface}]
	if !found || !entry.hostnameSet || entry.hostname == "" {
		return "", false, false
	}
	entry.last = c.now()
	return entry.hostname, entry.hostnameIsIP, true
}

// learnHost stores a hostname that was derived from validated L7 facts. The
// hostname_is_ip marker is derived here, like upstream callers pass bHostIsIp.
func (c *ipCache) learnHost(address netip.Addr, iface string, hostname string) bool {
	if c == nil || !c.config.hostnameEnabled || !address.IsValid() || hostname == "" {
		return false
	}
	_, isIP := parseIPLiteral(hostname)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	entry := c.entryLocked(ipCacheKey{address: address, iface: iface})
	entry.hostname, entry.hostnameSet = hostname, true
	entry.hostnameIsIP = isIP
	entry.last = c.now()
	return true
}

// lookupHop returns the cached hop count of the exact destination address.
func (c *ipCache) lookupHop(address netip.Addr) (uint8, bool) {
	if c == nil || !address.IsValid() {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	entry, found := c.entries[ipCacheKey{address: address}]
	if !found || !entry.hopsSet || entry.hops == 0 {
		return 0, false
	}
	entry.last = c.now()
	return entry.hops, true
}

// learnHop stores an upstream `hop_count_guess` of an observed reply TTL.
func (c *ipCache) learnHop(address netip.Addr, ttl uint8) (uint8, bool) {
	if c == nil || !address.IsValid() {
		return 0, false
	}
	hops := HopCountGuess(ttl)
	if hops == 0 {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeLocked()
	entry := c.entryLocked(ipCacheKey{address: address})
	entry.hops, entry.hopsSet = hops, true
	entry.last = c.now()
	return hops, true
}

func (c *ipCache) entryLocked(key ipCacheKey) *ipCacheEntry {
	if entry, found := c.entries[key]; found && entry != nil {
		return entry
	}
	if len(c.entries) >= c.config.maxEntries {
		c.evictOldestLocked()
	}
	entry := &ipCacheEntry{}
	c.entries[key] = entry
	return entry
}

func (c *ipCache) purgeLocked() {
	now := c.now()
	if now.Sub(c.lastPurge) < ipCachePurgeInterval {
		return
	}
	c.lastPurge = now
	if c.config.noExpiry {
		return
	}
	for key, entry := range c.entries {
		if now.Sub(entry.last) >= c.config.lifetime {
			delete(c.entries, key)
		}
	}
}

func (c *ipCache) evictOldestLocked() {
	var oldestKey ipCacheKey
	var oldest *ipCacheEntry
	for key, entry := range c.entries {
		if oldest == nil || entry.last.Before(oldest.last) {
			oldestKey, oldest = key, entry
		}
	}
	if oldest != nil {
		delete(c.entries, oldestKey)
	}
}

// forget drops one address (used when a flow learns conflicting facts).
func (c *ipCache) forget(address netip.Addr) {
	if c == nil {
		return
	}
	c.mu.Lock()
	for key := range c.entries {
		if key.address == address {
			delete(c.entries, key)
		}
	}
	c.mu.Unlock()
}

func (c *ipCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ipCache) close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[ipCacheKey]*ipCacheEntry)
	c.mu.Unlock()
}

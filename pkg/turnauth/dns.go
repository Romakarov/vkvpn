package turnauth

import (
	"context"
	"net"
	"sync"
	"time"
)

// DNS servers ordered by priority.
// Yandex DNS is first because it's whitelisted by Russian ISPs.
var fallbackDNSServers = []string{
	"77.88.8.8:53",  // Yandex DNS primary
	"77.88.8.1:53",  // Yandex DNS secondary
	"8.8.8.8:53",    // Google DNS (may be blocked)
	"1.1.1.1:53",    // Cloudflare DNS (may be blocked)
}

// NewFallbackResolver creates a DNS resolver that tries multiple DNS servers
// with fallback. It uses Yandex DNS first (whitelisted by Russian ISPs),
// then falls back to Google/Cloudflare, then system DNS.
func NewFallbackResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			for _, dns := range fallbackDNSServers {
				conn, err := d.DialContext(ctx, "udp", dns)
				if err == nil {
					return conn, nil
				}
			}
			// Last resort: system DNS
			return d.DialContext(ctx, network, address)
		},
	}
}

// NewDialerWithDNS creates an http.Transport that uses the fallback DNS resolver.
func NewDialerWithDNS() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  NewFallbackResolver(),
	}
}

// --- DNS cache ---

// dnsCache stores resolved addresses with expiry.
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	addrs     []string
	expiresAt time.Time
	staleAt   time.Time // stale-while-revalidate: use stale data up to this time
}

var globalDNSCache = &dnsCache{
	entries: make(map[string]dnsCacheEntry),
}

const (
	dnsCacheTTL      = 5 * time.Minute
	dnsCacheStaleTTL = 30 * time.Minute
)

// ResolveWithCache resolves a hostname using cache + fallback DNS.
// Returns cached results if fresh, stale results on error, or does a fresh lookup.
func ResolveWithCache(ctx context.Context, host string) ([]string, error) {
	// Check cache
	globalDNSCache.mu.RLock()
	entry, ok := globalDNSCache.entries[host]
	globalDNSCache.mu.RUnlock()

	now := time.Now()
	if ok && now.Before(entry.expiresAt) {
		return entry.addrs, nil
	}

	// Try fresh resolution
	resolver := NewFallbackResolver()
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		// On error, return stale cache if available
		if ok && now.Before(entry.staleAt) {
			return entry.addrs, nil
		}
		return nil, err
	}

	// Update cache
	globalDNSCache.mu.Lock()
	globalDNSCache.entries[host] = dnsCacheEntry{
		addrs:     addrs,
		expiresAt: now.Add(dnsCacheTTL),
		staleAt:   now.Add(dnsCacheStaleTTL),
	}
	globalDNSCache.mu.Unlock()

	return addrs, nil
}

// ClearDNSCache clears all cached DNS entries. Useful for testing.
func ClearDNSCache() {
	globalDNSCache.mu.Lock()
	globalDNSCache.entries = make(map[string]dnsCacheEntry)
	globalDNSCache.mu.Unlock()
}

package turnauth

import (
	"context"
	"testing"
	"time"
)

func TestNewFallbackResolver(t *testing.T) {
	r := NewFallbackResolver()
	if r == nil {
		t.Fatal("NewFallbackResolver returned nil")
	}
	if !r.PreferGo {
		t.Error("resolver should prefer Go implementation")
	}
}

func TestNewDialerWithDNS(t *testing.T) {
	d := NewDialerWithDNS()
	if d == nil {
		t.Fatal("NewDialerWithDNS returned nil")
	}
	if d.Resolver == nil {
		t.Error("dialer should have a resolver")
	}
}

func TestResolveWithCache(t *testing.T) {
	ClearDNSCache()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Resolve a well-known host
	addrs, err := ResolveWithCache(ctx, "localhost")
	if err != nil {
		t.Fatalf("ResolveWithCache(localhost): %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("expected at least one address for localhost")
	}

	// Second call should come from cache (fast)
	start := time.Now()
	addrs2, err := ResolveWithCache(ctx, "localhost")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("cached ResolveWithCache: %v", err)
	}
	if len(addrs2) == 0 {
		t.Fatal("cached lookup returned no addresses")
	}
	if elapsed > 1*time.Millisecond {
		t.Logf("warning: cached lookup took %v (expected <1ms)", elapsed)
	}
}

func TestResolveWithCacheStale(t *testing.T) {
	ClearDNSCache()

	// Manually insert a stale entry
	globalDNSCache.mu.Lock()
	globalDNSCache.entries["test.invalid"] = dnsCacheEntry{
		addrs:     []string{"1.2.3.4"},
		expiresAt: time.Now().Add(-1 * time.Minute), // expired
		staleAt:   time.Now().Add(10 * time.Minute),  // but still stale-valid
	}
	globalDNSCache.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Should return stale data since "test.invalid" won't resolve
	addrs, err := ResolveWithCache(ctx, "test.invalid")
	if err != nil {
		t.Fatalf("expected stale cache hit, got error: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Fatalf("expected stale [1.2.3.4], got %v", addrs)
	}
}

func TestClearDNSCache(t *testing.T) {
	globalDNSCache.mu.Lock()
	globalDNSCache.entries["test"] = dnsCacheEntry{
		addrs:     []string{"1.1.1.1"},
		expiresAt: time.Now().Add(1 * time.Hour),
		staleAt:   time.Now().Add(2 * time.Hour),
	}
	globalDNSCache.mu.Unlock()

	ClearDNSCache()

	globalDNSCache.mu.RLock()
	n := len(globalDNSCache.entries)
	globalDNSCache.mu.RUnlock()

	if n != 0 {
		t.Fatalf("expected empty cache, got %d entries", n)
	}
}

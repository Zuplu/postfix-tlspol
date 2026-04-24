/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

func TestIsLikelyHTTP(t *testing.T) {
	if !isLikelyHTTP(bufio.NewReader(strings.NewReader("GET /metrics HTTP/1.1\r\n"))) {
		t.Fatal("expected HTTP request to be detected")
	}
	if isLikelyHTTP(bufio.NewReader(strings.NewReader("14:QUERY example,"))) {
		t.Fatal("expected netstring payload not to be detected as HTTP")
	}
}

func TestObservePolicyMetrics(t *testing.T) {
	metricDaneTotal.Store(0)
	metricDaneOnlyTotal.Store(0)
	metricSecureTotal.Store(0)
	metricNoPolicyTotal.Store(0)

	observePolicy("dane-only")
	observePolicy("dane")
	observePolicy("secure match=mx.example")
	observePolicy("")

	if metricDaneTotal.Load() != 2 {
		t.Fatalf("expected dane total to be 2, got %d", metricDaneTotal.Load())
	}
	if metricDaneOnlyTotal.Load() != 1 {
		t.Fatalf("expected dane-only total to be 1, got %d", metricDaneOnlyTotal.Load())
	}
	if metricSecureTotal.Load() != 1 {
		t.Fatalf("expected secure total to be 1, got %d", metricSecureTotal.Load())
	}
	if metricNoPolicyTotal.Load() != 1 {
		t.Fatalf("expected no-policy total to be 1, got %d", metricNoPolicyTotal.Load())
	}
}

func TestBuildMetricsTextIncludesExpectedMetrics(t *testing.T) {
	metricQueriesTotal.Store(12)
	metricDaneTotal.Store(7) // includes dane-only
	metricDaneOnlyTotal.Store(3)
	metricSecureTotal.Store(4)
	metricNoPolicyTotal.Store(9)

	metrics := buildMetricsText()
	for _, expected := range []string{
		"postfix_tlspol_queries_total 12",
		"postfix_tlspol_policy_total{policy=\"dane\"} 4",
		"postfix_tlspol_policy_total{policy=\"dane-only\"} 3",
		"postfix_tlspol_policy_total{policy=\"secure\"} 4",
		"postfix_tlspol_policy_total{policy=\"no-policy\"} 9",
		"postfix_tlspol_go_goroutines ",
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("expected metrics output to contain %q", expected)
		}
	}
}

func TestPolicyCacheClosePersistsCacheDB(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "cache.db")
	now := time.Now()

	c1 := cache.New[*CacheStruct](tmpFile, time.Hour)
	c1.Set("example.org", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Policy:    "dane",
		TTL:       300,
		Counter:   2,
	})
	c1.Close()

	if _, err := os.Stat(tmpFile); err != nil {
		t.Fatalf("expected cache.db to be saved on close: %v", err)
	}

	c2 := cache.New[*CacheStruct](tmpFile, time.Hour)
	defer c2.Close()

	got, ok := c2.Get("example.org")
	if !ok {
		t.Fatal("expected cached policy after reload")
	}
	if got.Policy != "dane" || got.TTL != 300 || got.Counter != 2 {
		t.Fatalf("unexpected cached policy after reload: %+v", got)
	}
}

func TestTidyCacheRemovesExpiredNoPolicyAndOldStalePolicy(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	oldPolCache := polCache
	defer func() {
		config.Server.CacheFile = oldCacheFile
		polCache = oldPolCache
	}()

	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Hour)
	defer polCache.Close()

	now := time.Now()
	polCache.Set("expired-empty.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Second)},
		Policy:    "",
	})
	polCache.Set("old-stale.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Duration(CACHE_MAX_AGE+1) * time.Second)},
		Policy:    "dane",
	})
	polCache.Set("recent-stale.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(-time.Minute)},
		Policy:    "dane",
	})
	polCache.Set("fresh.example", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Minute)},
		Policy:    "dane",
	})

	entries := tidyCache()
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		seen[entry.Key] = true
	}

	for _, removed := range []string{"expired-empty.example", "old-stale.example"} {
		if seen[removed] {
			t.Fatalf("expected %s to be removed", removed)
		}
		if _, ok := polCache.Get(removed); ok {
			t.Fatalf("expected %s to be absent from cache", removed)
		}
	}
	for _, kept := range []string{"recent-stale.example", "fresh.example"} {
		if !seen[kept] {
			t.Fatalf("expected %s to be retained", kept)
		}
	}
}

func TestTryCachedPolicyUpdatesCopy(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	oldPolCache := polCache
	defer func() {
		config.Server.CacheFile = oldCacheFile
		polCache = oldPolCache
	}()

	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Hour)
	defer polCache.Close()

	original := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Minute)},
		Policy:    "dane",
	}
	polCache.Set("example.com", original)

	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(c2)
		close(done)
	}()

	updated, ok := tryCachedPolicy(c1, "example.com", false)
	c1.Close()
	c2.Close()
	<-done

	if !ok {
		t.Fatal("expected cached policy to be used")
	}
	if original.Counter != 0 {
		t.Fatalf("expected original cached pointer to remain unchanged, got counter %d", original.Counter)
	}
	if updated == original {
		t.Fatal("expected cache update to use a copied entry")
	}
	stored, ok := polCache.Get("example.com")
	if !ok {
		t.Fatal("expected updated cache entry to be stored")
	}
	if stored.Counter != 1 {
		t.Fatalf("expected stored counter to be 1, got %d", stored.Counter)
	}
}

func TestQueryDomainSingleflight(t *testing.T) {
	origFn := queryDomainOnce
	origGroup := queryGroup
	defer func() {
		queryDomainOnce = origFn
		queryGroup = origGroup
	}()

	var calls atomic.Int32
	block := make(chan struct{})
	queryDomainOnce = func(domain string) (string, string, uint32) {
		calls.Add(1)
		<-block
		return "dane", "", 300
	}

	const workers = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			queryDomain("example.com")
		}()
	}

	// Allow goroutines to block inside the first call
	time.Sleep(50 * time.Millisecond)
	close(block)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected single underlying call, got %d", got)
	}
}

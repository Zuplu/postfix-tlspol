/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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

func TestMetricStatsPersistenceRoundTrip(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	defer func() {
		config.Server.CacheFile = oldCacheFile
	}()
	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")

	metricQueriesTotal.Store(101)
	metricDaneTotal.Store(55)
	metricDaneOnlyTotal.Store(21)
	metricSecureTotal.Store(34)
	metricNoPolicyTotal.Store(13)

	if err := saveMetricStats(true); err != nil {
		t.Fatalf("saveMetricStats failed: %v", err)
	}

	metricQueriesTotal.Store(0)
	metricDaneTotal.Store(0)
	metricDaneOnlyTotal.Store(0)
	metricSecureTotal.Store(0)
	metricNoPolicyTotal.Store(0)

	if err := loadMetricStats(); err != nil {
		t.Fatalf("loadMetricStats failed: %v", err)
	}

	if metricQueriesTotal.Load() != 101 || metricDaneTotal.Load() != 55 || metricDaneOnlyTotal.Load() != 21 || metricSecureTotal.Load() != 34 || metricNoPolicyTotal.Load() != 13 {
		t.Fatalf("unexpected restored stats: queries=%d dane=%d dane-only=%d secure=%d no-policy=%d", metricQueriesTotal.Load(), metricDaneTotal.Load(), metricDaneOnlyTotal.Load(), metricSecureTotal.Load(), metricNoPolicyTotal.Load())
	}
}

func TestCachePurgeDoesNotTruncateStats(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	oldPolCache := polCache
	defer func() {
		config.Server.CacheFile = oldCacheFile
		polCache = oldPolCache
	}()

	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Hour)
	defer polCache.Close()

	metricQueriesTotal.Store(42)
	metricDaneTotal.Store(13)
	metricDaneOnlyTotal.Store(5)
	metricSecureTotal.Store(7)
	metricNoPolicyTotal.Store(11)
	if err := saveMetricStats(true); err != nil {
		t.Fatalf("saveMetricStats failed: %v", err)
	}

	before, err := os.ReadFile(metricStatsPath())
	if err != nil {
		t.Fatalf("read stats before purge failed: %v", err)
	}

	now := time.Now()
	polCache.Set("example.org", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Policy:    "dane",
		TTL:       300,
	})
	polCache.Purge()

	// Exercise the PURGE command path too.
	c1, c2 := net.Pipe()
	done := make(chan struct{})
	go func() {
		purgeCache(c1)
		c1.Close()
		close(done)
	}()
	_, _ = io.ReadAll(c2)
	c2.Close()
	<-done

	after, err := os.ReadFile(metricStatsPath())
	if err != nil {
		t.Fatalf("read stats after purge failed: %v", err)
	}
	if len(after) == 0 {
		t.Fatal("stats file was truncated to zero length")
	}
	if !bytes.Equal(before, after) {
		t.Fatal("stats file changed during cache purge")
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

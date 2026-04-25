/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

func TestMetricsOnlyHTTPHandler(t *testing.T) {
	metricQueriesTotal.Store(12)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()

	handleMetricsOnlyHTTPRequest(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "postfix_tlspol_queries_total 12") {
		t.Fatalf("expected metrics body, got %q", string(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("unexpected content type %q", got)
	}
}

func TestMetricsOnlyHTTPHandlerDoesNotExposeSocketmap(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/socketmap", nil)
	rec := httptest.NewRecorder()

	handleMetricsOnlyHTTPRequest(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp.StatusCode)
	}
}

func TestPolicyCacheClosePersistsCacheDB(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "cache.db")
	now := time.Now()

	c1 := cache.New[*CacheStruct](tmpFile, time.Hour)
	c1.Set("example.org", &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       300,
			ExpiresAt: now.Add(5 * time.Minute),
		},
		TTL:     300,
		Counter: 2,
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

func TestTryCachedPolicyDoesNotRewriteCacheEntry(t *testing.T) {
	oldCacheFile := config.Server.CacheFile
	oldPolCache := polCache
	oldCounters := cacheHitCounters
	defer func() {
		config.Server.CacheFile = oldCacheFile
		polCache = oldPolCache
		cacheHitCounters = oldCounters
	}()

	config.Server.CacheFile = filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Hour)
	cacheHitCounters = sync.Map{}
	defer polCache.Close()

	original := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Minute)},
		Policy:    "dane",
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       60,
			ExpiresAt: time.Now().Add(time.Minute),
		},
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
	if updated != original {
		t.Fatal("expected cache hit to return the stored entry without rewriting it")
	}
	stored, ok := polCache.Get("example.com")
	if !ok {
		t.Fatal("expected cache entry to remain stored")
	}
	if stored.Counter != 0 {
		t.Fatalf("expected stored counter to remain 0 before flush, got %d", stored.Counter)
	}
	if got := cacheEntryCounter("example.com", stored); got != 1 {
		t.Fatalf("expected combined counter to be 1, got %d", got)
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
	queryDomainOnce = func(domain string) domainResult {
		calls.Add(1)
		<-block
		return domainResult{
			Policy: "dane",
			TTL:    300,
			Dane:   branchFromResult("dane", "", 300),
		}
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

func TestSelectCachedPolicyPrioritizesFreshDane(t *testing.T) {
	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.example servername=hostname",
			Report:    "policy_type=sts",
			TTL:       3600,
			ExpiresAt: now.Add(time.Hour),
		},
	}

	if _, _, _, ok := selectCachedPolicy(c, now); ok {
		t.Fatal("expected MTA-STS-only cache entry to miss without fresh DANE state")
	}

	c.Dane = PolicyBranch{
		TTL:       300,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	policy, report, ttl, ok := selectCachedPolicy(c, now)
	if !ok {
		t.Fatal("expected MTA-STS to be usable with fresh no-DANE state")
	}
	if policy != c.MtaSts.Policy || report != c.MtaSts.Report || ttl != 300 {
		t.Fatalf("unexpected MTA-STS selection: policy=%q report=%q ttl=%d", policy, report, ttl)
	}

	c.Dane = PolicyBranch{
		Policy:    "dane-only",
		TTL:       600,
		ExpiresAt: now.Add(10 * time.Minute),
	}
	policy, _, ttl, ok = selectCachedPolicy(c, now)
	if !ok || policy != "dane-only" || ttl != 600 {
		t.Fatalf("expected fresh DANE to override MTA-STS, got policy=%q ttl=%d ok=%v", policy, ttl, ok)
	}
}

func TestQueryDomainDaneTempDoesNotDowngradeToMtaSts(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "TEMP", 0
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 86400
	}

	result := queryDomainOnceImpl("example.com")
	if result.Policy != "TEMP" || result.TTL != 0 {
		t.Fatalf("expected temporary DANE failure to win over MTA-STS, got %+v", result)
	}
	if result.MtaSts.Policy == "" || result.MtaSts.TTL != 86400 {
		t.Fatalf("expected MTA-STS branch to be retained for cache, got %+v", result.MtaSts)
	}
}

func TestQueryDomainUsesMtaStsOnlyAfterFreshNoDane(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		return "", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "secure match=mx.example servername=hostname", "policy_type=sts", 86400
	}

	result := queryDomainOnceImpl("example.com")
	if result.Policy != "secure match=mx.example servername=hostname" || result.Report != "policy_type=sts" || result.TTL != 300 {
		t.Fatalf("unexpected selected policy: %+v", result)
	}
}

func TestRefreshDomainReusesFreshMtaStsBranch(t *testing.T) {
	origDane := checkDanePolicy
	origMtaSts := checkMtaStsPolicy
	defer func() {
		checkDanePolicy = origDane
		checkMtaStsPolicy = origMtaSts
	}()

	var daneCalls atomic.Int32
	var mtaStsCalls atomic.Int32
	checkDanePolicy = func(context.Context, string, bool) (string, uint32) {
		daneCalls.Add(1)
		return "", 300
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		mtaStsCalls.Add(1)
		return "secure match=mx.example servername=hostname", "policy_type=sts", 600
	}

	now := time.Now()
	cached := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Hour)},
		Dane: PolicyBranch{
			ExpiresAt: now.Add(-time.Second),
		},
		MtaSts: PolicyBranch{
			Policy:    "secure match=mx.cached.example servername=hostname",
			Report:    "policy_type=sts policy_domain=example.com",
			TTL:       600,
			ExpiresAt: now.Add(10 * time.Minute),
		},
	}

	result := refreshDomainOnceImpl("example.com", cached)
	if daneCalls.Load() != 1 {
		t.Fatalf("expected one DANE refresh, got %d", daneCalls.Load())
	}
	if mtaStsCalls.Load() != 0 {
		t.Fatalf("expected fresh MTA-STS branch to be reused, got %d refreshes", mtaStsCalls.Load())
	}
	if result.Policy != cached.MtaSts.Policy {
		t.Fatalf("expected cached MTA-STS policy, got %q", result.Policy)
	}
	if !result.Dane.HasData() {
		t.Fatal("expected refreshed no-DANE branch to be returned for cache merge")
	}
	if result.MtaSts.HasData() {
		t.Fatal("expected fresh MTA-STS branch not to be returned as refreshed data")
	}
}

func TestNextPrefetchTime(t *testing.T) {
	now := time.Now()
	c := &CacheStruct{
		Expirable: &cache.Expirable{ExpiresAt: now.Add(5 * time.Minute)},
		Dane: PolicyBranch{
			Policy:    "dane",
			TTL:       300,
			ExpiresAt: now.Add(5 * time.Minute),
		},
	}

	due, ok := nextPrefetchTime(c, now)
	if !ok {
		t.Fatal("expected policy to be scheduled for prefetch")
	}
	expected := now.Add(time.Duration(300-PREFETCH_INTERVAL) * time.Second)
	if !due.Equal(expected) {
		t.Fatalf("unexpected prefetch time: got %s want %s", due, expected)
	}

	c.Dane.ExpiresAt = now.Add(-time.Second)
	due, ok = nextPrefetchTime(c, now)
	if !ok {
		t.Fatal("expected expired policy to be scheduled immediately")
	}
	if !due.Equal(now) {
		t.Fatalf("expected immediate prefetch, got %s", due)
	}
}

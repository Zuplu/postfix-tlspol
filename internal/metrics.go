/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
)

var (
	metricQueriesTotal  atomic.Uint64
	metricDaneTotal     atomic.Uint64
	metricDaneOnlyTotal atomic.Uint64
	metricSecureTotal   atomic.Uint64
	metricNoPolicyTotal atomic.Uint64
	metricCacheHits     atomic.Uint64
	metricCacheMisses   atomic.Uint64
	metricPrefetchOK    atomic.Uint64
	metricPrefetchFail  atomic.Uint64
	metricPrefetchDrop  atomic.Uint64
)

func addMetricQuery() {
	metricQueriesTotal.Add(1)
}

func observePolicy(policy string) {
	switch firstWord(policy) {
	case "dane-only":
		metricDaneOnlyTotal.Add(1)
		metricDaneTotal.Add(1)
	case "dane":
		metricDaneTotal.Add(1)
	case "secure":
		metricSecureTotal.Add(1)
	case "":
		metricNoPolicyTotal.Add(1)
	}
}

func observeCacheRequest(hit bool) {
	if hit {
		metricCacheHits.Add(1)
	} else {
		metricCacheMisses.Add(1)
	}
}

func observePrefetch(result string) {
	switch result {
	case "success":
		metricPrefetchOK.Add(1)
	case "failure":
		metricPrefetchFail.Add(1)
	case "discard":
		metricPrefetchDrop.Add(1)
	}
}

func buildMetricsText() string {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var b strings.Builder
	b.Grow(4096)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_queries_total Total socketmap query commands handled.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_queries_total counter\n")
	fmt.Fprintf(&b, "postfix_tlspol_queries_total %d\n", metricQueriesTotal.Load())
	daneOnly := metricDaneOnlyTotal.Load()
	daneAll := metricDaneTotal.Load()
	dane := uint64(0)
	if daneAll > daneOnly {
		dane = daneAll - daneOnly
	}
	fmt.Fprintf(&b, "# HELP postfix_tlspol_policy_total Total returned policies by policy type.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_policy_total counter\n")
	fmt.Fprintf(&b, "postfix_tlspol_policy_total{policy=\"dane\"} %d\n", dane)
	fmt.Fprintf(&b, "postfix_tlspol_policy_total{policy=\"dane-only\"} %d\n", daneOnly)
	fmt.Fprintf(&b, "postfix_tlspol_policy_total{policy=\"secure\"} %d\n", metricSecureTotal.Load())
	fmt.Fprintf(&b, "postfix_tlspol_policy_total{policy=\"no-policy\"} %d\n", metricNoPolicyTotal.Load())
	fmt.Fprintf(&b, "# HELP postfix_tlspol_cache_requests_total Total policy cache lookups by result.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_cache_requests_total counter\n")
	fmt.Fprintf(&b, "postfix_tlspol_cache_requests_total{result=\"hit\"} %d\n", metricCacheHits.Load())
	fmt.Fprintf(&b, "postfix_tlspol_cache_requests_total{result=\"miss\"} %d\n", metricCacheMisses.Load())
	cacheEntries := 0
	if polCache != nil {
		cacheEntries = polCache.Len()
	}
	fmt.Fprintf(&b, "# HELP postfix_tlspol_cache_entries Current number of in-memory policy cache entries.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_cache_entries gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_cache_entries %d\n", cacheEntries)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_prefetch_total Total policy prefetch outcomes by result.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_prefetch_total counter\n")
	fmt.Fprintf(&b, "postfix_tlspol_prefetch_total{result=\"success\"} %d\n", metricPrefetchOK.Load())
	fmt.Fprintf(&b, "postfix_tlspol_prefetch_total{result=\"failure\"} %d\n", metricPrefetchFail.Load())
	fmt.Fprintf(&b, "postfix_tlspol_prefetch_total{result=\"discard\"} %d\n", metricPrefetchDrop.Load())
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_goroutines Number of goroutines that currently exist.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_goroutines gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_alloc_bytes Number of bytes allocated and still in use.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_alloc_bytes gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_alloc_bytes %d\n", mem.Alloc)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_heap_alloc_bytes Number of heap bytes allocated and still in use.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_heap_alloc_bytes gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_heap_alloc_bytes %d\n", mem.HeapAlloc)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_heap_inuse_bytes Number of heap bytes in use.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_heap_inuse_bytes gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_heap_inuse_bytes %d\n", mem.HeapInuse)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_heap_sys_bytes Number of heap bytes obtained from system.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_heap_sys_bytes gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_heap_sys_bytes %d\n", mem.HeapSys)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_gc_sys_bytes Number of bytes used for garbage collection system metadata.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_gc_sys_bytes gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_gc_sys_bytes %d\n", mem.GCSys)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_next_gc_bytes Number of heap bytes when next garbage collection will happen.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_next_gc_bytes gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_next_gc_bytes %d\n", mem.NextGC)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_memstats_last_gc_time_seconds Time the last garbage collection finished as a Unix timestamp.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_memstats_last_gc_time_seconds gauge\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_memstats_last_gc_time_seconds %.9f\n", float64(mem.LastGC)/1e9)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_gc_cycles_total Count of completed GC cycles.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_gc_cycles_total counter\n")
	fmt.Fprintf(&b, "postfix_tlspol_go_gc_cycles_total %d\n", mem.NumGC)
	fmt.Fprintf(&b, "# HELP postfix_tlspol_go_threads Number of operating system threads created.\n")
	fmt.Fprintf(&b, "# TYPE postfix_tlspol_go_threads gauge\n")
	threads, _ := runtime.ThreadCreateProfile(nil)
	fmt.Fprintf(&b, "postfix_tlspol_go_threads %d\n", threads)
	return b.String()
}

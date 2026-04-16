/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"encoding/gob"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	metricQueriesTotal  atomic.Uint64
	metricDaneTotal     atomic.Uint64
	metricDaneOnlyTotal atomic.Uint64
	metricSecureTotal   atomic.Uint64
	metricNoPolicyTotal atomic.Uint64
	metricStatsDirty    atomic.Bool
	metricPersistQuit   chan struct{}
	metricPersistWG     sync.WaitGroup
)

type metricStats struct {
	Queries  uint64
	Dane     uint64
	DaneOnly uint64
	Secure   uint64
	NoPolicy uint64
}

const metricPersistInterval = 5 * time.Minute

func metricStatsPath() string {
	return filepath.Join(filepath.Dir(config.Server.CacheFile), "stats.db")
}

func loadMetricStats() error {
	f, err := os.Open(metricStatsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	var stats metricStats
	if err := gob.NewDecoder(f).Decode(&stats); err != nil {
		return err
	}
	metricQueriesTotal.Store(stats.Queries)
	metricDaneTotal.Store(stats.Dane)
	metricDaneOnlyTotal.Store(stats.DaneOnly)
	metricSecureTotal.Store(stats.Secure)
	metricNoPolicyTotal.Store(stats.NoPolicy)
	metricStatsDirty.Store(false)
	return nil
}

func saveMetricStats(force bool) error {
	if !force && !metricStatsDirty.Load() {
		return nil
	}
	stats := metricStats{
		Queries:  metricQueriesTotal.Load(),
		Dane:     metricDaneTotal.Load(),
		DaneOnly: metricDaneOnlyTotal.Load(),
		Secure:   metricSecureTotal.Load(),
		NoPolicy: metricNoPolicyTotal.Load(),
	}
	path := metricStatsPath()
	tmpPath := path + ".tmp"

	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	encErr := gob.NewEncoder(f).Encode(stats)
	closeErr := f.Close()
	if encErr != nil {
		_ = os.Remove(tmpPath)
		return encErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	metricStatsDirty.Store(false)
	return nil
}

func startMetricStatsPersistence() {
	metricPersistQuit = make(chan struct{})
	metricPersistWG.Add(1)
	go func() {
		defer metricPersistWG.Done()
		ticker := time.NewTicker(metricPersistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				_ = saveMetricStats(false)
			case <-metricPersistQuit:
				return
			}
		}
	}()
}

func stopMetricStatsPersistence() {
	if metricPersistQuit == nil {
		return
	}
	close(metricPersistQuit)
	metricPersistWG.Wait()
	metricPersistQuit = nil
}

func addMetricQuery() {
	metricQueriesTotal.Add(1)
	metricStatsDirty.Store(true)
}

func observePolicy(policy string) {
	switch firstWord(policy) {
	case "dane-only":
		metricDaneOnlyTotal.Add(1)
		metricDaneTotal.Add(1)
		metricStatsDirty.Store(true)
	case "dane":
		metricDaneTotal.Add(1)
		metricStatsDirty.Store(true)
	case "secure":
		metricSecureTotal.Add(1)
		metricStatsDirty.Store(true)
	case "":
		metricNoPolicyTotal.Add(1)
		metricStatsDirty.Store(true)
	}
}

func buildMetricsText() string {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	var b strings.Builder
	b.Grow(1024)
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

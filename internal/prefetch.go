/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

const (
	PREFETCH_INTERVAL uint32 = 30
)

var semaphore chan struct{}

func startPrefetching() {
	if !config.Server.Prefetch {
		return
	}
	slog.Info("Prefetching enabled")
	ticker := time.NewTicker(time.Duration(PREFETCH_INTERVAL) * time.Second)
	defer ticker.Stop()
	semaphore = make(chan struct{}, runtime.NumCPU()*4+2)
	for range ticker.C {
		prefetchCachedPolicies()
	}
}

func prefetchCachedPolicies() {
	var wg sync.WaitGroup
	var counter atomic.Uint32
	items := polCache.Items(false)
	itemsCount := len(items)
	now := time.Now()
	for _, entry := range items {
		policy, _, remainingTTL, usable := selectCachedPolicy(entry.Value, now)
		if usable && policy == "" {
			itemsCount--
			if remainingTTL == 0 {
				polCache.Remove(false, entry.Key)
			}
			continue
		}
		if entry.Value.Age(now) >= CACHE_MAX_AGE {
			itemsCount--
			polCache.Remove(false, entry.Key)
			continue
		}
		if usable && remainingTTL > PREFETCH_INTERVAL {
			continue
		}
		semaphore <- struct{}{}
		wg.Add(1)
		go func(c cache.Entry[*CacheStruct]) {
			defer func() {
				wg.Done()
				<-semaphore
			}()
			// Refresh the cached policy
			refreshed := refreshDomain(c.Key, c.Value)
			if refreshed.Dane.HasData() || refreshed.MtaSts.HasData() {
				counter.Add(1)
				polCache.Set(c.Key, mergeCacheResult(c.Value, refreshed, now))
			}
		}(entry)
	}
	wg.Wait()
	count := counter.Load()
	if count > 0 {
		slog.Debug("Prefetched policies", "count", count, "total", itemsCount)
	}
}

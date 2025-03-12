/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	PREFETCH_INTERVAL uint32 = 15
	PREFETCH_MARGIN   uint32 = 300
)

var semaphore chan struct{}

func startPrefetching() {
	if !config.Server.Prefetch {
		return
	}
	log.Info("Prefetching enabled!")
	ticker := time.NewTicker(time.Duration(PREFETCH_INTERVAL) * time.Second)
	semaphore = make(chan struct{}, runtime.NumCPU()*4)
	for range ticker.C {
		prefetchCachedPolicies()
	}
}

func prefetchCachedPolicies() {
	var wg sync.WaitGroup
	var counter atomic.Uint32
	items := polCache.Items()
	itemsCount := len(items)
	for _, entry := range items {
		remainingTTL := entry.Value.RemainingTTL()
		if entry.Value.Policy == "" || entry.Value.TTL < PREFETCH_MARGIN {
			itemsCount--
			if remainingTTL == 0 {
				polCache.Remove(entry.Key)
			}
			continue
		}
		if remainingTTL != 0 {
			continue
		}
		semaphore <- struct{}{}
		wg.Add(1)
		go func(entry cache.Entry[*CacheStruct]) {
			defer func() {
				wg.Done()
				<-semaphore
			}()
			// Refresh the cached policy
			refreshedPolicy, refreshedRpt, refreshedTTL := queryDomain(&entry.Key)
			if refreshedPolicy != "" && refreshedPolicy != "TEMP" {
				counter.Add(1)
				polCache.Set(entry.Key, &CacheStruct{Policy: refreshedPolicy, Report: refreshedRpt, TTL: refreshedTTL, Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Duration(refreshedTTL) * time.Second)}})
			}
		}(entry)
	}
	wg.Wait()
	count := counter.Load()
	if count > 0 {
		log.Debugf("Prefetched %d of %d policies", count, itemsCount)
	}
}

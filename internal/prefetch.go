/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
)

const (
	PREFETCH_INTERVAL uint32 = 30
)

var semaphore chan struct{}

func startPrefetching() {
	if !config.Server.Prefetch {
		return
	}
	log.Info("Prefetching enabled!")
	ticker := time.NewTicker(time.Duration(PREFETCH_INTERVAL) * time.Second)
	semaphore = make(chan struct{}, runtime.NumCPU()*4+2)
	for range ticker.C {
		go prefetchCachedPolicies()
	}
}

func prefetchCachedPolicies() {
	var wg sync.WaitGroup
	var counter atomic.Uint32
	items := polCache.Items(false)
	itemsCount := len(items)
	now := time.Now()
	for _, entry := range items {
		remainingTTL := entry.Value.RemainingTTL(now)
		if entry.Value.Policy == "" || entry.Value.Age(now) >= CACHE_MAX_AGE && remainingTTL+PREFETCH_INTERVAL <= 0 {
			itemsCount--
			if remainingTTL == 0 {
				polCache.Remove(false, entry.Key)
			}
			continue
		}
		if remainingTTL > PREFETCH_INTERVAL {
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
			refreshedPolicy, refreshedRpt, refreshedTTL := queryDomain(&c.Key)
			if refreshedPolicy != "" && refreshedPolicy != "TEMP" {
				counter.Add(1)
				c.Value.Policy = refreshedPolicy
				c.Value.Report = refreshedRpt
				c.Value.TTL = refreshedTTL
				c.Value.Expirable.ExpiresAt = now.Add(time.Duration(refreshedTTL+rand.Uint32N(20)) * time.Second)
			}
		}(entry)
	}
	wg.Wait()
	count := counter.Load()
	if count > 0 {
		log.Debugf("Prefetched %d of %d policies", count, itemsCount)
	}
}

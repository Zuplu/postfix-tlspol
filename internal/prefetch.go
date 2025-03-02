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

	"github.com/Zuplu/postfix-tlspol/internal/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
)

const (
	PREFETCH_INTERVAL float64 = 30
	PREFETCH_MARGIN           = 300 // seconds

	PREFETCH_FACTOR = (PREFETCH_INTERVAL + 1.0) / float64(PREFETCH_MARGIN)
)

func startPrefetching() {
	ticker := time.NewTicker(time.Duration(PREFETCH_INTERVAL) * time.Second)
	for range ticker.C {
		prefetchCachedPolicies()
	}
}

func prefetchCachedPolicies() {
	keys, err := cacheClient.Keys(bgCtx)
	if err != nil {
		log.Errorf("Error fetching keys from cache: %v", err)
		return
	}
	polCnt := len(keys) - 1
	if polCnt < 1 {
		return
	}
	semaphore := make(chan struct{}, runtime.NumCPU()*8)
	var wg sync.WaitGroup
	var counter atomic.Uint32
	for _, key := range keys {
		semaphore <- struct{}{}
		wg.Add(1)
		go func(key string) {
			defer func() {
				wg.Done()
				<-semaphore
			}()
			cachedPolicy, ttl, err := cacheClient.Get(bgCtx, key)
			if err != nil || cachedPolicy.Result == "" {
				return
			}
			// Check if the original TTL is greater than the margin and within the prefetching range
			if cachedPolicy.Ttl >= PREFETCH_MARGIN && float64(ttl-PREFETCH_MARGIN) < float64(cachedPolicy.Ttl)*PREFETCH_FACTOR+PREFETCH_INTERVAL {
				// Refresh the cached policy
				refreshedResult, refreshedRpt, refreshedTtl := queryDomain(&cachedPolicy.Domain)
				if refreshedResult != "" && refreshedResult != "TEMP" {
					counter.Add(1)
					dbTtl := time.Duration(ttl+PREFETCH_MARGIN-rand.Uint32N(60)) * time.Second
					cacheClient.Set(bgCtx, key, &cache.CacheStruct{Domain: cachedPolicy.Domain, Result: refreshedResult, Report: refreshedRpt, Ttl: refreshedTtl}, dbTtl)
				}
			}
		}(key)
	}
	wg.Wait()
	count := counter.Load()
	if count > 0 {
		log.Debugf("Prefetched %d of %d policies", count, polCnt)
	}
}

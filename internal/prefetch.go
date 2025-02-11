/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	PREFETCH_INTERVAL float64 = 20
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
	keys, err := redisClient.Keys(bgCtx, CACHE_KEY_PREFIX+"*").Result()
	if err != nil {
		log.Errorf("Error fetching keys from Redis: %v", err)
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
		if key == CACHE_KEY_PREFIX+"version" {
			continue
		}
		semaphore <- struct{}{}
		wg.Add(1)
		go func(key string) {
			defer func() {
				wg.Done()
				<-semaphore
			}()
			cachedPolicy, ttl, err := cacheJsonGet(redisClient, &key)
			if err != nil || cachedPolicy.Result == "" {
				return
			}
			// Check if the original TTL is greater than the margin and within the prefetching range
			if cachedPolicy.Ttl >= PREFETCH_MARGIN && float64(ttl-PREFETCH_MARGIN) < float64(cachedPolicy.Ttl)*PREFETCH_FACTOR+PREFETCH_INTERVAL {
				// Refresh the cached policy
				refreshedResult, refreshedRpt, refreshedTtl := queryDomain(&cachedPolicy.Domain)
				if refreshedResult != "" && refreshedResult != "TEMP" {
					counter.Add(1)
					cacheJsonSet(redisClient, &key, &CacheStruct{Domain: cachedPolicy.Domain, Result: refreshedResult, Report: refreshedRpt, Ttl: refreshedTtl})
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

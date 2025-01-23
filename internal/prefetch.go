/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package main

import (
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"runtime"
	"time"
)

const (
	PREFETCH_INTERVAL = 30
	PREFETCH_MARGIN   = 300 // seconds

	PREFETCH_FACTOR = float64(PREFETCH_INTERVAL+1) / float64(PREFETCH_MARGIN)
)

func startPrefetching() {
	ticker := time.NewTicker(PREFETCH_INTERVAL * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			prefetchCachedPolicies()
		}
	}
}

func prefetchCachedPolicies() {
	keys, err := redisClient.Keys(bgCtx, CACHE_KEY_PREFIX+"*").Result()
	if err != nil {
		log.Errorf("Error fetching keys from Redis: %v", err)
		return
	}

	semaphore := make(chan struct{}, runtime.NumCPU()*2)
	for _, key := range keys {
		if key == CACHE_KEY_PREFIX+"version" {
			continue
		}
		runtime.Gosched()
		semaphore <- struct{}{}
		go func(key string) {
			defer func() { <-semaphore }()
			cachedPolicy, ttl, err := cacheJsonGet(redisClient, key)
			if err != nil || cachedPolicy.Result == "" {
				return
			}
			// Check if the original TTL is greater than the margin and within the prefetching range
			if cachedPolicy.Ttl >= PREFETCH_MARGIN && float64(ttl-PREFETCH_MARGIN) < float64(cachedPolicy.Ttl)*PREFETCH_FACTOR+float64(PREFETCH_INTERVAL) {
				// Refresh the cached policy
				refreshedResult, refreshedRpt, refreshedTtl := queryDomain(cachedPolicy.Domain)
				if refreshedResult != "" && refreshedResult != "TEMP" {
					log.Debugf("Prefetched policy for %s: %s (cached for %ds)", cachedPolicy.Domain, refreshedResult, refreshedTtl)
					cacheJsonSet(redisClient, key, CacheStruct{Domain: cachedPolicy.Domain, Result: refreshedResult, Report: refreshedRpt, Ttl: refreshedTtl})
				}
			}
		}(key)
	}
}

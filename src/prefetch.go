package main

import (
	"fmt"
	"time"
)

const (
	PREFETCH_INTERVAL = 45 * time.Second
	PREFETCH_MARGIN   = 300 // seconds
)

func startPrefetching() {
	ticker := time.NewTicker(PREFETCH_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			prefetchCachedPolicies()
		}
	}
}

func prefetchCachedPolicies() {
	keys, err := redisClient.Keys(ctx, CACHE_KEY_PREFIX+"*").Result()
	if err != nil {
		fmt.Println("Error fetching keys from Redis:", err)
		return
	}

	semaphore := make(chan struct{}, 10)
	for _, key := range keys {
		if key == CACHE_KEY_PREFIX+"version" {
			continue
		}
		semaphore <- struct{}{}
		go func(key string) {
			defer func() { <-semaphore }()
			cachedPolicy, ttl, err := cacheJsonGet(redisClient, key)
			if err != nil || cachedPolicy.Result == "" {
				return
			}
			// Check if the original TTL is greater than the margin and within the prefetching range
			if cachedPolicy.Ttl >= PREFETCH_MARGIN && ttl < uint32(float64(cachedPolicy.Ttl)*0.05+PREFETCH_INTERVAL.Seconds()) {
				// Refresh the cached policy
				refreshedResult, refreshedRpt, refreshedTtl := queryDomain(cachedPolicy.Domain, false)
				if refreshedResult != "" && refreshedResult != "TEMP" {
					fmt.Printf("Prefetched policy for %s: %s (cached for %ds)\n", cachedPolicy.Domain, refreshedResult, refreshedTtl)
					cacheJsonSet(redisClient, key, CacheStruct{Domain: cachedPolicy.Domain, Result: refreshedResult, Report: refreshedRpt, Ttl: refreshedTtl})
				}
			}
		}(key)
	}
}

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

	for _, key := range keys {
		go func(key string) {
			// Get the cached policy
			cachedPolicy, ttl, err := cacheJsonGet(redisClient, key)
			if err != nil || cachedPolicy.Result == "" {
				return
			}
			// Check if the original TTL is greater than the margin and within the prefetching range (15% remaining)
			if cachedPolicy.Ttl >= PREFETCH_MARGIN && ttl < uint32(float64(cachedPolicy.Ttl)*0.15) {
				// Refresh the cached policy
				refreshedResult, refreshedTtl := queryDomain(cachedPolicy.Domain)
				if refreshedResult != "" {
					cacheJsonSet(redisClient, key, CacheStruct{Domain: cachedPolicy.Domain, Result: refreshedResult, Ttl: refreshedTtl})
				}
			}
		}(key)
	}
}

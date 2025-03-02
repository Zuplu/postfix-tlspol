/*
 * MIT License
 * Copyright (c) 2025 Vincent Breitmoser
 */

package cache

import (
	"context"
	"time"
)

type memoryEntry struct {
	expiresAt time.Time
	cs        *CacheStruct
}

type MemoryCache struct {
	cache map[string]memoryEntry
}

func NewMemoryCache() *MemoryCache {
	cache := make(map[string]memoryEntry)
	return &MemoryCache{cache}
}

func (c MemoryCache) Get(ctx context.Context, cacheKey string) (*CacheStruct, uint32, error) {
	data, ok := c.cache[cacheKey]
	if !ok {
		return nil, 0, nil
	}

	ttl := data.expiresAt.Sub(time.Now())
	if ttl < 0 {
		return nil, 0, nil
	}

	return data.cs, uint32(ttl.Seconds()), nil
}

func (c *MemoryCache) Set(ctx context.Context, cacheKey string, data *CacheStruct, ttl time.Duration) error {
	c.cache[cacheKey] = memoryEntry{cs: data, expiresAt: time.Now().Add(ttl)}
	return nil
}

func (c *MemoryCache) Keys(ctx context.Context) ([]string, error) {
	keys := make([]string, len(c.cache))

	i := 0
	for k := range c.cache {
		keys[i] = k
		i++
	}

	return keys, nil
}

func (c *MemoryCache) PurgeDatabase(ctx context.Context) error {
	clear(c.cache)
	return nil
}

func (c *MemoryCache) UpdateDatabase(ctx context.Context) error {
	// nothing to do here
	return nil
}

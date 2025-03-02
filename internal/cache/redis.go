/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
)

type RedisCache struct {
	dbAdapter valkeycompat.Cmdable
}

func NewRedisCache(address, password string, db int) *RedisCache {
	// Setup redis client for cache
	valkeyClient, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{address},
		Password:    password,
		SelectDB:    db,
	})
	if err != nil {
		log.Errorf("Could not initialize Valkey (Redis) client: %v", err)
		return nil
	}
	dbAdapter := valkeycompat.NewAdapter(valkeyClient)
	return &RedisCache{dbAdapter}
}

func (c RedisCache) Get(ctx context.Context, cacheKey string) (*CacheStruct, uint32, error) {
	var data *CacheStruct

	jsonData, err := c.dbAdapter.Cache(CACHE_MIN_TTL*time.Second).Get(ctx, VALKEY_CACHE_KEY_PREFIX+cacheKey).Result()
	if err != nil {
		return nil, 0, err
	}

	ttl, err := c.dbAdapter.Cache(CACHE_MIN_TTL*time.Second).TTL(ctx, VALKEY_CACHE_KEY_PREFIX+cacheKey).Result()
	if err != nil {
		log.Warnf("Error getting TTL: %v", err)
		return nil, 0, err
	}

	return data, uint32(ttl.Seconds()), json.Unmarshal([]byte(jsonData), data)
}

func (c *RedisCache) Set(ctx context.Context, cacheKey string, data *CacheStruct, ttl time.Duration) error {
	jsonData, err := json.Marshal(*data)
	if err != nil {
		return fmt.Errorf("Error marshaling JSON: %v", err)
	}

	return c.dbAdapter.Set(ctx, VALKEY_CACHE_KEY_PREFIX+cacheKey, jsonData, ttl).Err()
}

func (c *RedisCache) Keys(ctx context.Context) ([]string, error) {
	keys, err := c.dbAdapter.Keys(ctx, VALKEY_CACHE_KEY_PREFIX+"*").Result()
	if err != nil {
		return nil, err
	}

	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if k == VALKEY_CACHE_KEY_PREFIX+"version" {
			continue
		}

		result = append(result, strings.TrimPrefix(k, VALKEY_CACHE_KEY_PREFIX))
	}
	return result, nil
}

func (c *RedisCache) PurgeDatabase(ctx context.Context) error {
	keys, err := c.dbAdapter.Keys(ctx, VALKEY_CACHE_KEY_PREFIX+"*").Result()
	if err != nil {
		return fmt.Errorf("Error fetching keys: %v", err)
	}
	for _, key := range keys {
		c.dbAdapter.Del(ctx, key).Err()
	}
	return c.dbAdapter.Set(ctx, VALKEY_CACHE_KEY_PREFIX+"schema", VALKEY_DB_SCHEMA, 0).Err()
}

func (c *RedisCache) UpdateDatabase(ctx context.Context) error {
	currentSchema, err := c.dbAdapter.Get(ctx, VALKEY_CACHE_KEY_PREFIX+"schema").Result()
	if err != nil && err != valkeycompat.Nil {
		return fmt.Errorf("Error getting schema from Valkey (Redis): %v", err)
	}

	// Check if the schema matches, else clear the database
	if currentSchema != VALKEY_DB_SCHEMA {
		return c.PurgeDatabase(ctx)
	}

	return nil
}

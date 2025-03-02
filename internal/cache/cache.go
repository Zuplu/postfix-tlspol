/*
 * MIT License
 * Copyright (c) 2025 Vincent Breitmoser
 */

package cache

import (
	"context"
	"time"
)

const (
	CACHE_NOTFOUND_TTL = 600
	CACHE_MIN_TTL      = 180

	VALKEY_DB_SCHEMA        = "3"
	VALKEY_CACHE_KEY_PREFIX = "TLSPOL-"
)

type CacheStruct struct {
	Domain string `json:"d"`
	Result string `json:"r"`
	Report string `json:"p"`
	Ttl    uint32 `json:"t"`
}

type Cache interface {
	Get(ctx context.Context, cacheKey string) (*CacheStruct, uint32, error)
	Set(ctx context.Context, cacheKey string, data *CacheStruct, ttl time.Duration) error
	Keys(ctx context.Context) ([]string, error)
	UpdateDatabase(ctx context.Context) error
	PurgeDatabase(ctx context.Context) error
}

/*
 * MIT License
 * Copyright (c) 2025 Vincent Breitmoser
 */

package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	cache := NewMemoryCache()

	entry := &CacheStruct{
		Domain: "domain",
		Result: "result",
		Report: "report",
		Ttl:    30,
	}

	err := cache.Set(ctx, "cacheKey", entry, 20*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	time.Sleep(time.Millisecond)

	got, ttl, err := cache.Get(ctx, "cacheKey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ttl >= 20 {
		t.Errorf("expected ttl to be less than what we put (20), got %d", ttl)
	}
	if got != entry {
		t.Fatalf("expected entry to return same object %v, got %v", entry, got)
	}

	time.Sleep(20 * time.Millisecond)
	got, _, err = cache.Get(ctx, "cacheKey")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got != nil {
		t.Errorf("nuexpected return value: %v", got)
	}
}

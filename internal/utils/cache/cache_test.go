/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package cache

import (
	"encoding/gob"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type testValue struct {
	Expirable
	Payload string
}

func init() {
	gob.Register(&testValue{})
}

func newTestValue(expiresAt time.Time, payload string) *testValue {
	return &testValue{
		Expirable: Expirable{
			ExpiresAt: expiresAt,
		},
		Payload: payload,
	}
}

func TestExpirableAge(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 2, 16, 0, 0, 0, time.UTC)

	t.Run("past expiration returns positive age", func(t *testing.T) {
		t.Parallel()

		e := &Expirable{
			ExpiresAt: now.Add(-10 * time.Second),
		}

		age := e.Age(now)
		if age != 10 {
			t.Fatalf("expected age=10, got %d", age)
		}
	})

	t.Run("future expiration clamps to zero", func(t *testing.T) {
		t.Parallel()

		e := &Expirable{
			ExpiresAt: now.Add(10 * time.Second),
		}

		age := e.Age(now)
		if age != 0 {
			t.Fatalf("expected age=0, got %d", age)
		}
	})

	t.Run("fractional seconds are truncated", func(t *testing.T) {
		t.Parallel()

		e := &Expirable{
			ExpiresAt: now.Add(-1500 * time.Millisecond),
		}

		age := e.Age(now)
		if age != 1 {
			t.Fatalf("expected age=1, got %d", age)
		}
	})
}

func TestExpirableRemainingTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 2, 16, 0, 0, 0, time.UTC)

	t.Run("future expiration returns ttl", func(t *testing.T) {
		t.Parallel()

		e := &Expirable{
			ExpiresAt: now.Add(15 * time.Second),
		}

		ttl := e.RemainingTTL(now)
		if ttl != 15 {
			t.Fatalf("expected ttl=15, got %d", ttl)
		}
	})

	t.Run("past expiration clamps to zero", func(t *testing.T) {
		t.Parallel()

		e := &Expirable{
			ExpiresAt: now.Add(-2 * time.Second),
		}

		ttl := e.RemainingTTL(now)
		if ttl != 0 {
			t.Fatalf("expected ttl=0, got %d", ttl)
		}
	})

	t.Run("fractional seconds are truncated", func(t *testing.T) {
		t.Parallel()

		e := &Expirable{
			ExpiresAt: now.Add(1900 * time.Millisecond),
		}

		ttl := e.RemainingTTL(now)
		if ttl != 1 {
			t.Fatalf("expected ttl=1, got %d", ttl)
		}
	})
}

func TestCacheSetGetRemoveItemsPurge(t *testing.T) {
	t.Parallel()

	tmpFile := filepath.Join(t.TempDir(), "cache.gz")
	c := New[*testValue](tmpFile, time.Hour)
	t.Cleanup(c.Close)

	now := time.Now().UTC()
	v1 := newTestValue(now.Add(60*time.Second), "one")
	v2 := newTestValue(now.Add(120*time.Second), "two")

	c.Set("k1", v1)
	c.Set("k2", v2)

	got1, ok := c.Get("k1")
	if !ok {
		t.Fatalf("expected key k1 to exist")
	}
	if got1.Payload != "one" {
		t.Fatalf("expected payload one, got %q", got1.Payload)
	}

	entries := c.Items(false)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	c.Remove(false, "k1")
	if _, ok := c.Get("k1"); ok {
		t.Fatalf("expected key k1 to be removed")
	}

	c.Purge()
	entries = c.Items(false)
	if len(entries) != 0 {
		t.Fatalf("expected cache to be empty after purge, got %d entries", len(entries))
	}
}

func TestCacheSaveAndLoadRoundTrip(t *testing.T) {
	t.Parallel()

	tmpFile := filepath.Join(t.TempDir(), "cache.gz")
	now := time.Now().UTC()

	c1 := New[*testValue](tmpFile, time.Hour)
	c1.Set("alpha", newTestValue(now.Add(30*time.Second), "A"))
	c1.Set("beta", newTestValue(now.Add(45*time.Second), "B"))
	if err := c1.Save(false); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	c1.Close()

	c2 := New[*testValue](tmpFile, time.Hour)
	t.Cleanup(c2.Close)

	gotA, ok := c2.Get("alpha")
	if !ok {
		t.Fatalf("expected key alpha after load")
	}
	if gotA.Payload != "A" {
		t.Fatalf("expected payload A, got %q", gotA.Payload)
	}

	gotB, ok := c2.Get("beta")
	if !ok {
		t.Fatalf("expected key beta after load")
	}
	if gotB.Payload != "B" {
		t.Fatalf("expected payload B, got %q", gotB.Payload)
	}
}

func TestCacheSaveSkipsWhenNotDirty(t *testing.T) {
	t.Parallel()

	tmpFile := filepath.Join(t.TempDir(), "cache.gz")
	c := New[*testValue](tmpFile, time.Hour)
	t.Cleanup(c.Close)

	// Should not fail and should do nothing when not dirty.
	if err := c.Save(false); err != nil {
		t.Fatalf("expected no error on save when not dirty, got %v", err)
	}
}

func TestCacheConcurrentSetGet(t *testing.T) {
	t.Parallel()

	tmpFile := filepath.Join(t.TempDir(), "cache.gz")
	c := New[*testValue](tmpFile, time.Hour)
	t.Cleanup(c.Close)

	const workers = 16
	const perWorker = 64

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				key := time.Now().Add(time.Duration(w*perWorker+i) * time.Nanosecond).Format(time.RFC3339Nano)
				val := newTestValue(time.Now().Add(1*time.Minute), key)
				c.Set(key, val)
				if got, ok := c.Get(key); !ok || got == nil || got.Payload != key {
					t.Errorf("unexpected get result for key %q", key)
				}
			}
		}()
	}

	wg.Wait()

	items := c.Items(false)
	if len(items) == 0 {
		t.Fatalf("expected non-empty cache after concurrent writes")
	}
}

func TestCacheCloseIsSafeAfterUse(t *testing.T) {
	t.Parallel()

	tmpFile := filepath.Join(t.TempDir(), "cache.gz")
	c := New[*testValue](tmpFile, 10*time.Millisecond)

	c.Set("x", newTestValue(time.Now().Add(5*time.Second), "X"))
	c.Set("y", newTestValue(time.Now().Add(5*time.Second), "Y"))

	// Allow at least one periodic tick to happen.
	time.Sleep(30 * time.Millisecond)

	// Must not block or panic.
	c.Close()

	// Ensure persisted content can still be read.
	c2 := New[*testValue](tmpFile, time.Hour)
	defer c2.Close()

	if _, ok := c2.Get("x"); !ok {
		t.Fatalf("expected key x to be persisted")
	}
	if _, ok := c2.Get("y"); !ok {
		t.Fatalf("expected key y to be persisted")
	}
}

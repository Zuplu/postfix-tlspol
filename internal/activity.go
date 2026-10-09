/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

const PREFETCH_MAX_IDLE = 14 * 24 * time.Hour

// Timestamps are independent of policy replacement and query-counter resets.
// Only domains still present in the cache may acquire an activity record.
var pendingQueryAccesses sync.Map

func cachedLastAccess(domain string, c *CacheStruct) time.Time {
	if c == nil {
		return time.Time{}
	}
	last := c.LastAccess
	if value, ok := pendingQueryAccesses.Load(domain); ok {
		if pending := time.Unix(0, value.(*atomic.Int64).Load()); pending.After(last) {
			last = pending
		}
	}
	return last
}

func prefetchActive(c *CacheStruct, now time.Time) bool {
	return c != nil && !c.LastAccess.IsZero() && now.Sub(c.LastAccess) < PREFETCH_MAX_IDLE
}

func prefetchEntry(domain string, c *CacheStruct) *CacheStruct {
	if c == nil {
		return nil
	}
	last := cachedLastAccess(domain, c)
	if !last.After(c.LastAccess) {
		return c
	}
	updated := cloneCacheStruct(c)
	updated.LastAccess = last
	return updated
}

// Return whether a real query reactivated an idle cache entry. New records
// are created under the cache lock so eviction cannot leave orphan entries.
func recordCachedQuery(domain string, c *CacheStruct, now time.Time) bool {
	if c == nil {
		return false
	}
	last := cachedLastAccess(domain, c)
	value, found := pendingQueryAccesses.Load(domain)
	if !found {
		polCache.Update(false, domain, func(current *CacheStruct, exists bool) (*CacheStruct, bool) {
			if exists && current != nil {
				value, _ = pendingQueryAccesses.LoadOrStore(domain, &atomic.Int64{})
			}
			return nil, false
		})
		if value == nil {
			return false
		}
	}
	stamp := value.(*atomic.Int64)
	for previous := stamp.Load(); previous < now.UnixNano(); previous = stamp.Load() {
		if stamp.CompareAndSwap(previous, now.UnixNano()) {
			break
		}
	}
	return last.IsZero() || now.Sub(last) >= PREFETCH_MAX_IDLE
}

func flushQueryAccesses(c *cache.Cache[*CacheStruct], haveLock bool) {
	pendingQueryAccesses.Range(func(key, value any) bool {
		domain := key.(string)
		stamp := value.(*atomic.Int64)
		c.Update(haveLock, domain, func(current *CacheStruct, exists bool) (*CacheStruct, bool) {
			if !exists || current == nil {
				pendingQueryAccesses.CompareAndDelete(domain, stamp)
				return nil, false
			}
			last := time.Unix(0, stamp.Load())
			if !last.After(current.LastAccess) {
				return nil, false
			}
			updated := cloneCacheStruct(current)
			updated.LastAccess = last
			return updated, true
		})
		return true
	})
}

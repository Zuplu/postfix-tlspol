/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"container/heap"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

const (
	PREFETCH_INTERVAL uint32 = 30
)

var semaphore chan struct{}
var activePrefetchScheduler atomic.Pointer[prefetchScheduler]

type prefetchItem struct {
	key   string
	due   time.Time
	index int
}

type prefetchQueue []*prefetchItem

func (q prefetchQueue) Len() int {
	return len(q)
}

func (q prefetchQueue) Less(i int, j int) bool {
	return q[i].due.Before(q[j].due)
}

func (q prefetchQueue) Swap(i int, j int) {
	q[i], q[j] = q[j], q[i]
	q[i].index = i
	q[j].index = j
}

func (q *prefetchQueue) Push(x any) {
	item := x.(*prefetchItem)
	item.index = len(*q)
	*q = append(*q, item)
}

func (q *prefetchQueue) Pop() any {
	old := *q
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*q = old[:n-1]
	return item
}

type prefetchScheduler struct {
	mu    sync.Mutex
	items map[string]*prefetchItem
	queue prefetchQueue
	wake  chan struct{}
}

func newPrefetchScheduler() *prefetchScheduler {
	s := &prefetchScheduler{
		items: make(map[string]*prefetchItem),
		wake:  make(chan struct{}, 1),
	}
	heap.Init(&s.queue)
	return s
}

func (s *prefetchScheduler) schedule(key string, due time.Time) {
	s.mu.Lock()
	if item, ok := s.items[key]; ok {
		item.due = due
		heap.Fix(&s.queue, item.index)
	} else {
		item = &prefetchItem{key: key, due: due}
		s.items[key] = item
		heap.Push(&s.queue, item)
	}
	s.mu.Unlock()
	s.notify()
}

func (s *prefetchScheduler) remove(key string) {
	s.mu.Lock()
	if item, ok := s.items[key]; ok {
		heap.Remove(&s.queue, item.index)
		delete(s.items, key)
	}
	s.mu.Unlock()
}

func (s *prefetchScheduler) clear() {
	s.mu.Lock()
	s.items = make(map[string]*prefetchItem)
	s.queue = nil
	heap.Init(&s.queue)
	s.mu.Unlock()
	s.notify()
}

func (s *prefetchScheduler) nextDue() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return time.Time{}, false
	}
	return s.queue[0].due, true
}

func (s *prefetchScheduler) popDue(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var keys []string
	for len(s.queue) != 0 && !s.queue[0].due.After(now) {
		item := heap.Pop(&s.queue).(*prefetchItem)
		delete(s.items, item.key)
		keys = append(keys, item.key)
	}
	return keys
}

func (s *prefetchScheduler) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func startPrefetching() {
	if !config.Server.Prefetch {
		return
	}
	slog.Info("Prefetching enabled")
	semaphore = make(chan struct{}, runtime.NumCPU()*4+2)
	scheduler := newPrefetchScheduler()
	activePrefetchScheduler.Store(scheduler)
	now := time.Now()
	for _, entry := range polCache.Items(false) {
		scheduleCachedPolicyPrefetch(entry.Key, entry.Value, now)
	}
	for {
		due, ok := scheduler.nextDue()
		if !ok {
			<-scheduler.wake
			continue
		}
		wait := time.Until(due)
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-scheduler.wake:
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		}
		prefetchDuePolicies(scheduler)
	}
}

func scheduleCachedPolicyPrefetch(key string, c *CacheStruct, now time.Time) {
	scheduler := activePrefetchScheduler.Load()
	if scheduler == nil {
		return
	}
	due, ok := nextPrefetchTime(c, now)
	if !ok {
		scheduler.remove(key)
		return
	}
	scheduler.schedule(key, due)
}

func unscheduleCachedPolicyPrefetch(key string) {
	scheduler := activePrefetchScheduler.Load()
	if scheduler != nil {
		scheduler.remove(key)
	}
}

func clearPrefetchSchedule() {
	scheduler := activePrefetchScheduler.Load()
	if scheduler != nil {
		scheduler.clear()
	}
}

func nextPrefetchTime(c *CacheStruct, now time.Time) (time.Time, bool) {
	if c == nil || c.Age(now) >= CACHE_MAX_AGE {
		return time.Time{}, false
	}
	policy, _, remainingTTL, usable := selectCachedPolicy(c, now)
	if usable && policy == "" {
		return now.Add(time.Duration(remainingTTL) * time.Second), true
	}
	if usable && remainingTTL > PREFETCH_INTERVAL {
		return now.Add(time.Duration(remainingTTL-PREFETCH_INTERVAL) * time.Second), true
	}
	return now, true
}

func prefetchDuePolicies(scheduler *prefetchScheduler) {
	var wg sync.WaitGroup
	var counter atomic.Uint32
	now := time.Now()
	keys := scheduler.popDue(now)
	itemsCount := len(keys)
	for _, key := range keys {
		value, found := polCache.Get(key)
		if !found {
			continue
		}
		entry := cache.Entry[*CacheStruct]{Key: key, Value: value}
		policy, _, remainingTTL, usable := selectCachedPolicy(entry.Value, now)
		if usable && policy == "" {
			itemsCount--
			if remainingTTL == 0 {
				polCache.Remove(false, entry.Key)
				unscheduleCachedPolicyPrefetch(entry.Key)
			} else {
				scheduleCachedPolicyPrefetch(entry.Key, entry.Value, now)
			}
			continue
		}
		if entry.Value.Age(now) >= CACHE_MAX_AGE {
			itemsCount--
			polCache.Remove(false, entry.Key)
			unscheduleCachedPolicyPrefetch(entry.Key)
			continue
		}
		if usable && remainingTTL > PREFETCH_INTERVAL {
			scheduleCachedPolicyPrefetch(entry.Key, entry.Value, now)
			continue
		}
		semaphore <- struct{}{}
		wg.Add(1)
		go func(c cache.Entry[*CacheStruct]) {
			defer func() {
				wg.Done()
				<-semaphore
			}()
			// Refresh the cached policy
			refreshed := refreshDomain(c.Key, c.Value)
			if refreshed.Dane.HasData() || refreshed.MtaSts.HasData() {
				counter.Add(1)
				refreshedAt := time.Now()
				merged := mergeCacheResult(c.Value, refreshed, refreshedAt)
				polCache.Set(c.Key, merged)
				scheduleCachedPolicyPrefetch(c.Key, merged, refreshedAt)
			} else {
				scheduler.schedule(c.Key, time.Now().Add(time.Duration(PREFETCH_INTERVAL)*time.Second))
			}
		}(entry)
	}
	wg.Wait()
	count := counter.Load()
	if count > 0 {
		slog.Debug("Prefetched policies", "count", count, "total", itemsCount)
	}
}

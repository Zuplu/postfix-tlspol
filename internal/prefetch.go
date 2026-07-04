/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"container/heap"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

const (
	PREFETCH_INTERVAL           uint32 = 30
	PREFETCH_RETRY_MAX_AGE             = 30 * time.Minute
	PREFETCH_RETRY_MAX_INTERVAL        = 5 * time.Minute
	PREFETCH_SLOT_INTERVAL             = 10 * time.Second
)

var semaphore chan struct{}
var activePrefetchScheduler atomic.Pointer[prefetchScheduler]

type prefetchItem struct {
	due   time.Time
	key   string
	index int
}

type prefetchFailure struct {
	firstFailed time.Time
	attempts    uint32
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
	items    map[string]*prefetchItem
	failures map[string]prefetchFailure
	wake     chan struct{}
	queue    prefetchQueue
	mu       sync.Mutex
}

func newPrefetchScheduler() *prefetchScheduler {
	s := &prefetchScheduler{
		items:    make(map[string]*prefetchItem),
		failures: make(map[string]prefetchFailure),
		wake:     make(chan struct{}, 1),
	}
	heap.Init(&s.queue)
	return s
}

func (s *prefetchScheduler) schedule(key string, due time.Time) {
	s.mu.Lock()
	s.scheduleLocked(key, due)
	s.mu.Unlock()
	s.notify()
}

func (s *prefetchScheduler) scheduleLocked(key string, due time.Time) {
	if item, ok := s.items[key]; ok {
		item.due = due
		heap.Fix(&s.queue, item.index)
	} else {
		item = &prefetchItem{key: key, due: due}
		s.items[key] = item
		heap.Push(&s.queue, item)
	}
}

func (s *prefetchScheduler) remove(key string) {
	s.mu.Lock()
	if item, ok := s.items[key]; ok {
		heap.Remove(&s.queue, item.index)
		delete(s.items, key)
	}
	delete(s.failures, key)
	s.mu.Unlock()
}

func (s *prefetchScheduler) clear() {
	s.mu.Lock()
	s.items = make(map[string]*prefetchItem)
	s.failures = make(map[string]prefetchFailure)
	s.queue = nil
	heap.Init(&s.queue)
	s.mu.Unlock()
	s.notify()
}

func (s *prefetchScheduler) resetFailures(key string) {
	s.mu.Lock()
	delete(s.failures, key)
	s.mu.Unlock()
}

func (s *prefetchScheduler) scheduleRetry(key string, now time.Time) (time.Time, uint32, time.Duration, bool) {
	return s.scheduleRetryUntil(key, now, time.Time{})
}

func (s *prefetchScheduler) scheduleRetryUntil(key string, now time.Time, graceDeadline time.Time) (time.Time, uint32, time.Duration, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	failure, ok := s.failures[key]
	if !ok {
		failure = prefetchFailure{firstFailed: now}
	}
	retryDeadline := failure.firstFailed.Add(PREFETCH_RETRY_MAX_AGE)
	if graceDeadline.After(retryDeadline) {
		retryDeadline = graceDeadline
	}
	if !now.Before(retryDeadline) {
		if item, ok := s.items[key]; ok {
			heap.Remove(&s.queue, item.index)
			delete(s.items, key)
		}
		delete(s.failures, key)
		return time.Time{}, failure.attempts, 0, false
	}

	failure.attempts++
	delay := prefetchRetryDelay(failure.attempts)
	if due := now.Add(delay); due.After(retryDeadline) {
		delay = retryDeadline.Sub(now)
	}
	due := slotFuturePrefetchTime(now.Add(delay))
	if due.After(retryDeadline) {
		due = retryDeadline
	}
	delay = due.Sub(now)
	s.failures[key] = failure
	s.scheduleLocked(key, due)
	return due, failure.attempts, delay, true
}

func prefetchRetryDelay(attempts uint32) time.Duration {
	delay := time.Duration(PREFETCH_INTERVAL) * time.Second
	for i := uint32(1); i < attempts && delay < PREFETCH_RETRY_MAX_INTERVAL; i++ {
		delay *= 2
		if delay > PREFETCH_RETRY_MAX_INTERVAL {
			return PREFETCH_RETRY_MAX_INTERVAL
		}
	}
	return delay
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
		if shouldRetryCachedPolicyPrefetch(c, now) {
			scheduler.schedule(key, nextImmediatePrefetchTime(now))
			return
		}
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

func resetCachedPolicyPrefetchFailures(key string) {
	scheduler := activePrefetchScheduler.Load()
	if scheduler != nil {
		scheduler.resetFailures(key)
	}
}

func nextPrefetchTime(c *CacheStruct, now time.Time) (time.Time, bool) {
	if c == nil || c.Age(now) >= CACHE_MAX_AGE {
		return time.Time{}, false
	}
	policy, _, remainingTTL, usable := selectCachedPolicy(c, now)
	if !usable {
		return time.Time{}, false
	}
	if policy == "" && !hadPolicyWithin(c, now, POLICY_BRANCH_RECHECK) {
		return time.Time{}, false
	}
	if policy == "" {
		return slotFuturePrefetchTime(now.Add(time.Duration(remainingTTL) * time.Second)), true
	}
	return nextPolicyPrefetchTime(now, remainingTTL), true
}

func nextPolicyPrefetchTime(now time.Time, remainingTTL uint32) time.Time {
	expiry := now.Add(time.Duration(remainingTTL) * time.Second)
	window := time.Duration(remainingTTL) * time.Second
	if maxWindow := time.Duration(PREFETCH_INTERVAL) * time.Second; window > maxWindow {
		window = maxWindow
	}
	slots := int(window / PREFETCH_SLOT_INTERVAL)
	if slots < 1 {
		return now
	}
	lead := time.Duration(rand.IntN(slots)+1) * PREFETCH_SLOT_INTERVAL
	due := ceilToPrefetchSlot(expiry.Add(-lead))
	earliest := now
	if remainingTTL > PREFETCH_INTERVAL {
		earliest = now.Add(time.Duration(remainingTTL-PREFETCH_INTERVAL) * time.Second)
	}
	if due.Before(earliest) {
		due = ceilToPrefetchSlot(earliest)
	}
	if due.After(expiry) {
		due = floorToPrefetchSlot(expiry)
	}
	if due.Before(now) {
		return now
	}
	return due
}

func ceilToPrefetchSlot(t time.Time) time.Time {
	truncated := t.Truncate(PREFETCH_SLOT_INTERVAL)
	if truncated.Equal(t) {
		return t
	}
	return truncated.Add(PREFETCH_SLOT_INTERVAL)
}

func floorToPrefetchSlot(t time.Time) time.Time {
	return t.Truncate(PREFETCH_SLOT_INTERVAL)
}

func slotFuturePrefetchTime(t time.Time) time.Time {
	return ceilToPrefetchSlot(t)
}

func nextImmediatePrefetchTime(now time.Time) time.Time {
	return ceilToPrefetchSlot(now)
}

func hadPolicyWithin(c *CacheStruct, now time.Time, window time.Duration) bool {
	if c == nil {
		return false
	}
	return branchHadPolicyWithin(c.Dane, now, window) || branchHadPolicyWithin(c.MtaSts, now, window)
}

func branchHadPolicyWithin(branch PolicyBranch, now time.Time, window time.Duration) bool {
	if branch.Policy == "" {
		return false
	}
	if branch.RemainingTTL(now) != 0 {
		return true
	}
	return now.Before(branch.ExpiresAt.Add(window))
}

func shouldRetryCachedPolicyPrefetch(c *CacheStruct, now time.Time) bool {
	if c == nil || c.Age(now) >= CACHE_MAX_AGE || c.RemainingTTL(now) == 0 {
		return false
	}
	policy, _, _, usable := selectCachedPolicy(c, now)
	return !usable || policy != "" || hadPolicyWithin(c, now, POLICY_BRANCH_RECHECK)
}

func nextPrefetchTimeAfterMiss(c *CacheStruct, now time.Time) (time.Time, bool) {
	policy, _, remainingTTL, usable := selectCachedPolicy(c, now)
	if !usable || remainingTTL == 0 {
		return time.Time{}, false
	}
	if policy == "" && !hadPolicyWithin(c, now, POLICY_BRANCH_RECHECK) {
		return time.Time{}, false
	}
	return slotFuturePrefetchTime(now.Add(time.Duration(remainingTTL) * time.Second)), true
}

func scheduleFailedPolicyPrefetch(scheduler *prefetchScheduler, key string, c *CacheStruct, result domainResult, now time.Time) {
	if due, attempts, delay, ok := scheduler.scheduleRetryUntil(key, now, failedPolicyGraceDeadline(c, result)); ok {
		slog.Debug("Scheduled policy prefetch retry", "domain", key, "attempts", attempts, "delay", delay, "due", due)
		return
	}
	if updated, ok := cacheAfterFailedBranchDiscard(c, result, now); ok {
		polCache.Set(key, updated)
		if due, ok := nextPrefetchTime(updated, now); ok {
			scheduler.schedule(key, due)
		}
		if err := polCache.Save(false); err != nil {
			slog.Error("Could not save cache after failed branch discard", "domain", key, "error", err)
		}
		slog.Info("Cleared failed cached policy branch after repeated prefetch failures", "domain", key, "retry_window", PREFETCH_RETRY_MAX_AGE)
		return
	}
	discardCachedPolicyState(false, key, c)
	if err := polCache.Save(false); err != nil {
		slog.Error("Could not save cache after failed prefetch discard", "domain", key, "error", err)
	}
	slog.Info("Removed cached policy after repeated prefetch failures", "domain", key, "retry_window", PREFETCH_RETRY_MAX_AGE)
}

func failedPolicyGraceDeadline(c *CacheStruct, result domainResult) time.Time {
	if c == nil {
		return time.Time{}
	}
	var deadline time.Time
	if result.DaneAttempted && !result.Dane.HasData() && c.Dane.Policy != "" {
		deadline = c.Dane.ExpiresAt.Add(POLICY_BRANCH_RECHECK)
	}
	if result.MtaStsAttempted && !result.MtaSts.HasData() && c.MtaSts.Policy != "" {
		mtaStsDeadline := c.MtaSts.ExpiresAt.Add(POLICY_BRANCH_RECHECK)
		if mtaStsDeadline.After(deadline) {
			deadline = mtaStsDeadline
		}
	}
	return deadline
}

func cacheAfterFailedBranchDiscard(c *CacheStruct, result domainResult, now time.Time) (*CacheStruct, bool) {
	if c == nil {
		return nil, false
	}
	cs := cloneCacheStruct(c)
	switch {
	case result.DaneAttempted && !result.Dane.HasData() && c.MtaSts.Policy != "" && c.MtaSts.RemainingTTL(now) != 0:
		cs.Dane = expireBranch(PolicyBranch{TTL: policyBranchRecheckTTL()}, now)
		cs.DaneLastAttempt = now
	case result.MtaStsAttempted && !result.MtaSts.HasData() && c.Dane.Policy != "" && c.Dane.RemainingTTL(now) != 0:
		cs.MtaSts = expireBranch(PolicyBranch{TTL: policyBranchRecheckTTL()}, now)
		cs.MtaStsLastAttempt = now
	default:
		return nil, false
	}
	policy, report, ttl, ok := selectCachedPolicy(cs, now)
	if !ok {
		return nil, false
	}
	cs.Policy = policy
	cs.Report = report
	cs.TTL = ttl
	cs.Expirable.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)
	return cs, true
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
		if !usable {
			if !shouldRetryCachedPolicyPrefetch(entry.Value, now) {
				itemsCount--
				discardCachedPolicyState(false, entry.Key, entry.Value)
				unscheduleCachedPolicyPrefetch(entry.Key)
				continue
			}
		} else if policy == "" {
			itemsCount--
			if remainingTTL == 0 {
				discardCachedPolicyState(false, entry.Key, entry.Value)
				unscheduleCachedPolicyPrefetch(entry.Key)
			} else {
				scheduleCachedPolicyPrefetch(entry.Key, entry.Value, now)
			}
			continue
		}
		if entry.Value.Age(now) >= CACHE_MAX_AGE {
			itemsCount--
			discardCachedPolicyState(false, entry.Key, entry.Value)
			unscheduleCachedPolicyPrefetch(entry.Key)
			continue
		}
		if remainingTTL > PREFETCH_INTERVAL {
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
			refreshed := prefetchDomain(c.Key, c.Value)
			refreshedAt := time.Now()
			hasRefreshedData := refreshed.Dane.HasData() || refreshed.MtaSts.HasData()
			hasFailedAttempt := (refreshed.DaneAttempted && !refreshed.Dane.HasData()) ||
				(refreshed.MtaStsAttempted && !refreshed.MtaSts.HasData())
			if hasRefreshedData || refreshed.DaneAttempted || refreshed.MtaStsAttempted {
				merged := mergeCacheResult(c.Value, refreshed, refreshedAt)
				polCache.Set(c.Key, merged)
				if _, _, _, ok := selectCachedPolicy(merged, refreshedAt); ok {
					if hasRefreshedData {
						counter.Add(1)
					}
					if hasFailedAttempt {
						scheduleFailedPolicyPrefetch(scheduler, c.Key, merged, refreshed, refreshedAt)
						return
					}
					scheduler.resetFailures(c.Key)
					scheduleCachedPolicyPrefetch(c.Key, merged, refreshedAt)
				} else {
					scheduleFailedPolicyPrefetch(scheduler, c.Key, c.Value, refreshed, refreshedAt)
				}
			} else if _, _, _, ok := selectCachedPolicy(c.Value, refreshedAt); ok {
				scheduler.resetFailures(c.Key)
				if due, ok := nextPrefetchTimeAfterMiss(c.Value, refreshedAt); ok {
					scheduler.schedule(c.Key, due)
				} else {
					scheduleCachedPolicyPrefetch(c.Key, c.Value, refreshedAt)
				}
			} else {
				scheduleFailedPolicyPrefetch(scheduler, c.Key, c.Value, refreshed, refreshedAt)
			}
		}(entry)
	}
	wg.Wait()
	count := counter.Load()
	if count > 0 {
		slog.Debug("Prefetched policies", "count", count, "total", itemsCount)
	}
}

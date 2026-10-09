/*
 * MIT License
 * Copyright (c) 2026 Zuplu
 */

package tlspol

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

func prefetchActivityFixture(t *testing.T) (*prefetchScheduler, string) {
	t.Helper()
	oldCache, oldSemaphore := polCache, semaphore
	oldScheduler := activePrefetchScheduler.Load()
	pendingQueryAccesses.Clear()
	path := filepath.Join(t.TempDir(), "cache.db")
	polCache = cache.NewWithSaveHook[*CacheStruct](path, time.Hour, flushQueryAccesses)
	scheduler := newPrefetchScheduler()
	activePrefetchScheduler.Store(scheduler)
	semaphore = make(chan struct{}, 1)
	t.Cleanup(func() {
		polCache.Close()
		polCache, semaphore = oldCache, oldSemaphore
		activePrefetchScheduler.Store(oldScheduler)
		pendingQueryAccesses.Clear()
	})
	return scheduler, path
}

func TestPrefetchMtaStsUsesOriginalMaxAge(t *testing.T) {
	oldDane, oldMta := checkDanePolicy, checkMtaStsPolicy
	t.Cleanup(func() { checkDanePolicy, checkMtaStsPolicy = oldDane, oldMta })
	checkDanePolicy = func(context.Context, string, bool) daneResult {
		t.Fatal("fresh DANE state should not be queried")
		return daneResult{}
	}
	for _, maxAge := range []uint32{0, 1, 179, 299, 300, 301, 3600} {
		t.Run(fmt.Sprint(maxAge), func(t *testing.T) {
			now := time.Now()
			calls := 0
			checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
				calls++
				return "secure match=mx.example.test", "policy_type=sts", maxAge
			}
			entry := &CacheStruct{
				LastAccess: now, DaneLastAttempt: now, MtaStsLastAttempt: now.Add(-time.Hour),
				Dane:   PolicyBranch{TTL: 86400, ExpiresAt: now.Add(24 * time.Hour)},
				MtaSts: PolicyBranch{Policy: "secure match=mx.example.test", TTL: maxAge, ExpiresAt: now.Add(time.Second)},
			}
			result := prefetchDomainOnceImpl("example.test", entry)
			wantCalls := 0
			if maxAge >= 300 {
				wantCalls = 1
			}
			if result.MtaStsAttempted != (maxAge >= 300) || calls != wantCalls {
				t.Fatalf("max_age=%d: attempted=%v calls=%d", maxAge, result.MtaStsAttempted, calls)
			}
			entry.MtaSts.ExpiresAt = now.Add(-time.Second)
			entry.MtaStsLastAttempt = entry.MtaSts.ExpiresAt.Add(-time.Duration(maxAge) * time.Second)
			calls = 0
			result = refreshDomainOnceImpl("example.test", entry)
			if !result.MtaStsAttempted || calls != 1 {
				t.Fatal("foreground request must still fetch an expired short-lived policy")
			}
		})
	}
}

func TestPrefetchRemembersShortMaxAgeWhenDiscoveryTTLChanges(t *testing.T) {
	now := time.Now()
	for _, maxAge := range []uint32{0, 1, 299} {
		previous := &CacheStruct{LastAccess: now, Dane: PolicyBranch{Policy: "dane-only", TTL: 86400, ExpiresAt: now.Add(24 * time.Hour)}}
		result := domainResult{MtaSts: PolicyBranch{Report: "policy_type=sts", TTL: maxAge}, MtaStsAttempted: true, MtaStsMaxAge: &maxAge}
		merged := mergeCacheResult(previous, result, now)
		if mtaStsPrefetchAllowed(merged) {
			t.Fatalf("max_age=%d became eligible after caching discovery state", maxAge)
		}
	}
}

func TestShortMtaStsDoesNotStopDaneRediscovery(t *testing.T) {
	scheduler, _ := prefetchActivityFixture(t)
	now := time.Now()
	maxAge := uint32(1)
	entry := &CacheStruct{
		LastAccess: now, DaneLastAttempt: now.Add(-25 * time.Hour), MtaStsMaxAge: &maxAge,
		Dane:   PolicyBranch{TTL: 86400, ExpiresAt: now.Add(-time.Second)},
		MtaSts: PolicyBranch{Policy: "secure match=mx.example.test", TTL: 1, ExpiresAt: now.Add(-time.Second)},
	}
	polCache.Set("example.test", entry)
	oldDane, oldMta := checkDanePolicy, checkMtaStsPolicy
	t.Cleanup(func() { checkDanePolicy, checkMtaStsPolicy = oldDane, oldMta })
	calls := 0
	checkDanePolicy = func(context.Context, string, bool) daneResult {
		calls++
		return daneResult{Policy: "dane-only", TTL: 600}
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		t.Fatal("short MTA-STS policy was prefetched during DANE rediscovery")
		return "", "", 0
	}
	scheduler.schedule("example.test", now.Add(-time.Second))
	prefetchDuePolicies(scheduler)
	current, _ := polCache.Get("example.test")
	if calls != 1 || current.Dane.Policy != "dane-only" || !current.LastAccess.Equal(now) {
		t.Fatalf("DANE refresh or activity tracking failed: calls=%d current=%+v", calls, current)
	}
}

func TestZeroAgeMtaStsWaitsForDaneInsteadOfRetryingSkippedWork(t *testing.T) {
	scheduler, _ := prefetchActivityFixture(t)
	now := time.Now()
	maxAge := uint32(0)
	entry := &CacheStruct{LastAccess: now, MtaStsMaxAge: &maxAge,
		Dane: PolicyBranch{TTL: 1800, ExpiresAt: now.Add(30 * time.Minute)}}
	polCache.Set("zero-age.test", entry)
	scheduler.scheduleCachedPolicy("zero-age.test", entry, now)
	due, found := scheduler.nextDue()
	if !found || due.Before(now.Add(time.Duration(1800-PREFETCH_INTERVAL)*time.Second)) {
		t.Fatalf("skipped MTA-STS work caused an early retry: %v %s", found, due)
	}
}

func TestIdlePrefetchStopsWithoutRemovingPolicyAndQueryResumesIt(t *testing.T) {
	scheduler, _ := prefetchActivityFixture(t)
	now := time.Now()
	key := "idle.example.test"
	entry := &CacheStruct{LastAccess: now.Add(-PREFETCH_MAX_IDLE), Dane: PolicyBranch{Policy: "dane-only", TTL: 3600, ExpiresAt: now.Add(time.Minute)}}
	polCache.Set(key, entry)
	scheduler.schedule(key, now.Add(-time.Second))
	old := prefetchDomainOnce
	prefetchDomainOnce = func(string, *CacheStruct) domainResult {
		t.Fatal("inactive domain reached network prefetch")
		return domainResult{}
	}
	t.Cleanup(func() { prefetchDomainOnce = old })
	prefetchDuePolicies(scheduler)
	if _, found := scheduler.nextDue(); found {
		t.Fatal("inactive domain stayed scheduled")
	}
	if current, found := polCache.Get(key); !found || current != entry {
		t.Fatal("stopping prefetch must preserve the cached policy")
	}
	if _, found := tryCachedPolicy(&recordingConn{}, key, false); !found {
		t.Fatal("the first returning query should still hit the cache")
	}
	if _, found := scheduler.nextDue(); !found {
		t.Fatal("reactivated domain was not scheduled")
	}
	// A worker that already observed the old idle timestamp must not erase
	// the schedule restored by the foreground query.
	scheduler.stopUnusedPrefetch(key, time.Now())
	if _, found := scheduler.nextDue(); !found {
		t.Fatal("a late idle cancellation erased the returning query's schedule")
	}
}

func TestPrefetchIdleBoundary(t *testing.T) {
	now := time.Now()
	for _, age := range []time.Duration{PREFETCH_MAX_IDLE - time.Nanosecond, PREFETCH_MAX_IDLE, PREFETCH_MAX_IDLE + time.Second} {
		entry := &CacheStruct{LastAccess: now.Add(-age)}
		if got := prefetchActive(entry, now); got != (age < PREFETCH_MAX_IDLE) {
			t.Fatalf("age %s: eligible=%v", age, got)
		}
	}
}

func TestLastAccessSurvivesBackgroundMergeAndSnapshot(t *testing.T) {
	_, path := prefetchActivityFixture(t)
	now := time.Now().UTC()
	key := "active.example.test"
	entry := &CacheStruct{LastAccess: now.Add(-time.Hour), Dane: PolicyBranch{Policy: "dane", TTL: 86400, ExpiresAt: now.Add(time.Hour)}}
	polCache.Set(key, entry)
	recordCachedQuery(key, entry, now)
	_, merged := storeMergedDomainResult(key, domainResult{Dane: PolicyBranch{Policy: "dane-only", TTL: 86400}, DaneAttempted: true}, now.Add(time.Minute), 0)
	if !merged.LastAccess.Equal(now) {
		t.Fatalf("background refresh changed query time: %s", merged.LastAccess)
	}
	queried := now.Add(2 * time.Minute)
	recordCachedQuery(key, merged, queried)
	if err := polCache.Save(false); err != nil {
		t.Fatal(err)
	}
	restored := cache.New[*CacheStruct](path, time.Hour)
	t.Cleanup(restored.Close)
	stored, found := restored.Get(key)
	if !found || !stored.LastAccess.Equal(queried) {
		t.Fatalf("snapshot lost pending query activity: %+v", stored)
	}
}

func TestStartupPurgesEntriesWithoutLastAccess(t *testing.T) {
	_, path := prefetchActivityFixture(t)
	now := time.Now()
	polCache.Set("legacy.example.test", &CacheStruct{Counter: 123, Dane: PolicyBranch{Policy: "dane", TTL: 86400, ExpiresAt: now.Add(time.Hour)}})
	if err := polCache.Save(false); err != nil {
		t.Fatal(err)
	}
	_ = tidyCache()
	if polCache.Len() != 0 {
		t.Fatal("cache with unknown last access was retained")
	}
	restored := cache.New[*CacheStruct](path, time.Hour)
	t.Cleanup(restored.Close)
	if restored.Len() != 0 {
		t.Fatal("legacy cache removal was not persisted")
	}
}

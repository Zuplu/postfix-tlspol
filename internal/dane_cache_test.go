package tlspol

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
)

func TestPartialDaneResultsDoNotCacheOrDelayRecovery(t *testing.T) {
	origDane, origSts := checkDanePolicy, checkMtaStsPolicy
	t.Cleanup(func() { checkDanePolicy, checkMtaStsPolicy = origDane, origSts })
	for _, policy := range []string{"", "dane"} {
		for _, sts := range []string{"", "secure match=mx.example.test"} {
			t.Run(policy+"/"+sts, func(t *testing.T) {
				calls := 0
				checkDanePolicy = func(context.Context, string, bool) daneResult {
					calls++
					return daneResult{Policy: policy, Partial: true}
				}
				checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
					return sts, "", 86400
				}
				now := time.Now()
				// A previous negative answer must not be renewed by the partial result.
				previous := &CacheStruct{
					Expirable:       &cache.Expirable{},
					Dane:            PolicyBranch{TTL: 300, ExpiresAt: now.Add(-time.Second)},
					DaneLastAttempt: now.Add(-25 * time.Hour),
				}
				result := queryDomainBranches("example.test", previous, now)
				want := policy
				if want == "" {
					want = sts
				}
				if result.Policy != want || result.TTL != 0 || !result.DanePartial || result.Dane.HasData() {
					t.Fatalf("unexpected partial result: %+v", result)
				}
				merged := mergeCacheResult(previous, result, now)
				if merged.Dane.HasData() {
					t.Fatalf("partial lookup cached as DANE: %+v", merged.Dane)
				}
				if _, _, _, ok := selectCachedPolicy(merged, now); ok {
					t.Fatal("partial lookup made a reusable policy")
				}
				// Recovery must be visible on the next request, including with STS cached.
				checkDanePolicy = func(context.Context, string, bool) daneResult {
					calls++
					return daneResult{Policy: "dane-only", TTL: 300}
				}
				result = queryDomainBranches("example.test", merged, now.Add(time.Second))
				if calls != 2 || result.Policy != "dane-only" || result.DanePartial {
					t.Fatalf("DANE recovery was suppressed: calls=%d result=%+v", calls, result)
				}
				merged = mergeCacheResult(merged, result, now.Add(time.Second))
				if got, _, _, ok := selectCachedPolicy(merged, now.Add(time.Second)); !ok || got != "dane-only" {
					t.Fatalf("complete DANE recovery was not cached: %q, %v", got, ok)
				}
			})
		}
	}
}

func TestPartialDaneRefreshPreservesFreshProtection(t *testing.T) {
	origDane, origSts := checkDanePolicy, checkMtaStsPolicy
	t.Cleanup(func() { checkDanePolicy, checkMtaStsPolicy = origDane, origSts })
	checkDanePolicy = func(context.Context, string, bool) daneResult {
		return daneResult{Partial: true}
	}
	checkMtaStsPolicy = func(context.Context, string, bool) (string, string, uint32) {
		return "TEMP", "", 0
	}
	for _, danePolicy := range []string{"", "dane-only"} {
		t.Run(danePolicy, func(t *testing.T) {
			now := time.Now()
			previous := &CacheStruct{
				Expirable: &cache.Expirable{},
				MtaSts: PolicyBranch{
					Policy: "secure match=mx.example.test", Report: "policy_type=sts",
					TTL: 300, ExpiresAt: now.Add(10 * time.Second),
				},
			}
			if danePolicy != "" {
				previous.Dane = PolicyBranch{Policy: danePolicy, TTL: 300, ExpiresAt: now.Add(10 * time.Second)}
			}
			result := queryDomainBranchesWithOptions("example.test", previous, now, queryBranchOptions{renewBefore: 30})
			want := danePolicy
			if want == "" {
				want = previous.MtaSts.Policy
			}
			if result.Policy != want || !result.DanePartial {
				t.Fatalf("fresh protection not selected: %+v", result)
			}
			merged := mergeCacheResult(previous, result, now)
			if merged.Dane != previous.Dane || merged.MtaSts != previous.MtaSts {
				t.Fatalf("partial refresh changed cached protection or expiry: %+v", merged)
			}
		})
	}
}

func TestPartialDanePrefetchNeverInventsNegativePolicy(t *testing.T) {
	originalCache := polCache
	polCache = cache.New[*CacheStruct](filepath.Join(t.TempDir(), "cache.db"), time.Hour)
	t.Cleanup(func() { polCache.Close(); polCache = originalCache })
	now := time.Now()
	key := "partial.example.test"
	previous := &CacheStruct{
		LastAccess: time.Now(),
		Expirable:  &cache.Expirable{},
		Dane: PolicyBranch{
			Policy: "dane-only", TTL: 300, ExpiresAt: now.Add(-48 * time.Hour),
		},
		MtaSts: PolicyBranch{
			Policy: "secure match=mx.example.test", TTL: 3600, ExpiresAt: now.Add(time.Hour),
		},
	}
	polCache.Set(key, previous)
	scheduler := newPrefetchScheduler()
	scheduler.failures[key] = prefetchFailure{firstFailed: now.Add(-PREFETCH_RETRY_MAX_AGE), attempts: 8}
	scheduleFailedPolicyPrefetch(scheduler, key, previous, domainResult{DaneAttempted: true, DanePartial: true}, now)
	stored, found := polCache.Get(key)
	if !found || stored != previous {
		t.Fatal("partial prefetch replaced or discarded cached protection")
	}
	if _, _, _, ok := selectCachedPolicy(stored, now); ok {
		t.Fatal("partial prefetch created an authoritative negative DANE result")
	}
	if _, ok := scheduler.nextDue(); !ok {
		t.Fatal("partial prefetch was not rescheduled")
	}
}

/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"

	"github.com/miekg/dns"
)

type ResultWithTTL struct {
	Err    error
	Result string
	TTL    uint32
}

type mxRecord struct {
	host string
	ttl  uint32
}

type mxCheckResult struct {
	host   string
	ttl    uint32
	status uint8
}

const DANE_MX_LOOKUP_CONCURRENCY = 4
const DANE_CNAME_MAX_DEPTH = 8

func getMxRecords(ctx context.Context, domain string, resolverAddress string) ([]string, uint32, error, bool) {
	records, incompl, err := lookupMxRecords(ctx, domain, resolverAddress, 0)
	if err != nil || len(records) == 0 {
		return nil, 0, err, incompl
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var lookupErr error
	var mxRecords []string
	var minTTL uint32
	haveTTL := false
	for result := range checkMxRecords(cctx, records, resolverAddress) {
		switch result.status {
		case MxOk:
			mxRecords = append(mxRecords, result.host)
			if !haveTTL || result.ttl < minTTL {
				minTTL = result.ttl
				haveTTL = true
			}
		case MxFail:
			if lookupErr == nil {
				lookupErr = errors.New("DNS error during MX address lookup")
				cancel()
			}
		case MxNotSec:
			incompl = true
		}
	}
	if lookupErr != nil {
		return nil, 0, lookupErr, false
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err, false
	}

	return mxRecords, minTTL, nil, incompl
}

func lookupMxRecords(ctx context.Context, domain string, resolverAddress string, depth int) ([]mxRecord, bool, error) {
	if depth > DANE_CNAME_MAX_DEPTH {
		return nil, false, errors.New("too many CNAME records during MX lookup")
	}
	m := newDNSQuery(domain, dns.TypeMX, true)
	r, err := exchangeDNS(ctx, m, resolverAddress)
	if err != nil {
		return nil, false, err
	}
	incompl := false
	switch r.Rcode {
	case dns.RcodeSuccess:
		if !r.MsgHdr.AuthenticatedData {
			incompl = true
		}
	case dns.RcodeNameError:
		return nil, !r.MsgHdr.AuthenticatedData, nil
	default:
		return nil, false, errors.New(dns.RcodeToString[r.Rcode])
	}

	type cnameHop struct {
		target string
		ttl    uint32
	}
	cnameHops := make(map[string]cnameHop)
	for _, answer := range r.Answer {
		rr, ok := answer.(*dns.CNAME)
		if !ok {
			continue
		}
		owner := strings.ToLower(dns.Fqdn(strings.TrimSpace(rr.Hdr.Name)))
		target := strings.ToLower(dns.Fqdn(strings.TrimSpace(rr.Target)))
		if previous, ok := cnameHops[owner]; ok && previous.target != target {
			return nil, false, errors.New("multiple CNAME targets during MX lookup")
		}
		cnameHops[owner] = cnameHop{target: target, ttl: rr.Hdr.Ttl}
	}

	mxOwner := strings.ToLower(dns.Fqdn(domain))
	var cnameTTL uint32
	haveCnameTTL := false
	seenCnames := make(map[string]struct{})
	hops := 0
	for {
		hop, ok := cnameHops[mxOwner]
		if !ok {
			break
		}
		if _, ok := seenCnames[mxOwner]; ok {
			return nil, false, errors.New("CNAME loop during MX lookup")
		}
		seenCnames[mxOwner] = struct{}{}
		hops++
		if depth+hops > DANE_CNAME_MAX_DEPTH {
			return nil, false, errors.New("too many CNAME records during MX lookup")
		}
		if !valid.IsDNSName(hop.target) {
			return nil, false, errors.New("invalid CNAME target during MX lookup")
		}
		if !haveCnameTTL || hop.ttl < cnameTTL {
			cnameTTL = hop.ttl
			haveCnameTTL = true
		}
		mxOwner = hop.target
	}

	records := make([]mxRecord, 0, len(r.Answer))
	seen := make(map[string]int)
	for _, answer := range r.Answer {
		if mx, ok := answer.(*dns.MX); ok {
			if !strings.EqualFold(mx.Hdr.Name, mxOwner) {
				continue
			}
			host := strings.ToLower(strings.TrimSpace(mx.Mx))
			key := strings.TrimSuffix(host, ".")
			if index, ok := seen[key]; ok {
				if mx.Hdr.Ttl < records[index].ttl {
					records[index].ttl = mx.Hdr.Ttl
				}
				continue
			}
			seen[key] = len(records)
			records = append(records, mxRecord{host: dns.Fqdn(host), ttl: mx.Hdr.Ttl})
		}
	}
	if len(records) != 0 && haveCnameTTL {
		for i := range records {
			records[i].ttl = min(records[i].ttl, cnameTTL)
		}
	}
	if len(records) == 0 && hops != 0 {
		records, childIncompl, err := lookupMxRecords(ctx, mxOwner, resolverAddress, depth+hops)
		if haveCnameTTL {
			for i := range records {
				records[i].ttl = min(records[i].ttl, cnameTTL)
			}
		}
		return records, incompl || childIncompl, err
	}
	if len(records) == 0 {
		if incompl {
			return nil, true, nil
		}
		records = append(records, mxRecord{
			host: dns.Fqdn(domain),
			ttl:  negativeResponseTTL(r),
		})
	}
	return records, incompl, nil
}

func negativeResponseTTL(r *dns.Msg) uint32 {
	// RFC 2308 Section 5 defines the negative TTL as the smaller SOA value.
	var ttl uint32
	haveTTL := false
	for _, authority := range r.Ns {
		soa, ok := authority.(*dns.SOA)
		if !ok {
			continue
		}
		candidate := min(soa.Hdr.Ttl, soa.Minttl)
		if !haveTTL || candidate < ttl {
			ttl = candidate
			haveTTL = true
		}
	}
	return ttl
}

func checkMxRecords(ctx context.Context, records []mxRecord, resolverAddress string) <-chan mxCheckResult {
	results := make(chan mxCheckResult, len(records))
	if len(records) == 0 {
		close(results)
		return results
	}
	if len(records) == 1 {
		if ctx.Err() == nil {
			record := records[0]
			results <- mxCheckResult{
				host:   record.host,
				ttl:    record.ttl,
				status: checkMx(ctx, record.host, resolverAddress),
			}
		}
		close(results)
		return results
	}

	jobs := make(chan mxRecord)
	workers := min(DANE_MX_LOOKUP_CONCURRENCY, len(records))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case record, ok := <-jobs:
					if !ok {
						return
					}
					result := mxCheckResult{
						host:   record.host,
						ttl:    record.ttl,
						status: checkMx(ctx, record.host, resolverAddress),
					}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, record := range records {
			select {
			case jobs <- record:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

const (
	MxOk uint8 = iota
	MxFail
	MxNotSec
)

// Checks whether a specific MX record has DNSSEC-signed A/AAAA records
func checkMx(ctx context.Context, mx string, resolverAddress string) uint8 {
	if !valid.IsDNSName(mx) {
		return MxNotSec
	}

	failed := false
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		switch checkMxAddress(ctx, mx, resolverAddress, t) {
		case MxOk:
			return MxOk
		case MxFail:
			failed = true
		}
	}
	if failed {
		return MxFail
	}
	return MxNotSec
}

func checkMxAddress(ctx context.Context, mx string, resolverAddress string, recordType uint16) uint8 {
	m := newDNSQuery(mx, recordType, true)
	r, err := exchangeDNS(ctx, m, resolverAddress)
	if err != nil {
		return MxFail
	}
	switch r.Rcode {
	case dns.RcodeSuccess:
		if !r.MsgHdr.AuthenticatedData {
			return MxNotSec
		}
		for _, answer := range r.Answer {
			switch recordType {
			case dns.TypeA:
				if _, ok := answer.(*dns.A); ok {
					return MxOk
				}
			case dns.TypeAAAA:
				if _, ok := answer.(*dns.AAAA); ok {
					return MxOk
				}
			}
		}
		return MxNotSec
	case dns.RcodeNameError:
		if r.MsgHdr.AuthenticatedData {
			return MxNotSec
		}
		return MxFail
	default:
		return MxFail
	}
}

func isTlsaUsable(r *dns.TLSA) bool {
	if r.Usage != 3 && r.Usage != 2 {
		return false
	}

	if r.Selector != 1 && r.Selector != 0 {
		return false
	}

	switch r.MatchingType {
	case 1: // SHA-256
		if !valid.IsSHA256(r.Certificate) {
			return false
		}
	case 2: // SHA-512
		if !valid.IsSHA512(r.Certificate) {
			return false
		}
	case 0: // Full certificate
		cert, err := hex.DecodeString(r.Certificate)
		if err != nil {
			return false
		}
		_, err = x509.ParseCertificate(cert)
		if err != nil {
			return false
		}
	default:
		return false
	}

	return true
}

func checkTlsa(ctx context.Context, mx string, resolverAddress string) ResultWithTTL {
	m := newDNSQuery("_25._tcp."+mx, dns.TypeTLSA, true)
	r, err := exchangeDNS(ctx, m, resolverAddress)
	if err != nil {
		return ResultWithTTL{Result: "", TTL: 0, Err: err}
	}
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		if !r.MsgHdr.AuthenticatedData {
			return ResultWithTTL{Result: "", TTL: 0}
		}
	default:
		return ResultWithTTL{Result: "", TTL: 0, Err: errors.New(dns.RcodeToString[r.Rcode])}
	}
	if len(r.Answer) == 0 {
		return ResultWithTTL{Result: "", TTL: 0}
	}

	result := ""
	var minTTL uint32
	haveTTL := false
	for _, answer := range r.Answer {
		if tlsa, ok := answer.(*dns.TLSA); ok {
			if isTlsaUsable(tlsa) {
				// TLSA records are usable, enforce DANE, return directly
				return ResultWithTTL{Result: "dane-only", TTL: tlsa.Hdr.Ttl}
			} else {
				// let Postfix decide if DANE is possible, it downgrades to "encrypt" if not; continue searching
				result = "dane"
				if !haveTTL || tlsa.Hdr.Ttl < minTTL {
					minTTL = tlsa.Hdr.Ttl
					haveTTL = true
				}
			}
		}
	}

	return ResultWithTTL{Result: result, TTL: minTTL}
}

const (
	NoDane uint8 = iota
	Dane
	DaneOnly
)

func checkDane(ctx context.Context, domain string, mayRetry bool) (string, uint32) {
	resolverAddress, err := config.Dns.GetResolverAddress()
	if err != nil {
		logPolicyLookupFailure(ctx, "DNS resolver configuration error during DANE lookup", "domain", domain, "error", err)
		return "TEMP", 0
	}
	attempts := 1
	if mayRetry {
		attempts = POLICY_ATTEMPTS
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		policy, ttl, err := checkDaneOnce(ctx, domain, resolverAddress)
		if err == nil {
			return policy, ttl
		}
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return "TEMP", 0
		}
		if attempt == attempts {
			logPolicyLookupFailure(ctx, "DNS error during DANE lookup", "domain", domain, "error", err, "attempts", attempts)
			return "TEMP", 0
		}
		if !waitPolicyRetry(ctx, attempt) {
			return "TEMP", 0
		}
	}
	return "TEMP", 0
}

func checkDaneOnce(ctx context.Context, domain string, resolverAddress string) (string, uint32, error) {
	mxRecords, ttl, err, incompl := getMxRecords(ctx, domain, resolverAddress)
	if err != nil {
		return "", 0, err
	}
	numRecords := len(mxRecords)
	if numRecords == 0 {
		return "", 0, nil
	}
	cctx, cancel := context.WithCancel(ctx)
	tlsaResults := checkTlsaRecords(cctx, mxRecords, resolverAddress)
	return getDanePolicy(cctx, cancel, ttl, incompl, numRecords, tlsaResults)
}

func checkTlsaRecords(ctx context.Context, mxRecords []string, resolverAddress string) <-chan ResultWithTTL {
	results := make(chan ResultWithTTL, len(mxRecords))
	if len(mxRecords) == 0 {
		close(results)
		return results
	}
	if len(mxRecords) == 1 {
		if ctx.Err() == nil {
			results <- checkTlsa(ctx, mxRecords[0], resolverAddress)
		}
		close(results)
		return results
	}

	jobs := make(chan string)
	workers := min(DANE_MX_LOOKUP_CONCURRENCY, len(mxRecords))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case mx, ok := <-jobs:
					if !ok {
						return
					}
					result := checkTlsa(ctx, mx, resolverAddress)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, mx := range mxRecords {
			select {
			case jobs <- mx:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

func getDanePolicy(ctx context.Context, cancel func(), ttl uint32, incompl bool, numRecords int, tlsaResults <-chan ResultWithTTL) (string, uint32, error) {
	defer cancel()
	minTTL := ttl
	minPolicy := uint8(DaneOnly)
	maxPolicy := uint8(NoDane)
	if incompl {
		minPolicy = NoDane
	}
	for i := 0; i < numRecords; i++ {
		var res ResultWithTTL
		select {
		case result, ok := <-tlsaResults:
			if !ok {
				if err := ctx.Err(); err != nil {
					return "", 0, err
				}
				return "", 0, errors.New("incomplete TLSA lookup results")
			}
			res = result
		case <-ctx.Done():
			return "", 0, ctx.Err()
		}
		if res.Err != nil {
			return "", 0, res.Err
		}
		if res.TTL < minTTL {
			minTTL = res.TTL
		}
		var policy uint8
		switch res.Result {
		case "dane-only":
			policy = DaneOnly
		case "dane":
			policy = Dane
		default:
			policy = NoDane
		}
		if policy < minPolicy {
			minPolicy = policy
		}
		if policy > maxPolicy {
			maxPolicy = policy
		}
	}
	pol := ""
	if maxPolicy >= Dane {
		if minPolicy <= Dane {
			pol = "dane"
		} else {
			pol = "dane-only"
		}
	}
	return pol, minTTL, nil
}

func waitPolicyRetry(ctx context.Context, attempt int) bool {
	delay := POLICY_RETRY_BASE * time.Duration(attempt)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

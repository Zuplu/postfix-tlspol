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
	"log/slog"
	"slices"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"

	"github.com/miekg/dns"
)

type ResultWithTTL struct {
	Err    error
	Result string
	TTL    uint32
}

func getMxRecords(ctx context.Context, domain string) ([]string, uint32, error, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.SetEdns0(4096, true)

	resolverAddress, err := config.Dns.GetResolverAddress()
	if err != nil {
		return nil, 0, err, false
	}
	r, _, err := client.ExchangeContext(ctx, m, resolverAddress)
	if err != nil {
		return nil, 0, err, false
	}
	incompl := false
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError:
		if !r.MsgHdr.AuthenticatedData {
			incompl = true
		}
	default:
		return nil, 0, errors.New(dns.RcodeToString[r.Rcode]), false
	}

	var mxRecords []string
	var ttls []uint32
	for _, answer := range r.Answer {
		if mx, ok := answer.(*dns.MX); ok {
			if checkMx(ctx, mx.Mx) != MxOk {
				incompl = true
				continue
			}
			mxRecords = append(mxRecords, mx.Mx)
			ttls = append(ttls, mx.Hdr.Ttl)
		}
	}

	return mxRecords, findMin(ttls), nil, incompl
}

const (
	MxOk uint8 = iota
	MxFail
	MxNotSec
)

// Checks whether a specific MX record has DNSSEC-signed A/AAAA records
func checkMx(ctx context.Context, mx string) uint8 {
	if !valid.IsDNSName(mx) {
		return MxFail
	}
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	hasRecord := false
ipCheck:
	for _, t := range types {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(mx), t)
		m.SetEdns0(4096, true)

		resolverAddress, err := config.Dns.GetResolverAddress()
		if err != nil {
			return MxFail
		}
		r, _, err := client.ExchangeContext(ctx, m, resolverAddress)
		if err != nil {
			return MxFail
		}
		switch r.Rcode {
		case dns.RcodeSuccess:
			if r.MsgHdr.AuthenticatedData {
				hasRecord = true
				break ipCheck
			}
		default:
		}
	}
	if hasRecord {
		return MxOk
	}
	return MxNotSec
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

func checkTlsa(ctx context.Context, mx string) ResultWithTTL {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_25._tcp."+mx), dns.TypeTLSA)
	m.SetEdns0(4096, true)

	resolverAddress, err := config.Dns.GetResolverAddress()
	if err != nil {
		return ResultWithTTL{Result: "", TTL: 0, Err: err}
	}
	r, _, err := client.ExchangeContext(ctx, m, resolverAddress)
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
	var ttls []uint32
	for _, answer := range r.Answer {
		if tlsa, ok := answer.(*dns.TLSA); ok {
			if isTlsaUsable(tlsa) {
				// TLSA records are usable, enforce DANE, return directly
				return ResultWithTTL{Result: "dane-only", TTL: tlsa.Hdr.Ttl}
			} else {
				// let Postfix decide if DANE is possible, it downgrades to "encrypt" if not; continue searching
				result = "dane"
				ttls = append(ttls, tlsa.Hdr.Ttl)
			}
		}
	}

	return ResultWithTTL{Result: result, TTL: findMin(ttls)}
}

const (
	NoDane uint8 = iota
	Dane
	DaneOnly
)

func checkDane(ctx context.Context, domain string, mayRetry bool) (string, uint32) {
	attempts := 1
	if mayRetry {
		attempts = POLICY_ATTEMPTS
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		policy, ttl, err := checkDaneOnce(ctx, domain)
		if err == nil {
			return policy, ttl
		}
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return "TEMP", 0
		}
		if attempt == attempts {
			slog.Warn("DNS error during DANE lookup", "domain", domain, "error", err, "attempts", attempts)
			return "TEMP", 0
		}
		if !waitPolicyRetry(ctx, attempt) {
			return "TEMP", 0
		}
	}
	return "TEMP", 0
}

func checkDaneOnce(ctx context.Context, domain string) (string, uint32, error) {
	mxRecords, ttl, err, incompl := getMxRecords(ctx, domain)
	if err != nil {
		return "", 0, err
	}
	numRecords := len(mxRecords)
	if numRecords == 0 {
		return "", 0, nil
	}
	tlsaResults := make(chan ResultWithTTL, numRecords)
	cctx, cancel := context.WithCancel(ctx)
	for _, mx := range mxRecords {
		go func(mx string) {
			tlsaResults <- checkTlsa(cctx, mx)
		}(mx)
	}
	return getDanePolicy(cctx, cancel, ttl, incompl, numRecords, tlsaResults)
}

func getDanePolicy(ctx context.Context, cancel func(), ttl uint32, incompl bool, numRecords int, tlsaResults <-chan ResultWithTTL) (string, uint32, error) {
	defer cancel()
	var ttls []uint32
	ttls = append(ttls, ttl)
	var pols []uint8
	if incompl {
		pols = append(pols, NoDane)
	}
	for i := 0; i < numRecords; i++ {
		res := <-tlsaResults
		if res.Err != nil {
			return "", 0, res.Err
		}
		ttls = append(ttls, res.TTL)
		switch res.Result {
		case "dane-only":
			pols = append(pols, DaneOnly)
		case "dane":
			pols = append(pols, Dane)
		default:
			pols = append(pols, NoDane)
		}
	}
	pol := ""
	if findMax(pols) >= Dane {
		if findMin(pols) <= Dane {
			pol = "dane"
		} else {
			pol = "dane-only"
		}
	}
	return pol, findMin(ttls), nil
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

func findMin[T uint8 | uint32](s []T) T {
	if len(s) == 0 {
		return 0
	}
	return slices.Min(s)
}

func findMax[T uint8 | uint32](s []T) T {
	if len(s) == 0 {
		return 0
	}
	return slices.Max(s)
}

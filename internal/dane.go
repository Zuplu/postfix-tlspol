/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"
	"github.com/miekg/dns"
	"slices"
	"time"
)

type ResultWithTTL struct {
	Err    error
	Result string
	TTL    uint32
}

func getMxRecords(ctx *context.Context, domain *string) ([]string, uint32, error, bool) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*domain), dns.TypeMX)
	m.SetEdns0(4096, true)

	r, _, err := client.ExchangeContext(*ctx, m, config.Dns.Address)
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
			if checkMx(ctx, &mx.Mx) != MxOk {
				incompl = true
				continue
			}
			mxRecords = append(mxRecords, mx.Mx)
			ttls = append(ttls, mx.Hdr.Ttl)
		}
	}

	return mxRecords, findMin(&ttls), nil, incompl
}

const (
	MxOk uint8 = iota
	MxFail
	MxNotSec
)

// Checks whether a specific MX record has DNSSEC-signed A/AAAA records
func checkMx(ctx *context.Context, mx *string) uint8 {
	if !valid.IsDNSName(*mx) {
		return MxFail
	}
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	hasRecord := false
ipCheck:
	for _, t := range types {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(*mx), t)
		m.SetEdns0(4096, true)

		r, _, err := client.ExchangeContext(*ctx, m, config.Dns.Address)
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

func checkTlsa(ctx *context.Context, mx *string) ResultWithTTL {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_25._tcp."+*mx), dns.TypeTLSA)
	m.SetEdns0(4096, true)

	r, _, err := client.ExchangeContext(*ctx, m, config.Dns.Address)
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

	return ResultWithTTL{Result: result, TTL: findMin(&ttls)}
}

const (
	NoDane uint8 = iota
	Dane
	DaneOnly
)

func checkDane(ctx *context.Context, domain *string, mayRetry bool) (string, uint32) {
	mxRecords, ttl, err, incompl := getMxRecords(ctx, domain)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			if mayRetry {
				time.Sleep(750 * time.Millisecond)
				return checkDane(ctx, domain, false)
			}
			log.Warnf("DNS error during MX lookup for %q: %v", *domain, err)
		}
		return "TEMP", 0
	}
	numRecords := len(mxRecords)
	if numRecords == 0 {
		return "", 0
	}
	tlsaResults := make(chan ResultWithTTL)
	for _, mx := range mxRecords {
		go func(mx string) {
			tlsaResults <- checkTlsa(ctx, &mx)
		}(mx)
	}
	return getDanePolicy(ctx, domain, mayRetry, ttl, incompl, numRecords, &tlsaResults)
}

func getDanePolicy(ctx *context.Context, domain *string, mayRetry bool, ttl uint32, incompl bool, numRecords int, tlsaResults *chan ResultWithTTL) (string, uint32) {
	var ttls []uint32
	ttls = append(ttls, ttl)
	var i int = 0
	var pols []uint8
	if incompl {
		pols = append(pols, NoDane)
	}
	for res := range *tlsaResults {
		i++
		if i >= numRecords {
			close(*tlsaResults)
		}
		if res.Err != nil {
			if !errors.Is(res.Err, context.Canceled) {
				if mayRetry {
					time.Sleep(750 * time.Millisecond)
					return checkDane(ctx, domain, false)
				}
				log.Warnf("DNS error during TLSA lookup for %q: %v", *domain, res.Err)
			}
			return "TEMP", 0
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
	if findMax(&pols) >= Dane {
		if findMin(&pols) <= Dane {
			pol = "dane"
		} else {
			pol = "dane-only"
		}
	}
	return pol, findMin(&ttls)
}

func findMin[T uint8 | uint32](s *[]T) T {
	if len(*s) == 0 {
		return 0
	}
	return slices.Min(*s)
}

func findMax[T uint8 | uint32](s *[]T) T {
	if len(*s) == 0 {
		return 0
	}
	return slices.Max(*s)
}

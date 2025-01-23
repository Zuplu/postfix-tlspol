/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
)

type ResultWithTtl struct {
	Result string
	Ttl    uint32
	Err    error
}

func getMxRecords(ctx context.Context, domain string) ([]string, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.SetEdns0(1232, true)

	r, _, err := client.ExchangeContext(ctx, m, config.Dns.Address)
	if err != nil {
		return nil, 0, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, 0, fmt.Errorf("DNS error: %v", dns.RcodeToString[r.Rcode])
	}

	var mxRecords []string
	var ttls []uint32
	if r.MsgHdr.AuthenticatedData {
		for _, answer := range r.Answer {
			if mx, ok := answer.(*dns.MX); ok {
				if !govalidator.IsDNSName(mx.Mx) {
					return nil, 0, fmt.Errorf("Invalid MX record")
				}
				mxRecords = append(mxRecords, mx.Mx)
				ttls = append(ttls, mx.Hdr.Ttl)
			}
		}
	}

	return mxRecords, findMin(ttls), nil
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
		if !govalidator.IsSHA256(r.Certificate) {
			return false
		}
	case 2: // SHA-512
		if !govalidator.IsSHA512(r.Certificate) {
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

func checkTlsa(ctx context.Context, mx string) ResultWithTtl {
	tlsaName := "_25._tcp." + mx
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tlsaName), dns.TypeTLSA)
	m.SetEdns0(1232, true)

	r, _, err := client.ExchangeContext(ctx, m, config.Dns.Address)
	if err != nil {
		return ResultWithTtl{Result: "", Ttl: 0, Err: err}
	}
	if len(r.Answer) == 0 {
		return ResultWithTtl{Result: "", Ttl: 0}
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return ResultWithTtl{Result: "", Ttl: 0, Err: fmt.Errorf("DNS error: %v", r.Rcode)}
	}

	result := ""
	var ttls []uint32
	if r.MsgHdr.AuthenticatedData {
		for _, answer := range r.Answer {
			if tlsa, ok := answer.(*dns.TLSA); ok {
				if isTlsaUsable(tlsa) {
					// TLSA records are usable, enforce DANE, return directly
					return ResultWithTtl{Result: "dane-only", Ttl: tlsa.Hdr.Ttl}
				} else {
					// let Postfix decide if DANE is possible, it downgrades to "encrypt" if not; continue searching
					result = "dane"
					ttls = append(ttls, tlsa.Hdr.Ttl)
				}
			}
		}
	}

	return ResultWithTtl{Result: result, Ttl: findMin(ttls)}
}

func checkDane(ctx context.Context, domain string) (string, uint32) {
	mxRecords, ttl, err := getMxRecords(ctx, domain)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Warnf("DNS error (MX): %v", err)
		}
		return "TEMP", 0
	}
	numRecords := len(mxRecords)
	if numRecords == 0 {
		return "", 0
	}

	tlsaResults := make(chan ResultWithTtl)
	for _, mx := range mxRecords {
		go func(mx string) {
			tlsaResults <- checkTlsa(ctx, mx)
		}(mx)
	}

	canDane, hasError := false, false
	var ttls []uint32
	ttls = append(ttls, ttl)
	var i int = 0
	for res := range tlsaResults {
	    i++
	    if i >= numRecords {
	        close(tlsaResults)
	    }
		if res.Err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Warnf("DNS error (TLSA): %v", res.Err)
			}
			hasError = true
			continue
		}
		ttls = append(ttls, res.Ttl)
		if res.Result == "dane-only" {
			return "dane-only", findMin(ttls) // at least one record is supported
		} else if res.Result == "dane" {
			canDane = true
		}
	}

	if canDane {
		return "dane", findMin(ttls) // might be supported, Postfix has to decide
	}

	if hasError {
		return "TEMP", 0
	}

	return "", findMin(ttls)
}

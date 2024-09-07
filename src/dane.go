/*
 * MIT License
 * Copyright (c) 2024 Zuplu
 */

package main

import (
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
)

type ResultWithTtl struct {
	Result string
	Ttl    uint32
	Err    error
}

func getMxRecords(domain string) ([]string, uint32, error) {
	client := &dns.Client{Timeout: REQUEST_TIMEOUT}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, config.Dns.Address)
	if err != nil {
		return nil, 0, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, 0, fmt.Errorf("DNS error")
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

func checkTlsa(mx string) ResultWithTtl {
	tlsaName := "_25._tcp." + mx
	client := &dns.Client{Timeout: REQUEST_TIMEOUT}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tlsaName), dns.TypeTLSA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, config.Dns.Address)
	if err != nil {
		return ResultWithTtl{Result: "", Ttl: 0, Err: err}
	}
	if len(r.Answer) == 0 {
		return ResultWithTtl{Result: "", Ttl: 0}
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return ResultWithTtl{Result: "", Ttl: 0, Err: fmt.Errorf("DNS error")}
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

func checkDane(domain string) (string, uint32) {
	mxRecords, ttl, err := getMxRecords(domain)
	if err != nil {
		return "TEMP", 0
	}
	if len(mxRecords) == 0 {
		return "", 0
	}

	var wg sync.WaitGroup
	tlsaResults := make(chan ResultWithTtl, len(mxRecords))
	for _, mx := range mxRecords {
		wg.Add(1)
		go func(mx string) {
			defer wg.Done()
			tlsaResults <- checkTlsa(mx)
		}(mx)
	}
	wg.Wait()
	close(tlsaResults)

	canDane := false
	var ttls []uint32
	ttls = append(ttls, ttl)
	for res := range tlsaResults {
		if res.Err != nil {
			return "TEMP", 0
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

	return "", findMin(ttls)
}

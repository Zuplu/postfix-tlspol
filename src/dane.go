/*
 * MIT License
 * Copyright (c) 2024 Zuplu
 */

package main

import (
	"fmt"
	"sync"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
)

type ResultWithTtl struct {
	Result bool
	Ttl    uint32
	Err    error
}

func getMxRecords(domain string) ([]string, uint32, error) {
	client := &dns.Client{Timeout: REQUEST_TIMEOUT}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, config.DNS.Address)
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

func checkTlsa(mx string) ResultWithTtl {
	tlsaName := "_25._tcp." + mx
	client := &dns.Client{Timeout: REQUEST_TIMEOUT}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(tlsaName), dns.TypeTLSA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, config.DNS.Address)
	if err != nil {
		return ResultWithTtl{Result: false, Ttl: 0, Err: err}
	}
	if len(r.Answer) == 0 {
		return ResultWithTtl{Result: false, Ttl: 0}
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return ResultWithTtl{Result: false, Ttl: 0, Err: fmt.Errorf("DNS error")}
	}

	if r.MsgHdr.AuthenticatedData {
		for _, answer := range r.Answer {
			if tlsa, ok := answer.(*dns.TLSA); ok {
				return ResultWithTtl{Result: true, Ttl: tlsa.Hdr.Ttl}
			}
		}
	}

	return ResultWithTtl{Result: false, Ttl: 0}
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

	allHaveTLSA := true
	var ttls []uint32
	ttls = append(ttls, ttl)
	for res := range tlsaResults {
		if res.Err != nil {
			return "TEMP", 0
		}
		ttls = append(ttls, res.Ttl)
		if !res.Result {
			allHaveTLSA = false
		}
	}

	if allHaveTLSA {
		return "dane", findMin(ttls)
	}

	return "", findMin(ttls)
}

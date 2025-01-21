/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"net/http"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
)

func checkMtaStsRecord(domain string) (bool, error) {
	client := &dns.Client{Timeout: REQUEST_TIMEOUT}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_mta-sts."+domain), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, config.Dns.Address)
	if err != nil {
		return false, err
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return false, fmt.Errorf("DNS error: %v", r.Rcode)
	}
	if len(r.Answer) == 0 {
		return false, nil
	}

	for _, answer := range r.Answer {
		if txt, ok := answer.(*dns.TXT); ok {
			for _, txtRecord := range txt.Txt {
				if strings.HasPrefix(txtRecord, "v=STSv1") {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

func checkMtaSts(domain string) (string, string, uint32) {
	hasRecord, err := checkMtaStsRecord(domain)
	if err != nil {
		log.Warnf("DNS error (MTA-STS): %v", err)
		return "TEMP", "", 0
	}
	if !hasRecord {
		return "", "", 0
	}

	client := &http.Client{
		// Disable following redirects (see [RFC 8461, 3.3])
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,            // Ensure SSL certificate validation
				MinVersion:         tls.VersionTLS12, // set minimum to TLSv1.2
			},
			DisableKeepAlives: true,
		},
		Timeout: REQUEST_TIMEOUT, // Set a timeout for the request
	}

	mtaSTSURL := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	resp, err := client.Get(mtaSTSURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", "", 0
	}
	defer resp.Body.Close()

	var mxServers []string
	mode := ""
	var maxAge uint32 = 0
	report := ""
	mxHosts := ""
	existingKeys := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !govalidator.IsPrintableASCII(line) && !govalidator.IsUTFLetterNumeric(line) {
			return "", "", 0 // invalid policy, neither printable ASCII nor alphanumeric UTF-8 (latter is allowed in extended key/vals only)
		}
		if len(line) != len(govalidator.BlackList(line, "{}")) {
			continue // skip lines containing { or }, they are only allowed in  extended key/vals, and we don't need them anyway
		}
		keyValPair := strings.SplitN(line, ":", 2)
		if len(keyValPair) != 2 {
			return "", "", 0 // invalid policy
		}
		key, val := strings.TrimSpace(keyValPair[0]), strings.TrimSpace(keyValPair[1])
		if key != "mx" && existingKeys[key] {
			continue // only mx keys can be duplicated, others are ignored (as of [RFC 8641, 3.2])
		}
		existingKeys[key] = true
		report = report + " { policy_string = " + key + ": " + val + " }"
		switch key {
		case "mx":
			if !govalidator.IsDNSName(strings.ReplaceAll(val, "*.", "")) {
				return "", "", 0 // invalid policy
			}
			mxHosts = mxHosts + " mx_host_pattern=" + val
			if strings.HasPrefix(val, "*.") {
				val = val[1:]
			}
			mxServers = append(mxServers, val)
		case "mode":
			mode = val
		case "max_age":
			age, err := strconv.ParseUint(val, 10, 32)
			if err == nil {
				maxAge = uint32(age)
			}
		}
	}
	report = "policy_type=sts policy_domain=" + domain + fmt.Sprintf(" policy_ttl=%d", maxAge) + mxHosts + report

	if mode == "enforce" {
		res := "secure match=" + strings.Join(mxServers, ":") + " servername=hostname"
		return res, report, maxAge
	}

	return "", "", maxAge
}

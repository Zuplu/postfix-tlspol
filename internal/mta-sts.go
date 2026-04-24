/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"

	"github.com/miekg/dns"
)

const MTASTS_MAX_AGE uint64 = 31557600 // RFC 8461, 3.2

func checkMtaStsRecord(ctx context.Context, domain string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_mta-sts."+domain), dns.TypeTXT)
	m.SetEdns0(4096, false)

	resolverAddress, err := config.Dns.GetResolverAddress()
	if err != nil {
		return false, err
	}
	r, _, err := client.ExchangeContext(ctx, m, resolverAddress)
	if err != nil {
		return false, err
	}
	switch r.Rcode {
	case dns.RcodeSuccess, dns.RcodeNameError, dns.RcodeServerFailure:
	default:
		return false, errors.New(dns.RcodeToString[r.Rcode])
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

var httpClient = &http.Client{
	// Disable following redirects (see [RFC 8461, 3.3])
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify:     false,            // Ensure SSL certificate validation
			MinVersion:             tls.VersionTLS12, // set minimum to TLSv1.2
			SessionTicketsDisabled: true,
			ClientSessionCache:     nil,
		},
		IdleConnTimeout:   1 * time.Second,
		MaxIdleConns:      1,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
	},
	Timeout: REQUEST_TIMEOUT, // Set a timeout for the request
}

type mtaStsPolicyParser struct {
	existingKeys map[string]bool
	mode         string
	report       strings.Builder
	mxHosts      strings.Builder
	mxServers    []string
	maxAge       uint32
	hasMaxAge    bool
	hasVersion   bool
}

func newMtaStsPolicyParser() mtaStsPolicyParser {
	return mtaStsPolicyParser{
		existingKeys: make(map[string]bool),
	}
}

//gocyclo:ignore
func (p *mtaStsPolicyParser) parseLine(line string) bool {
	line = strings.TrimSpace(line)
	lineLen := len(line)
	if lineLen == 0 {
		return true
	}
	if !valid.IsPrintableASCII(line) && !valid.IsUTF8(line) {
		return false // invalid policy, neither printable ASCII nor alphanumeric UTF-8 (latter is allowed in extended key/vals only)
	}
	if strings.ContainsAny(line, "{}") {
		return true // skip lines containing { or }, they are only allowed in  extended key/vals, and we don't need them anyway
	}
	keyValPair := strings.SplitN(line, ":", 2)
	if len(keyValPair) != 2 {
		return false // invalid policy
	}
	key, val := strings.TrimSpace(keyValPair[0]), strings.TrimSpace(keyValPair[1])
	if key != "mx" && p.existingKeys[key] {
		return true // only mx keys can be duplicated, others are ignored (as of [RFC 8641, 3.2])
	}
	p.existingKeys[key] = true
	p.report.WriteString(" { policy_string = ")
	p.report.WriteString(key)
	p.report.WriteString(": ")
	p.report.WriteString(val)
	p.report.WriteString(" }")
	switch key {
	case "version":
		if val != "STSv1" {
			return false
		}
		p.hasVersion = true
	case "mx":
		if strings.HasPrefix(val, "*.") {
			if !valid.IsDNSName(val[2:]) {
				return false
			}
		} else if !valid.IsDNSName(val) {
			return false
		}
		val = strings.ToLower(val)
		p.mxHosts.WriteString(" mx_host_pattern=")
		p.mxHosts.WriteString(val)
		if strings.HasPrefix(val, "*.") {
			val = val[1:]
		}
		p.mxServers = append(p.mxServers, val)
	case "mode":
		if val != "enforce" && val != "testing" && val != "none" {
			return false
		}
		p.mode = val
	case "max_age":
		age, err := strconv.ParseUint(val, 10, 64) // 10-digit value allowed despite upper limit fitting in 32 bits (see RFC Errata 7282)
		if err != nil {
			return false
		}
		if age > MTASTS_MAX_AGE { // cap to upper limit in RFC 8461
			p.maxAge = uint32(MTASTS_MAX_AGE)
		} else {
			p.maxAge = uint32(age)
		}
		p.hasMaxAge = true
	default:
	}
	return true
}

func (p *mtaStsPolicyParser) reportFor(domain string) string {
	return "policy_type=sts policy_domain=" + domain + p.mxHosts.String() + p.report.String()
}

func parseMtaStsPolicy(domain string, r io.Reader) (string, string, uint32) {
	parser := newMtaStsPolicyParser()
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if !parser.parseLine(scanner.Text()) {
			return "", "", 0
		}
	}
	if scanner.Err() != nil {
		return "", "", 0
	}
	if !parser.hasVersion || !parser.hasMaxAge {
		return "", "", 0
	}
	report := parser.reportFor(domain)

	if parser.mode == "enforce" && len(parser.mxServers) != 0 {
		res := "secure match=" + strings.Join(parser.mxServers, ":") + " servername=hostname"
		return res, report, parser.maxAge
	}

	return "", "", parser.maxAge
}

func checkMtaSts(ctx context.Context, domain string, mayRetry bool) (string, string, uint32) {
	attempts := 1
	if mayRetry {
		attempts = POLICY_ATTEMPTS
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		policy, report, ttl, err := checkMtaStsOnce(ctx, domain)
		if err == nil {
			return policy, report, ttl
		}
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return "TEMP", "", 0
		}
		if attempt == attempts {
			slog.Warn("Error during MTA-STS lookup", "domain", domain, "error", err, "attempts", attempts)
			return "TEMP", "", 0
		}
		if !waitPolicyRetry(ctx, attempt) {
			return "TEMP", "", 0
		}
	}
	return "TEMP", "", 0
}

func checkMtaStsOnce(ctx context.Context, domain string) (string, string, uint32, error) {
	hasRecord, err := checkMtaStsRecord(ctx, domain)
	if err != nil {
		return "", "", 0, err
	}
	if !hasRecord {
		return "", "", 0, nil
	}

	mtaSTSURL := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mtaSTSURL, nil)
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("User-Agent", "postfix-tlspol/"+Version)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, nil
	}

	policy, report, ttl := parseMtaStsPolicy(domain, resp.Body)
	return policy, report, ttl, nil
}

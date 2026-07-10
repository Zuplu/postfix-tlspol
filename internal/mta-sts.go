/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"

	"github.com/miekg/dns"
)

const (
	MTASTS_MAX_AGE               uint64 = 31557600 // RFC 8461, 3.2
	MTASTS_MAX_POLICY_SIZE              = 64 << 10 // RFC 8461, 3.3 recommended maximum
	MTA_STS_FETCH_RETRY_INTERVAL        = 5 * time.Minute
)

func checkMtaStsRecord(ctx context.Context, domain string, resolverAddress string) (bool, error) {
	m := newDNSQuery("_mta-sts."+domain, dns.TypeTXT, false)
	r, err := exchangeDNS(ctx, m, resolverAddress)
	if err != nil {
		return false, err
	}
	return mtaStsRecordAvailable(r)
}

func mtaStsRecordAvailable(r *dns.Msg) (bool, error) {
	switch r.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return false, nil
	default:
		return false, errors.New(dns.RcodeToString[r.Rcode])
	}

	var candidates []string
	for _, answer := range r.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}
		record := strings.Join(txt.Txt, "")
		if isMtaStsTXTVersionCandidate(record) {
			candidates = append(candidates, record)
		}
	}
	return len(candidates) == 1 && isValidMtaStsTXTRecord(candidates[0]), nil
}

func isMtaStsTXTVersionCandidate(record string) bool {
	const version = "v=STSv1"
	if !strings.HasPrefix(record, version) {
		return false
	}
	rest := record[len(version):]
	for len(rest) != 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	return len(rest) != 0 && rest[0] == ';'
}

func isValidMtaStsTXTRecord(record string) bool {
	if !isMtaStsTXTASCII(record) || !isMtaStsTXTVersionCandidate(record) {
		return false
	}
	fields := strings.Split(record, ";")
	if strings.TrimRight(fields[0], " \t") != "v=STSv1" {
		return false
	}
	hasID := false
	for i, rawField := range fields[1:] {
		lastField := i == len(fields)-2
		field := strings.TrimLeft(rawField, " \t")
		if !lastField {
			field = strings.TrimRight(field, " \t")
		}
		if field == "" {
			if lastField {
				continue
			}
			return false
		}
		keyValue := strings.SplitN(field, "=", 2)
		if len(keyValue) != 2 {
			return false
		}
		key, value := keyValue[0], keyValue[1]
		if key == "id" {
			if hasID {
				continue
			}
			if len(value) == 0 || len(value) > 32 {
				return false
			}
			for i := 0; i < len(value); i++ {
				if !isMtaStsAlphanum(value[i]) {
					return false
				}
			}
			hasID = true
			continue
		}
		if !isMtaStsExtensionName(key) || !isMtaStsTXTExtensionValue(value) {
			return false
		}
	}
	return hasID
}

func isMtaStsTXTASCII(record string) bool {
	for i := 0; i < len(record); i++ {
		if record[i] != '\t' && (record[i] < 0x20 || record[i] > 0x7e) {
			return false
		}
	}
	return true
}

func isMtaStsTXTExtensionValue(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !(c >= 0x21 && c <= 0x3a || c == 0x3c || c >= 0x3e && c <= 0x7e) {
			return false
		}
	}
	return true
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
	hasMode      bool
	hasVersion   bool
}

func newMtaStsPolicyParser() mtaStsPolicyParser {
	return mtaStsPolicyParser{
		existingKeys: make(map[string]bool),
	}
}

func isMtaStsAlphanum(b byte) bool {
	return b >= 'a' && b <= 'z' ||
		b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9'
}

func isMtaStsExtensionName(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	if !isMtaStsAlphanum(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !isMtaStsAlphanum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

func isMtaStsExtensionValue(s string) bool {
	if len(s) == 0 || !utf8.ValidString(s) {
		return false
	}
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		switch {
		case r == ' ':
		case r >= 0x21 && r <= 0x7e:
		case r >= 0x80 && !unicode.IsControl(r):
		default:
			return false
		}
		s = s[size:]
	}
	return true
}

func isMtaStsDigits(s string) bool {
	if len(s) == 0 || len(s) > 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (p *mtaStsPolicyParser) writeReportField(key, val string) {
	p.report.WriteString(" { policy_string = ")
	p.report.WriteString(key)
	p.report.WriteString(": ")
	p.report.WriteString(val)
	p.report.WriteString(" }")
}

//gocyclo:ignore
func (p *mtaStsPolicyParser) parseLine(line string) bool {
	line = strings.TrimRight(line, " \t")
	lineLen := len(line)
	if lineLen == 0 {
		return false
	}
	keyValPair := strings.SplitN(line, ":", 2)
	if len(keyValPair) != 2 {
		return false // invalid policy
	}
	key, val := keyValPair[0], strings.TrimLeft(keyValPair[1], " \t")
	reportVal := val
	isExtension := key != "version" && key != "mode" && key != "mx" && key != "max_age"
	if isExtension && !isMtaStsExtensionName(key) {
		return false
	}
	if key != "mx" && p.existingKeys[key] {
		return true // Only mx keys can be repeated; later values are ignored per RFC 8461, Section 3.2.
	}
	p.existingKeys[key] = true
	switch key {
	case "version":
		if val != "STSv1" {
			return false
		}
		p.hasVersion = true
		p.writeReportField(key, reportVal)
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
		p.writeReportField(key, reportVal)
	case "mode":
		if val != "enforce" && val != "testing" && val != "none" {
			return false
		}
		p.mode = val
		p.hasMode = true
		p.writeReportField(key, reportVal)
	case "max_age":
		if !isMtaStsDigits(val) {
			return false
		}
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
		p.writeReportField(key, reportVal)
	default:
		if !isMtaStsExtensionValue(val) {
			return false
		}
		if strings.ContainsAny(val, "{}") {
			return true // avoid copying extension braces into the report field syntax
		}
		p.writeReportField(key, reportVal)
	}
	return true
}

func (p *mtaStsPolicyParser) reportFor(domain string) string {
	return "policy_type=sts policy_domain=" + domain + p.mxHosts.String() + p.report.String()
}

func parseMtaStsPolicy(domain string, r io.Reader) (string, string, uint32) {
	body, err := io.ReadAll(io.LimitReader(r, MTASTS_MAX_POLICY_SIZE+1))
	if err != nil || len(body) > MTASTS_MAX_POLICY_SIZE {
		return "", "", 0
	}
	parser := newMtaStsPolicyParser()
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		if !parser.parseLine(scanner.Text()) {
			return "", "", 0
		}
	}
	if scanner.Err() != nil {
		return "", "", 0
	}
	if !parser.hasVersion || !parser.hasMode || !parser.hasMaxAge || (parser.mode != "none" && len(parser.mxServers) == 0) {
		return "", "", 0
	}
	report := parser.reportFor(domain)

	if parser.mode == "enforce" && len(parser.mxServers) != 0 {
		res := "secure match=" + strings.Join(parser.mxServers, ":") + " servername=hostname"
		return res, report, parser.maxAge
	}

	return "", "", parser.maxAge
}

func isValidMtaStsPolicyMediaType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mediaType, "text/plain") {
		return false
	}
	return true
}

func checkMtaSts(ctx context.Context, domain string, mayRetry bool) (string, string, uint32) {
	resolverAddress, err := config.Dns.GetResolverAddress()
	if err != nil {
		slog.Warn("DNS resolver configuration error during MTA-STS lookup", "domain", domain, "error", err)
		return "TEMP", "", 0
	}
	attempts := 1
	if mayRetry {
		attempts = POLICY_ATTEMPTS
	}
	for attempt := 1; attempt <= attempts; attempt++ {
		policy, report, ttl, err := checkMtaStsOnce(ctx, domain, resolverAddress)
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

func checkMtaStsOnce(ctx context.Context, domain string, resolverAddress string) (string, string, uint32, error) {
	hasRecord, err := checkMtaStsRecord(ctx, domain, resolverAddress)
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
	if !isValidMtaStsPolicyMediaType(resp.Header.Get("Content-Type")) {
		return "", "", 0, nil
	}

	policy, report, ttl := parseMtaStsPolicy(domain, resp.Body)
	return policy, report, ttl, nil
}

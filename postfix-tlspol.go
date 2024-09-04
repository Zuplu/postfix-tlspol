/*
 * MIT License
 * Copyright (c) 2024 Zuplu
 */

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-redis/redis/v8"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
)

const VERSION = "0.1.1-dev"

type ServerConfig struct {
	Address string `yaml:"address"`
	TlsRpt  bool   `yaml:"tlsrpt"`
}

type DNSConfig struct {
	Address string `yaml:"address"`
}

type RedisConfig struct {
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type Config struct {
	Server ServerConfig `yaml:"server"`
	DNS    DNSConfig    `yaml:"dns"`
	Redis  RedisConfig  `yaml:"redis"`
}

type ResultWithTtl struct {
	Result bool
	Ttl    uint32
	Err    error
}

const (
	CACHE_KEY_PREFIX = "TLSPOL-"
	CACHE_MIN        = 300
	REQUEST_TIMEOUT  = 5 * time.Second
)

var (
	ctx    = context.Background()
	config Config
	client *redis.Client
)

func printVersion() {
	fmt.Println("postfix-tlspol (c) 2024 Zuplu — v" + VERSION + "\nThis program is licensed under the MIT License.")
}

func main() {
	// Print version at start
	printVersion()

	if len(os.Args) < 2 {
		fmt.Println("Usage: postfix-tlspol <config.yaml>")
		return
	}

	param := os.Args[1]
	if strings.ToLower(param) == "version" {
		return
	}

	// Read config.yaml
	var err error
	config, err = loadConfig(param)
	if err != nil {
		fmt.Println("Error loading config:", err)
		return
	}

	// Setup redis client for cache
	client = redis.NewClient(&redis.Options{
		Addr:     config.Redis.Address,
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	// Start the socketmap server for Postfix
	go startTcpServer()

	// Keep the main function alive
	select {}
}

func startTcpServer() {
	listener, err := net.Listen("tcp", config.Server.Address)
	if err != nil {
		fmt.Println("Error starting TCP server:", err)
		return
	}
	defer listener.Close()

	fmt.Printf("Listening on %s...\n", config.Server.Address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the incoming query
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Println("Error reading from connection:", err)
		return
	}
	query := strings.TrimSpace(string(buffer[:n]))
	parts := strings.Split(query, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		subParts := strings.SplitN(part, ":", 2)
		if len(subParts) > 1 {
			query = strings.TrimSpace(subParts[1])
		}
	}
	parts = strings.SplitN(query, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "query" {
		fmt.Printf("Malformed query: %s\n", query)
		conn.Write([]byte("5:PERM ,"))
		return
	}

	// Parse domain from query and validate
	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	if govalidator.IsIPv4(domain) || govalidator.IsIPv6(domain) {
		fmt.Printf("Skipping policy for non-domain %s\n", domain)
		conn.Write([]byte("9:NOTFOUND ,"))
		return
	}
	if strings.HasPrefix(domain, ".") {
		fmt.Printf("Skipping policy for parent domain %s\n", domain)
		conn.Write([]byte("9:NOTFOUND ,"))
		return
	}

	suffix := ""
	if config.Server.TlsRpt {
		suffix = "!TLSRPT" // configurable option needs unique cache key
	}
	hashedDomain := sha256.Sum256([]byte(domain + suffix))
	cacheKey := CACHE_KEY_PREFIX + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hashedDomain[:])
	cachedResult, err := client.Get(ctx, cacheKey).Result()
	if err == nil {
		if cachedResult == "" {
			fmt.Printf("No policy found for %s (from cache)\n", domain)
			conn.Write([]byte("9:NOTFOUND ,"))

		} else {
			fmt.Printf("Evaluated policy for %s: %s (from cache)\n", domain, cachedResult)
			conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(cachedResult)+3, cachedResult)))
		}
		return
	}

	result := ""
	var resultTtl int32 = CACHE_MIN
	var mutex sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)

	// DANE query
	var daneTtl uint32 = 0
	go func() {
		defer wg.Done()
		var danePol string
		danePol, daneTtl = checkDane(domain)
		mutex.Lock()
		if danePol != "" {
			result = danePol
			resultTtl = int32(daneTtl)
		}
		mutex.Unlock()
	}()

	// MTA-STS query
	var stsTtl uint32 = 0
	go func() {
		defer wg.Done()
		var stsPol string
		stsPol, stsTtl = checkMtaSts(domain)
		mutex.Lock()
		if stsPol != "" && result == "" {
			result = stsPol
			resultTtl = int32(stsTtl)
		}
		mutex.Unlock()
	}()

	// Wait for completion
	wg.Wait()

	if result == "" {
		resultTtl = CACHE_MIN
		fmt.Printf("No policy found for %s (cached for %ds)\n", domain, resultTtl)
		conn.Write([]byte("9:NOTFOUND ,"))
	} else if result == "TEMP" {
		resultTtl = 10
		fmt.Printf("Evaluating policy for %s failed temporarily (cached for %ds)\n", domain, resultTtl)
		conn.Write([]byte("5:TEMP ,"))
	} else {
		fmt.Printf("Evaluated policy for %s: %s (cached for %ds)\n", domain, result, resultTtl)
		conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(result)+3, result)))
	}

	client.Set(ctx, cacheKey, result, time.Duration(resultTtl)*time.Second).Err()
}

func loadConfig(filename string) (Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	return config, yaml.Unmarshal(data, &config)
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

func checkMtaStsRecord(domain string) (bool, error) {
	client := &dns.Client{Timeout: REQUEST_TIMEOUT}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_mta-sts."+domain), dns.TypeTXT)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := client.Exchange(m, config.DNS.Address)
	if err != nil {
		return false, fmt.Errorf("DNS error")
	}
	if r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return false, fmt.Errorf("DNS error")
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

func checkMtaSts(domain string) (string, uint32) {
	hasRecord, err := checkMtaStsRecord(domain)
	if err != nil {
		return "TEMP", 0
	}
	if !hasRecord {
		return "", 0
	}

	client := &http.Client{
		// Disable following redirects (see [RFC 8461, 3.3])
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, // Ensure SSL certificate validation
			},
			DisableKeepAlives: true,
		},
		Timeout: REQUEST_TIMEOUT, // Set a timeout for the request
	}

	mtaSTSURL := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	resp, err := client.Get(mtaSTSURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", 0
	}
	defer resp.Body.Close()

	var mxServers []string
	mode := ""
	var maxAge uint32 = 0
	policy := ""
	mxHosts := ""
	existingKeys := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !govalidator.IsPrintableASCII(line) && !govalidator.IsUTFLetterNumeric(line) {
			return "", 0 // invalid policy
		}
		keyValPair := strings.SplitN(line, ":", 2)
		if len(keyValPair) != 2 {
			return "", 0 // invalid policy
		}
		key, val := strings.TrimSpace(keyValPair[0]), strings.TrimSpace(keyValPair[1])
		if key != "mx" && existingKeys[key] {
			continue // only mx keys can be duplicated, others are ignored (as of [RFC 8641, 3.2])
		}
		existingKeys[key] = true
		policy = policy + " { policy_string = " + key + ": " + val + " }"
		switch key {
		case "mode":
			mode = val
		case "mx":
			if !govalidator.IsDNSName(strings.ReplaceAll(val, "*.", "")) {
				return "", 0 // invalid policy
			}
			mxHosts = mxHosts + " mx_host_pattern=" + val
			if strings.HasPrefix(val, "*.") {
				val = val[1:]
			}
			mxServers = append(mxServers, val)
		case "max_age":
			age, err := strconv.ParseUint(val, 10, 32)
			if err == nil {
				maxAge = uint32(age)
			}
		}
	}
	policy = " policy_type=sts policy_domain=" + domain + fmt.Sprintf(" policy_ttl=%d", maxAge) + policy + mxHosts

	if mode == "enforce" {
		res := "secure match=" + strings.Join(mxServers, ":") + " servername=hostname"
		if config.Server.TlsRpt {
			res = res + policy
		}
		return res, maxAge
	}

	return "", maxAge
}

func findMin(arr []uint32) uint32 {
	if len(arr) == 0 {
		return 0
	}

	min := arr[0]
	for _, v := range arr {
		if v < min {
			min = v
		}
	}
	return min
}

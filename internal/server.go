/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"github.com/asaskevich/govalidator/v11"
	"github.com/miekg/dns"
	"github.com/neilotoole/jsoncolor"
	"github.com/redis/go-redis/v9"
)

type CacheStruct struct {
	Domain string `json:"d"`
	Result string `json:"r"`
	Report string `json:"p"`
	Ttl    uint32 `json:"t"`
}

const (
	DB_SCHEMA          = "3"
	CACHE_KEY_PREFIX   = "TLSPOL-"
	CACHE_NOTFOUND_TTL = 900
	CACHE_MIN_TTL      = 180
	REQUEST_TIMEOUT    = 5 * time.Second
)

var (
	VERSION     = "undefined"
	bgCtx       = context.Background()
	client      = new(dns.Client)
	config      Config
	redisClient *redis.Client
)

var showVersion = false
var configFile string
var queryMode = false

func init() {
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.StringVar(&configFile, "config", "configs/config.yaml", "Path to the config.yaml")
	flag.String("query", "", "Query a domain")
}

func flagQueryFunc(f *flag.Flag) {
	if (*f).Name != "query" {
		return
	}
	queryMode = true
	domain := (*f).Value
	conn, err := net.Dial("tcp", config.Server.Address)
	if err != nil {
		log.Errorf("Could not query domain %q. Is postfix-tlspol running? (%v)", domain, err)
		return
	}
	defer conn.Close()
	fmt.Fprintf(conn, ":json %s", domain)
	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		log.Errorf("Could not query domain %q. (%v)", domain, err)
		return
	}
	result := new(Result)
	err = json.Unmarshal(raw, &result)
	if err != nil {
		log.Errorf("Could not query domain %q. (%v)", domain, err)
		return
	}
	o, err := os.Stdout.Stat()
	if err == nil && (o.Mode()&os.ModeCharDevice) != 0 {
		enc := jsoncolor.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetColors(jsoncolor.DefaultColors())
		err = enc.Encode(result)
	} else {
		enc := json.NewEncoder(os.Stdout)
		err = enc.Encode(result)
	}
	if err != nil {
		log.Errorf("Could not query domain %q. (%v)", domain, err)
		return
	}
	return
}

func main() {
	curYear, _, _ := time.Now().Date()
	fmt.Fprintf(os.Stderr, "postfix-tlspol (c) 2024-%d Zuplu — %s\nThis program is licensed under the MIT License.\n\n", curYear, VERSION)

	flag.Parse()

	if showVersion {
		fmt.Printf("Version: %s\n\n", VERSION)
		return
	}

	// Read config.yaml
	var err error
	config, err = loadConfig(configFile)

	flag.Visit(flagQueryFunc)

	if queryMode {
		return
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	if err != nil {
		log.Errorf("Error loading config: %v", err)
		return
	}

	envPrefetch, envExists := os.LookupEnv("TLSPOL_PREFETCH")
	if envExists {
		config.Server.Prefetch = envPrefetch == "1"
	}
	envTlsRpt, envExists := os.LookupEnv("TLSPOL_TLSRPT")
	if envExists {
		config.Server.TlsRpt = envTlsRpt == "1"
	}

	if !config.Redis.Disable {
		// Setup redis client for cache
		redisClient = redis.NewClient(&redis.Options{
			Addr:     config.Redis.Address,
			Password: config.Redis.Password,
			DB:       config.Redis.DB,
		})
		go func() {
			updateDatabase()
			if config.Server.Prefetch {
				log.Info("Prefetching enabled!")
				startPrefetching()
			}
		}()
	} else if config.Server.Prefetch {
		log.Warn("Cannot prefetch with Redis disabled!")
	}

	// Start the socketmap server for Postfix
	startTcpServer()
}

func startTcpServer() {
	listener, err := net.Listen("tcp", config.Server.Address)
	if err != nil {
		log.Errorf("Error starting TCP server: %v", err)
		return
	}
	defer listener.Close()

	log.Debugf("Listening on %s...", config.Server.Address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func parseQuery(rawQuery []byte) string {
	query := strings.TrimSpace(string(rawQuery))
	parts := strings.Split(query, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		subParts := strings.SplitN(part, ":", 2)
		if len(subParts) > 1 {
			query = strings.TrimSpace(subParts[1])
		}
	}
	return query
}

func getCacheKey(domain *string) string {
	hash := sha256.Sum256([]byte(*domain))
	return CACHE_KEY_PREFIX + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
}

func tryCachedPolicy(conn *net.Conn, domain *string, cacheKey *string) bool {
	if !config.Redis.Disable {
		cache, ttl, err := cacheJsonGet(redisClient, cacheKey)
		if err == nil && ttl > PREFETCH_MARGIN {
			ttl := ttl - PREFETCH_MARGIN
			switch cache.Result {
			case "":
				log.Infof("No policy found for %q (from cache, %ds remaining)", *domain, ttl)
				(*conn).Write([]byte("9:NOTFOUND ,"))
			case "TEMP":
				log.Warnf("Evaluating policy for %q failed temporarily (from cache, %ds remaining)", *domain, ttl)
				(*conn).Write([]byte("5:TEMP ,"))
			default:
				log.Infof("Evaluated policy for %q: %s (from cache, %ds remaining)", *domain, cache.Result, ttl)
				if config.Server.TlsRpt {
					cache.Result = cache.Result + " " + cache.Report
				}
				(*conn).Write([]byte(fmt.Sprintf("%d:OK %s,", len(cache.Result)+3, cache.Result)))
			}
			return true
		}
	}
	return false
}

type DanePolicy struct {
	Policy string `json:"policy"`
	Ttl    uint32 `json:"ttl"`
	Time   string `json:"time"`
}
type MtaStsPolicy struct {
	Policy string `json:"policy"`
	Ttl    uint32 `json:"ttl"`
	Report string `json:"report"`
	Time   string `json:"time"`
}
type Result struct {
	Domain string       `json:"domain"`
	Dane   DanePolicy   `json:"dane"`
	MtaSts MtaStsPolicy `json:"mta-sts"`
}

func replyJson(ctx *context.Context, conn *net.Conn, domain *string) {
	ta := time.Now()
	dPol, dTtl := checkDane(ctx, domain)
	tb := time.Now()
	msPol, msRpt, msTtl := checkMtaSts(ctx, domain)
	tc := time.Now()

	r := Result{
		Domain: *domain,
		Dane: DanePolicy{
			Policy: dPol,
			Ttl:    dTtl,
			Time:   tb.Sub(ta).Truncate(time.Millisecond).String(),
		},
		MtaSts: MtaStsPolicy{
			Policy: msPol,
			Ttl:    msTtl,
			Report: msRpt,
			Time:   tc.Sub(tb).Truncate(time.Millisecond).String(),
		},
	}

	b, err := json.Marshal(r)
	if err != nil {
		log.Errorf("Could not marshal JSON: %v", err)
		return
	}

	(*conn).Write(b)
	(*conn).Write([]byte("\n"))
}

func replySocketmap(conn *net.Conn, domain *string, policy *string, report *string, ttl *uint32) {
	switch *policy {
	case "":
		log.Infof("No policy found for %q (cached for %ds)", *domain, *ttl)
		(*conn).Write([]byte("9:NOTFOUND ,"))
	case "TEMP":
		log.Warnf("Evaluating policy for %q failed temporarily (cached for %ds)", *domain, *ttl)
		(*conn).Write([]byte("5:TEMP ,"))
	default:
		log.Infof("Evaluated policy for %q: %s (cached for %ds)", *domain, *policy, *ttl)
		res := *policy
		if config.Server.TlsRpt {
			res = res + " " + (*report)
		}
		(*conn).Write([]byte(fmt.Sprintf("%d:OK %s,", len(res)+3, res)))
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the incoming query
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Errorf("Error reading from connection: %v", err)
		return
	}
	query := parseQuery(buffer[:n])
	parts := strings.SplitN(query, " ", 2)
	if len(parts) != 2 {
		log.Warnf("Malformed query: %q", query)
		conn.Write([]byte("5:PERM ,"))
		return
	}
	cmd := strings.ToLower(parts[0])
	if cmd != "query" && cmd != "json" {
		log.Warnf("Unknown command: %q", query)
		conn.Write([]byte("5:PERM ,"))
		return
	}

	// Parse domain from query
	domain := strings.ToLower(strings.TrimSpace(parts[1]))

	if cmd == "json" {
		ctx, cancel := context.WithTimeout(bgCtx, REQUEST_TIMEOUT)
		defer cancel()
		replyJson(&ctx, &conn, &domain)
		return
	}

	// Validate domain
	if govalidator.IsIPv4(domain) || govalidator.IsIPv6(domain) {
		log.Debugf("Skipping policy for non-domain: %q", domain)
		conn.Write([]byte("9:NOTFOUND ,"))
		return
	}
	if strings.HasPrefix(domain, ".") {
		log.Debugf("Skipping policy for parent domain: %q", domain)
		conn.Write([]byte("9:NOTFOUND ,"))
		return
	}

	cacheKey := getCacheKey(&domain)
	if tryCachedPolicy(&conn, &domain, &cacheKey) {
		return
	}

	policy, report, ttl := queryDomain(&domain)

	replySocketmap(&conn, &domain, &policy, &report, &ttl)

	if !config.Redis.Disable {
		cacheJsonSet(redisClient, &cacheKey, &CacheStruct{Domain: domain, Result: policy, Report: report, Ttl: ttl})
	}
}

type PolicyResult struct {
	IsDane bool
	Policy string
	Rpt    string
	Ttl    uint32
}

func queryDomain(domain *string) (string, string, uint32) {
	results := make(chan PolicyResult)
	ctx, cancel := context.WithTimeout(bgCtx, REQUEST_TIMEOUT)
	defer cancel()

	// DANE query
	go func() {
		policy, ttl := checkDane(&ctx, domain)
		results <- PolicyResult{IsDane: true, Policy: policy, Rpt: "", Ttl: ttl}
	}()

	// MTA-STS query
	go func() {
		policy, rpt, ttl := checkMtaSts(&ctx, domain)
		results <- PolicyResult{IsDane: false, Policy: policy, Rpt: rpt, Ttl: ttl}
	}()

	policy, report := "", ""
	var ttl uint32 = CACHE_NOTFOUND_TTL
	var i uint8 = 0
	for r := range results {
		i++
		if i >= 2 {
			close(results)
		}
		policy = r.Policy
		report = r.Rpt
		ttl = r.Ttl
		if r.IsDane && r.Policy != "" {
			break
		}
	}

	if policy == "" {
		ttl = CACHE_NOTFOUND_TTL
	} else if policy == "TEMP" || ttl < CACHE_MIN_TTL {
		ttl = CACHE_MIN_TTL
	}

	return policy, report, ttl
}

func cacheJsonGet(redisClient *redis.Client, cacheKey *string) (CacheStruct, uint32, error) {
	var data CacheStruct

	jsonData, err := redisClient.Get(bgCtx, *cacheKey).Result()
	if err != nil {
		return data, 0, err
	}

	ttl, err := redisClient.TTL(bgCtx, *cacheKey).Result()
	if err != nil {
		log.Warnf("Error getting TTL: %v", err)
		return data, 0, err
	}

	return data, uint32(ttl.Seconds()), json.Unmarshal([]byte(jsonData), &data)
}

func cacheJsonSet(redisClient *redis.Client, cacheKey *string, data *CacheStruct) error {
	jsonData, err := json.Marshal(*data)
	if err != nil {
		return fmt.Errorf("Error marshaling JSON: %v", err)
	}

	return redisClient.Set(bgCtx, *cacheKey, jsonData, time.Duration(data.Ttl+PREFETCH_MARGIN-rand.Uint32N(60))*time.Second).Err()
}

func updateDatabase() error {
	schemaKey := CACHE_KEY_PREFIX + "schema"

	currentSchema, err := redisClient.Get(bgCtx, schemaKey).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("error getting schema from Redis: %v", err)
	}

	// Check if the schema matches, else clear the database
	if currentSchema != DB_SCHEMA {
		keys, err := redisClient.Keys(bgCtx, CACHE_KEY_PREFIX+"*").Result()
		if err != nil {
			return fmt.Errorf("error fetching keys: %v", err)
		}
		for _, key := range keys {
			redisClient.Del(bgCtx, key).Err()
		}
		return redisClient.Set(bgCtx, schemaKey, DB_SCHEMA, 0).Err()
	}

	return nil
}

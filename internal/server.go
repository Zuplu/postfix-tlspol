/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/miekg/dns"
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

func printVersion() {
	curYear, _, _ := time.Now().Date()
	log.Infof("postfix-tlspol (c) 2024-%d Zuplu — %s\nThis program is licensed under the MIT License.\n", curYear, VERSION)
}

func main() {
	// Print version at start
	printVersion()

	if len(os.Args) < 2 {
		log.Info("Usage: postfix-tlspol <config.yaml>")
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

func tryCachedPolicy(domain *string, cacheKey *string, conn *net.Conn) bool {
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

func replyJson(ctx *context.Context, conn *net.Conn, domain *string) {
	type DanePolicy struct {
		Policy string `json:"policy"`
		Ttl    uint32 `json:"ttl"`
	}
	type MtaStsPolicy struct {
		Policy string `json:"policy"`
		Ttl    uint32 `json:"ttl"`
		Report string `json:"report"`
	}
	type Result struct {
		Dane   DanePolicy   `json:"dane"`
		MtaSts MtaStsPolicy `json:"mta-sts"`
	}
	dPol, dTtl := checkDane(ctx, domain)
	msPol, msRpt, msTtl := checkMtaSts(ctx, domain)
	r := Result{
		Dane: DanePolicy{
			Policy: dPol,
			Ttl:    dTtl,
		},
		MtaSts: MtaStsPolicy{
			Policy: msPol,
			Ttl:    msTtl,
			Report: msRpt,
		},
	}
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	(*conn).Write(b)
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
	if tryCachedPolicy(&domain, &cacheKey, &conn) {
		return
	}

	result, resultRpt, resultTtl := queryDomain(&domain)

	switch result {
	case "":
		log.Infof("No policy found for %q (cached for %ds)", domain, resultTtl)
		conn.Write([]byte("9:NOTFOUND ,"))
	case "TEMP":
		log.Warnf("Evaluating policy for %q failed temporarily (cached for %ds)", domain, resultTtl)
		conn.Write([]byte("5:TEMP ,"))
	default:
		log.Infof("Evaluated policy for %q: %s (cached for %ds)", domain, result, resultTtl)
		res := result
		if config.Server.TlsRpt {
			res = res + " " + resultRpt
		}
		conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(res)+3, res)))
	}

	if !config.Redis.Disable {
		cacheJsonSet(redisClient, &cacheKey, &CacheStruct{Domain: domain, Result: result, Report: resultRpt, Ttl: resultTtl})
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

	result, resultRpt := "", ""
	var resultTtl uint32 = CACHE_NOTFOUND_TTL
	var i uint8 = 0
	for r := range results {
		i++
		if i >= 2 {
			close(results)
		}
		result = r.Policy
		resultRpt = r.Rpt
		resultTtl = r.Ttl
		if r.IsDane && r.Policy != "" {
			break
		}
	}

	if result == "" {
		resultTtl = CACHE_NOTFOUND_TTL
	} else if result == "TEMP" || resultTtl < CACHE_MIN_TTL {
		resultTtl = CACHE_MIN_TTL
	}

	return result, resultRpt, resultTtl
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

func findMax(arr []uint32) uint32 {
	if len(arr) == 0 {
		return 0
	}
	max := arr[0]
	for _, v := range arr {
		if v > max {
			max = v
		}
	}
	return max
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

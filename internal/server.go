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
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
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
	CACHE_MIN_TTL      = 60
	REQUEST_TIMEOUT    = 5 * time.Second
)

var (
	VERSION     = "undefined"
	ctx         = context.Background()
	config      Config
	redisClient *redis.Client
)

func printVersion() {
	curYear, _, _ := time.Now().Date()
	log.Infof("postfix-tlspol (c) 2024-%d Zuplu — %s\nThis program is licensed under the MIT License.", curYear, VERSION)
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
		go updateDatabase()
	}

	// Start the socketmap server for Postfix
	go startTcpServer()

	if config.Server.Prefetch {
		if config.Redis.Disable {
			log.Error("Cannot prefetch with Redis disabled!")
		} else {
			log.Info("Prefetching enabled!")
			go startPrefetching()
		}
	}

	// Keep the main function alive
	select {}
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

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read the incoming query
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Errorf("Error reading from connection: %v", err)
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
		log.Warnf("Malformed query: %s", query)
		conn.Write([]byte("5:PERM ,"))
		return
	}

	// Parse domain from query and validate
	domain := strings.ToLower(strings.TrimSpace(parts[1]))
	if govalidator.IsIPv4(domain) || govalidator.IsIPv6(domain) {
		log.Debugf("Skipping policy for non-domain %s", domain)
		conn.Write([]byte("9:NOTFOUND ,"))
		return
	}
	if strings.HasPrefix(domain, ".") {
		log.Debugf("Skipping policy for parent domain %s", domain)
		conn.Write([]byte("9:NOTFOUND ,"))
		return
	}

	var cacheKey string
	if !config.Redis.Disable {
		hashedDomain := sha256.Sum256([]byte(domain))
		cacheKey = CACHE_KEY_PREFIX + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hashedDomain[:])
		cache, ttl, err := cacheJsonGet(redisClient, cacheKey)
		if err == nil && ttl > PREFETCH_MARGIN {
			if cache.Result == "" {
				log.Infof("No policy found for %s (from cache, %ds remaining)", domain, ttl)
				conn.Write([]byte("9:NOTFOUND ,"))
			} else if cache.Result == "TEMP" {
				log.Warnf("Evaluating policy for %s failed temporarily (from cache, %ds remaining)", domain, ttl)
				conn.Write([]byte("5:TEMP ,"))
			} else {
				log.Infof("Evaluated policy for %s: %s (from cache, %ds remaining)", domain, cache.Result, ttl)
				if config.Server.TlsRpt {
					cache.Result = cache.Result + " " + cache.Report
				}
				conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(cache.Result)+3, cache.Result)))
			}
			return
		}
	}

	result, resultRpt, resultTtl := queryDomain(domain, true)

	if result == "" {
		log.Infof("No policy found for %s (cached for %ds)", domain, resultTtl)
		conn.Write([]byte("9:NOTFOUND ,"))
	} else if result == "TEMP" {
		log.Warnf("Evaluating policy for %s failed temporarily (cached for %ds)", domain, resultTtl)
		conn.Write([]byte("5:TEMP ,"))
	} else {
		log.Infof("Evaluated policy for %s: %s (cached for %ds)", domain, result, resultTtl)
		res := result
		if config.Server.TlsRpt {
			res = res + " " + resultRpt
		}
		conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(res)+3, res)))
	}

	if !config.Redis.Disable {
		cacheJsonSet(redisClient, cacheKey, CacheStruct{Domain: domain, Result: result, Report: resultRpt, Ttl: resultTtl})
	}
}

func queryDomain(domain string, parallelize bool) (string, string, uint32) {
	result := ""
	resultRpt := ""
	var resultTtl uint32 = CACHE_NOTFOUND_TTL
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// DANE query
	wg.Add(1)
	go func() {
		defer wg.Done()
		danePol, daneTtl := checkDane(domain)
		mutex.Lock()
		if danePol != "" {
			result = danePol
			resultRpt = ""
			resultTtl = daneTtl
		}
		mutex.Unlock()
	}()

	if !parallelize {
		wg.Wait()
	}

	// MTA-STS query
	wg.Add(1)
	go func() {
		defer wg.Done()
		if result != "" {
			return
		}
		var stsPol string
		stsPol, stsRpt, stsTtl := checkMtaSts(domain)
		mutex.Lock()
		if stsPol != "" && result == "" {
			result = stsPol
			resultRpt = stsRpt
			resultTtl = stsTtl
		}
		mutex.Unlock()
	}()

	// Wait for completion
	wg.Wait()

	if result == "" {
		resultTtl = CACHE_NOTFOUND_TTL
	} else if result == "TEMP" || resultTtl < CACHE_MIN_TTL {
		resultTtl = CACHE_MIN_TTL
	}

	return result, resultRpt, resultTtl
}

func cacheJsonGet(redisClient *redis.Client, cacheKey string) (CacheStruct, uint32, error) {
	var data CacheStruct

	jsonData, err := redisClient.Get(ctx, cacheKey).Result()
	if err != nil {
		return data, 0, err
	}

	ttl, err := redisClient.TTL(ctx, cacheKey).Result()
	if err != nil {
		log.Warnf("Error getting TTL: %v", err)
		return data, 0, err
	}

	return data, uint32(ttl.Seconds() - PREFETCH_MARGIN), json.Unmarshal([]byte(jsonData), &data)
}

func cacheJsonSet(redisClient *redis.Client, cacheKey string, data CacheStruct) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}

	return redisClient.Set(ctx, cacheKey, jsonData, time.Duration(data.Ttl+PREFETCH_MARGIN)*time.Second).Err()
}

func updateDatabase() error {
	schemaKey := CACHE_KEY_PREFIX + "schema"

	currentSchema, err := redisClient.Get(ctx, schemaKey).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("error getting schema from Redis: %v", err)
	}

	// Check if the schema matches, else clear the database
	if currentSchema != DB_SCHEMA {
		keys, err := redisClient.Keys(ctx, CACHE_KEY_PREFIX+"*").Result()
		if err != nil {
			return fmt.Errorf("error fetching keys: %v", err)
		}
		for _, key := range keys {
			redisClient.Del(ctx, key).Err()
		}
		return redisClient.Set(ctx, schemaKey, DB_SCHEMA, 0).Err()
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

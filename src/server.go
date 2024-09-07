/*
 * MIT License
 * Copyright (c) 2024 Zuplu
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-redis/redis/v8"
)

const VERSION = "1.1.0"

type CacheStruct struct {
	Domain string `json:"d"`
	Result string `json:"r"`
	Ttl    uint32 `json:"t"`
}

const (
	CACHE_KEY_PREFIX   = "TLSPOL-"
	CACHE_NOTFOUND_TTL = 180
	CACHE_MIN_TTL      = 60
	REQUEST_TIMEOUT    = 5 * time.Second
)

var (
	ctx         = context.Background()
	config      Config
	redisClient *redis.Client
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

	if !config.Redis.Disable {
		// Setup redis client for cache
		redisClient = redis.NewClient(&redis.Options{
			Addr:     config.Redis.Address,
			Password: config.Redis.Password,
			DB:       config.Redis.DB,
		})
	}

	// Start the socketmap server for Postfix
	go startTcpServer()

	if config.Server.Prefetch {
		go startPrefetching()
	}

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

	var cacheKey string
	if !config.Redis.Disable {
		suffix := "!" + VERSION // resets cache after updates
		if config.Server.TlsRpt {
			suffix = suffix + "!TLSRPT" // configurable option needs unique cache key
		}
		hashedDomain := sha256.Sum256([]byte(domain + suffix))
		cacheKey = CACHE_KEY_PREFIX + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hashedDomain[:])
		cache, ttl, err := cacheJsonGet(redisClient, cacheKey)
		if err == nil {
			if cache.Result == "" {
				fmt.Printf("No policy found for %s (from cache, %ds remaining)\n", domain, ttl)
				conn.Write([]byte("9:NOTFOUND ,"))

			} else {
				fmt.Printf("Evaluated policy for %s: %s (from cache, %ds remaining)\n", domain, cache.Result, ttl)
				conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(cache.Result)+3, cache.Result)))
			}
			return
		}
	}

	result, resultTtl := queryDomain(domain)

	if result == "" {
		conn.Write([]byte("9:NOTFOUND ,"))
	} else if result == "TEMP" {
		conn.Write([]byte("5:TEMP ,"))
	} else {
		conn.Write([]byte(fmt.Sprintf("%d:OK %s,", len(result)+3, result)))
	}

	if !config.Redis.Disable {
		cacheJsonSet(redisClient, cacheKey, CacheStruct{Domain: domain, Result: result, Ttl: resultTtl})
	}
}

func queryDomain(domain string) (string, uint32) {
	result := ""
	var resultTtl uint32 = CACHE_NOTFOUND_TTL
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
			resultTtl = daneTtl
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
			resultTtl = stsTtl
		}
		mutex.Unlock()
	}()

	// Wait for completion
	wg.Wait()

	if result == "" {
		resultTtl = CACHE_NOTFOUND_TTL
		fmt.Printf("No policy found for %s (cached for %ds)\n", domain, resultTtl)
	} else if result == "TEMP" {
		resultTtl = CACHE_MIN_TTL
		fmt.Printf("Evaluating policy for %s failed temporarily (cached for %ds)\n", domain, resultTtl)
	} else {
		resultTtl = findMax([]uint32{CACHE_MIN_TTL, resultTtl})
		fmt.Printf("Evaluated policy for %s: %s (cached for %ds)\n", domain, result, resultTtl)
	}

	return result, resultTtl
}

func cacheJsonGet(redisClient *redis.Client, cacheKey string) (CacheStruct, uint32, error) {
	var data CacheStruct
	jsonData, err := redisClient.Get(ctx, cacheKey).Result()
	if err != nil {
		return data, 0, err
	}
	ttl, err := redisClient.TTL(ctx, cacheKey).Result()
	if err != nil {
		fmt.Println("Error getting TTL:", err)
		return data, 0, err
	}
	err = json.Unmarshal([]byte(jsonData), &data)
	return data, uint32(ttl.Seconds()), err
}

func cacheJsonSet(redisClient *redis.Client, cacheKey string, data CacheStruct) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("error marshaling JSON: %v", err)
	}
	err = redisClient.Set(ctx, cacheKey, jsonData, time.Duration(data.Ttl)*time.Second).Err()
	if err != nil {
		return fmt.Errorf("error setting cache: %v", err)
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

/*
 * MIT License
 * Copyright (c) 2024 Zuplu
 */

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/go-redis/redis/v8"
	"gopkg.in/yaml.v2"
)

const VERSION = "1.0.2"

type ServerConfig struct {
	Address string `yaml:"address"`
	TlsRpt  bool   `yaml:"tlsrpt"`
}

type DNSConfig struct {
	Address string `yaml:"address"`
}

type RedisConfig struct {
	Disable  bool   `yaml:"disable"`
	Address  string `yaml:"address"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type Config struct {
	Server ServerConfig `yaml:"server"`
	DNS    DNSConfig    `yaml:"dns"`
	Redis  RedisConfig  `yaml:"redis"`
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

	if !config.Redis.Disable {
		// Setup redis client for cache
		client = redis.NewClient(&redis.Options{
			Addr:     config.Redis.Address,
			Password: config.Redis.Password,
			DB:       config.Redis.DB,
		})
	}

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

	var cacheKey string
	if !config.Redis.Disable {
		suffix := "!" + VERSION // resets cache after updates
		if config.Server.TlsRpt {
			suffix = suffix + "!TLSRPT" // configurable option needs unique cache key
		}
		hashedDomain := sha256.Sum256([]byte(domain + suffix))
		cacheKey = CACHE_KEY_PREFIX + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hashedDomain[:])
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

	if !config.Redis.Disable {
		client.Set(ctx, cacheKey, result, time.Duration(resultTtl)*time.Second).Err()
	}
}

func loadConfig(filename string) (Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return Config{}, err
	}

	var config Config
	return config, yaml.Unmarshal(data, &config)
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

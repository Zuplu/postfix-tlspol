/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	valid "github.com/asaskevich/govalidator/v11"
	"github.com/miekg/dns"
)

type CacheStruct struct {
	*cache.Expirable
	Policy string
	Report string
	TTL    uint32
}

const (
	CACHE_NOTFOUND_TTL uint32 = 600
	CACHE_MIN_TTL      uint32 = 180
	CACHE_MAX_TTL      uint32 = 2592000
	CACHE_MAX_AGE      uint32 = 86400 // max age for stale queries (only for prefetching, not served)
	REQUEST_TIMEOUT           = 2 * time.Second
)

var (
	Version     = "undefined"
	bgCtx       = context.Background()
	client      = dns.Client{UDPSize: 4096, Timeout: REQUEST_TIMEOUT}
	config      Config
	polCache    *cache.Cache[*CacheStruct]
	NS_NOTFOUND = netstring.Marshal("NOTFOUND ")
	NS_TEMP     = netstring.Marshal("TEMP ")
	NS_PERM     = netstring.Marshal("PERM ")
	NS_TIMEOUT  = netstring.Marshal("TIMEOUT ")
	listener    net.Listener
	serverWg    sync.WaitGroup
	showVersion = false
	showLicense = false
	configFile  string
	cliConnMode = false
)

func init() {
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&showLicense, "license", false, "Show LICENSE")
	flag.StringVar(&configFile, "config", "/etc/postfix-tlspol/config.yaml", "Path to the config.yaml")
	flag.String("query", "", "Query a domain")
	flag.Bool("dump", false, "Dump cache")
	flag.Bool("purge", false, "Manually clear the cache")
}

func StartDaemon(v *string, licenseText *string) {
	Version = *v
	curYear, _, _ := time.Now().Date()

	flag.Parse()

	if showVersion {
		fmt.Printf("postfix-tlspol v%s\n", Version)
		return
	}

	if showLicense {
		fmt.Printf("%s\n", *licenseText)
		return
	}

	// Read config.yaml
	var err error
	config, err = loadConfig(configFile)

	flag.Visit(flagCliConnFunc)

	if cliConnMode {
		return
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	fmt.Fprintf(os.Stderr, "postfix-tlspol (c) 2024-%d Zuplu — v%s\nThis program is licensed under the MIT License.\n", curYear, Version)

	if err != nil {
		log.Errorf("Error loading config: %v", err)
		return
	}

	polCache = cache.New(&CacheStruct{}, config.Server.CacheFile, time.Duration(600*time.Second))
	defer polCache.Close()
	tidyCache()
	listenForSignals()

	readEnv()

	go startPrefetching()
	go startServer()

	select {}
}

func listenForSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGHUP)
	go func() {
		for {
			sig := <-signals
			log.Infof("Received signal: %v, saving cache...", sig)
			tidyCache()
			if sig == syscall.SIGHUP {
				continue
			}
			polCache.Close()
			if listener != nil {
				listener.Close()
				serverWg.Wait()
			}
			os.Exit(0)
			break
		}
	}()
}

func readEnv() {
	envPrefetch, envExists := os.LookupEnv("TLSPOL_PREFETCH")
	if envExists {
		config.Server.Prefetch = envPrefetch == "1"
	}
	envTlsRpt, envExists := os.LookupEnv("TLSPOL_TLSRPT")
	if envExists {
		config.Server.TlsRpt = envTlsRpt == "1"
	}
}

func startServer() {
	var err error
	if strings.HasPrefix(config.Server.Address, "unix:") {
		socketPath := config.Server.Address[5:]
		listener, err = net.Listen("unix", socketPath)
		if err == nil {
			err = os.Chmod(socketPath, config.Server.SocketPermissions)
		}
	} else {
		listener, err = net.Listen("tcp", config.Server.Address)
	}
	if err != nil {
		log.Errorf("Error starting socketmap server: %v", err)
		return
	}
	serverWg.Add(1)
	defer func() {
		listener = nil
		serverWg.Done()
	}()

	log.Infof("Listening on %s...", config.Server.Address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				break
			}
			log.Errorf("Error accepting connection: %v", err)
			break
		}
		go handleConnection(&conn)
	}

	log.Info("Socketmap server terminated.")
}

func tryCachedPolicy(conn *net.Conn, domain *string, withTlsRpt *bool) bool {
	c, found := polCache.Get(*domain)
	if found {
		ttl := c.RemainingTTL()
		if ttl > 0 {
			switch c.Policy {
			case "":
				log.Infof("No policy found for %q (from cache, %s remaining)", *domain, time.Duration(ttl)*time.Second)
				(*conn).Write(NS_NOTFOUND)
			default:
				log.Infof("Evaluated policy for %q: %s (from cache, %s remaining)", *domain, c.Policy, time.Duration(ttl)*time.Second)
				var res string
				if *withTlsRpt {
					res = c.Policy + " " + c.Report
				} else {
					res = c.Policy
				}
				(*conn).Write(netstring.Marshal("OK " + res))
			}
			return true
		}
	}
	return false
}

type DanePolicy struct {
	Policy string `json:"policy"`
	Time   string `json:"time"`
	TTL    uint32 `json:"ttl"`
}
type MtaStsPolicy struct {
	Policy string `json:"policy"`
	Report string `json:"report"`
	Time   string `json:"time"`
	TTL    uint32 `json:"ttl"`
}
type Result struct {
	Version string       `json:"version"`
	Domain  string       `json:"domain"`
	Dane    DanePolicy   `json:"dane"`
	MtaSts  MtaStsPolicy `json:"mta-sts"`
}

func replyJson(ctx *context.Context, conn *net.Conn, domain *string) {
	ta := time.Now()
	var (
		wg    sync.WaitGroup
		tb    time.Time = ta
		dPol  string
		dTTL  uint32
		tc    time.Time = ta
		msPol string
		msRpt string
		msTTL uint32
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		dPol, dTTL = checkDane(ctx, domain, true)
		tb = time.Now()
	}()
	go func() {
		defer wg.Done()
		msPol, msRpt, msTTL = checkMtaSts(ctx, domain, true)
		tc = time.Now()
	}()
	wg.Wait()
	r := Result{
		Version: Version,
		Domain:  *domain,
		Dane: DanePolicy{
			Policy: dPol,
			TTL:    dTTL,
			Time:   tb.Sub(ta).Truncate(time.Millisecond).String(),
		},
		MtaSts: MtaStsPolicy{
			Policy: msPol,
			TTL:    msTTL,
			Report: msRpt,
			Time:   tc.Sub(ta).Truncate(time.Millisecond).String(),
		},
	}

	b, err := json.Marshal(r)
	if err != nil {
		log.Errorf("Could not marshal JSON: %v", err)
		return
	}

	(*conn).Write(append(b, '\n'))
}

func replySocketmap(conn *net.Conn, domain *string, policy *string, report *string, ttl *uint32, withTlsRpt *bool) {
	switch *policy {
	case "":
		log.Infof("No policy found for %q (cached for %s)", *domain, time.Duration(*ttl)*time.Second)
		(*conn).Write(NS_NOTFOUND)
	case "TEMP":
		log.Warnf("Evaluating policy for %q failed temporarily (cached for %s)", *domain, time.Duration(*ttl)*time.Second)
		(*conn).Write(NS_TEMP)
	default:
		log.Infof("Evaluated policy for %q: %s (cached for %s)", *domain, *policy, time.Duration(*ttl)*time.Second)
		res := *policy
		if *withTlsRpt {
			res = res + " " + *report
		}
		(*conn).Write(netstring.Marshal("OK " + res))
	}
}

func handleConnection(conn *net.Conn) {
	defer (*conn).Close()

	ns := netstring.NewScanner(*conn)

	workChan := make(chan bool, 1)
	for ns.Scan() {
		go func(query string) {
			parts := strings.SplitN(query, " ", 2)
			cmd := strings.ToUpper(parts[0])
			withTlsRpt := config.Server.TlsRpt
			switch cmd {
			case "QUERYWITHTLSRPT": // QUERYwithTLSRPT
				withTlsRpt = true
			case "QUERY", "JSON":
			case "DUMP":
				dumpCachedPolicies(conn)
				workChan <- false
				return
			case "PURGE":
				purgeCache(conn)
				workChan <- false
				return
			default:
				log.Warnf("Unknown command: %q", query)
				(*conn).Write(NS_PERM)
				workChan <- false
				return
			}
			if len(parts) != 2 { // empty query
				(*conn).Write(NS_NOTFOUND)
				workChan <- true
				return
			}

			domain := normalizeDomain(parts[1])

			if cmd == "JSON" {
				ctx, cancel := context.WithTimeout(bgCtx, 2*REQUEST_TIMEOUT)
				defer cancel()
				replyJson(&ctx, conn, &domain)
				workChan <- true
				return
			}

			if !valid.IsDNSName(domain) || strings.HasPrefix(domain, ".") {
				(*conn).Write(NS_NOTFOUND)
				workChan <- true
				return
			}

			if tryCachedPolicy(conn, &domain, &withTlsRpt) {
				workChan <- true
				return
			}

			policy, report, ttl := queryDomain(&domain)

			replySocketmap(conn, &domain, &policy, &report, &ttl, &withTlsRpt)

			if ttl != 0 {
				now := time.Now()
				polCache.Set(domain, &CacheStruct{Policy: policy, Report: report, TTL: ttl, Expirable: &cache.Expirable{ExpiresAt: now.Add(time.Duration(ttl+rand.Uint32N(15)) * time.Second), LastUpdate: now}})
			}
			workChan <- true
		}(ns.Text())
		if !<-workChan {
			return
		}
	}
}

type PolicyResult struct {
	Policy string
	Report string
	TTL    uint32
	IsDane bool
}

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func queryDomain(domain *string) (string, string, uint32) {
	results := make(chan PolicyResult)
	ctx, cancel := context.WithTimeout(bgCtx, 2*REQUEST_TIMEOUT)
	defer cancel()

	// DANE query
	go func() {
		policy, ttl := checkDane(&ctx, domain, true)
		results <- PolicyResult{IsDane: true, Policy: policy, Report: "", TTL: ttl}
	}()

	// MTA-STS query
	go func() {
		policy, rpt, ttl := checkMtaSts(&ctx, domain, true)
		results <- PolicyResult{IsDane: false, Policy: policy, Report: rpt, TTL: ttl}
	}()

	policy, report := "", ""
	var ttl uint32 = CACHE_NOTFOUND_TTL
	var i uint8 = 0
	for r := range results {
		i++
		if i >= 2 {
			close(results)
		}
		if r.Policy == "" {
			continue
		}
		policy = r.Policy
		report = r.Report
		ttl = r.TTL
		if r.IsDane {
			break
		}
	}

	if ttl < CACHE_MIN_TTL {
		ttl = CACHE_MIN_TTL
	} else if ttl > CACHE_MAX_TTL {
		ttl = CACHE_MAX_TTL
	}
	if policy == "" {
		ttl = CACHE_NOTFOUND_TTL
	} else if policy == "TEMP" {
		ttl = 0
	}

	return policy, report, ttl
}

func dumpCachedPolicies(conn *net.Conn) {
	tidyCache()
	items := polCache.Items()
	now := time.Now()
	for _, entry := range items {
		remainingTTL := entry.Value.RemainingTTL(now)
		if entry.Value.Policy == "" || remainingTTL == 0 {
			continue
		}
		fmt.Fprintf(*conn, "%-21s %s\n", entry.Key, entry.Value.Policy)
	}
}

func purgeCache(conn *net.Conn) {
	polCache.Purge()
	fmt.Fprintln(*conn, "OK")
}

func tidyCache() {
	defer polCache.Save()
	items := polCache.Items()
	now := time.Now()
	for _, entry := range items {
		// Cleanup v1.8.0 bug that duplicated cache entries
		if strings.Contains(entry.Value.Policy, "policy_type") || normalizeDomain(entry.Key) != entry.Key {
			polCache.Remove(entry.Key)
			continue
		}
		if (entry.Value.Policy == "" || entry.Value.Age(now) >= CACHE_MAX_AGE) && entry.Value.RemainingTTL(now) == 0 {
			polCache.Remove(entry.Key)
		}
	}
}

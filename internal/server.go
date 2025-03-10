/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
 */

package tlspol

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/log"
	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	valid "github.com/asaskevich/govalidator/v11"
	"github.com/miekg/dns"
	"github.com/neilotoole/jsoncolor"
)

type CacheStruct struct {
	*cache.Expirable
	Domain string
	Policy string
	Report string
	TTL    uint32
}

const (
	CACHE_NOTFOUND_TTL = 600
	CACHE_MIN_TTL      = 180
	REQUEST_TIMEOUT    = 4 * time.Second
)

var (
	Version     = "undefined"
	bgCtx       = context.Background()
	client      = dns.Client{Timeout: REQUEST_TIMEOUT}
	config      Config
	polCache    *cache.Cache[*CacheStruct]
	NS_NOTFOUND = netstring.Marshal("NOTFOUND ")
	NS_TEMP     = netstring.Marshal("TEMP ")
	NS_PERM     = netstring.Marshal("PERM ")
	NS_TIMEOUT  = netstring.Marshal("TIMEOUT ")
)

var showVersion = false
var showLicense = false
var configFile string
var queryMode = false
var purgeCache = false

func init() {
	flag.BoolVar(&showVersion, "version", false, "Show version")
	flag.BoolVar(&showLicense, "license", false, "Show LICENSE")
	flag.StringVar(&configFile, "config", "/etc/postfix-tlspol/config.yaml", "Path to the config.yaml")
	flag.String("query", "", "Query a domain")
	flag.BoolVar(&purgeCache, "purge", false, "Manually clear the cache")
}

func flagQueryFunc(f *flag.Flag) {
	if (*f).Name != "query" {
		return
	}
	queryMode = true
	domain := (*f).Value.String()
	if len(domain) == 0 || !valid.IsDNSName(domain) {
		log.Errorf("Invalid domain: %q", domain)
		return
	}
	var conn net.Conn
	var err error
	if strings.HasPrefix(config.Server.Address, "unix:") {
		conn, err = net.Dial("unix", config.Server.Address[5:])
	} else {
		conn, err = net.Dial("tcp", config.Server.Address)
	}
	if err != nil {
		log.Errorf("Could not query domain %q. Is postfix-tlspol running? (%v)", domain, err)
		return
	}
	defer conn.Close()
	conn.Write(netstring.Marshal("JSON " + domain))
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

	flag.Visit(flagQueryFunc)

	if queryMode {
		return
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	fmt.Fprintf(os.Stderr, "postfix-tlspol (c) 2024-%d Zuplu — v%s\nThis program is licensed under the MIT License.\n\n", curYear, Version)

	if err != nil {
		log.Errorf("Error loading config: %v", err)
		return
	}

	polCache = cache.New(&CacheStruct{}, config.Server.CacheFile, time.Duration(600*time.Second))
	defer polCache.Close()
	go func() {
		items := polCache.Items()
		for _, entry := range items {
			remainingTTL := entry.Value.RemainingTTL()
			if entry.Value.Policy == "" || entry.Value.TTL <
				PREFETCH_MARGIN {
				if remainingTTL == 0 {
					polCache.Remove(entry.Key)
				}
			}
			// Cleanup v1.8.0 bug that duplicated cache entries
			if strings.Contains(entry.Value.Policy, "policy_type") {
				polCache.Remove(entry.Key)
			}
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGHUP)
	go func() {
		sig := <-signals
		log.Infof("Received signal: %v, saving cache...", sig)
		polCache.Close()
		os.Exit(0)
	}()

	envPrefetch, envExists := os.LookupEnv("TLSPOL_PREFETCH")
	if envExists {
		config.Server.Prefetch = envPrefetch == "1"
	}
	envTlsRpt, envExists := os.LookupEnv("TLSPOL_TLSRPT")
	if envExists {
		config.Server.TlsRpt = envTlsRpt == "1"
	}

	if config.Server.Prefetch {
		log.Info("Prefetching enabled!")
		go startPrefetching()
	}

	if purgeCache {
		polCache.Purge()
		log.Info("Cache purged!")
		return
	}

	// Start the socketmap server for Postfix
	startServer()
}

func startServer() {
	var listener net.Listener
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
	defer listener.Close()

	log.Infof("Listening on %s...", config.Server.Address)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("Error accepting connection: %v", err)
			continue
		}
		go handleConnection(&conn)
	}
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
			case "TEMP":
				log.Warnf("Evaluating policy for %q failed temporarily (from cache, %s remaining)", *domain, time.Duration(ttl)*time.Second)
				(*conn).Write(NS_TEMP)
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
	TTL    uint32 `json:"ttl"`
	Time   string `json:"time"`
}
type MtaStsPolicy struct {
	Policy string `json:"policy"`
	TTL    uint32 `json:"ttl"`
	Report string `json:"report"`
	Time   string `json:"time"`
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
		dPol, dTTL = checkDane(ctx, domain)
		tb = time.Now()
	}()
	go func() {
		defer wg.Done()
		msPol, msRpt, msTTL = checkMtaSts(ctx, domain)
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
			res = res + " " + (*report)
		}
		(*conn).Write(netstring.Marshal("OK " + res))
	}
}

func handleConnection(conn *net.Conn) {
	defer (*conn).Close()

	ns := netstring.NewScanner(*conn)

	for ns.Scan() {
		query := ns.Text()
		parts := strings.SplitN(query, " ", 2)
		cmd := strings.ToUpper(parts[0])
		withTlsRpt := config.Server.TlsRpt
		switch cmd {
		case "QUERYWITHTLSRPT": // QUERYwithTLSRPT
			withTlsRpt = true
		case "QUERY", "JSON":
		default:
			log.Warnf("Unknown command: %q", query)
			(*conn).Write(NS_PERM)
			return
		}
		if len(parts) != 2 { // empty query
			(*conn).Write(NS_NOTFOUND)
			continue
		}

		domain := strings.ToLower(strings.TrimSpace(parts[1]))

		if cmd == "JSON" {
			ctx, cancel := context.WithTimeout(bgCtx, REQUEST_TIMEOUT)
			defer cancel()
			replyJson(&ctx, conn, &domain)
			continue
		}

		if !valid.IsDNSName(domain) || strings.HasPrefix(domain, ".") {
			(*conn).Write(NS_NOTFOUND)
			continue
		}

		if tryCachedPolicy(conn, &domain, &withTlsRpt) {
			continue
		}

		policy, report, ttl := queryDomain(&domain)

		replySocketmap(conn, &domain, &policy, &report, &ttl, &withTlsRpt)

		polCache.Set(domain, &CacheStruct{Domain: domain, Policy: policy, Report: report, TTL: ttl, Expirable: &cache.Expirable{ExpiresAt: time.Now().Add(time.Duration(ttl) * time.Second)}})
	}
}

type PolicyResult struct {
	IsDane bool
	Policy string
	Report string
	TTL    uint32
}

func queryDomain(domain *string) (string, string, uint32) {
	results := make(chan PolicyResult)
	ctx, cancel := context.WithTimeout(bgCtx, REQUEST_TIMEOUT)
	defer cancel()

	// DANE query
	go func() {
		policy, ttl := checkDane(&ctx, domain)
		results <- PolicyResult{IsDane: true, Policy: policy, Report: "", TTL: ttl}
	}()

	// MTA-STS query
	go func() {
		policy, rpt, ttl := checkMtaSts(&ctx, domain)
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

	if policy == "" {
		ttl = CACHE_NOTFOUND_TTL
	} else if policy == "TEMP" || ttl < CACHE_MIN_TTL {
		ttl = CACHE_MIN_TTL
	}

	return policy, report, ttl
}

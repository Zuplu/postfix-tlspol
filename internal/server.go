/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/cache"
	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

type CacheStruct struct {
	*cache.Expirable
	Policy  string
	Report  string
	TTL     uint32
	Counter uint32
}

func cloneCacheStruct(c *CacheStruct) *CacheStruct {
	if c == nil {
		return &CacheStruct{
			Expirable: &cache.Expirable{},
		}
	}
	cloned := *c
	if c.Expirable == nil {
		cloned.Expirable = &cache.Expirable{}
	} else {
		expirable := *c.Expirable
		cloned.Expirable = &expirable
	}
	return &cloned
}

const (
	CACHE_NOTFOUND_TTL uint32 = 600
	CACHE_MIN_TTL      uint32 = 180
	CACHE_MAX_TTL      uint32 = 2592000
	CACHE_MAX_AGE      uint32 = 1800 // max age for stale queries (only for prefetching, not served to postfix)
	REQUEST_TIMEOUT           = 2 * time.Second
)

var (
	Version     = "undefined"
	bgCtx       = context.Background()
	levelVar    = new(slog.LevelVar)
	queryGroup  singleflight.Group
	client      = dns.Client{UDPSize: 4096, Timeout: REQUEST_TIMEOUT}
	config      Config
	polCache    *cache.Cache[*CacheStruct]
	NS_NOTFOUND = netstring.Marshal("NOTFOUND ")
	NS_TEMP     = netstring.Marshal("TEMP ")
	NS_PERM     = netstring.Marshal("PERM ")
	NS_TIMEOUT  = netstring.Marshal("TIMEOUT ")
	listeners   []net.Listener
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
	flag.Bool("dump", false, "Dump cache with query counter")
	flag.Bool("export", false, "Dump cache in postfix hash format")
	flag.Bool("purge", false, "Manually clear the cache")
}

func StartDaemon(v string, licenseText string) {
	Version = v
	curYear, _, _ := time.Now().Date()

	flag.Parse()

	if showVersion {
		fmt.Printf("postfix-tlspol v%s\n", Version)
		return
	}

	if showLicense {
		fmt.Printf("%s\n", licenseText)
		return
	}

	// Read config.yaml
	var err error
	config, err = loadConfig(configFile)
	if err != nil {
		slog.Error("Error loading config", "error", err)
		return
	}
	levelVar.Set(config.Server.LogLevel)
	handlerOpts := &slog.HandlerOptions{
		Level: levelVar,
	}
	var handler slog.Handler
	if strings.ToLower(strings.TrimSpace(config.Server.LogFormat)) == "json" {
		handler = slog.NewJSONHandler(os.Stdout, handlerOpts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, handlerOpts)
	}
	slog.SetDefault(slog.New(handler))

	flag.Visit(flagCliConnFunc)

	if cliConnMode {
		return
	}

	if len(os.Args) < 2 {
		flag.PrintDefaults()
		return
	}

	fmt.Fprintf(os.Stderr, "postfix-tlspol (c) 2024-%d Zuplu — v%s\nThis program is licensed under the MIT License.\n", curYear, Version)

	polCache = cache.New[*CacheStruct](config.Server.CacheFile, time.Duration(600*time.Second))
	defer polCache.Close()
	defer func() {
		stopMetricStatsPersistence()
		if err := saveMetricStats(true); err != nil {
			slog.Warn("Could not save metric stats", "error", err)
		}
	}()
	_ = tidyCache()
	if err := loadMetricStats(); err != nil {
		slog.Warn("Could not load metric stats", "error", err)
	}
	startMetricStatsPersistence()
	listenForSignals()

	readEnv()

	go startPrefetching()
	go startServer()

	select {}
}

func listenForSignals() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		for {
			sig := <-signals
			slog.Info("Received signal, saving cache...", "signal", sig)
			_ = tidyCache()
			if err := saveMetricStats(true); err != nil {
				slog.Warn("Could not save metric stats", "error", err)
			}
			if sig == syscall.SIGHUP {
				continue
			}
			polCache.Close()
			if len(listeners) > 0 {
				for _, l := range listeners {
					if l != nil {
						l.Close()
					}
				}
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

func listenSystemdSocket() ([]net.Listener, bool, error) {
	listenPID, ok := os.LookupEnv("LISTEN_PID")
	if !ok {
		return nil, false, nil
	}
	pid, err := strconv.Atoi(strings.TrimSpace(listenPID))
	if err != nil || pid != os.Getpid() {
		return nil, false, nil
	}

	listenFDS, ok := os.LookupEnv("LISTEN_FDS")
	if !ok {
		return nil, false, nil
	}
	fds, err := strconv.Atoi(strings.TrimSpace(listenFDS))
	if err != nil || fds < 1 {
		return nil, false, nil
	}

	listeners := make([]net.Listener, 0, fds)
	for i := 0; i < fds; i++ {
		fdNum := uintptr(3 + i)
		fdFile := os.NewFile(fdNum, fmt.Sprintf("systemd-listen-fd-%d", fdNum))
		if fdFile == nil {
			for _, existing := range listeners {
				existing.Close()
			}
			return nil, false, fmt.Errorf("could not open inherited systemd socket fd %d", fdNum)
		}

		l, err := net.FileListener(fdFile)
		fdFile.Close()
		if err != nil {
			for _, existing := range listeners {
				existing.Close()
			}
			return nil, false, fmt.Errorf("failed to inherit socket activation fd %d: %w", fdNum, err)
		}
		listeners = append(listeners, l)
	}

	_ = os.Unsetenv("LISTEN_PID")
	_ = os.Unsetenv("LISTEN_FDS")
	_ = os.Unsetenv("LISTEN_FDNAMES")

	return listeners, true, nil
}

func serveListener(l net.Listener) {
	defer serverWg.Done()

	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				break
			}
			addr := l.Addr()
			if addr == nil {
				slog.Error("Error accepting connection", "error", err, "network", "<unknown>", "address", "<unknown>")
			} else {
				slog.Error("Error accepting connection", "error", err, "network", addr.Network(), "address", addr.String())
			}
			break
		}
		go handleConnection(conn)
	}
}

func startServer() {
	var err error
	listeners, inherited, err := listenSystemdSocket()
	if err != nil {
		slog.Error("Error inheriting systemd-activated socket", "error", err)
		os.Exit(1)
	}

	if !inherited {
		var directListener net.Listener
		if strings.HasPrefix(config.Server.Address, "unix:") {
			socketPath := config.Server.Address[5:]
			err = os.Remove(socketPath)
			if err == nil || os.IsNotExist(err) {
				directListener, err = net.Listen("unix", socketPath)
				if err == nil {
					err = os.Chmod(socketPath, config.Server.SocketPermissions)
				}
			}
		} else {
			directListener, err = net.Listen("tcp", config.Server.Address)
		}
		if err == nil {
			listeners = []net.Listener{directListener}
		}
	} else {
		slog.Info("Using systemd socket activation")
	}
	if err != nil {
		slog.Error("Error starting socketmap server", "error", err)
		os.Exit(1)
	}

	if len(listeners) == 0 {
		slog.Error("Error starting socketmap server", "error", "no listeners available")
		os.Exit(1)
	}

	if inherited {
		for _, l := range listeners {
			addr := l.Addr()
			if addr == nil {
				slog.Info("Server listening", "activation", "systemd", "network", "<unknown>", "address", "<unknown>")
				continue
			}
			slog.Info("Server listening", "activation", "systemd", "network", addr.Network(), "address", addr.String())
		}
		slog.Warn("Ignoring configured server.address because systemd socket activation is active", "configured_address", config.Server.Address)
		slog.Info("Listening on all systemd-provided sockets", "count", len(listeners))
	} else {
		addr := listeners[0].Addr()
		if addr == nil {
			slog.Info("Server listening", "activation", "direct", "network", "<unknown>", "address", "<unknown>")
		} else {
			slog.Info("Server listening", "activation", "direct", "network", addr.Network(), "address", addr.String())
		}
	}

	defer func() {
		listeners = nil
	}()

	serverWg.Add(len(listeners))
	for _, l := range listeners {
		go serveListener(l)
	}
	serverWg.Wait()

	slog.Info("Socketmap server terminated")
}

func tryCachedPolicy(conn net.Conn, domain string, withTlsRpt bool) (*CacheStruct, bool) {
	c, found := polCache.Get(domain)
	if found {
		ttl := c.RemainingTTL()
		if ttl > 0 {
			switch c.Policy {
			case "":
				slog.Info("No policy found", "origin", "cache", "domain", domain, "ttl", ttl)
				conn.Write(NS_NOTFOUND)
			default:
				slog.Info("Evaluated policy", "origin", "cache", "domain", domain, "policy", firstWord(c.Policy), "ttl", ttl)
				var res string
				if withTlsRpt {
					res = c.Policy + " " + c.Report
				} else {
					res = c.Policy
				}
				conn.Write(netstring.Marshal("OK " + res))
			}
			observePolicy(c.Policy)
			updated := cloneCacheStruct(c)
			updated.Counter++
			polCache.Set(domain, updated)
			return updated, true
		}
	}
	return c, false
}

type DanePolicy struct {
	Policy string  `json:"policy"`
	Time   float64 `json:"time"`
	TTL    uint32  `json:"ttl"`
}
type MtaStsPolicy struct {
	Policy string  `json:"policy"`
	Report string  `json:"report"`
	Time   float64 `json:"time"`
	TTL    uint32  `json:"ttl"`
}
type Result struct {
	Version string       `json:"version"`
	Domain  string       `json:"domain"`
	Dane    DanePolicy   `json:"dane"`
	MtaSts  MtaStsPolicy `json:"mta-sts"`
}

func replyJson(ctx context.Context, conn net.Conn, domain string) {
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
		Domain:  domain,
		Dane: DanePolicy{
			Policy: dPol,
			TTL:    dTTL,
			Time:   tb.Sub(ta).Truncate(time.Millisecond).Seconds(),
		},
		MtaSts: MtaStsPolicy{
			Policy: msPol,
			TTL:    msTTL,
			Report: msRpt,
			Time:   tc.Sub(ta).Truncate(time.Millisecond).Seconds(),
		},
	}

	b, err := json.Marshal(r)
	if err != nil {
		slog.Error("Could not marshal JSON", "error", err)
		return
	}

	conn.Write(append(b, '\n'))
}

func replySocketmap(conn net.Conn, domain string, policy string, report string, ttl uint32, withTlsRpt bool) {
	switch policy {
	case "":
		slog.Info("No policy found", "origin", "network", "domain", domain, "ttl", ttl)
		conn.Write(NS_NOTFOUND)
	case "TEMP":
		slog.Warn("Evaluating policy failed temporarily", "origin", "network", "domain", domain, "ttl", ttl)
		conn.Write(NS_TEMP)
	default:
		slog.Info("Evaluated policy", "origin", "network", "domain", domain, "policy", firstWord(policy), "ttl", ttl)
		res := policy
		if withTlsRpt {
			res = res + " " + report
		}
		conn.Write(netstring.Marshal("OK " + res))
	}
	observePolicy(policy)
}

func isLikelyHTTP(reader *bufio.Reader) bool {
	b, err := reader.ReadByte()
	if err != nil {
		return false
	}
	_ = reader.UnreadByte()
	if b >= '0' && b <= '9' {
		return false
	}
	if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
		return true
	}
	return false
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	if isLikelyHTTP(reader) {
		handleHTTPConnection(conn, reader)
		return
	}
	handleSocketmapConnection(conn, reader)
}

func handleHTTPConnection(conn net.Conn, reader *bufio.Reader) {
	writer := bufio.NewWriter(conn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}
		_ = req.Body.Close()

		shouldClose := req.Close || (req.ProtoMajor == 1 && req.ProtoMinor == 0 && !strings.EqualFold(req.Header.Get("Connection"), "keep-alive"))
		resp := &http.Response{
			Proto:      req.Proto,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
			Header:     make(http.Header),
			Close:      shouldClose,
		}

		if req.URL.Path == "/metrics" && (req.Method == http.MethodGet || req.Method == http.MethodHead) {
			body := buildMetricsText()
			resp.StatusCode = http.StatusOK
			resp.Status = "200 OK"
			resp.Header.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			resp.ContentLength = int64(len(body))
			if req.Method == http.MethodGet {
				resp.Body = io.NopCloser(strings.NewReader(body))
			} else {
				resp.Body = http.NoBody
			}
		} else {
			body := "not found\n"
			resp.StatusCode = http.StatusNotFound
			resp.Status = "404 Not Found"
			resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
			resp.ContentLength = int64(len(body))
			if req.Method == http.MethodHead {
				resp.Body = http.NoBody
			} else {
				resp.Body = io.NopCloser(strings.NewReader(body))
			}
		}

		if err := resp.Write(writer); err != nil {
			return
		}
		if err := writer.Flush(); err != nil {
			return
		}
		if shouldClose {
			return
		}
	}
}

//gocyclo:ignore
func handleSocketmapConnection(conn net.Conn, reader io.Reader) {
	ns := netstring.NewScanner(reader)

	for ns.Scan() {
		query := ns.Text()
		parts := strings.SplitN(query, " ", 2)
		cmd := strings.ToUpper(parts[0])
		withTlsRpt := config.Server.TlsRpt
		switch cmd {
		case "QUERYWITHTLSRPT": // QUERYwithTLSRPT
			withTlsRpt = true
			addMetricQuery()
		case "QUERY":
			addMetricQuery()
		case "JSON":
		case "DUMP":
			dumpCachedPolicies(conn, false)
			return
		case "EXPORT":
			dumpCachedPolicies(conn, true)
			return
		case "PURGE":
			purgeCache(conn)
			return
		default:
			slog.Warn("Unknown command", "query", query)
			conn.Write(NS_PERM)
			return
		}
		if len(parts) != 2 { // empty query
			conn.Write(NS_NOTFOUND)
			continue
		}

		domain := normalizeDomain(parts[1])

		if cmd == "JSON" {
			ctx, cancel := context.WithTimeout(bgCtx, 2*REQUEST_TIMEOUT)
			replyJson(ctx, conn, domain)
			cancel()
			continue
		}

		if !valid.IsDNSName(domain) || strings.HasPrefix(domain, ".") {
			conn.Write(NS_NOTFOUND)
			continue
		}

		c, found := tryCachedPolicy(conn, domain, withTlsRpt)
		if found {
			continue
		}

		policy, report, ttl := queryDomain(domain)

		replySocketmap(conn, domain, policy, report, ttl, withTlsRpt)

		if ttl != 0 {
			now := time.Now()
			cs := cloneCacheStruct(c)
			if c == nil {
				cs.Counter = 1
			} else {
				cs.Counter++
			}
			cs.Policy = policy
			cs.Report = report
			cs.TTL = ttl
			cs.Expirable.ExpiresAt = now.Add(time.Duration(ttl+rand.Uint32N(20)) * time.Second)
			polCache.Set(domain, cs)
		}
	}
}

type PolicyResult struct {
	Policy string
	Report string
	TTL    uint32
	IsDane bool
}

type domainResult struct {
	Policy string
	Report string
	TTL    uint32
}

var queryDomainOnce = queryDomainOnceImpl

func normalizeDomain(domain string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
}

func queryDomain(domain string) (string, string, uint32) {
	res, _, _ := queryGroup.Do(domain, func() (any, error) {
		pol, rpt, ttl := queryDomainOnce(domain)
		return domainResult{Policy: pol, Report: rpt, TTL: ttl}, nil
	})
	dr := res.(domainResult)
	return dr.Policy, dr.Report, dr.TTL
}

func queryDomainOnceImpl(domain string) (string, string, uint32) {
	results := make(chan PolicyResult, 2)
	ctx, cancel := context.WithTimeout(bgCtx, 2*REQUEST_TIMEOUT+time.Second) // one retry may add up to ~750ms delay between attempts
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(2)

	// DANE query
	go func() {
		defer wg.Done()
		policy, ttl := checkDane(ctx, domain, true)
		if ctx.Err() == nil {
			select {
			case results <- PolicyResult{IsDane: true, Policy: policy, Report: "", TTL: ttl}:
			case <-ctx.Done():
			}
		}
	}()

	// MTA-STS query
	go func() {
		defer wg.Done()
		policy, rpt, ttl := checkMtaSts(ctx, domain, true)
		if ctx.Err() == nil {
			select {
			case results <- PolicyResult{IsDane: false, Policy: policy, Report: rpt, TTL: ttl}:
			case <-ctx.Done():
			}
		}
	}()

	go func() {
		wg.Wait()
		cancel()
		close(results)
	}()

	policy, report := "", ""
	var ttl uint32 = CACHE_NOTFOUND_TTL
	for r := range results {
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

func dumpCachedPolicies(conn net.Conn, export bool) {
	items := tidyCache()
	sort.Slice(items, func(i, j int) bool {
		if items[i].Value.Counter != items[j].Value.Counter {
			return items[i].Value.Counter > items[j].Value.Counter
		}
		return items[i].Key < items[j].Key
	})
	now := time.Now()
	for _, entry := range items {
		remainingTTL := entry.Value.RemainingTTL(now)
		if entry.Value.Policy == "" || remainingTTL < PREFETCH_INTERVAL+1 {
			continue
		}
		if export {
			fmt.Fprintf(conn, "%-28s %s\n", entry.Key, entry.Value.Policy)
		} else {
			fmt.Fprintf(conn, "%-28s  %6d  %s\n", entry.Key, entry.Value.Counter, entry.Value.Policy)
		}
	}
}

func purgeCache(conn net.Conn) {
	polCache.Purge()
	fmt.Fprintln(conn, "OK")
}

func tidyCache() []cache.Entry[*CacheStruct] {
	polCache.Lock()
	defer polCache.Unlock()
	defer polCache.Save(true)
	items := polCache.Items(true)
	now := time.Now()
	var entries []cache.Entry[*CacheStruct]
	for _, entry := range items {
		removeExpiredNoPolicy := entry.Value.Policy == "" && entry.Value.RemainingTTL(now) == 0
		removeStalePolicy := entry.Value.Age(now) >= CACHE_MAX_AGE
		removeLegacyBadPolicy := strings.Contains(entry.Value.Report, "mx_host_pattern=.") || strings.Contains(entry.Value.Policy, "match= ")
		if removeExpiredNoPolicy || removeStalePolicy || removeLegacyBadPolicy {
			polCache.Remove(true, entry.Key)
		} else {
			entries = append(entries, entry)
		}
	}
	return entries
}

func firstWord(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return s[:i]
		}
	}
	return s
}
